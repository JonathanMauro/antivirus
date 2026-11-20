//! Scanner de arquivos e pastas.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
#[cfg(feature = "yara")]
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use walkdir::WalkDir;

use crate::analysis::{analyze_bytes, analyze_file, FileFacts};
use crate::classify::ThreatCategory;
use crate::heuristics::{self, Indicator};
use crate::pe::{self, PeInfo};
use crate::signatures::SignatureDb;
use crate::yara::YaraMatch;
#[cfg(feature = "yara")]
use crate::yara::YaraRules;

/// Risk Score a partir do qual um arquivo é considerado suspeito.
pub const SUSPICIOUS_THRESHOLD: u8 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub verdict: Verdict,
    /// Pontuação de 0 a 100.
    pub risk_score: u8,
    /// Nome da ameaça (assinatura ou regra YARA maliciosa).
    pub threat_name: Option<String>,
    /// Categoria da ameaça; `None` quando o arquivo está limpo.
    pub category: Option<ThreatCategory>,
    /// Motivos da detecção (base do "relatório inteligente").
    pub indicators: Vec<Indicator>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanError {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanReport {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub skipped_too_large: u64,
    /// Apenas arquivos com veredito diferente de `Clean`.
    pub detections: Vec<Detection>,
    pub errors: Vec<ScanError>,
    /// Verdadeiro se a varredura foi interrompida pelo callback.
    pub cancelled: bool,
    #[serde(with = "duration_ms")]
    pub elapsed: Duration,
}

impl ScanReport {
    pub fn has_threats(&self) -> bool {
        !self.detections.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Arquivos maiores que isto são ignorados (0 = sem limite).
    pub max_file_size: u64,
    pub follow_symlinks: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: 512 * 1024 * 1024,
            follow_symlinks: false,
        }
    }
}

/// Arquivos até este tamanho recebem análise profunda (PE + YARA), que exige
/// o conteúdo em memória. Acima disso, apenas hash e cabeçalho.
pub const DEEP_ANALYSIS_MAX: u64 = 64 * 1024 * 1024;

pub struct Scanner {
    db: SignatureDb,
    config: ScanConfig,
    #[cfg(feature = "yara")]
    yara: Option<Arc<YaraRules>>,
}

impl Scanner {
    pub fn new(db: SignatureDb, config: ScanConfig) -> Self {
        Self {
            db,
            config,
            #[cfg(feature = "yara")]
            yara: None,
        }
    }

    /// Ativa as regras YARA neste scanner.
    #[cfg(feature = "yara")]
    pub fn with_yara(mut self, rules: Arc<YaraRules>) -> Self {
        self.yara = Some(rules);
        self
    }

    pub fn signatures(&self) -> &SignatureDb {
        &self.db
    }

    /// Quantidade de regras YARA ativas.
    pub fn yara_rule_count(&self) -> usize {
        #[cfg(feature = "yara")]
        {
            self.yara.as_ref().map_or(0, |r| r.len())
        }
        #[cfg(not(feature = "yara"))]
        {
            0
        }
    }

    fn yara_scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        #[cfg(feature = "yara")]
        if let Some(rules) = &self.yara {
            // Falha de YARA (ex.: timeout) não impede o restante da análise.
            return rules.scan(data).unwrap_or_default();
        }
        let _ = data;
        Vec::new()
    }

    /// Classifica um arquivo combinando assinaturas, YARA e heurísticas.
    ///
    /// Prioridade do veredito:
    /// 1. hash na base de assinaturas → MALICIOSO;
    /// 2. regra YARA marcada `malicious = true` → MALICIOSO;
    /// 3. soma das pontuações (heurísticas + regras YARA) ≥ 40 → SUSPEITO.
    pub fn classify(
        &self,
        path: &Path,
        facts: &FileFacts,
        pe: Option<&PeInfo>,
        yara: &[YaraMatch],
    ) -> Detection {
        let file_name = path.file_name().and_then(|n| n.to_str());
        let mut indicators = heuristics::evaluate(file_name, facts, pe);
        for m in yara {
            indicators.push(Indicator {
                id: "yara_rule",
                description: match &m.description {
                    Some(d) => format!("regra YARA '{}': {d}", m.rule),
                    None => format!("regra YARA '{}'", m.rule),
                },
                score: m.score,
            });
        }

        let (verdict, risk_score, threat_name, category) =
            if let Some(sig) = self.db.lookup_entry(&facts.sha256) {
                indicators.insert(
                    0,
                    Indicator {
                        id: "signature_match",
                        description: format!("hash corresponde à assinatura '{}'", sig.name),
                        score: 100,
                    },
                );
                (
                    Verdict::Malicious,
                    100,
                    Some(sig.name.clone()),
                    Some(sig.category.unwrap_or(ThreatCategory::Generic)),
                )
            } else if let Some(m) = yara.iter().find(|m| m.malicious) {
                let name = m.threat.clone().unwrap_or_else(|| m.rule.clone());
                let category = m
                    .category
                    .or_else(|| ThreatCategory::infer(&name))
                    .unwrap_or(ThreatCategory::Generic);
                (Verdict::Malicious, 100, Some(name), Some(category))
            } else {
                let score: u32 = indicators.iter().map(|i| i.score as u32).sum();
                let score = score.min(100) as u8;
                if score >= SUSPICIOUS_THRESHOLD {
                    // Categoria da regra YARA mais forte, ou genérica.
                    let category = yara
                        .iter()
                        .find_map(|m| m.category)
                        .unwrap_or(ThreatCategory::Generic);
                    (Verdict::Suspicious, score, None, Some(category))
                } else {
                    (Verdict::Clean, score, None, None)
                }
            };

        Detection {
            path: path.to_path_buf(),
            sha256: facts.sha256.clone(),
            size: facts.size,
            verdict,
            risk_score,
            threat_name,
            category,
            indicators,
        }
    }

    /// Análise completa de um conteúdo em memória.
    fn analyze(&self, path: &Path, data: &[u8]) -> Detection {
        let facts = analyze_bytes(data);
        let pe = if facts.is_pe() { pe::parse(data) } else { None };
        let yara = self.yara_scan(data);
        self.classify(path, &facts, pe.as_ref(), &yara)
    }

    /// Analisa um único arquivo.
    pub fn scan_file(&self, path: &Path) -> crate::Result<Detection> {
        let size = std::fs::metadata(path)
            .map_err(|e| crate::Error::io(path, e))?
            .len();
        if size <= DEEP_ANALYSIS_MAX {
            let data = std::fs::read(path).map_err(|e| crate::Error::io(path, e))?;
            Ok(self.analyze(path, &data))
        } else {
            let facts = analyze_file(path)?;
            Ok(self.classify(path, &facts, None, &[]))
        }
    }

    /// Analisa conteúdo em memória (útil para testes e, no futuro, AMSI).
    pub fn scan_bytes(&self, name: &str, data: &[u8]) -> Detection {
        self.analyze(Path::new(name), data)
    }

    /// Varre um arquivo ou uma pasta (recursivamente).
    /// `on_file` é chamado antes de cada arquivo (progresso na interface);
    /// devolver `ControlFlow::Break(())` cancela a varredura.
    pub fn scan_path<F>(&self, root: &Path, on_file: F) -> ScanReport
    where
        F: FnMut(&Path) -> ControlFlow<()>,
    {
        self.scan_paths(&[root.to_path_buf()], on_file)
    }

    /// Varre vários arquivos/pastas, acumulando um único relatório.
    pub fn scan_paths<F>(&self, roots: &[PathBuf], mut on_file: F) -> ScanReport
    where
        F: FnMut(&Path) -> ControlFlow<()>,
    {
        let start = Instant::now();
        let mut report = ScanReport::default();
        for root in roots {
            if self.walk(root, &mut report, &mut on_file).is_break() {
                report.cancelled = true;
                break;
            }
        }
        report
            .detections
            .sort_by_key(|d| std::cmp::Reverse(d.risk_score));
        report.elapsed = start.elapsed();
        report
    }

    fn walk<F>(&self, root: &Path, report: &mut ScanReport, on_file: &mut F) -> ControlFlow<()>
    where
        F: FnMut(&Path) -> ControlFlow<()>,
    {
        let walker = WalkDir::new(root).follow_links(self.config.follow_symlinks);
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    report.errors.push(ScanError {
                        path: err.path().map(Path::to_path_buf).unwrap_or_default(),
                        message: err.to_string(),
                    });
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();

            if self.config.max_file_size > 0 {
                if let Ok(meta) = entry.metadata() {
                    if meta.len() > self.config.max_file_size {
                        report.skipped_too_large += 1;
                        continue;
                    }
                }
            }

            on_file(path)?;
            match self.scan_file(path) {
                Ok(det) => {
                    report.files_scanned += 1;
                    report.bytes_scanned += det.size;
                    if det.verdict != Verdict::Clean {
                        report.detections.push(det);
                    }
                }
                Err(err) => report.errors.push(ScanError {
                    path: path.to_path_buf(),
                    message: err.to_string(),
                }),
            }
        }
        ControlFlow::Continue(())
    }
}

mod duration_ms {
    use serde::Serializer;
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u128(d.as_millis())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::analyze_bytes;

    /// O conteúdo EICAR é montado em partes para que o próprio código-fonte
    /// e o binário de testes não sejam sinalizados pelo Windows Defender.
    /// Nunca é gravado em disco.
    fn eicar_bytes() -> Vec<u8> {
        let parts = [
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}",
            "$EICAR-STANDARD-",
            "ANTIVIRUS-TEST-FILE!$H+H*",
        ];
        parts.concat().into_bytes()
    }

    fn scanner() -> Scanner {
        Scanner::new(SignatureDb::with_builtin(), ScanConfig::default())
    }

    #[test]
    fn eicar_is_malicious() {
        let data = eicar_bytes();
        assert_eq!(data.len(), 68);
        let det = scanner().scan_bytes("eicar.com", &data);
        assert_eq!(det.verdict, Verdict::Malicious);
        assert_eq!(det.risk_score, 100);
        assert_eq!(det.threat_name.as_deref(), Some("EICAR-Test-File"));
    }

    #[test]
    fn plain_text_is_clean() {
        let det = scanner().scan_bytes("notas.txt", b"lista de compras");
        assert_eq!(det.verdict, Verdict::Clean);
        assert_eq!(det.risk_score, 0);
    }

    #[test]
    fn double_extension_is_suspicious() {
        let det = scanner().scan_bytes("fatura.pdf.exe", b"qualquer coisa");
        assert_eq!(det.verdict, Verdict::Suspicious);
    }

    #[test]
    fn scans_directory_with_custom_signature() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();

        let bad = b"conteudo marcado como ameaca de teste";
        std::fs::write(sub.join("amostra.bin"), bad).unwrap();
        std::fs::write(dir.path().join("limpo.txt"), b"ola mundo").unwrap();

        let mut db = SignatureDb::with_builtin();
        db.insert(&analyze_bytes(bad).sha256, "Teste.Personalizado");
        let scanner = Scanner::new(db, ScanConfig::default());

        let mut seen = 0;
        let report = scanner.scan_path(dir.path(), |_| {
            seen += 1;
            ControlFlow::Continue(())
        });

        assert_eq!(seen, 2);
        assert_eq!(report.files_scanned, 2);
        assert!(report.errors.is_empty());
        assert_eq!(report.detections.len(), 1);
        assert_eq!(
            report.detections[0].threat_name.as_deref(),
            Some("Teste.Personalizado")
        );
    }

    #[test]
    fn respects_max_file_size() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("grande.bin"), vec![0u8; 2048]).unwrap();
        let scanner = Scanner::new(
            SignatureDb::with_builtin(),
            ScanConfig {
                max_file_size: 1024,
                ..ScanConfig::default()
            },
        );
        let report = scanner.scan_path(dir.path(), |_| ControlFlow::Continue(()));
        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.skipped_too_large, 1);
    }

    #[test]
    fn scan_can_be_cancelled_and_handles_multiple_roots() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        for i in 0..5 {
            std::fs::write(a.path().join(format!("a{i}.txt")), b"a").unwrap();
            std::fs::write(b.path().join(format!("b{i}.txt")), b"b").unwrap();
        }
        let roots = [a.path().to_path_buf(), b.path().to_path_buf()];

        let full = scanner().scan_paths(&roots, |_| ControlFlow::Continue(()));
        assert_eq!(full.files_scanned, 10);
        assert!(!full.cancelled);

        let mut seen = 0;
        let partial = scanner().scan_paths(&roots, |_| {
            seen += 1;
            if seen > 3 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert!(partial.cancelled);
        assert_eq!(partial.files_scanned, 3);
    }
}
