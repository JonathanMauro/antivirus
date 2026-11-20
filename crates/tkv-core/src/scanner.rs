//! Scanner de arquivos e pastas.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use walkdir::WalkDir;

use crate::analysis::{analyze_bytes, analyze_file, FileFacts};
use crate::heuristics::{self, Indicator};
use crate::signatures::SignatureDb;

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
    /// Nome da ameaça, quando houver correspondência de assinatura.
    pub threat_name: Option<String>,
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

pub struct Scanner {
    db: SignatureDb,
    config: ScanConfig,
}

impl Scanner {
    pub fn new(db: SignatureDb, config: ScanConfig) -> Self {
        Self { db, config }
    }

    pub fn signatures(&self) -> &SignatureDb {
        &self.db
    }

    /// Classifica um arquivo a partir de suas características.
    pub fn classify(&self, path: &Path, facts: &FileFacts) -> Detection {
        let file_name = path.file_name().and_then(|n| n.to_str());
        let mut indicators = heuristics::evaluate(file_name, facts);

        let threat_name = self.db.lookup(&facts.sha256).map(str::to_string);
        let (verdict, risk_score) = if let Some(name) = &threat_name {
            indicators.insert(
                0,
                Indicator {
                    id: "signature_match",
                    description: format!("hash corresponde à assinatura '{name}'"),
                    score: 100,
                },
            );
            (Verdict::Malicious, 100)
        } else {
            let score: u32 = indicators.iter().map(|i| i.score as u32).sum();
            let score = score.min(100) as u8;
            let verdict = if score >= SUSPICIOUS_THRESHOLD {
                Verdict::Suspicious
            } else {
                Verdict::Clean
            };
            (verdict, score)
        };

        Detection {
            path: path.to_path_buf(),
            sha256: facts.sha256.clone(),
            size: facts.size,
            verdict,
            risk_score,
            threat_name,
            indicators,
        }
    }

    /// Analisa um único arquivo.
    pub fn scan_file(&self, path: &Path) -> crate::Result<Detection> {
        let facts = analyze_file(path)?;
        Ok(self.classify(path, &facts))
    }

    /// Analisa conteúdo em memória (útil para testes e, no futuro, AMSI).
    pub fn scan_bytes(&self, name: &str, data: &[u8]) -> Detection {
        let facts = analyze_bytes(data);
        self.classify(Path::new(name), &facts)
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
