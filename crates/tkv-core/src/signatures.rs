//! Base de assinaturas por hash SHA-256.
//!
//! Formato do arquivo (UTF-8), uma assinatura por linha:
//!
//! ```text
//! # comentário
//! <sha256-hex>;<nome-da-ameaça>[;<categoria>]
//! ```
//!
//! A categoria é opcional (ver [`ThreatCategory`]); sem ela, é deduzida do nome.

use std::collections::HashMap;
use std::path::Path;

use crate::classify::ThreatCategory;
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntry {
    pub name: String,
    pub category: Option<ThreatCategory>,
}

/// SHA-256 do arquivo de teste padrão EICAR (68 bytes).
/// Ele é inofensivo e serve para validar a detecção.
pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
pub const EICAR_NAME: &str = "EICAR-Test-File";

#[derive(Debug, Clone, Default)]
pub struct SignatureDb {
    by_sha256: HashMap<String, SignatureEntry>,
}

impl SignatureDb {
    /// Base vazia.
    pub fn new() -> Self {
        Self::default()
    }

    /// Base com as assinaturas embutidas (atualmente só o EICAR).
    pub fn with_builtin() -> Self {
        let mut db = Self::new();
        db.insert(EICAR_SHA256, EICAR_NAME);
        db
    }

    /// Insere uma assinatura; a categoria é deduzida do nome.
    pub fn insert(&mut self, sha256: &str, name: &str) {
        self.insert_with_category(sha256, name, ThreatCategory::infer(name));
    }

    pub fn insert_with_category(
        &mut self,
        sha256: &str,
        name: &str,
        category: Option<ThreatCategory>,
    ) {
        self.by_sha256.insert(
            sha256.trim().to_ascii_lowercase(),
            SignatureEntry {
                name: name.trim().to_string(),
                category,
            },
        );
    }

    /// Retorna o nome da ameaça, se o hash for conhecido.
    pub fn lookup(&self, sha256: &str) -> Option<&str> {
        self.lookup_entry(sha256).map(|e| e.name.as_str())
    }

    pub fn lookup_entry(&self, sha256: &str) -> Option<&SignatureEntry> {
        self.by_sha256.get(&sha256.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.by_sha256.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_sha256.is_empty()
    }

    /// Lê assinaturas de um texto e as adiciona à base. Retorna quantas foram lidas.
    pub fn load_str(&mut self, text: &str) -> Result<usize> {
        let mut count = 0;
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (hash, name) = line.split_once(';').ok_or_else(|| Error::InvalidSignature {
                line: idx + 1,
                reason: "esperado '<sha256>;<nome>'".into(),
            })?;
            let hash = hash.trim();
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Error::InvalidSignature {
                    line: idx + 1,
                    reason: format!("hash SHA-256 inválido: '{hash}'"),
                });
            }
            let (name, category) = match name.split_once(';') {
                Some((n, c)) => {
                    let cat = ThreatCategory::parse(c).ok_or_else(|| Error::InvalidSignature {
                        line: idx + 1,
                        reason: format!("categoria desconhecida: '{}'", c.trim()),
                    })?;
                    (n.trim(), Some(cat))
                }
                None => (name.trim(), ThreatCategory::infer(name)),
            };
            if name.is_empty() {
                return Err(Error::InvalidSignature {
                    line: idx + 1,
                    reason: "nome da ameaça vazio".into(),
                });
            }
            self.insert_with_category(hash, name, category);
            count += 1;
        }
        Ok(count)
    }

    /// Lê assinaturas de um arquivo e as adiciona à base.
    pub fn load_file(&mut self, path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        self.load_str(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_has_eicar() {
        let db = SignatureDb::with_builtin();
        assert_eq!(db.lookup(EICAR_SHA256), Some(EICAR_NAME));
        assert_eq!(db.lookup(&EICAR_SHA256.to_uppercase()), Some(EICAR_NAME));
    }

    #[test]
    fn parses_file_format() {
        let mut db = SignatureDb::new();
        let text = format!("# comentário\n\n{};Teste.Generico\n", "a".repeat(64));
        assert_eq!(db.load_str(&text).unwrap(), 1);
        assert_eq!(db.lookup(&"a".repeat(64)), Some("Teste.Generico"));
    }

    #[test]
    fn parses_category_field_and_infers_otherwise() {
        let mut db = SignatureDb::new();
        let text = format!(
            "{};Amostra.X;ransomware\n{};Trojan.Win32.Y\n",
            "c".repeat(64),
            "d".repeat(64)
        );
        assert_eq!(db.load_str(&text).unwrap(), 2);
        let c = db.lookup_entry(&"c".repeat(64)).unwrap();
        assert_eq!(c.category, Some(ThreatCategory::Ransomware));
        let d = db.lookup_entry(&"d".repeat(64)).unwrap();
        assert_eq!(d.category, Some(ThreatCategory::Trojan));
        assert_eq!(
            SignatureDb::with_builtin()
                .lookup_entry(EICAR_SHA256)
                .unwrap()
                .category,
            Some(ThreatCategory::Test)
        );
        assert!(db
            .load_str(&format!("{};Nome;categoria-inexistente", "e".repeat(64)))
            .is_err());
    }

    #[test]
    fn rejects_bad_lines() {
        let mut db = SignatureDb::new();
        assert!(db.load_str("sem-separador").is_err());
        assert!(db.load_str("1234;curto").is_err());
        assert!(db.load_str(&format!("{};", "b".repeat(64))).is_err());
    }
}
