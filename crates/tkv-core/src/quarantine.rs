//! Quarentena reversível.
//!
//! O arquivo isolado é gravado como `<id>.qtn` no diretório de quarentena:
//!
//! ```text
//! "TKVQ" | versão (1 byte) | conteúdo original XOR fluxo-de-chave
//! ```
//!
//! O XOR **não é criptografia forte**. Ele serve para que o arquivo isolado não
//! possa ser executado por engano e não seja detectado de novo (pelo próprio
//! THUGAS ou por outro antivírus). A chave deriva do id do item.
//!
//! Ordem das operações em `add` (para nunca perder o arquivo):
//! 1. grava a cópia cifrada e faz `fsync`;
//! 2. registra no banco;
//! 3. remove o original. Se falhar, desfaz os passos 1 e 2.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::storage::{Database, QuarantineItem, QuarantineStatus};

const MAGIC: &[u8; 4] = b"TKVQ";
const FORMAT_VERSION: u8 = 1;
const KEY_CONTEXT: &[u8] = b"THUGAS-KILL-VIRUS-QUARANTINE-V1";
const BUFFER_LEN: usize = 64 * 1024;

pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    /// Abre (ou cria) o diretório de quarentena.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        let dir = std::path::absolute(&dir).map_err(|e| Error::io(&dir, e))?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn file_for(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.qtn"))
    }

    /// Move um arquivo para a quarentena.
    pub fn add(
        &self,
        db: &Database,
        path: &Path,
        threat_name: Option<&str>,
        risk_score: u8,
    ) -> Result<QuarantineItem> {
        let path = std::path::absolute(path).map_err(|e| Error::io(path, e))?;
        let meta = fs::metadata(&path).map_err(|e| Error::io(&path, e))?;
        if !meta.is_file() {
            return Err(Error::quarantine(format!(
                "'{}' não é um arquivo",
                path.display()
            )));
        }
        if path.starts_with(&self.dir) {
            return Err(Error::quarantine("o arquivo já está no diretório de quarentena"));
        }

        let id = new_id(&path);
        let qfile = self.file_for(&id);

        // 1. cópia cifrada
        let (sha256, size) = match encode(&path, &qfile, &id) {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_file(&qfile);
                return Err(e);
            }
        };

        let item = QuarantineItem {
            id: id.clone(),
            original_path: path.clone(),
            sha256,
            size,
            threat_name: threat_name.map(str::to_string),
            risk_score,
            quarantined_at: db.now()?,
            status: QuarantineStatus::Quarantined,
        };

        // 2. registro no banco
        if let Err(e) = db.insert_quarantine(&item) {
            let _ = fs::remove_file(&qfile);
            return Err(e);
        }

        // 3. remoção do original
        if let Err(e) = fs::remove_file(&path) {
            let _ = db.remove_quarantine_row(&id);
            let _ = fs::remove_file(&qfile);
            return Err(Error::io(&path, e));
        }

        Ok(item)
    }

    /// Restaura um item para o caminho original, conferindo o SHA-256.
    pub fn restore(&self, db: &Database, id: &str, overwrite: bool) -> Result<QuarantineItem> {
        let mut item = self.active_item(db, id)?;
        let target = item.original_path.clone();

        if target.exists() && !overwrite {
            return Err(Error::quarantine(format!(
                "'{}' já existe (use a opção de sobrescrever)",
                target.display()
            )));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }

        // Decodifica para um arquivo temporário ao lado do destino e só
        // depois o renomeia, para não deixar um arquivo parcial no lugar.
        let mut tmp_name = target.as_os_str().to_owned();
        tmp_name.push(".tkv-restore");
        let tmp = PathBuf::from(tmp_name);

        let sha = match decode(&self.file_for(id), &tmp, id) {
            Ok(sha) => sha,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        if sha != item.sha256 {
            let _ = fs::remove_file(&tmp);
            return Err(Error::quarantine(format!(
                "integridade violada: esperado {}, obtido {sha}",
                item.sha256
            )));
        }

        // No Windows, rename substitui o destino de forma atômica quando ele existe.
        fs::rename(&tmp, &target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            Error::io(&target, e)
        })?;

        let _ = fs::remove_file(self.file_for(id));
        db.set_quarantine_status(id, QuarantineStatus::Restored)?;
        item.status = QuarantineStatus::Restored;
        Ok(item)
    }

    /// Exclui definitivamente um item da quarentena.
    pub fn delete(&self, db: &Database, id: &str) -> Result<QuarantineItem> {
        let mut item = self.active_item(db, id)?;
        let qfile = self.file_for(id);
        match fs::remove_file(&qfile) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(&qfile, e)),
        }
        db.set_quarantine_status(id, QuarantineStatus::Deleted)?;
        item.status = QuarantineStatus::Deleted;
        Ok(item)
    }

    fn active_item(&self, db: &Database, id: &str) -> Result<QuarantineItem> {
        let item = db
            .get_quarantine(id)?
            .ok_or_else(|| Error::quarantine(format!("item '{id}' não encontrado")))?;
        if item.status != QuarantineStatus::Quarantined {
            return Err(Error::quarantine(format!(
                "item '{id}' não está em quarentena (status: {})",
                item.status.as_str()
            )));
        }
        Ok(item)
    }
}

/// Gera um id único de 32 caracteres hexadecimais.
fn new_id(path: &Path) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(path.to_string_lossy().as_bytes());
    h.update(nanos.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hex::encode(&h.finalize()[..16])
}

fn key_for(id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KEY_CONTEXT);
    h.update(id.as_bytes());
    h.finalize().into()
}

fn xor_in_place(buf: &mut [u8], key: &[u8; 32], offset: &mut u64) {
    for b in buf {
        *b ^= key[(*offset % 32) as usize];
        *offset += 1;
    }
}

/// Lê `src`, grava a versão cifrada em `dst`. Retorna (sha256 original, tamanho).
fn encode(src: &Path, dst: &Path, id: &str) -> Result<(String, u64)> {
    let key = key_for(id);
    let mut input = BufReader::new(File::open(src).map_err(|e| Error::io(src, e))?);
    let out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| Error::io(dst, e))?;
    let mut output = BufWriter::new(out_file);

    output
        .write_all(MAGIC)
        .and_then(|_| output.write_all(&[FORMAT_VERSION]))
        .map_err(|e| Error::io(dst, e))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUFFER_LEN];
    let mut offset = 0u64;
    loop {
        let n = input.read(&mut buf).map_err(|e| Error::io(src, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        xor_in_place(&mut buf[..n], &key, &mut offset);
        output.write_all(&buf[..n]).map_err(|e| Error::io(dst, e))?;
    }

    let file = output.into_inner().map_err(|e| Error::io(dst, e.into_error()))?;
    file.sync_all().map_err(|e| Error::io(dst, e))?;
    Ok((hex::encode(hasher.finalize()), offset))
}

/// Lê o arquivo cifrado `src` e grava o conteúdo original em `dst`. Retorna o sha256.
fn decode(src: &Path, dst: &Path, id: &str) -> Result<String> {
    let key = key_for(id);
    let mut input = BufReader::new(File::open(src).map_err(|e| Error::io(src, e))?);

    let mut header = [0u8; 5];
    input
        .read_exact(&mut header)
        .map_err(|e| Error::io(src, e))?;
    if &header[..4] != MAGIC || header[4] != FORMAT_VERSION {
        return Err(Error::quarantine(format!(
            "'{}' não é um arquivo de quarentena válido",
            src.display()
        )));
    }

    let out_file = File::create(dst).map_err(|e| Error::io(dst, e))?;
    let mut output = BufWriter::new(out_file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUFFER_LEN];
    let mut offset = 0u64;
    loop {
        let n = input.read(&mut buf).map_err(|e| Error::io(src, e))?;
        if n == 0 {
            break;
        }
        xor_in_place(&mut buf[..n], &key, &mut offset);
        hasher.update(&buf[..n]);
        output.write_all(&buf[..n]).map_err(|e| Error::io(dst, e))?;
    }
    let file = output.into_inner().map_err(|e| Error::io(dst, e.into_error()))?;
    file.sync_all().map_err(|e| Error::io(dst, e))?;
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Env {
        _dir: tempfile::TempDir,
        root: PathBuf,
        db: Database,
        q: Quarantine,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let db = Database::open(&root.join("tkv.db")).unwrap();
        let q = Quarantine::open(root.join("quarantine")).unwrap();
        Env {
            _dir: dir,
            root,
            db,
            q,
        }
    }

    #[test]
    fn quarantine_and_restore_roundtrip() {
        let e = env();
        let original = e.root.join("docs").join("amostra.bin");
        fs::create_dir_all(original.parent().unwrap()).unwrap();
        let data: Vec<u8> = (0..150_000u32).map(|i| (i * 7 % 256) as u8).collect();
        fs::write(&original, &data).unwrap();

        let item = e.q.add(&e.db, &original, Some("Teste"), 100).unwrap();
        assert!(!original.exists(), "original deve ser removido");
        let qfile = e.q.file_for(&item.id);
        let stored = fs::read(&qfile).unwrap();
        assert_eq!(&stored[..4], MAGIC);
        assert_ne!(&stored[5..], &data[..], "conteúdo deve estar cifrado");
        assert_eq!(item.size, data.len() as u64);
        assert_eq!(e.db.quarantine_items(false).unwrap().len(), 1);

        let restored = e.q.restore(&e.db, &item.id, false).unwrap();
        assert_eq!(restored.status, QuarantineStatus::Restored);
        assert_eq!(fs::read(&original).unwrap(), data);
        assert!(!qfile.exists());
        assert!(e.db.quarantine_items(false).unwrap().is_empty());
        assert_eq!(e.db.quarantine_items(true).unwrap().len(), 1);

        // Não pode restaurar duas vezes.
        assert!(e.q.restore(&e.db, &item.id, false).is_err());
    }

    #[test]
    fn restore_does_not_overwrite_without_flag() {
        let e = env();
        let original = e.root.join("arquivo.txt");
        fs::write(&original, b"malicioso").unwrap();
        let item = e.q.add(&e.db, &original, None, 50).unwrap();

        fs::write(&original, b"novo arquivo do usuario").unwrap();
        assert!(e.q.restore(&e.db, &item.id, false).is_err());
        assert_eq!(fs::read(&original).unwrap(), b"novo arquivo do usuario");

        e.q.restore(&e.db, &item.id, true).unwrap();
        assert_eq!(fs::read(&original).unwrap(), b"malicioso");
    }

    #[test]
    fn delete_removes_file() {
        let e = env();
        let original = e.root.join("x.exe");
        fs::write(&original, b"conteudo").unwrap();
        let item = e.q.add(&e.db, &original, None, 100).unwrap();

        let deleted = e.q.delete(&e.db, &item.id).unwrap();
        assert_eq!(deleted.status, QuarantineStatus::Deleted);
        assert!(!e.q.file_for(&item.id).exists());
        assert!(e.q.restore(&e.db, &item.id, false).is_err());
    }

    #[test]
    fn detects_tampering() {
        let e = env();
        let original = e.root.join("y.bin");
        fs::write(&original, b"conteudo original").unwrap();
        let item = e.q.add(&e.db, &original, None, 100).unwrap();

        let qfile = e.q.file_for(&item.id);
        let mut bytes = fs::read(&qfile).unwrap();
        *bytes.last_mut().unwrap() ^= 0xFF;
        fs::write(&qfile, bytes).unwrap();

        assert!(e.q.restore(&e.db, &item.id, false).is_err());
        assert!(!original.exists(), "não deve restaurar conteúdo adulterado");
        let mut tmp = original.as_os_str().to_owned();
        tmp.push(".tkv-restore");
        assert!(!PathBuf::from(tmp).exists(), "temporário deve ser limpo");
    }

    #[test]
    fn missing_file_errors() {
        let e = env();
        assert!(e.q.add(&e.db, &e.root.join("nao-existe"), None, 0).is_err());
        assert!(e.q.add(&e.db, &e.root, None, 0).is_err(), "pasta não é arquivo");
        assert!(e.q.restore(&e.db, "id-inexistente", false).is_err());
    }
}
