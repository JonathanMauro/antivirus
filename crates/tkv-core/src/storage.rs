//! Armazenamento local em SQLite.
//!
//! Tabelas: `scans` (histórico de varreduras), `detections` (itens não limpos
//! de cada varredura), `quarantine` (metadados dos arquivos isolados) e
//! `settings` (chave/valor). Datas em UTC, formato ISO-8601.
//! O esquema é versionado com `PRAGMA user_version`.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::scanner::ScanReport;

const SCHEMA_VERSION: i64 = 1;

const SCHEMA_V1: &str = r#"
CREATE TABLE scans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    target            TEXT    NOT NULL,
    finished_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    files_scanned     INTEGER NOT NULL,
    bytes_scanned     INTEGER NOT NULL,
    skipped_too_large INTEGER NOT NULL,
    detections        INTEGER NOT NULL,
    errors            INTEGER NOT NULL,
    duration_ms       INTEGER NOT NULL
);

CREATE TABLE detections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path        TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    verdict     TEXT    NOT NULL CHECK (verdict IN ('clean', 'suspicious', 'malicious')),
    risk_score  INTEGER NOT NULL,
    threat_name TEXT,
    indicators  TEXT    NOT NULL,
    detected_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_detections_scan   ON detections(scan_id);
CREATE INDEX idx_detections_sha256 ON detections(sha256);

CREATE TABLE quarantine (
    id                TEXT    PRIMARY KEY,
    original_path     TEXT    NOT NULL,
    sha256            TEXT    NOT NULL,
    size              INTEGER NOT NULL,
    threat_name       TEXT,
    risk_score        INTEGER NOT NULL,
    quarantined_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    status            TEXT    NOT NULL DEFAULT 'quarantined'
                              CHECK (status IN ('quarantined', 'restored', 'deleted')),
    status_changed_at TEXT
);
CREATE INDEX idx_quarantine_status ON quarantine(status);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub id: i64,
    pub target: String,
    pub finished_at: String,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub skipped_too_large: u64,
    pub detections: u64,
    pub errors: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredDetection {
    pub id: i64,
    pub scan_id: i64,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub verdict: String,
    pub risk_score: u8,
    pub threat_name: Option<String>,
    /// Lista de indicadores serializada em JSON.
    pub indicators_json: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Quarantined,
    Restored,
    Deleted,
}

impl QuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            QuarantineStatus::Quarantined => "quarantined",
            QuarantineStatus::Restored => "restored",
            QuarantineStatus::Deleted => "deleted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "quarantined" => Some(QuarantineStatus::Quarantined),
            "restored" => Some(QuarantineStatus::Restored),
            "deleted" => Some(QuarantineStatus::Deleted),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub threat_name: Option<String>,
    pub risk_score: u8,
    pub quarantined_at: String,
    pub status: QuarantineStatus,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    /// Abre (ou cria) o banco no caminho indicado e aplica as migrações.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let conn = Connection::open(path)?;
        // journal_mode devolve uma linha; por isso query_row em vez de execute.
        conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        Self::init(conn)
    }

    /// Banco temporário em memória (testes).
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(Error::UnsupportedSchema(version));
        }
        if version < 1 {
            let tx = self.conn.unchecked_transaction()?;
            tx.execute_batch(SCHEMA_V1)?;
            tx.execute_batch("PRAGMA user_version = 1;")?;
            tx.commit()?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- scans

    /// Grava uma varredura e suas detecções. Retorna o id da varredura.
    pub fn record_scan(&self, target: &str, report: &ScanReport) -> Result<i64> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO scans (target, files_scanned, bytes_scanned, skipped_too_large,
                                detections, errors, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                target,
                report.files_scanned as i64,
                report.bytes_scanned as i64,
                report.skipped_too_large as i64,
                report.detections.len() as i64,
                report.errors.len() as i64,
                report.elapsed.as_millis() as i64,
            ],
        )?;
        let scan_id = tx.last_insert_rowid();
        {
            let mut stmt = tx.prepare(
                "INSERT INTO detections (scan_id, path, sha256, size, verdict, risk_score,
                                         threat_name, indicators)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for d in &report.detections {
                stmt.execute(params![
                    scan_id,
                    d.path.to_string_lossy().into_owned(),
                    d.sha256,
                    d.size as i64,
                    d.verdict.as_str(),
                    d.risk_score as i64,
                    d.threat_name,
                    serde_json::to_string(&d.indicators)?,
                ])?;
            }
        }
        tx.commit()?;
        Ok(scan_id)
    }

    /// Varreduras mais recentes primeiro.
    pub fn recent_scans(&self, limit: usize) -> Result<Vec<ScanSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, target, finished_at, files_scanned, bytes_scanned, skipped_too_large,
                    detections, errors, duration_ms
             FROM scans ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |r| {
            Ok(ScanSummary {
                id: r.get(0)?,
                target: r.get(1)?,
                finished_at: r.get(2)?,
                files_scanned: r.get::<_, i64>(3)? as u64,
                bytes_scanned: r.get::<_, i64>(4)? as u64,
                skipped_too_large: r.get::<_, i64>(5)? as u64,
                detections: r.get::<_, i64>(6)? as u64,
                errors: r.get::<_, i64>(7)? as u64,
                duration_ms: r.get::<_, i64>(8)? as u64,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Detecções de uma varredura, maior risco primeiro.
    pub fn scan_detections(&self, scan_id: i64) -> Result<Vec<StoredDetection>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, scan_id, path, sha256, size, verdict, risk_score, threat_name,
                    indicators, detected_at
             FROM detections WHERE scan_id = ?1 ORDER BY risk_score DESC, id",
        )?;
        let rows = stmt.query_map([scan_id], |r| {
            Ok(StoredDetection {
                id: r.get(0)?,
                scan_id: r.get(1)?,
                path: r.get(2)?,
                sha256: r.get(3)?,
                size: r.get::<_, i64>(4)? as u64,
                verdict: r.get(5)?,
                risk_score: r.get::<_, i64>(6)? as u8,
                threat_name: r.get(7)?,
                indicators_json: r.get(8)?,
                detected_at: r.get(9)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ----------------------------------------------------------- quarantine

    pub fn insert_quarantine(&self, item: &QuarantineItem) -> Result<()> {
        self.conn.execute(
            "INSERT INTO quarantine (id, original_path, sha256, size, threat_name, risk_score,
                                     quarantined_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                item.id,
                item.original_path.to_string_lossy().into_owned(),
                item.sha256,
                item.size as i64,
                item.threat_name,
                item.risk_score as i64,
                item.quarantined_at,
                item.status.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Remove o registro (usado apenas para desfazer uma quarentena que falhou).
    pub(crate) fn remove_quarantine_row(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM quarantine WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn get_quarantine(&self, id: &str) -> Result<Option<QuarantineItem>> {
        Ok(self
            .conn
            .query_row(
                &format!("{QUARANTINE_SELECT} WHERE id = ?1"),
                [id],
                row_to_quarantine,
            )
            .optional()?)
    }

    /// Itens da quarentena. Com `include_history`, inclui restaurados e excluídos.
    pub fn quarantine_items(&self, include_history: bool) -> Result<Vec<QuarantineItem>> {
        let sql = if include_history {
            format!("{QUARANTINE_SELECT} ORDER BY quarantined_at DESC")
        } else {
            format!("{QUARANTINE_SELECT} WHERE status = 'quarantined' ORDER BY quarantined_at DESC")
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_quarantine)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn set_quarantine_status(&self, id: &str, status: QuarantineStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE quarantine
             SET status = ?2, status_changed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = ?1",
            params![id, status.as_str()],
        )?;
        Ok(())
    }

    /// Data/hora atual do SQLite (UTC, ISO-8601).
    pub fn now(&self) -> Result<String> {
        Ok(self.conn.query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            [],
            |r| r.get(0),
        )?)
    }

    // ------------------------------------------------------------- settings

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

const QUARANTINE_SELECT: &str = "SELECT id, original_path, sha256, size, threat_name, risk_score, \
                                 quarantined_at, status FROM quarantine";

fn row_to_quarantine(r: &Row<'_>) -> rusqlite::Result<QuarantineItem> {
    let status: String = r.get(7)?;
    Ok(QuarantineItem {
        id: r.get(0)?,
        original_path: PathBuf::from(r.get::<_, String>(1)?),
        sha256: r.get(2)?,
        size: r.get::<_, i64>(3)? as u64,
        threat_name: r.get(4)?,
        risk_score: r.get::<_, i64>(5)? as u8,
        quarantined_at: r.get(6)?,
        // A restrição CHECK da tabela garante um valor válido.
        status: QuarantineStatus::parse(&status).unwrap_or(QuarantineStatus::Quarantined),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanConfig, Scanner};
    use crate::signatures::SignatureDb;

    #[test]
    fn records_and_lists_scans() {
        let db = Database::open_in_memory().unwrap();
        let scanner = Scanner::new(SignatureDb::with_builtin(), ScanConfig::default());
        let mut report = ScanReport {
            files_scanned: 3,
            ..ScanReport::default()
        };
        report
            .detections
            .push(scanner.scan_bytes("fatura.pdf.exe", b"x"));

        let id = db.record_scan("C:\\teste", &report).unwrap();
        let scans = db.recent_scans(10).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].id, id);
        assert_eq!(scans[0].files_scanned, 3);
        assert_eq!(scans[0].detections, 1);

        let dets = db.scan_detections(id).unwrap();
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].verdict, "suspicious");
        assert!(dets[0].indicators_json.contains("double_extension"));
    }

    #[test]
    fn settings_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.get_setting("tema").unwrap(), None);
        db.set_setting("tema", "escuro").unwrap();
        db.set_setting("tema", "claro").unwrap();
        assert_eq!(db.get_setting("tema").unwrap().as_deref(), Some("claro"));
    }

    #[test]
    fn reopening_keeps_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("tkv.db");
        {
            let db = Database::open(&path).unwrap();
            db.set_setting("k", "v").unwrap();
        }
        let db = Database::open(&path).unwrap();
        assert_eq!(db.get_setting("k").unwrap().as_deref(), Some("v"));
    }
}
