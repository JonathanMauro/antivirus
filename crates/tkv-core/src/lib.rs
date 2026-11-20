//! Núcleo do THUGAS KILL VIRUS.
//!
//! Módulos:
//! - [`analysis`]   — leitura em passagem única: SHA-256, entropia e cabeçalho.
//! - [`signatures`] — base de assinaturas por hash (SHA-256).
//! - [`heuristics`] — indicadores estáticos (extensão dupla, PE disfarçado, entropia).
//! - [`scanner`]    — varredura de arquivos/pastas e cálculo de Risk Score.
//! - [`storage`]    — banco SQLite: histórico, detecções, quarentena, configurações.
//! - [`quarantine`] — isolamento reversível de arquivos.

pub mod analysis;
pub mod error;
pub mod heuristics;
pub mod quarantine;
pub mod scanner;
pub mod signatures;
pub mod storage;

pub use error::{Error, Result};
pub use quarantine::Quarantine;
pub use scanner::{Detection, ScanConfig, ScanReport, Scanner, Verdict};
pub use signatures::SignatureDb;
pub use storage::{Database, QuarantineItem, QuarantineStatus};
