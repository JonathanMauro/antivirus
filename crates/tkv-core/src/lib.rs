//! Núcleo do THUGAS KILL VIRUS.
//!
//! Módulos:
//! - [`analysis`]   — leitura em passagem única: SHA-256, entropia e cabeçalho.
//! - [`signatures`] — base de assinaturas por hash (SHA-256).
//! - [`heuristics`] — indicadores estáticos (extensão dupla, PE disfarçado, entropia).
//! - [`scanner`]    — varredura de arquivos/pastas e cálculo de Risk Score.

pub mod analysis;
pub mod error;
pub mod heuristics;
pub mod scanner;
pub mod signatures;

pub use error::{Error, Result};
pub use scanner::{Detection, ScanConfig, ScanReport, Scanner, Verdict};
pub use signatures::SignatureDb;
