use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("erro de E/S em '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("linha {line} inválida no arquivo de assinaturas: {reason}")]
    InvalidSignature { line: usize, reason: String },

    #[error("banco de dados: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("serialização: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("quarentena: {0}")]
    Quarantine(String),

    #[error("o banco de dados foi criado por uma versão mais nova (esquema {0})")]
    UnsupportedSchema(i64),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    pub fn quarantine(msg: impl Into<String>) -> Self {
        Error::Quarantine(msg.into())
    }
}
