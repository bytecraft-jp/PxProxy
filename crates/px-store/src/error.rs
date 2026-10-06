use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("manifest parse: {0}")]
    ManifestDe(#[from] toml::de::Error),
    #[error("manifest write: {0}")]
    ManifestSer(#[from] toml::ser::Error),
    #[error("{0}")]
    Invalid(String),
    /// 進捗コールバックが中止を返した
    #[error("cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, StoreError>;
