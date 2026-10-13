use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),
    #[error("decryption failed: {0}")]
    Decrypt(#[from] age::DecryptError),
    #[error("policy refused: {0}")]
    Policy(#[from] crate::policy::PolicyError),
    #[error("extraction refused: {0}")]
    Extract(#[from] crate::extract::ExtractError),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("invalid recipient `{0}`")]
    InvalidRecipient(String),
    #[error("invalid identity")]
    InvalidIdentity,
    #[error("manifest error: {0}")]
    Manifest(String),
    #[error("release service: {0}")]
    Release(String),
    #[error("package has expired at the release service")]
    ReleaseExpired,
    #[error("key store error: {0}")]
    KeyStore(String),
    #[error("already exists: {0}")]
    Exists(PathBuf),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
