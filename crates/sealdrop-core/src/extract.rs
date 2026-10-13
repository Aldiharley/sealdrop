//! (filled in by a later task)

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtractError {
    #[error("bad path {0}")]
    BadPath(String),
}
