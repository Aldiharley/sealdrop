//! (filled in by a later task)

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("no recipients given")]
    NoRecipients,
}
