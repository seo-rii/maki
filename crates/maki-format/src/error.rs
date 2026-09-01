//! Format error taxonomy. Decoders return errors — they never panic.

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("truncated input: {0}")]
    Truncated(String),
    #[error("bad magic: {0}")]
    BadMagic(String),
    #[error("bad checksum: {0}")]
    BadChecksum(String),
    #[error("unsupported version: {0}")]
    Unsupported(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("integer overflow: {0}")]
    Overflow(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
