//! Core error taxonomy.

use maki_format::FormatError;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Format(#[from] FormatError),
    /// On-disk state contradicts metadata — surfaced to the block layer as
    /// EIO; never fabricated data (SPEC §12, §22).
    #[error("corrupt: {0}")]
    Corrupt(String),
    /// A durability guarantee could not be established (e.g. FUA verify).
    #[error("durability violation: {0}")]
    Durability(String),
    /// Malformed request (range, alignment) — EINVAL at the block layer.
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error(transparent)]
    Crypto(#[from] maki_crypto::CryptoError),
}
