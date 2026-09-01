//! `SecretBuffer` — plaintext container with restricted semantics (SPEC §15).
//!
//! Required properties:
//! - minimize Clone support (no `Clone` impl; explicit [`SecretBuffer::duplicate`])
//! - zeroize on Drop
//! - never print contents in Debug
//! - participate in memory budgeting (exact `len` is always known)

use zeroize::Zeroize;

/// A byte buffer holding plaintext or key material.
///
/// Deliberately does **not** implement `Clone`; copying secret material must be
/// an explicit, visible act via [`SecretBuffer::duplicate`].
pub struct SecretBuffer {
    data: Vec<u8>,
}

impl SecretBuffer {
    /// A zero-filled buffer of `len` bytes.
    pub fn zeroed(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
        }
    }

    /// Take ownership of an existing byte vector.
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Copy from a slice.
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    pub fn expose(&self) -> &[u8] {
        &self.data
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Explicit, intentional copy of secret material.
    pub fn duplicate(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }

    /// Consume, returning the inner vector. The caller takes over the
    /// zeroization obligation.
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl std::fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBuffer({} bytes, redacted)", self.data.len())
    }
}

/// Constant-time-ish equality (length leak only). For tests and self-checks.
impl PartialEq for SecretBuffer {
    fn eq(&self, other: &Self) -> bool {
        if self.data.len() != other.data.len() {
            return false;
        }
        let mut acc = 0u8;
        for (a, b) in self.data.iter().zip(other.data.iter()) {
            acc |= a ^ b;
        }
        acc == 0
    }
}
impl Eq for SecretBuffer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_contents() {
        let s = SecretBuffer::from_slice(b"super-secret-key-material");
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("super"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn duplicate_is_explicit_and_equal() {
        let s = SecretBuffer::from_slice(b"abc");
        let d = s.duplicate();
        assert_eq!(s, d);
    }
}
