//! Library-owned plaintext buffers. Public output transfers remain caller-owned.

use std::{io, mem, ops::Deref};
use zeroize::{Zeroize, Zeroizing};

/// Grow without giving the allocator an old allocation containing plaintext.
pub(crate) fn reserve(buffer: &mut Vec<u8>, additional: usize) {
    let required = buffer
        .len()
        .checked_add(additional)
        .expect("buffer capacity overflow");
    if required <= buffer.capacity() {
        return;
    }
    let capacity = required.max(buffer.capacity().saturating_mul(2)).max(8);
    // The replacement owns its guard before the first plaintext copy.
    let mut replacement = Zeroizing::new(Vec::with_capacity(capacity));
    replacement.extend_from_slice(buffer);
    mem::swap(buffer, &mut replacement);
    // Zeroizing wipes the old allocation's entire capacity before freeing it.
}

/// Compact a queue and erase both consumed bytes and the obsolete duplicate tail.
pub(crate) fn consume(buffer: &mut Vec<u8>, count: usize) {
    assert!(count <= buffer.len());
    let remaining = buffer.len() - count;
    buffer.copy_within(count.., 0);
    buffer[remaining..].zeroize();
    buffer.truncate(remaining);
}

#[derive(Debug, Default)]
pub(crate) struct OwnedBuffer(Zeroizing<Vec<u8>>);

impl OwnedBuffer {
    pub(crate) fn from_vec(buffer: Vec<u8>) -> Self {
        Self(Zeroizing::new(buffer))
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        reserve(&mut self.0, bytes.len());
        self.0.extend_from_slice(bytes);
    }

    #[cfg(feature = "handshake")]
    pub(crate) fn zeroize_range(&mut self, range: std::ops::Range<usize>) {
        self.0[range].zeroize();
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        // This is an explicit successful transfer to a public owner.
        mem::take(&mut self.0)
    }
}

impl Deref for OwnedBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for OwnedBuffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl io::Write for OwnedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
