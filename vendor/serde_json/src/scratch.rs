//! Maki's parser-private heap owners. Never grow a live secret Vec in place.

use alloc::vec::Vec;
use core::fmt::{self, Display, Write};
use core::mem;
use core::ops::Deref;
use core::str;
use zeroize::Zeroize;

// Public only because the sealed Read trait names this type in hidden methods.
// Its buffer is deliberately never exposed as &mut Vec.
#[doc(hidden)]
pub struct Scratch {
    bytes: Vec<u8>,
}

impl Scratch {
    pub(crate) fn new() -> Self {
        Scratch { bytes: Vec::new() }
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        let required = self
            .bytes
            .len()
            .checked_add(additional)
            .expect("capacity overflow");
        if required <= self.bytes.capacity() {
            return;
        }
        let doubled = self.bytes.capacity().checked_mul(2).unwrap_or(required);
        let capacity = required.max(doubled).max(8);
        // Establish the replacement's wiping owner before copying any bytes.
        // The explicit reservation guarantees this extend cannot reallocate.
        let mut replacement = Scratch {
            bytes: Vec::with_capacity(capacity),
        };
        replacement.bytes.extend_from_slice(&self.bytes);
        mem::swap(self, &mut replacement);
        // Drop wipes the old full allocation before deallocating it.
    }

    pub(crate) fn push(&mut self, byte: u8) {
        self.reserve(1);
        self.bytes.push(byte);
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        self.bytes.extend_from_slice(bytes);
    }

    pub(crate) fn clear(&mut self) {
        // Every removed byte is wiped here or in truncate/pop. Wiping only the
        // current initialized contents avoids re-erasing a large retained
        // allocation for every short string that follows it.
        self.bytes.as_mut_slice().zeroize();
        self.bytes.clear();
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        if len < self.bytes.len() {
            self.bytes[len..].zeroize();
            self.bytes.truncate(len);
        }
    }

    pub(crate) fn pop(&mut self) -> Option<u8> {
        let last = match self.bytes.last_mut() {
            Some(last) => last,
            None => return None,
        };
        let value = *last;
        last.zeroize();
        let _ = self.bytes.pop();
        Some(value)
    }
}

impl Deref for Scratch {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Extend<u8> for Scratch {
    fn extend<I: IntoIterator<Item = u8>>(&mut self, iter: I) {
        for byte in iter {
            self.push(byte);
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Error messages can contain decoded input. Format directly into a guarded
/// owner so growth and error destruction erase every owned message copy.
pub(crate) struct GuardedString(Scratch);

impl GuardedString {
    pub(crate) fn from_display(value: impl Display) -> Self {
        let mut message = GuardedString(Scratch::new());
        fmt::write(&mut message, format_args!("{}", value))
            .expect("a Display implementation returned an error unexpectedly");
        message
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        assert!(self.is_char_boundary(len));
        self.0.truncate(len);
    }
}

impl Deref for GuardedString {
    type Target = str;

    fn deref(&self) -> &str {
        // Every write originates from a valid &str and truncation preserves a
        // character boundary. Check the invariant before exposing a string.
        str::from_utf8(&self.0).expect("guarded error messages are UTF-8")
    }
}

impl Write for GuardedString {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }
}
