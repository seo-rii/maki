//! `SecretBuffer` — plaintext container with restricted semantics (SPEC §15).
//!
//! Required properties:
//! - minimize Clone support (no `Clone` impl; explicit [`SecretBuffer::duplicate`])
//! - zeroize on Drop
//! - never print contents in Debug
//! - participate in memory budgeting (exact `len` is always known)
//! - optionally pinned in RAM (SPEC §36 `secure-buffers`): when
//!   [`set_page_locking`] is on, every buffer's pages are `mlock`ed for its
//!   lifetime (Unix), so plaintext and keys never reach swap. Locking is
//!   best-effort per buffer because `RLIMIT_MEMLOCK` can be exhausted;
//!   failures are counted ([`page_lock_failures`]) and reported by the
//!   daemon, and the secure-swap policy is the second line of defence.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(unix)]
use std::{collections::HashMap, sync::OnceLock};

use zeroize::Zeroize;

static LOCK_PAGES: AtomicBool = AtomicBool::new(false);
static LOCK_FAILURES: AtomicU64 = AtomicU64::new(0);
static UNGUARDED_WRAPS: AtomicU64 = AtomicU64::new(0);

/// Buffers created by [`SecretBuffer::from_vec`] since process start: secret
/// bytes that already existed in an ordinary, unguarded allocation before
/// they were wrapped. A data path that decrypts or loads keys correctly
/// allocates the guarded buffer *first* and fills it in place, so this
/// counter must not move while it runs (R4-002). Diagnostic; tests compare
/// deltas around an operation.
pub fn unguarded_wraps() -> u64 {
    UNGUARDED_WRAPS.load(Ordering::SeqCst)
}

/// Enable or disable page locking for buffers created from now on.
pub fn set_page_locking(enabled: bool) {
    LOCK_PAGES.store(enabled, Ordering::SeqCst);
}

pub fn page_locking_enabled() -> bool {
    LOCK_PAGES.load(Ordering::SeqCst)
}

/// Buffers that could not be locked while locking was enabled.
pub fn page_lock_failures() -> u64 {
    LOCK_FAILURES.load(Ordering::SeqCst)
}

#[cfg(unix)]
struct PageLock {
    start: usize,
    last: usize,
    page_size: usize,
}

#[cfg(unix)]
fn locked_pages() -> &'static parking_lot::Mutex<HashMap<usize, usize>> {
    static REFERENCES: OnceLock<parking_lot::Mutex<HashMap<usize, usize>>> = OnceLock::new();
    REFERENCES.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

#[cfg(unix)]
fn lock_pages(address: *const u8, length: usize) -> Option<PageLock> {
    if length == 0 {
        return None;
    }
    // SAFETY: sysconf has no pointer arguments.
    let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .ok()
        .filter(|size| *size > 0)?;
    let address = address as usize;
    let start = address / page_size * page_size;
    let last = address.checked_add(length - 1)? / page_size * page_size;
    let mut references = locked_pages().lock();
    // mlock/munlock do not stack: serialize them with the ownership counts.
    // A failed mlock changes no locks and earns no references.
    // SAFETY: every page intersects this buffer's live allocation. The
    // aligned range also works on Unix hosts requiring page alignment.
    if unsafe { libc::mlock(start as *const libc::c_void, last - start + page_size) } != 0 {
        return None;
    }
    for page in (start..=last).step_by(page_size) {
        *references.entry(page).or_default() += 1;
    }
    Some(PageLock {
        start,
        last,
        page_size,
    })
}

#[cfg(unix)]
impl Drop for PageLock {
    fn drop(&mut self) {
        let mut references = locked_pages().lock();
        for page in (self.start..=self.last).step_by(self.page_size) {
            let owners = references.get_mut(&page).expect("page lock is registered");
            *owners -= 1;
            if *owners == 0 {
                references.remove(&page);
                // SAFETY: the buffer still owns its allocation during
                // unlock, and no other SecretBuffer owns this page's lock.
                unsafe {
                    libc::munlock(page as *const libc::c_void, self.page_size);
                }
            }
        }
    }
}

#[cfg(not(unix))]
struct PageLock;

#[cfg(not(unix))]
fn lock_pages(_address: *const u8, _length: usize) -> Option<PageLock> {
    None
}

/// A byte buffer holding plaintext or key material.
///
/// Deliberately does **not** implement `Clone`; copying secret material must be
/// an explicit, visible act via [`SecretBuffer::duplicate`].
pub struct SecretBuffer {
    data: Vec<u8>,
    page_lock: Option<PageLock>,
}

/// A fixed-capacity secret buffer cannot accept more bytes without moving
/// plaintext through an unguarded allocator growth path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretBufferCapacityError;

impl std::fmt::Display for SecretBufferCapacityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("secret buffer capacity exceeded")
    }
}

impl std::error::Error for SecretBufferCapacityError {}

impl SecretBuffer {
    fn wrap(data: Vec<u8>) -> Self {
        let page_lock = if page_locking_enabled() {
            // Drop erases the complete allocation, including spare capacity,
            // so the page lock must cover that same range.
            let lock = lock_pages(data.as_ptr(), data.capacity());
            if lock.is_none() && data.capacity() != 0 {
                LOCK_FAILURES.fetch_add(1, Ordering::SeqCst);
            }
            lock
        } else {
            None
        };
        Self { data, page_lock }
    }

    /// A zero-filled buffer of `len` bytes.
    pub fn zeroed(len: usize) -> Self {
        Self::wrap(vec![0u8; len])
    }

    /// Allocate fixed-capacity guarded storage without initializing its
    /// logical contents. The allocation is page-locked, when enabled, before
    /// callers can write secret bytes into it.
    pub fn with_capacity(capacity: usize) -> Result<Self, std::collections::TryReserveError> {
        let mut data = Vec::new();
        data.try_reserve_exact(capacity)?;
        Ok(Self::wrap(data))
    }

    /// Take ownership of an existing byte vector.
    ///
    /// The bytes were produced outside guarded memory (unlocked, and not
    /// zeroized if a copy was reallocated on the way). Prefer allocating
    /// the buffer first ([`zeroed`](Self::zeroed), [`with_capacity`](Self::with_capacity),
    /// [`from_slice`](Self::from_slice)) and producing the secret in place;
    /// every call here is counted by [`unguarded_wraps`].
    pub fn from_vec(data: Vec<u8>) -> Self {
        UNGUARDED_WRAPS.fetch_add(1, Ordering::SeqCst);
        Self::wrap(data)
    }

    /// Shorten the logical contents to `len` bytes without reallocating.
    /// The bytes beyond `len` stay inside the guarded allocation until the
    /// buffer is dropped (Drop zeroizes the whole capacity). A `len` beyond
    /// the current length is a no-op.
    pub fn truncate(&mut self, len: usize) {
        if len < self.data.len() {
            self.data[len..].zeroize();
            self.data.truncate(len);
        }
    }

    /// Copy from a slice.
    pub fn from_slice(data: &[u8]) -> Self {
        let mut copy = Self::with_capacity(data.len()).expect("secret buffer allocation failed");
        copy.try_extend_from_slice(data)
            .expect("secret buffer capacity was preallocated");
        copy
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

    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Append without reallocating. On failure the buffer is unchanged.
    pub fn try_extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), SecretBufferCapacityError> {
        let length = self
            .data
            .len()
            .checked_add(bytes.len())
            .ok_or(SecretBufferCapacityError)?;
        if length > self.data.capacity() {
            return Err(SecretBufferCapacityError);
        }
        self.data.extend_from_slice(bytes);
        Ok(())
    }

    /// Whether this buffer's pages are pinned in RAM.
    pub fn is_page_locked(&self) -> bool {
        self.page_lock.is_some()
    }

    /// Explicit, intentional copy of secret material.
    pub fn duplicate(&self) -> Self {
        Self::from_slice(&self.data)
    }

    /// Consume, returning the inner vector. The caller takes over the
    /// zeroization obligation. This releases the buffer's page-lock
    /// ownership; a peer on the same page may still keep that page pinned.
    pub fn into_vec(mut self) -> Vec<u8> {
        self.page_lock.take();
        std::mem::take(&mut self.data)
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        // Keep the page locks through zeroization. The guard remembers the
        // original range even though Vec::zeroize clears its length
        // (C-02 / BUG-006).
        self.data.zeroize();
        self.page_lock.take();
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
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Page locking is a process-global toggle.
    fn serial() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

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

    #[test]
    fn page_locking_is_opt_in_and_accounted() {
        let _serial = serial();
        assert!(!SecretBuffer::zeroed(64).is_page_locked());
        set_page_locking(true);
        let before = page_lock_failures();
        let buffer = SecretBuffer::zeroed(64);
        // Either the pages are pinned or the failure was counted (e.g. an
        // exhausted RLIMIT_MEMLOCK, or a non-Unix host).
        assert!(buffer.is_page_locked() || page_lock_failures() > before);
        let plain = buffer.into_vec();
        assert_eq!(plain.len(), 64);
        set_page_locking(false);
        assert!(!SecretBuffer::zeroed(64).is_page_locked());
    }

    #[test]
    fn spare_capacity_is_part_of_the_protected_allocation() {
        let _serial = serial();
        let mut data = Vec::with_capacity(8192);
        data.push(0x5a);
        set_page_locking(true);
        let buffer = SecretBuffer::from_vec(data);
        assert_eq!(buffer.capacity(), 8192);
        assert!(buffer.is_page_locked() || page_lock_failures() > 0);
        set_page_locking(false);
    }

    #[test]
    fn truncate_keeps_the_allocation_and_erases_the_tail() {
        let mut buffer = SecretBuffer::from_slice(b"plaintext-and-tag");
        let address = buffer.expose().as_ptr();
        let capacity = buffer.capacity();
        buffer.truncate(9);
        assert_eq!(buffer.expose(), b"plaintext");
        assert_eq!(buffer.expose().as_ptr(), address);
        assert_eq!(buffer.capacity(), capacity);
        // The tail is erased eagerly, not only at drop.
        // SAFETY: the bytes are inside the buffer's own capacity, which is
        // still allocated and was initialized by from_slice.
        let tail = unsafe { std::slice::from_raw_parts(address.add(9), capacity - 9) };
        assert!(tail.iter().all(|b| *b == 0), "{tail:?}");
        buffer.truncate(100);
        assert_eq!(buffer.len(), 9);
    }

    #[test]
    fn guarded_constructors_are_not_counted_as_unguarded_wraps() {
        let _serial = serial();
        let before = unguarded_wraps();
        let _a = SecretBuffer::zeroed(32);
        let _b = SecretBuffer::with_capacity(32).unwrap();
        let _c = SecretBuffer::from_slice(b"copied into guarded memory first");
        let _d = _c.duplicate();
        assert_eq!(unguarded_wraps(), before);
        let _e = SecretBuffer::from_vec(vec![1, 2, 3]);
        assert_eq!(unguarded_wraps(), before + 1);
    }

    #[test]
    fn fixed_capacity_append_never_reallocates() {
        let mut buffer = SecretBuffer::with_capacity(4).unwrap();
        let address = buffer.expose().as_ptr();
        buffer.try_extend_from_slice(b"test").unwrap();
        assert_eq!(buffer.expose(), b"test");
        assert_eq!(buffer.expose().as_ptr(), address);
        assert!(buffer.try_extend_from_slice(b"!").is_err());
        assert_eq!(buffer.expose(), b"test");
    }
}
