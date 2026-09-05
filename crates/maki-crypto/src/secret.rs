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
fn lock_pages(data: &[u8]) -> Option<PageLock> {
    if data.is_empty() {
        return None;
    }
    // SAFETY: sysconf has no pointer arguments.
    let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .ok()
        .filter(|size| *size > 0)?;
    let address = data.as_ptr() as usize;
    let start = address / page_size * page_size;
    let last = (address + data.len() - 1) / page_size * page_size;
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
fn lock_pages(_data: &[u8]) -> Option<PageLock> {
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

impl SecretBuffer {
    fn wrap(data: Vec<u8>) -> Self {
        let page_lock = if page_locking_enabled() {
            let lock = lock_pages(&data);
            if lock.is_none() && !data.is_empty() {
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

    /// Take ownership of an existing byte vector.
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self::wrap(data)
    }

    /// Copy from a slice.
    pub fn from_slice(data: &[u8]) -> Self {
        Self::wrap(data.to_vec())
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

    /// Whether this buffer's pages are pinned in RAM.
    pub fn is_page_locked(&self) -> bool {
        self.page_lock.is_some()
    }

    /// Explicit, intentional copy of secret material.
    pub fn duplicate(&self) -> Self {
        Self::wrap(self.data.clone())
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
}
