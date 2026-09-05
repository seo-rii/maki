//! `SecretBuffer` — plaintext container with restricted semantics (SPEC §15).
//!
//! Required properties:
//! - minimize Clone support (no `Clone` impl; explicit [`SecretBuffer::duplicate`])
//! - zeroize on Drop
//! - never print contents in Debug
//! - participate in memory budgeting (exact `len` is always known)
//! - optionally pinned in RAM (SPEC §36 `secure-buffers`): when
//!   [`set_page_locking`] is on, every buffer lives in its *own* page-aligned
//!   allocation whose pages are `mlock`ed for its lifetime (Unix), so
//!   plaintext and keys never reach swap. Locking is best-effort per buffer
//!   because `RLIMIT_MEMLOCK` can be exhausted; failures are counted
//!   ([`page_lock_failures`]) and reported by the daemon, and the
//!   secure-swap policy is the second line of defence.
//!
//! Page isolation is what makes the lock a per-buffer guarantee: `mlock`
//! and `munlock` work on whole pages and keep no reference count, so two
//! buffers sharing a heap page would unlock each other's bytes when the
//! first one dropped (third review, F04). A locked buffer therefore never
//! shares a page with anything else, is wiped in place while still locked,
//! and is unlocked only after the wipe.

use std::alloc::Layout;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

/// The system page size (the unit `mlock` works in).
pub fn page_size() -> usize {
    use std::sync::OnceLock;
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        #[cfg(unix)]
        {
            // SAFETY: sysconf is a plain query.
            let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if value > 0 {
                return value as usize;
            }
        }
        4096
    })
}

#[cfg(unix)]
fn lock_pages(ptr: *const u8, len: usize) -> bool {
    // SAFETY: the range is exactly this buffer's own page-aligned allocation.
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

#[cfg(unix)]
fn unlock_pages(ptr: *const u8, len: usize) {
    // SAFETY: the range was locked by `lock_pages` on the same allocation.
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(not(unix))]
fn lock_pages(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(unix))]
fn unlock_pages(_ptr: *const u8, _len: usize) {}

/// Where a buffer's bytes live.
enum Storage {
    /// Plain heap memory (locking disabled, or an empty buffer).
    Heap(Vec<u8>),
    /// A page-aligned, page-multiple allocation shared with nothing else.
    Pages {
        ptr: NonNull<u8>,
        len: usize,
        layout: Layout,
        locked: bool,
    },
}

/// Allocate `len` bytes of zeroed, page-aligned memory rounded up to whole
/// pages. `None` when the allocator refuses.
fn alloc_pages(len: usize) -> Option<(NonNull<u8>, Layout)> {
    let page = page_size();
    let size = len.checked_next_multiple_of(page)?;
    let layout = Layout::from_size_align(size, page).ok()?;
    // SAFETY: the layout has a non-zero size (len > 0 rounds up to >= page).
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    NonNull::new(ptr).map(|p| (p, layout))
}

/// A byte buffer holding plaintext or key material.
///
/// Deliberately does **not** implement `Clone`; copying secret material must be
/// an explicit, visible act via [`SecretBuffer::duplicate`].
pub struct SecretBuffer {
    storage: Storage,
}

// SAFETY: a buffer uniquely owns its allocation (no aliasing pointers
// escape), so moving it or sharing references across threads is as sound
// as for a `Vec<u8>`.
unsafe impl Send for SecretBuffer {}
unsafe impl Sync for SecretBuffer {}

impl SecretBuffer {
    /// Build page-isolated storage for `len` bytes, locking it when
    /// possible. `None` when locking is off, `len` is zero, or the
    /// allocator refuses (the caller falls back to the heap).
    fn isolated(len: usize) -> Option<Storage> {
        if !page_locking_enabled() || len == 0 {
            return None;
        }
        let (ptr, layout) = match alloc_pages(len) {
            Some(alloc) => alloc,
            None => {
                LOCK_FAILURES.fetch_add(1, Ordering::SeqCst);
                return None;
            }
        };
        let locked = lock_pages(ptr.as_ptr(), layout.size());
        if !locked {
            LOCK_FAILURES.fetch_add(1, Ordering::SeqCst);
        }
        Some(Storage::Pages {
            ptr,
            len,
            layout,
            locked,
        })
    }

    /// Take ownership of `data`. With locking on, the bytes move into an
    /// isolated allocation and the source vector is wiped.
    fn wrap(mut data: Vec<u8>) -> Self {
        match Self::isolated(data.len()) {
            Some(storage) => {
                let mut buffer = Self { storage };
                buffer.expose_mut().copy_from_slice(&data);
                data.zeroize();
                buffer
            }
            None => Self {
                storage: Storage::Heap(data),
            },
        }
    }

    /// A zero-filled buffer of `len` bytes.
    pub fn zeroed(len: usize) -> Self {
        match Self::isolated(len) {
            Some(storage) => Self { storage },
            None => Self {
                storage: Storage::Heap(vec![0u8; len]),
            },
        }
    }

    /// Take ownership of an existing byte vector (wiped if the bytes are
    /// copied into locked pages).
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self::wrap(data)
    }

    /// Copy from a slice.
    pub fn from_slice(data: &[u8]) -> Self {
        let mut buffer = Self::zeroed(data.len());
        buffer.expose_mut().copy_from_slice(data);
        buffer
    }

    pub fn expose(&self) -> &[u8] {
        match &self.storage {
            Storage::Heap(v) => v,
            // SAFETY: `ptr` is a live allocation of at least `len` bytes,
            // initialized (zeroed at allocation), owned by `self`.
            Storage::Pages { ptr, len, .. } => unsafe {
                std::slice::from_raw_parts(ptr.as_ptr(), *len)
            },
        }
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        match &mut self.storage {
            Storage::Heap(v) => v,
            // SAFETY: as in `expose`, and `&mut self` guarantees uniqueness.
            Storage::Pages { ptr, len, .. } => unsafe {
                std::slice::from_raw_parts_mut(ptr.as_ptr(), *len)
            },
        }
    }

    pub fn len(&self) -> usize {
        match &self.storage {
            Storage::Heap(v) => v.len(),
            Storage::Pages { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this buffer's pages are pinned in RAM.
    pub fn is_page_locked(&self) -> bool {
        matches!(self.storage, Storage::Pages { locked: true, .. })
    }

    /// Whether this buffer lives in its own page-aligned allocation.
    pub fn is_page_isolated(&self) -> bool {
        matches!(self.storage, Storage::Pages { .. })
    }

    /// Explicit, intentional copy of secret material.
    pub fn duplicate(&self) -> Self {
        Self::from_slice(self.expose())
    }

    /// Consume, returning the bytes as a plain vector. The caller takes
    /// over the zeroization obligation; the pages this buffer held are
    /// wiped and unlocked as it drops.
    pub fn into_vec(mut self) -> Vec<u8> {
        match &mut self.storage {
            Storage::Heap(v) => std::mem::take(v),
            Storage::Pages { .. } => self.expose().to_vec(),
        }
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        match &mut self.storage {
            Storage::Heap(v) => v.zeroize(),
            Storage::Pages {
                ptr,
                len: _,
                layout,
                locked,
            } => {
                // Wipe while still locked (the bytes never become
                // swappable), then unlock the whole allocation (only ours),
                // then free it.
                // SAFETY: the allocation is live and exclusively owned.
                unsafe {
                    std::slice::from_raw_parts_mut(ptr.as_ptr(), layout.size()).zeroize();
                }
                if *locked {
                    unlock_pages(ptr.as_ptr(), layout.size());
                    *locked = false;
                }
                // SAFETY: allocated by `alloc_pages` with this exact layout.
                unsafe { std::alloc::dealloc(ptr.as_ptr(), *layout) };
            }
        }
    }
}

impl std::fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBuffer({} bytes, redacted)", self.len())
    }
}

/// Constant-time-ish equality (length leak only). For tests and self-checks.
impl PartialEq for SecretBuffer {
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (self.expose(), other.expose());
        if a.len() != b.len() {
            return false;
        }
        let mut acc = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            acc |= x ^ y;
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

    /// With locking on, every buffer gets its own page-aligned allocation:
    /// no two buffers can share a page, whatever the allocator would do.
    #[test]
    fn locked_buffers_are_page_isolated() {
        let _serial = serial();
        set_page_locking(true);
        let page = page_size();
        let buffers: Vec<SecretBuffer> = (0..8)
            .map(|_| SecretBuffer::from_slice(&[7u8; 64]))
            .collect();
        for b in &buffers {
            assert!(b.is_page_isolated());
            assert_eq!(b.expose().as_ptr() as usize % page, 0, "page aligned");
            assert_eq!(b.expose(), &[7u8; 64]);
            assert_eq!(b.len(), 64);
        }
        let mut pages: Vec<usize> = buffers
            .iter()
            .map(|b| b.expose().as_ptr() as usize / page)
            .collect();
        pages.sort_unstable();
        pages.dedup();
        assert_eq!(pages.len(), buffers.len(), "two buffers share a page");
        // from_vec copies into isolated pages and wipes the source.
        let mut v = vec![9u8; 100];
        let ptr = v.as_ptr();
        let b = SecretBuffer::from_vec(std::mem::take(&mut v));
        assert!(b.is_page_isolated());
        assert_ne!(b.expose().as_ptr(), ptr);
        assert_eq!(b.into_vec(), vec![9u8; 100]);
        assert!(
            !SecretBuffer::zeroed(0).is_page_isolated(),
            "empty buffers allocate nothing"
        );
        set_page_locking(false);
        assert!(!SecretBuffer::zeroed(64).is_page_isolated());
    }
}
