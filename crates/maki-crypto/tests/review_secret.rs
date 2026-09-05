//! C-02: a page-locked `SecretBuffer` must `munlock` its pages when it is
//! dropped. Zeroizing first emptied the vector, so the unlock saw a
//! zero-length range and every dropped buffer stayed pinned; once the
//! locked total crossed `RLIMIT_MEMLOCK`, every later `mlock` failed and
//! new plaintext silently became swappable.

#[cfg(target_os = "linux")]
fn serial() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

#[cfg(target_os = "linux")]
#[test]
fn dropping_locked_buffers_releases_their_pages() {
    use maki_crypto::secret::{page_lock_failures, set_page_locking};
    use maki_crypto::SecretBuffer;

    let _serial = serial();
    // A small lock limit for this process only (the test has its own
    // binary). 1 MiB: sixteen 64 KiB buffers alive at once would exceed it.
    let limit = libc::rlimit {
        rlim_cur: 1 << 20,
        rlim_max: 1 << 20,
    };
    // SAFETY: plain libc call with a valid pointer.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    assert_eq!(rc, 0, "setrlimit failed");

    set_page_locking(true);
    let probe = SecretBuffer::zeroed(64 << 10);
    if !probe.is_page_locked() {
        eprintln!("mlock unavailable in this environment; skipping");
        set_page_locking(false);
        return;
    }
    drop(probe);
    let before = page_lock_failures();
    for _ in 0..64 {
        let buffer = SecretBuffer::zeroed(64 << 10);
        assert!(
            buffer.is_page_locked(),
            "lock failed mid-run (pages leaked?)"
        );
        drop(buffer);
    }
    assert_eq!(
        page_lock_failures(),
        before,
        "later mlock calls failed: dropped buffers left their pages pinned"
    );
    set_page_locking(false);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn dropping_locked_buffers_releases_their_pages() {
    // Page locking is a Unix feature; the Linux run under WSL covers it.
}

/// F04 (third review): `mlock`/`munlock` work on whole pages with no
/// reference count. Buffers that shared a heap page unlocked each other
/// when the first one dropped, while the survivor still reported itself
/// locked. Dropping one buffer must never unlock a live neighbour: each
/// survivor's address must still sit in a VMA the kernel marks locked.
#[cfg(target_os = "linux")]
#[test]
fn dropping_a_buffer_never_unlocks_a_live_neighbours_pages() {
    use maki_crypto::secret::set_page_locking;
    use maki_crypto::SecretBuffer;

    /// `VmFlags` of the VMA containing `addr` in /proc/self/smaps includes
    /// `lo` (VM_LOCKED)?
    fn vma_is_locked(addr: usize) -> bool {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut inside = false;
        for line in smaps.lines() {
            let first = line.split_whitespace().next().unwrap_or("");
            if let Some((start, end)) = first.split_once('-') {
                if let (Ok(s), Ok(e)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                ) {
                    inside = s <= addr && addr < e;
                    continue;
                }
            }
            if inside && line.starts_with("VmFlags:") {
                return line.split_whitespace().any(|f| f == "lo");
            }
        }
        false
    }

    let _serial = serial();
    set_page_locking(true);
    let probe = SecretBuffer::zeroed(64);
    if !probe.is_page_locked() || !vma_is_locked(probe.expose().as_ptr() as usize) {
        eprintln!("mlock unavailable or not visible in smaps here; skipping");
        set_page_locking(false);
        return;
    }
    drop(probe);

    // Many small secrets, allocated back to back: a heap allocator packs
    // them onto shared pages.
    let buffers: Vec<SecretBuffer> = (0..32u8)
        .map(|i| SecretBuffer::from_slice(&[i; 64]))
        .collect();
    assert!(buffers.iter().all(SecretBuffer::is_page_locked));
    let mut survivors = Vec::new();
    for (i, buffer) in buffers.into_iter().enumerate() {
        if i % 2 == 0 {
            drop(buffer);
        } else {
            survivors.push(buffer);
        }
    }
    for (i, survivor) in survivors.iter().enumerate() {
        assert!(survivor.is_page_locked());
        assert!(
            vma_is_locked(survivor.expose().as_ptr() as usize),
            "survivor {i} reports locked but its page is no longer VM_LOCKED"
        );
        assert_eq!(survivor.expose(), &[(2 * i + 1) as u8; 64]);
    }
    drop(survivors);
    set_page_locking(false);
}
