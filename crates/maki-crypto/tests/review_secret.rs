//! C-02: a page-locked `SecretBuffer` must `munlock` its pages when it is
//! dropped. Zeroizing first emptied the vector, so the unlock saw a
//! zero-length range and every dropped buffer stayed pinned; once the
//! locked total crossed `RLIMIT_MEMLOCK`, every later `mlock` failed and
//! new plaintext silently became swappable.

#[cfg(target_os = "linux")]
#[test]
fn dropping_locked_buffers_releases_their_pages() {
    use maki_crypto::{page_lock_failures, set_page_locking, SecretBuffer};

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
