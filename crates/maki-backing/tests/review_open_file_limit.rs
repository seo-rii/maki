//! BUG-124: every cataloged shard keeps its data file open, and systemd
//! starts services with a soft descriptor limit of 1024 (the hard limit is
//! 524288 by default), so a volume with about a thousand shards failed to
//! attach. Openers raise the soft limit to the hard limit first. This file
//! is its own test binary: lowering the limit cannot disturb other tests.
#![cfg(unix)]
// `rlim_t` is `u64` on Linux, not on every Unix.
#![allow(clippy::unnecessary_cast)]

use maki_backing::raise_open_file_limit;

fn limits() -> (libc::rlim_t, libc::rlim_t) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a valid, owned struct.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
    (limit.rlim_cur, limit.rlim_max)
}

fn set_soft(soft: libc::rlim_t) {
    let (_, hard) = limits();
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: setrlimit reads a valid struct; lowering the soft limit is
    // always permitted.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
}

#[test]
fn the_soft_descriptor_limit_is_raised_toward_the_hard_limit() {
    let (_, hard) = limits();
    if hard <= 64 {
        eprintln!("hard RLIMIT_NOFILE {hard} leaves nothing to raise");
        return;
    }
    set_soft(64);

    let raised = raise_open_file_limit().expect("raising within the hard limit is permitted");
    let (soft, after_hard) = limits();
    assert_eq!(after_hard, hard, "the hard limit is never changed");
    assert_eq!(soft as u64, raised, "the reported limit is the one in effect");
    assert!(
        soft > 64,
        "the soft limit stayed at 64 below a hard limit of {hard}"
    );
    assert!(
        soft == hard || soft as u64 == 1 << 20,
        "the soft limit {soft} is neither the hard limit {hard} nor the cap"
    );

    // Calling it again is harmless and never lowers the limit.
    assert_eq!(raise_open_file_limit().unwrap(), raised);
    assert_eq!(limits().0, soft);
}
