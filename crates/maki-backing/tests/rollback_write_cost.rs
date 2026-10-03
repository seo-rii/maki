//! R5-034: every page write rebuilt the committed and working slot sets and
//! cloned the file's whole page map, and every write rebuilt all
//! reservation coordinates, so a write's cost grew with committed data: a
//! 64 KiB write into an already reserved range took about 190 ms with
//! 128 MiB committed (release build), and filling 128 MiB took minutes.
//! The slot sets are now maintained incrementally and a write into a range
//! both views already reserve skips the recount.
#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use maki_backing::{Backing, RollbackBacking};

#[test]
#[ignore = "release gate: rollback-protected write cost at 128 MiB committed"]
fn phase_r5_rollback_write_cost_gate_full() {
    let root = tempfile::tempdir().unwrap();
    let witness = tempfile::tempdir_in("/dev/shm").unwrap();
    let backing = RollbackBacking::create(root.path(), witness.path(), 256 << 20).unwrap();
    let file = backing.open("journal", true).unwrap();
    let chunk = vec![7u8; 64 << 10];
    file.allocate_range(0, 136 << 20).unwrap();
    let started = Instant::now();
    let mut offset = 0u64;
    while offset < 128 << 20 {
        file.write_at(offset, &chunk).unwrap();
        offset += chunk.len() as u64;
    }
    file.sync_data().unwrap();
    let fill = started.elapsed();
    let started = Instant::now();
    for _ in 0..16 {
        file.write_at(offset, &chunk).unwrap();
        offset += chunk.len() as u64;
    }
    let per_write = started.elapsed() / 16;
    eprintln!("fill 128 MiB: {fill:?}; 64 KiB write at 128 MiB committed: {per_write:?}");
    assert!(
        per_write < Duration::from_millis(20),
        "a 64 KiB write took {per_write:?} with 128 MiB committed"
    );
    assert!(fill < Duration::from_secs(60), "filling 128 MiB took {fill:?}");
}
