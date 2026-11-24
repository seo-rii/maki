//! Round-9 audit (slug `r8-privileged`): the device move of #383 (an attach
//! gives up an auto-allocated device the kernel keeps refusing as busy)
//! against the older machinery: rollback, the failed-start hook, cleanup,
//! recover, detach, grow, a second volume and somebody else's connection.
//!
//! `System`, `execute_with`, `cleanup_with` and
//! `finish_interrupted_activation_with` are crate-private, and this audit adds
//! no file under `src/`. As the round-8 audit did, this integration test
//! compiles the crate's own sources a second time through the directory
//! `tests/audit9_mirror/`: every production source there, and the two-volume
//! harness `review_stale_attach_record.rs`, is a symbolic link to the file
//! under `src/`; the other in-crate test modules are one-line files; and
//! `audit9_mirror/review_busy_allocated_device.rs`, the module the harness
//! declares below itself, holds this audit's tests instead of the crate's.
//!
//! Run with:
//! `cargo test -p maki-privileged --locked --test audit9_device_move -- --test-threads=2 audit9 --nocapture`
//! (the filter leaves out the harness file's own tests and the in-source
//! unit tests of `recover.rs`, which the mirror compiles as well).
#![cfg(target_os = "linux")]
#![allow(dead_code, unused_imports, unused_variables, unused_macros)]

#[path = "audit9_mirror/config.rs"]
pub mod config;
#[path = "audit9_mirror/plan.rs"]
pub mod plan;
#[path = "audit9_mirror/probe.rs"]
pub mod probe;
#[path = "audit9_mirror/verify.rs"]
pub mod verify;

#[path = "audit9_mirror/exec.rs"]
pub mod exec;

#[path = "audit9_mirror/nbd_kernel.rs"]
pub mod nbd_kernel;

#[path = "audit9_mirror/state.rs"]
mod state;

#[path = "audit9_mirror/detach.rs"]
mod detach;

/// The mirror must be the production source: every link resolves to the file
/// of the same name under `src/` (or `src/nbd_kernel/`).
#[test]
fn audit9_the_mirror_links_to_the_production_sources() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mirror = manifest.join("tests/audit9_mirror");
    let mut links = 0;
    for entry in std::fs::read_dir(&mirror).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        let meta = std::fs::symlink_metadata(entry.path()).unwrap();
        if !meta.file_type().is_symlink() {
            continue;
        }
        links += 1;
        let resolved = std::fs::canonicalize(entry.path()).unwrap();
        let direct = manifest.join("src").join(&name);
        let nested = manifest.join("src/nbd_kernel").join(&name);
        let expected = if direct.exists() { direct } else { nested };
        assert_eq!(
            resolved,
            std::fs::canonicalize(&expected).unwrap(),
            "{name} does not link to the production source"
        );
    }
    assert_eq!(links, 17, "the mirror's production sources and the harness");
}
