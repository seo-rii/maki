//! Round-8 audit (slug `privileged-nbd`): the helper against the kernel's NBD
//! semantics, read from the CentOS Stream 9 driver, and the wire code (the
//! NBD handshake and generic netlink) as an attack surface.
//!
//! `System`, the executor entry points (`execute_with`, `cleanup_with`,
//! `recover_with`, `finish_interrupted_activation_with`) and the netlink
//! parser are crate-private, and new files under `src/` are not allowed in
//! this audit. This integration test therefore compiles the crate's own
//! sources a second time, as its own crate root, through the directory
//! `tests/audit8_mirror/`:
//!
//! - every production source there is a symbolic link to the file under
//!   `src/` (so exactly the code `maki-attach` runs is compiled);
//! - the in-crate test modules are empty files there, except
//!   `review_step_faults.rs`, which is an extended copy of the crate's
//!   step-fault harness: being the module `exec::review_step_faults`, the
//!   name `exec.rs` declares, it reaches the private `System` trait. It adds
//!   to the simulated kernel what the driver does and the original model
//!   leaves out (see that file's header);
//! - `audit8_mirror/audit8_wire.rs` holds the property tests of the handshake and of the
//!   netlink answer parser, and the probes against this host's kernel.
//!
//! Run with:
//! `cargo test -p maki-privileged --locked --test audit8_kernel_semantics -- --test-threads=2 audit8`
//! (the filter leaves out the four in-source unit tests of `recover.rs`,
//! which the mirror compiles as well; `logging.rs`, which nothing in the
//! mirror uses, is not part of it).
#![cfg(target_os = "linux")]
#![allow(dead_code, unused_imports, unused_variables, unused_macros)]

#[path = "audit8_mirror/config.rs"]
pub mod config;
#[path = "audit8_mirror/plan.rs"]
pub mod plan;
#[path = "audit8_mirror/probe.rs"]
pub mod probe;
#[path = "audit8_mirror/verify.rs"]
pub mod verify;

#[path = "audit8_mirror/exec.rs"]
pub mod exec;

#[path = "audit8_mirror/nbd_kernel.rs"]
pub mod nbd_kernel;

#[path = "audit8_mirror/state.rs"]
mod state;

#[path = "audit8_mirror/detach.rs"]
mod detach;

#[path = "audit8_mirror/audit8_wire.rs"]
mod audit8_wire;

/// The mirror must be the production source: every link resolves to the file
/// of the same name under `src/` (or `src/nbd_kernel/`).
#[test]
fn audit8_the_mirror_links_to_the_production_sources() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mirror = manifest.join("tests/audit8_mirror");
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
    assert_eq!(links, 16, "the mirror's production sources");
}
