//! Audit probe (round 2, #153 follow-up): #153 made every *privileged*
//! observer read `/proc/self/mountinfo` as bytes, because Linux emits
//! non-UTF-8 path bytes verbatim and one such mount anywhere in the
//! namespace (a user's FUSE mount, a Latin-1 USB/CIFS mount) made every
//! observation fail. The daemon's `[security.memory_budget]` admission
//! (`security/memory.rs`) still reads the table with `read_to_string` and
//! decodes every mount path as UTF-8, so the same unrelated mount refuses
//! attach and readiness of a memory-budgeted volume.
//!
//! The probe re-runs itself inside a private mount namespace (`unshare -m`),
//! so the extra tmpfs mount it creates never reaches the host. It compares
//! `memory::verify` on the same host with and without one unrelated mount
//! whose path is not UTF-8: the outcome must not depend on that mount.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;

use maki_format::config::parse_config;

const MODE: &str = "AUDIT2_MOUNTINFO_MODE";

const CONFIG: &str = r#"
config_schema_version = 1
[volume]
name = "budget"
max_virtual_size = "1MiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = "/unused-audit2-budget"
[security.memory_budget]
max_bytes = "1GiB"
startup_headroom_bytes = "1MiB"
required_memlock_bytes = 1024
"#;

fn verify_outcome() -> String {
    let config = parse_config(CONFIG).unwrap();
    match maki_nbdkit::security::memory::verify(&config) {
        Ok(posture) => format!("ok {posture:?}"),
        Err(error) => format!("err {error}"),
    }
}

/// Child half: runs only inside `unshare -m` (see the parent test).
#[test]
#[ignore = "child process of mountinfo_bytes_do_not_change_memory_budget_admission"]
fn audit2_memory_budget_child() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let mut mounted: Option<PathBuf> = None;
    let scratch = tempfile::tempdir().unwrap();
    if mode == "nonutf8" {
        // A directory name that is valid on Linux but not UTF-8.
        let mut name = scratch.path().as_os_str().as_bytes().to_vec();
        name.extend_from_slice(b"/mnt-\xff");
        let path = PathBuf::from(OsStr::from_bytes(&name));
        std::fs::create_dir(&path).unwrap();
        let status = Command::new("mount")
            .args(["-t", "tmpfs", "audit2-none"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success(), "mount in the private namespace failed");
        mounted = Some(path);
    }
    let outcome = verify_outcome();
    if let Some(path) = mounted {
        let _ = Command::new("umount").arg(&path).status();
        let _ = std::fs::remove_dir(&path);
    }
    println!("AUDIT2-OUTCOME: {outcome}");
}

fn run_child(mode: &str) -> Option<String> {
    let exe = std::env::current_exe().unwrap();
    let output = Command::new("unshare")
        .args(["-m", "--propagation", "private"])
        .arg(exe)
        .args([
            "--exact",
            "audit2_memory_budget_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, mode)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.split_once("AUDIT2-OUTCOME: ").map(|(_, rest)| rest))
        .map(str::to_owned)
}

#[test]
fn mountinfo_bytes_do_not_change_memory_budget_admission() {
    let Some(plain) = run_child("plain") else {
        eprintln!("skipped: cannot create a private mount namespace here");
        return;
    };
    let Some(nonutf8) = run_child("nonutf8") else {
        panic!("child with the extra mount produced no outcome");
    };
    println!("without the extra mount: {plain}");
    println!("with a non-UTF-8 mount:  {nonutf8}");
    assert_eq!(
        plain, nonutf8,
        "one unrelated mount whose path is not UTF-8 changed the memory-budget admission"
    );
}
