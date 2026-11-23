//! Audit (round 4, config-ops): `[security.memory_budget]` admission
//! (`security/memory.rs`) parses the daemon's whole `/proc/self/mountinfo`
//! before it looks for the cgroup-v2 mount. Two properties of *unrelated*
//! mounts elsewhere in the namespace change its verdict:
//!
//! - a mount whose source string is empty is printed by Linux as an empty
//!   field (`- tmpfs  rw,...`); `mountinfo_fields` drops empty fields, so the
//!   record has two filesystem fields and admission fails with "malformed
//!   mountinfo fields";
//! - the table is read with a 1 MiB bound, so a host with enough mounts
//!   (a few thousand) fails with "oversized kernel field".
//!
//! Each probe runs in a child process inside a private mount namespace
//! (`unshare -m`), so its extra mounts never reach the host. The child joins
//! a private, empty cgroup-v2 group created for this test (removed again
//! afterwards) so that admission gets past the membership check and reads
//! the mount table, exactly as a daemon in `maki@<volume>.service` would.
//! The verdict with and without the unrelated mounts must be the same.
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use maki_format::config::parse_config;

const MODE: &str = "AUDIT4_MEMORY_BUDGET_MODE";
const GROUP: &str = "AUDIT4_MEMORY_BUDGET_GROUP";
const UNIFIED: &str = "/sys/fs/cgroup/unified";

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
root = "/unused-audit4-budget"
[security.memory_budget]
max_bytes = "1GiB"
startup_headroom_bytes = "1MiB"
required_memlock_bytes = 1024
"#;

fn mount(source: &str, target: &Path, fstype: &str, flags: libc::c_ulong) {
    let source = CString::new(source).unwrap();
    let target_c = CString::new(target.as_os_str().as_bytes()).unwrap();
    let fstype = CString::new(fstype).unwrap();
    // SAFETY: valid NUL-terminated strings; data is null.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    assert_eq!(
        rc,
        0,
        "mount {target:?}: {}",
        std::io::Error::last_os_error()
    );
}

fn outcome() -> String {
    let config = parse_config(CONFIG).unwrap();
    match maki_nbdkit::security::memory::verify(&config) {
        Ok(posture) => format!("ok {posture:?}"),
        Err(error) => format!("err {error}"),
    }
}

/// Child half: runs only inside `unshare -m` (see the parent test).
#[test]
#[ignore = "child process of audit4_unrelated_mounts_do_not_change_memory_budget_admission"]
fn audit4_memory_budget_child() {
    let (Ok(mode), Ok(group)) = (std::env::var(MODE), std::env::var(GROUP)) else {
        return;
    };
    std::fs::write(Path::new(&group).join("cgroup.procs"), "0").unwrap();
    let scratch = tempfile::tempdir().unwrap();
    match mode.as_str() {
        "plain" => {}
        "empty-source" => {
            let target = scratch.path().join("empty-source");
            std::fs::create_dir(&target).unwrap();
            mount("", &target, "tmpfs", 0);
        }
        "many" => {
            let source = scratch.path().join("source");
            std::fs::create_dir(&source).unwrap();
            let long = "m".repeat(200);
            let mut count = 0;
            while std::fs::read("/proc/self/mountinfo").unwrap().len() <= (1 << 20) + 4096 {
                let target: PathBuf = scratch.path().join(format!("{long}{count}"));
                std::fs::create_dir(&target).unwrap();
                mount(source.to_str().unwrap(), &target, "", libc::MS_BIND);
                count += 1;
            }
            println!("AUDIT4-MOUNTS: {count}");
        }
        other => panic!("unknown mode {other}"),
    }
    println!("AUDIT4-OUTCOME: {}", outcome());
}

fn run_child(mode: &str, group: &Path) -> Option<String> {
    let exe = std::env::current_exe().unwrap();
    let output = Command::new("unshare")
        .args(["-m", "--propagation", "private"])
        .arg(exe)
        .args([
            "--exact",
            "audit4_memory_budget_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, mode)
        .env(GROUP, group)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().filter(|l| l.starts_with("AUDIT4-MOUNTS")) {
        println!("{mode}: {line}");
    }
    let found = stdout
        .lines()
        .find_map(|line| line.split_once("AUDIT4-OUTCOME: ").map(|(_, rest)| rest))
        .map(str::to_owned);
    if found.is_none() {
        println!("{mode} child output:\n{stdout}{}", String::from_utf8_lossy(&output.stderr));
    }
    found
}

#[test]
fn audit4_unrelated_mounts_do_not_change_memory_budget_admission() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 || !Path::new(UNIFIED).join("cgroup.procs").exists() {
        eprintln!("skipped: needs root and a cgroup-v2 hierarchy at {UNIFIED}");
        return;
    }
    let group = Path::new(UNIFIED).join(format!("audit4-cfgops-{}", std::process::id()));
    std::fs::create_dir(&group).unwrap();
    let plain = run_child("plain", &group);
    let empty = run_child("empty-source", &group);
    let many = run_child("many", &group);
    let _ = std::fs::remove_dir(&group);
    let plain = plain.expect("child without extra mounts produced no outcome");
    println!("without extra mounts:         {plain}");
    println!("with one empty-source mount:  {empty:?}");
    println!("with a >1 MiB mount table:    {many:?}");
    assert!(
        !plain.contains("mountinfo") && !plain.contains("oversized"),
        "control: the baseline verdict comes from the cgroup itself: {plain}"
    );
    assert_eq!(
        Some(&plain),
        empty.as_ref(),
        "BUG: one unrelated empty-source mount changed the memory-budget admission"
    );
    assert_eq!(
        Some(&plain),
        many.as_ref(),
        "BUG: a large but valid mount table changed the memory-budget admission"
    );
}
