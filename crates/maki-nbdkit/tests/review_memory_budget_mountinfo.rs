//! `[security.memory_budget]` admission reads the kernel's mount table. A
//! mount unrelated to the cgroup-v2 hierarchy must not change its outcome,
//! whatever its path bytes: Linux escapes only space, tab, newline and
//! backslash in mountinfo and emits every other byte as is, so a user's FUSE
//! mount or a Latin-1 USB label anywhere in the daemon's namespace puts
//! non-UTF-8 bytes, `\012` escapes or deep paths into the table.
//!
//! The test re-runs itself in a private mount namespace, so the tmpfs mounts
//! it adds never reach the host, and compares `memory::verify` with and
//! without them. Where a mount namespace or a tmpfs mount is not permitted
//! (unprivileged CI), it prints why and checks nothing.

#![cfg(target_os = "linux")]

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MODE: &str = "MAKI_REVIEW_MOUNTINFO_MODE";
const TEST: &str = "unrelated_mount_path_bytes_do_not_change_memory_budget_admission";

const CONFIG: &str = r#"
config_schema_version = 1
[volume]
name = "memory-mountinfo"
max_virtual_size = "1MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = { source = "env", name = "unused" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/unused"
[cache]
lock_memory = false
[security]
memory_lock_mode = "off"
[security.memory_budget]
max_bytes = "1GiB"
startup_headroom_bytes = "1MiB"
required_memlock_bytes = 0
"#;

/// The admission verdict, without the host's fluctuating usage figures.
fn outcome() -> String {
    let config = maki_nbdkit::daemon::parse_and_validate(CONFIG).unwrap();
    match maki_nbdkit::security::memory::verify(&config) {
        Ok(_) => "admitted".into(),
        Err(error) => error.to_string(),
    }
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

fn mount_tmpfs(path: &Path) -> std::io::Result<()> {
    let target = c_path(path);
    // SAFETY: NUL-terminated strings that outlive the call; no data.
    let rc = unsafe {
        libc::mount(
            c"maki-review".as_ptr(),
            target.as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn unmount_all(paths: &[PathBuf]) {
    for path in paths.iter().rev() {
        let target = c_path(path);
        // SAFETY: a NUL-terminated path that outlives the call.
        unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    }
}

/// Child half, already inside the private mount namespace.
fn child(mode: &str) {
    let scratch = tempfile::tempdir().unwrap();
    let mut mounted = Vec::new();
    if mode == "foreign" {
        let base = scratch.path().as_os_str().as_bytes();
        let deep = b"/d".repeat(300);
        for name in [b"/fuse-\xff".as_slice(), b"/usb\nstick", &deep] {
            let path = PathBuf::from(OsStr::from_bytes(&[base, name].concat()));
            std::fs::create_dir_all(&path).unwrap();
            if let Err(error) = mount_tmpfs(&path) {
                unmount_all(&mounted);
                println!("SKIP: cannot mount tmpfs in a private mount namespace: {error}");
                return;
            }
            mounted.push(path);
        }
        let table = std::fs::read("/proc/self/mountinfo").unwrap();
        for shown in [b"/fuse-\xff ".as_slice(), b"/usb\\012stick "] {
            assert!(
                table.windows(shown.len()).any(|window| window == shown),
                "the kernel did not list {}",
                String::from_utf8_lossy(shown)
            );
        }
    }
    let outcome = outcome();
    unmount_all(&mounted);
    println!("OUTCOME: {outcome}");
}

/// Run the child half in a fresh mount namespace whose mounts do not
/// propagate to the host. `Err` is the reason the host does not permit it.
fn run_in_private_namespace(mode: &str) -> Result<String, String> {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(MODE, mode);
    // SAFETY: runs in the forked child before exec and only makes raw
    // system calls on static strings.
    unsafe {
        command.pre_exec(|| {
            if libc::unshare(libc::CLONE_NEWNS) != 0
                || libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command
        .output()
        .map_err(|e| format!("cannot enter a private mount namespace: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let field = |tag: &str| {
        stdout
            .lines()
            .find_map(|line| line.split_once(tag).map(|(_, rest)| rest.to_owned()))
    };
    if let Some(reason) = field("SKIP: ") {
        return Err(reason);
    }
    Ok(field("OUTCOME: ").unwrap_or_else(|| {
        panic!(
            "child ({mode}) reported no outcome:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    }))
}

#[test]
fn unrelated_mount_path_bytes_do_not_change_memory_budget_admission() {
    if let Ok(mode) = std::env::var(MODE) {
        child(&mode);
        return;
    }
    let mut outcomes = Vec::new();
    for mode in ["plain", "foreign"] {
        match run_in_private_namespace(mode) {
            Ok(outcome) => outcomes.push(outcome),
            Err(reason) => {
                eprintln!("skipped: {reason}");
                return;
            }
        }
    }
    println!("without the extra mounts: {}", outcomes[0]);
    println!("with the extra mounts:    {}", outcomes[1]);
    assert_eq!(
        outcomes[0], outcomes[1],
        "mounts unrelated to the cgroup-v2 hierarchy changed the memory-budget admission"
    );
}
