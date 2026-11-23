//! `[security.memory_budget]` admission reads the daemon's whole mount
//! table before it finds the cgroup-v2 mount, so ordinary host state
//! elsewhere in the namespace must not change its verdict:
//!
//! - a mount whose source string is empty (`mount -t tmpfs '' /dir`, a FUSE
//!   mount with an empty `fsname`), which Linux prints as an empty field:
//!   `- tmpfs  rw,...`;
//! - a mount table larger than 1 MiB, as on a host with a few thousand
//!   mounts (container hosts, many snap or loop mounts).
//!
//! Each scenario runs in a child process inside a private mount namespace
//! (`unshare(CLONE_NEWNS)` plus recursive private propagation), so its
//! mounts never reach the host, and compares `memory::verify` with and
//! without the extra mounts. The children join a private, empty cgroup-v2
//! group created for the test and removed afterwards, so that admission
//! gets past the membership check and parses the table, as it does for a
//! daemon in a service cgroup. Where the hierarchy has the memory
//! controller, the group's `memory.max` is set to the configured budget, so
//! admission runs to its end, including the final recheck of the table;
//! elsewhere it stops at the missing controller files, after the table has
//! been read and parsed. Without root, a private mount namespace or a
//! writable cgroup-v2 hierarchy, or where admission stops before the table,
//! the test prints why and checks nothing.

#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MODE: &str = "MAKI_REVIEW_MOUNT_TABLE_MODE";
const GROUP: &str = "MAKI_REVIEW_MOUNT_TABLE_GROUP";

/// The configured `max_bytes`.
const BUDGET_BYTES: u64 = 1 << 30;

const CONFIG: &str = r#"
config_schema_version = 1
[volume]
name = "memory-mount-table"
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

/// Phrases of verdicts that come from the membership file or the mount
/// table rather than from the cgroup: with one of them the comparison would
/// not reach the code under test.
const BEFORE_THE_CGROUP: [&str; 6] = [
    "membership",
    "mountinfo",
    "cgroup-v2 mount",
    "nested mount",
    "subtree cgroup mount",
    "cgroup path",
];

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

fn mount(source: &CStr, target: &Path, fstype: &CStr, flags: libc::c_ulong) -> std::io::Result<()> {
    let target = c_path(target);
    // SAFETY: NUL-terminated strings that outlive the call; no data.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Lazily detaches a mount and everything below it when dropped, so the
/// scratch directory under it can be removed.
struct Detach(PathBuf);

impl Drop for Detach {
    fn drop(&mut self) {
        let target = c_path(&self.0);
        // SAFETY: a NUL-terminated path that outlives the call.
        unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    }
}

/// Child half, already inside the private mount namespace. Everything it
/// mounts lies on a tmpfs at a scratch directory, detached at the end.
fn child(mode: &str) {
    let group = std::env::var_os(GROUP).expect("the parent names the cgroup");
    std::fs::write(Path::new(&group).join("cgroup.procs"), "0").unwrap();
    let scratch = tempfile::tempdir().unwrap();
    if let Err(error) = mount(c"maki-review", scratch.path(), c"tmpfs", 0) {
        println!("SKIP: cannot mount tmpfs in a private mount namespace: {error}");
        return;
    }
    let _detach = Detach(scratch.path().to_owned());
    match mode {
        "plain" => {}
        "empty-source" => {
            let target = scratch.path().join("empty-source");
            std::fs::create_dir(&target).unwrap();
            mount(c"", &target, c"tmpfs", 0).unwrap();
            let table = std::fs::read("/proc/self/mountinfo").unwrap();
            assert!(
                table.windows(10).any(|window| window == b" - tmpfs  "),
                "the kernel prints the empty source as an empty field"
            );
        }
        "large" => {
            // Bind mounts with long names, checked in batches, until the
            // table is larger than 1 MiB.
            let source = scratch.path().join("source");
            std::fs::create_dir(&source).unwrap();
            let name = "m".repeat(200);
            let mut count = 0;
            while std::fs::read("/proc/self/mountinfo").unwrap().len() <= (1 << 20) + (64 << 10) {
                for _ in 0..256 {
                    let target = scratch.path().join(format!("{name}{count}"));
                    std::fs::create_dir(&target).unwrap();
                    mount(&c_path(&source), &target, c"", libc::MS_BIND).unwrap();
                    count += 1;
                }
            }
            println!("bind mounts: {count}");
        }
        other => panic!("unknown mode {other}"),
    }
    println!("OUTCOME: {}", outcome());
}

/// A private, empty cgroup-v2 group under the hierarchy's mount, removed
/// when dropped (the children that joined it have exited by then).
struct Group(PathBuf);

impl Group {
    fn create(label: &str) -> Result<Self, String> {
        let table = std::fs::read("/proc/self/mountinfo").map_err(|e| e.to_string())?;
        let mut mounts = table.split(|&byte| byte == b'\n').filter_map(|line| {
            let line = std::str::from_utf8(line).ok()?;
            let (mount, filesystem) = line.split_once(" - ")?;
            (filesystem.split(' ').next() == Some("cgroup2"))
                .then(|| mount.split(' ').nth(4).map(PathBuf::from))
                .flatten()
        });
        let (Some(mount), None) = (mounts.next(), mounts.next()) else {
            return Err("no single cgroup-v2 mount in this namespace".into());
        };
        let name = format!("maki-review-mount-table-{}-{label}", std::process::id());
        let group = mount.join(name);
        std::fs::create_dir(&group)
            .map_err(|e| format!("cannot create a cgroup-v2 group under {mount:?}: {e}"))?;
        let group = Self(group);
        let limit = group.0.join("memory.max");
        if limit.exists() {
            std::fs::write(&limit, BUDGET_BYTES.to_string())
                .map_err(|e| format!("cannot set {limit:?}: {e}"))?;
        }
        Ok(group)
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir(&self.0) {
            eprintln!("cannot remove the test cgroup {:?}: {error}", self.0);
        }
    }
}

/// Run `test`'s child half in `mode`, in a fresh mount namespace whose
/// mounts do not propagate to the host. `Err` is the reason the host does
/// not permit it.
fn run(test: &str, mode: &str, group: &Group) -> Result<String, String> {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(MODE, mode)
        .env(GROUP, &group.0);
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
    if let Some(count) = field("bind mounts: ") {
        println!("{mode}: {count} bind mounts");
    }
    Ok(field("OUTCOME: ").unwrap_or_else(|| {
        panic!(
            "child ({mode}) reported no outcome:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    }))
}

/// Compare the verdict without extra mounts with the verdict in `mode`.
fn compare(test: &str, mode: &str) {
    if let Ok(mode) = std::env::var(MODE) {
        child(&mode);
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: a private mount namespace and cgroup need root");
        return;
    }
    let group = match Group::create(mode) {
        Ok(group) => group,
        Err(reason) => {
            eprintln!("skipped: {reason}");
            return;
        }
    };
    let outcomes = (run(test, "plain", &group), run(test, mode, &group));
    drop(group);
    let (plain, changed) = match outcomes {
        (Ok(plain), Ok(changed)) => (plain, changed),
        (Err(reason), _) | (_, Err(reason)) => {
            eprintln!("skipped: {reason}");
            return;
        }
    };
    println!("without the extra mounts: {plain}");
    println!("with the extra mounts ({mode}): {changed}");
    if BEFORE_THE_CGROUP.iter().any(|stage| plain.contains(stage)) {
        eprintln!("skipped: admission does not get past the mount table here: {plain}");
        return;
    }
    assert_eq!(
        plain, changed,
        "ordinary mounts unrelated to the cgroup-v2 hierarchy changed the memory-budget admission"
    );
}

#[test]
fn empty_source_mounts_do_not_change_memory_budget_admission() {
    compare(
        "empty_source_mounts_do_not_change_memory_budget_admission",
        "empty-source",
    );
}

#[test]
fn large_mount_tables_do_not_change_memory_budget_admission() {
    compare(
        "large_mount_tables_do_not_change_memory_budget_admission",
        "large",
    );
}
