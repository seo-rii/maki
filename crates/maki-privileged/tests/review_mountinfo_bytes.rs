//! `/proc/self/mountinfo` is bytes, not UTF-8 text: Linux escapes only
//! space, tab, newline and backslash in its fields and emits every other
//! byte as is. One mount whose path or source is not UTF-8, anywhere in the
//! helper's mount namespace (a user's FUSE mount on a directory they own, a
//! Latin-1 CIFS or USB mount), must not make the privileged observations
//! fail: reading the table as a string blocked NBD allocation and cleanup
//! (planned stop, `maki-recover@`) for every volume, and the post-mount
//! verifier reported "nothing is mounted".
//!
//! The kernel scenario needs root and `unshare`. It runs in a child process
//! inside a private mount namespace (`unshare --mount --propagation
//! private`) that mounts a tmpfs over `/run` and further tmpfs mounts below
//! it. Nothing is mounted in the test's own namespace: the child refuses to
//! run unless its namespace differs from the parent's. Without root or a
//! usable `unshare` the test is skipped.
#![cfg(target_os = "linux")]

use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use maki_privileged::exec::{allocate_nbd_device, cleanup, observe_mount, ExecError};

const CHILD_ENV: &str = "MAKI_REVIEW_MOUNTINFO_BYTES_PARENT_NAMESPACE";
const TEST_NAME: &str = "review_non_utf8_mounts_do_not_block_privileged_observation";
const VOLUME: &str = "reviewbytes";
const VOLUME_UUID: &str = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

fn mount_tmpfs(source: &[u8], target: &Path) {
    let source = CString::new(source).unwrap();
    let target_c = CString::new(target.as_os_str().as_bytes()).unwrap();
    let fstype = CString::new("tmpfs").unwrap();
    let data = CString::new("mode=0755").unwrap();
    // SAFETY: every pointer is a valid NUL-terminated string for the call.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            data.as_ptr().cast(),
        )
    };
    assert_eq!(
        rc,
        0,
        "mount {target:?}: {}",
        std::io::Error::last_os_error()
    );
}

/// A trusted record for a disconnected device with no live resources:
/// cleanup must retire it.
fn write_record() -> std::path::PathBuf {
    let state = Path::new("/run/maki-attach");
    std::fs::create_dir_all(state).unwrap();
    std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let record = format!(
        r#"{{"version":1,"volume":"{VOLUME}","attachment":{{"volume_uuid":"{VOLUME_UUID}","nbd_socket":"/run/maki/{VOLUME}/nbd.sock","mountpoint":"/srv/{VOLUME}","vg_name":"vg_maki_{VOLUME}","lv_name":"data"}},"device":"/dev/nbd250","connection_id":"maki-11111111-2222-3333-4444-555555555555"}}"#
    );
    let path = state.join(format!("{VOLUME}.nbd"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut file, record.as_bytes()).unwrap();
    path
}

fn detach_plan() -> maki_privileged::plan::Plan {
    let config =
        maki_privileged::config::parse(&format!("volume_uuid = \"{VOLUME_UUID}\"\n")).unwrap();
    let request = config
        .into_request(VOLUME, Default::default(), false)
        .unwrap();
    maki_privileged::plan::plan_detach(&request)
}

fn namespace() -> OsString {
    std::fs::read_link("/proc/self/ns/mnt")
        .expect("mount namespace link")
        .into_os_string()
}

fn child(parent_namespace: OsString) {
    // Never mount anything in the namespace the test was started in.
    assert_ne!(
        namespace(),
        parent_namespace,
        "refusing to mount outside a private mount namespace"
    );
    let mounts = std::fs::read("/proc/self/mountinfo").unwrap();
    assert!(
        !mounts.windows(8).any(|field| field == b" shared:"),
        "the child's mounts must not propagate to another namespace"
    );

    mount_tmpfs(b"review-run", Path::new("/run"));
    let visible = Path::new("/run/review-visible");
    std::fs::create_dir(visible).unwrap();
    mount_tmpfs(b"review-visible", visible);
    let record = write_record();

    // Neither the path nor the source of this mount is UTF-8.
    let foreign = Path::new(OsStr::from_bytes(b"/run/review-\xff"));
    std::fs::create_dir(foreign).unwrap();
    mount_tmpfs(b"review-\xfe", foreign);
    let table = std::fs::read("/proc/self/mountinfo").unwrap();
    assert!(
        std::str::from_utf8(&table).is_err(),
        "the kernel emits the non-UTF-8 path unescaped"
    );

    let observed = observe_mount("/run/review-visible", "/dev/nbd250");
    assert_eq!(
        observed.fstype.as_deref(),
        Some("tmpfs"),
        "an unrelated non-UTF-8 mount hid every mount from the post-mount verifier"
    );
    let allocation = allocate_nbd_device();
    assert!(
        matches!(allocation, Ok(_) | Err(ExecError::NoFreeDevice)),
        "an unrelated non-UTF-8 mount made NBD allocation fail: {allocation:?}"
    );
    let cleaned = cleanup(&detach_plan());
    assert!(
        cleaned.is_ok(),
        "an unrelated non-UTF-8 mount made cleanup fail: {cleaned:?}"
    );
    assert!(!record.exists(), "cleanup retires the resource-free record");
}

#[test]
fn review_non_utf8_mounts_do_not_block_privileged_observation() {
    if let Some(parent_namespace) = std::env::var_os(CHILD_ENV) {
        child(parent_namespace);
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: a private mount namespace needs root");
        return;
    }
    let usable = Command::new("unshare")
        .args(["--mount", "--propagation", "private", "true"])
        .output()
        .is_ok_and(|output| output.status.success());
    if !usable {
        eprintln!("skipping: unshare cannot create a private mount namespace here");
        return;
    }
    let output = Command::new("unshare")
        .args(["--mount", "--propagation", "private"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, namespace())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "child failed:\n{text}");
    assert!(
        text.contains("test result: ok. 1 passed"),
        "the child did not run the scenario:\n{text}"
    );
}
