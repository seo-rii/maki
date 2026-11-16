//! Audit (privileged scope): `/proc/self/mountinfo` is read with
//! `std::fs::read_to_string`, which fails on any byte sequence that is not
//! UTF-8. The kernel escapes only space, tab, newline and backslash in path
//! fields, so one mount anywhere in the helper's namespace whose path (or
//! source) contains a non-UTF-8 byte makes every kernel observation fail:
//! cleanup (the packaged ExecStop and recovery coordinator), detach,
//! recover, attach preflight, allocation and the workload `verify` gate.
//! Any local user who can create such a mount (for example a FUSE mount on
//! a directory they own, via the setuid `fusermount3`) blocks all volumes.
//!
//! The scenario runs in a child process inside a private mount namespace
//! (root only), so nothing outside the test is touched: a tmpfs is mounted
//! over `/run` there, a hand-written trusted record names a disconnected NBD
//! device with no live resources (cleanup must retire it), and a tmpfs is
//! mounted at a non-UTF-8 path.
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

const CHILD_ENV: &str = "MAKI_AUDIT_MOUNTINFO_NON_UTF8_CHILD";
const VOLUME: &str = "auditnonutf8";
const VOLUME_UUID: &str = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

fn mount(source: &str, target: &Path, fstype: &str, flags: libc::c_ulong, data: &str) {
    let source = CString::new(source).unwrap();
    let target = CString::new(target.as_os_str().as_bytes()).unwrap();
    let fstype = CString::new(fstype).unwrap();
    let data = CString::new(data).unwrap();
    // SAFETY: all pointers are valid NUL-terminated strings for the call.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
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

fn umount(target: &Path) {
    let target = CString::new(target.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::umount(target.as_ptr()) }, 0);
}

fn write_record() {
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
}

fn plan() -> maki_privileged::plan::Plan {
    let config =
        maki_privileged::config::parse(&format!("volume_uuid = \"{VOLUME_UUID}\"\n")).unwrap();
    let request = config
        .into_request(VOLUME, Default::default(), false)
        .unwrap();
    maki_privileged::plan::plan_detach(&request)
}

fn child() {
    // The parent started this process with `unshare --mount --propagation
    // private`: every thread shares that private namespace, and
    // `/proc/self/mountinfo` (read by the helper) describes it.
    mount("tmpfs", Path::new("/run"), "tmpfs", 0, "mode=0755");

    // A visible, ordinary mount the observer must find.
    let visible = Path::new("/run/audit-visible");
    std::fs::create_dir(visible).unwrap();
    mount("tmpfs", visible, "tmpfs", 0, "mode=0755");
    // A mount whose path contains the byte 0xff (as an unprivileged FUSE
    // mount on a user-owned directory could).
    let hostile = Path::new(std::ffi::OsStr::from_bytes(b"/run/audit-\xff"));
    std::fs::create_dir(hostile).unwrap();

    let observed = maki_privileged::exec::observe_mount("/run/audit-visible", "/dev/nbd250");
    println!("baseline observe_mount fstype = {:?}", observed.fstype);
    assert_eq!(observed.fstype.as_deref(), Some("tmpfs"));

    write_record();
    mount("tmpfs", hostile, "tmpfs", 0, "mode=0755");

    let observed = maki_privileged::exec::observe_mount("/run/audit-visible", "/dev/nbd250");
    println!(
        "with non-UTF-8 mount: observe_mount fstype = {:?}",
        observed.fstype
    );
    let allocation = maki_privileged::exec::allocate_nbd_device();
    println!("with non-UTF-8 mount: allocate_nbd_device = {allocation:?}");
    let cleanup = maki_privileged::exec::cleanup(&plan());
    println!("with non-UTF-8 mount: cleanup = {cleanup:?}");
    let record_kept = Path::new(&format!("/run/maki-attach/{VOLUME}.nbd")).exists();

    umount(hostile);
    let cleanup_after = maki_privileged::exec::cleanup(&plan());
    println!("after removing the mount: cleanup = {cleanup_after:?}");
    let record_after = Path::new(&format!("/run/maki-attach/{VOLUME}.nbd")).exists();

    assert!(
        cleanup_after.is_ok() && !record_after,
        "control: cleanup retires a disconnected, resource-free record"
    );
    assert_eq!(
        observed.fstype.as_deref(),
        Some("tmpfs"),
        "BUG: an unrelated non-UTF-8 mount hides every mount from the observer"
    );
    assert!(
        cleanup.is_ok() && !record_kept,
        "BUG: an unrelated non-UTF-8 mount makes cleanup fail: {cleanup:?}"
    );
}

#[test]
fn audit_unrelated_non_utf8_mount_blocks_privileged_observation() {
    if std::env::var_os(CHILD_ENV).is_some() {
        child();
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: a private mount namespace needs root");
        return;
    }
    let output = Command::new("unshare")
        .args(["--mount", "--propagation", "private"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "audit_unrelated_non_utf8_mount_blocks_privileged_observation",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{text}");
    assert!(output.status.success(), "child failed:\n{text}");
}
