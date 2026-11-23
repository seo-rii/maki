//! Audit (round 4, config-ops): the mountinfo parsers of the privileged
//! helper split a record on ASCII spaces and *drop empty fields*. Linux
//! prints a mount whose source string is empty as an empty field
//! (`... - tmpfs  rw,mode=755`): the source column disappears, the
//! filesystem part has two fields instead of three, and the helper treats
//! the whole table as malformed. One such mount anywhere in the helper's
//! namespace then makes automatic NBD allocation (every attach) and the
//! cleanup / recovery observation fail for every volume, until the mount is
//! removed. This is the empty-field residual of the non-UTF-8 fix (#153).
//!
//! The scenario runs in a child process inside a private mount namespace
//! (root only), so nothing outside the test is touched: a tmpfs is mounted
//! over `/run` there, a hand-written trusted record names a disconnected NBD
//! device with no live resources (cleanup must retire it), and a tmpfs with
//! an empty source string is mounted at an unrelated path.
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

const CHILD_ENV: &str = "MAKI_AUDIT4_MOUNTINFO_EMPTY_SOURCE_CHILD";
const VOLUME: &str = "audit4empty";
const VOLUME_UUID: &str = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

fn mount(source: &str, target: &Path, fstype: &str, data: &str) {
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
            0,
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
        .into_existing_request(VOLUME, Default::default(), false)
        .unwrap();
    maki_privileged::plan::plan_detach(&request)
}

fn child() {
    mount("tmpfs", Path::new("/run"), "tmpfs", "mode=0755");
    let empty = Path::new("/run/audit4-empty-source");
    std::fs::create_dir(empty).unwrap();

    let baseline = maki_privileged::exec::allocate_nbd_device();
    println!("baseline: allocate_nbd_device = {baseline:?}");

    write_record();
    // An unrelated mount whose source string is empty (an unprivileged
    // FUSE mount with `-o fsname=` produces the same record).
    mount("", empty, "tmpfs", "mode=0755");
    let line = std::fs::read("/proc/self/mountinfo")
        .unwrap()
        .split(|&b| b == b'\n')
        .find(|line| line.windows(24).any(|w| w == b"/run/audit4-empty-source"))
        .map(|line| String::from_utf8_lossy(line).into_owned());
    println!("mountinfo record: {line:?}");

    let allocation = maki_privileged::exec::allocate_nbd_device();
    println!("with empty-source mount: allocate_nbd_device = {allocation:?}");
    let cleanup = maki_privileged::exec::cleanup(&plan());
    println!("with empty-source mount: cleanup = {cleanup:?}");
    let record_kept = Path::new(&format!("/run/maki-attach/{VOLUME}.nbd")).exists();

    umount(empty);
    let cleanup_after = maki_privileged::exec::cleanup(&plan());
    println!("after removing the mount: cleanup = {cleanup_after:?}");
    let record_after = Path::new(&format!("/run/maki-attach/{VOLUME}.nbd")).exists();

    assert!(
        matches!(baseline, Err(maki_privileged::exec::ExecError::NoFreeDevice)),
        "control: without NBD devices allocation reports NoFreeDevice: {baseline:?}"
    );
    assert!(
        cleanup_after.is_ok() && !record_after,
        "control: cleanup retires a disconnected, resource-free record"
    );
    assert!(
        matches!(allocation, Err(maki_privileged::exec::ExecError::NoFreeDevice)),
        "BUG: an unrelated empty-source mount makes NBD allocation fail: {allocation:?}"
    );
    assert!(
        cleanup.is_ok() && !record_kept,
        "BUG: an unrelated empty-source mount makes cleanup fail: {cleanup:?}"
    );
}

#[test]
fn audit4_unrelated_empty_source_mount_blocks_privileged_observation() {
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
            "audit4_unrelated_empty_source_mount_blocks_privileged_observation",
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
