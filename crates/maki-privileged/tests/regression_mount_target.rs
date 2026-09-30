//! The XFS mount runs as root onto a path the configuration names, and the
//! directories along that path may belong to the workload (for example a
//! `postgres`-owned parent). `mount(8)` resolves symlinks, so a workload
//! that replaced the mountpoint with a symlink to `/etc` got a filesystem
//! it controls mounted over `/etc`, and neither rollback nor detach could
//! undo it (they look for a mount at the configured path). The helper now
//! refuses a mountpoint unless every ancestor is a real directory owned by
//! a trusted uid and not writable by group or others (so the path cannot
//! change between the check and the mount) and the mountpoint itself is a
//! real directory, not a symlink.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use maki_privileged::exec::check_mount_target;

/// A private tree under the target directory: its ancestors are owned by
/// root or by the test user and are not group/other-writable (unlike /tmp).
fn tree(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("mount-target-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    root
}

fn trusted() -> Vec<u32> {
    // SAFETY: geteuid has no preconditions.
    vec![0, unsafe { libc::geteuid() }]
}

fn ancestors_are_safe(path: &Path) -> bool {
    // CARGO_TARGET_TMPDIR itself may sit below a group-writable directory
    // on some hosts; skip rather than report a false failure there.
    check_mount_target(path.to_str().unwrap(), &trusted()).is_ok()
}

#[test]
fn a_real_directory_below_trusted_ancestors_is_accepted() {
    let root = tree("ok");
    let mountpoint = root.join("data");
    std::fs::create_dir(&mountpoint).unwrap();
    if !ancestors_are_safe(&root) {
        eprintln!("skipping: the target directory has an untrusted ancestor");
        return;
    }
    check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap();
}

#[test]
fn a_symlinked_mountpoint_is_refused() {
    let root = tree("symlink");
    if !ancestors_are_safe(&root) {
        return;
    }
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let mountpoint = root.join("data");
    std::os::unix::fs::symlink(&elsewhere, &mountpoint).unwrap();
    let error = check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap_err();
    assert!(error.to_string().contains("symlink"), "{error}");
}

#[test]
fn a_symlinked_ancestor_is_refused() {
    let root = tree("symlink-parent");
    if !ancestors_are_safe(&root) {
        return;
    }
    let real = root.join("real");
    std::fs::create_dir_all(real.join("data")).unwrap();
    std::os::unix::fs::symlink(&real, root.join("link")).unwrap();
    let mountpoint = root.join("link").join("data");
    assert!(check_mount_target(mountpoint.to_str().unwrap(), &trusted()).is_err());
}

#[test]
fn an_ancestor_writable_by_others_or_owned_by_an_untrusted_uid_is_refused() {
    let root = tree("writable-parent");
    if !ancestors_are_safe(&root) {
        return;
    }
    let parent = root.join("parent");
    std::fs::create_dir_all(parent.join("data")).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mountpoint = parent.join("data");
    let error = check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap_err();
    assert!(error.to_string().contains("writable"), "{error}");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Only root trusted: the test user's directories are not.
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        assert!(check_mount_target(mountpoint.to_str().unwrap(), &[0]).is_err());
    }
    check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap();
}

#[test]
fn a_missing_or_non_directory_mountpoint_is_refused() {
    let root = tree("missing");
    if !ancestors_are_safe(&root) {
        return;
    }
    assert!(check_mount_target(root.join("absent").to_str().unwrap(), &trusted()).is_err());
    std::fs::write(root.join("file"), b"x").unwrap();
    assert!(check_mount_target(root.join("file").to_str().unwrap(), &trusted()).is_err());
}
