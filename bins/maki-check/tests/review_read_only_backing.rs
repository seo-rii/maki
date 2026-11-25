//! `maki-check <root>` and `maki-check <root> --deep` on a backing root this
//! process cannot write.
//!
//! They failed on a root on a read-only mount with "Read-only file system
//! (os error 30)", and on a tree whose files and directories this user may
//! not write with "Permission denied": they opened every file read-write,
//! and the deep check took the volume lock exclusively. When the root cannot
//! be written they now open it read-only, change nothing, take the volume
//! lock shared through a read-only descriptor, and say that the check was
//! read-only (the deep verdict is `unproven`, never `clean`).
//!
//! Root ignores mode bits, so a root run drops CAP_DAC_OVERRIDE from the
//! command's bounding set before it starts. The read-only mount needs a
//! private mount namespace and the immutable flag needs root: without it
//! those cases print why they are skipped.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::SystemTime;

use maki_backing::{Backing, FileBacking};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;

const MOUNT_CHILD: &str = "MAKI_REVIEW_READ_ONLY_CHECK_MOUNT";
const MOUNT_TEST: &str = "maki_check_reads_a_root_on_a_read_only_mount";

fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Run `maki-check`; as root, without CAP_DAC_OVERRIDE, so that modes apply.
fn maki_check(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki-check"));
    command.args(args);
    // SAFETY: runs in the forked child before exec and only makes raw
    // system calls.
    unsafe {
        command.pre_exec(|| {
            const CAP_DAC_OVERRIDE: libc::c_ulong = 1;
            if libc::geteuid() == 0
                && libc::prctl(libc::PR_CAPBSET_DROP, CAP_DAC_OVERRIDE, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.output().expect("spawn maki-check")
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Every entry below `root` with its mode, its bytes if it is a file, and
/// its modification time.
fn tree(root: &Path) -> Vec<(PathBuf, u32, Option<Vec<u8>>, SystemTime)> {
    let mut entries = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let bytes = if metadata.is_dir() {
            for entry in std::fs::read_dir(&path).unwrap() {
                pending.push(entry.unwrap().path());
            }
            None
        } else {
            Some(std::fs::read(&path).unwrap())
        };
        entries.push((
            path,
            metadata.permissions().mode(),
            bytes,
            metadata.modified().unwrap(),
        ));
    }
    entries.sort();
    entries
}

fn set_modes(root: &Path, file: u32, directory: u32) {
    for (path, mode, _, _) in tree(root) {
        let mode = if mode & 0o040000 != 0 {
            directory
        } else {
            file
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// A volume with a checkpointed unit, in `directory/vol`.
fn volume(directory: &Path) -> PathBuf {
    let root = directory.join("vol");
    let backing = Arc::new(FileBacking::new(&root).unwrap());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x0EAD_0471),
            provider_type: "local-aes-gcm-siv".into(),
            crypto_compatibility_id: "local-aes-gcm-siv-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 544, 1 << 20, 64 << 10).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(
        backing as Arc<dyn Backing>,
        VolumeOptions {
            journal_segment_size: 4096,
        },
    )
    .unwrap();
    volume.write_ct(3, &[0x11; 540], true).unwrap();
    volume.checkpoint().unwrap();
    root
}

/// The fast and the deep check read the root without changing it and say
/// that they read it read-only.
fn read_only_checks(root: &Path) {
    let before = tree(root);
    let shown = root.to_str().unwrap();
    let fast = maki_check(&[shown]);
    assert!(fast.status.success(), "{}", text(&fast));
    let report = String::from_utf8_lossy(&fast.stdout);
    assert!(
        report.contains("warning: read-only check: ") && report.ends_with("check passed\n"),
        "{}",
        text(&fast)
    );
    let deep = maki_check(&[shown, "--deep"]);
    assert!(deep.status.success(), "{}", text(&deep));
    let report = String::from_utf8_lossy(&deep.stdout);
    assert!(
        report.contains("slots: 1 allocated, 0 invalid")
            && report.contains("warning: read-only check: ")
            && report.contains("info: deep check verdict: unproven\n")
            && !report.contains("verdict: clean")
            && report.ends_with("check passed\n"),
        "{}",
        text(&deep)
    );
    assert_eq!(tree(root), before, "a read-only check changed the backing");
}

#[test]
fn maki_check_reads_a_tree_it_may_not_write() {
    let directory = tempfile::tempdir().unwrap();
    let root = volume(directory.path());
    set_modes(&root, 0o400, 0o500);
    let result = std::panic::catch_unwind(|| read_only_checks(&root));
    set_modes(&root, 0o600, 0o700);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    let deep = maki_check(&[root.to_str().unwrap(), "--deep"]);
    assert!(deep.status.success(), "{}", text(&deep));
    let report = String::from_utf8_lossy(&deep.stdout);
    assert!(
        report.contains("info: deep check verdict: clean\n") && !report.contains("read-only"),
        "{}",
        text(&deep)
    );
}

const FS_IMMUTABLE_FL: libc::c_int = 0x10;

fn set_immutable(path: &Path, immutable: bool) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path)?;
    let mut flags: libc::c_int = 0;
    // SAFETY: the descriptor is open and both ioctls access one c_int.
    unsafe {
        if libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if immutable {
            flags |= FS_IMMUTABLE_FL;
        } else {
            flags &= !FS_IMMUTABLE_FL;
        }
        if libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Clears the immutable flag again on drop.
struct Immutable(Vec<PathBuf>);

impl Drop for Immutable {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = set_immutable(path, false);
        }
    }
}

/// An immutable tree refuses even root's writes, and its directory answers
/// the write-access probe EPERM, not EROFS or EACCES.
#[test]
fn maki_check_reads_an_immutable_root() {
    if !running_as_root() {
        eprintln!("skipping: setting the immutable flag needs root");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = volume(directory.path());
    let mut immutable = Immutable(Vec::new());
    for (path, _, _, _) in tree(&root) {
        if let Err(error) = set_immutable(&path, true) {
            eprintln!("skipping: the filesystem refuses the immutable flag ({error})");
            return;
        }
        immutable.0.push(path);
    }
    let error = std::fs::OpenOptions::new()
        .write(true)
        .open(root.join("superblock.a"))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    read_only_checks(&root);
}

/// Detaches the read-only bind mount on drop, before the fixture's
/// directories are removed.
struct Mounted(std::ffi::CString);

impl Drop for Mounted {
    fn drop(&mut self) {
        // SAFETY: the path is a valid NUL-terminated string for the call.
        unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
    }
}

fn bind_read_only(path: &Path) -> Mounted {
    use std::os::unix::ffi::OsStrExt;
    let target = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: every pointer is null or a valid NUL-terminated string for
    // the call; this runs in a private mount namespace.
    unsafe {
        assert_eq!(
            libc::mount(
                target.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            ),
            0,
            "bind mount: {}",
            std::io::Error::last_os_error()
        );
        let mounted = Mounted(target);
        assert_eq!(
            libc::mount(
                std::ptr::null(),
                mounted.0.as_ptr(),
                std::ptr::null(),
                libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
                std::ptr::null(),
            ),
            0,
            "read-only remount: {}",
            std::io::Error::last_os_error()
        );
        mounted
    }
}

#[test]
fn maki_check_reads_a_root_on_a_read_only_mount() {
    if std::env::var_os(MOUNT_CHILD).is_some() {
        let directory = tempfile::tempdir().unwrap();
        let root = volume(directory.path());
        let _mounted = bind_read_only(&root);
        let error = std::fs::OpenOptions::new()
            .write(true)
            .open(root.join("superblock.a"))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
        read_only_checks(&root);
        return;
    }
    if !running_as_root() {
        eprintln!("skipping: a read-only bind mount in a private mount namespace needs root");
        return;
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", MOUNT_TEST, "--nocapture", "--test-threads=1"])
        .env(MOUNT_CHILD, "1");
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
    let output = command.output().unwrap();
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{}",
        text(&output)
    );
}
