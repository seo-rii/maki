//! `maki volume inspect`, `maki check` and `maki check --deep` on a backing
//! this process cannot write.
//!
//! They failed on a backing on a read-only mount with "Read-only file system
//! (os error 30)", and on a tree whose files and directories this user may
//! not write with "Permission denied": they opened every file read-write,
//! and the deep check took the volume lock exclusively. When the backing
//! root cannot be written they now open it read-only: nothing is written,
//! synced, created or removed, the deep check takes the volume lock shared
//! through a read-only descriptor, and the report says that it was read-only
//! and what that cannot prove (the deep verdict is `unproven`, never
//! `clean`). A rollback-protected backing has no read-only open and is
//! refused with the reason.
//!
//! Root ignores mode bits, so a root run drops CAP_DAC_OVERRIDE from the
//! command's bounding set before it starts. The read-only mount needs a
//! private mount namespace, which needs root: without it that case prints
//! why it is skipped.
#![cfg(target_os = "linux")]

#[path = "support/volume_config.rs"]
mod volume_config;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::SystemTime;

const KEY_ENV: &str = "MAKI_CREDENTIAL_READ_ONLY_BACKING_KEY";
const KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const MOUNT_CHILD: &str = "MAKI_REVIEW_READ_ONLY_BACKING_MOUNT";
const MOUNT_TEST: &str = "check_and_inspect_read_a_backing_on_a_read_only_mount";

fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn config(root: &Path, witness: Option<&Path>) -> String {
    let rollback = witness
        .map(|witness| {
            format!(
                "[backing.rollback_protection]\nwitness_root = {}\ncapacity = \"8MiB\"\n",
                serde_json::to_string(witness.to_str().unwrap()).unwrap()
            )
        })
        .unwrap_or_default();
    format!(
        r#"
config_schema_version = 1
[volume]
name = "read-only-backing"
max_virtual_size = "16MiB"
shard_logical_size = "8MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "read-only-backing-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = {}
journal_segment_size = "64KiB"
journal_max_bytes = "1MiB"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "64KiB"
{rollback}[nbd]
maximum_io = "64KiB"
"#,
        serde_json::to_string(root.to_str().unwrap()).unwrap(),
    )
}

/// Run `maki`; as root, without CAP_DAC_OVERRIDE, so that modes apply.
fn maki(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki"));
    command.args(args).env(KEY_ENV, KEY_HEX);
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
    command.output().expect("spawn maki")
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn succeeded(what: &str, output: &Output) {
    assert!(output.status.success(), "{what}: {}", text(output));
}

/// Every entry below `root` with its mode, its bytes if it is a file, and
/// its modification time, which a rewrite of identical bytes and a created
/// or removed entry (in its directory) change.
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

struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    /// A volume created by `maki volume create`.
    fn new() -> Self {
        let fixture = Self {
            directory: tempfile::tempdir().unwrap(),
        };
        volume_config::write(fixture.config(), config(&fixture.root(), None)).unwrap();
        succeeded(
            "create",
            &maki(&["volume", "create", fixture.config().to_str().unwrap()]),
        );
        fixture
    }

    fn root(&self) -> PathBuf {
        self.directory.path().join("volume")
    }

    fn config(&self) -> PathBuf {
        self.directory.path().join("volume.toml")
    }

    /// A configuration of a rollback-protected backing at the volume's
    /// root, with a witness directory beside it.
    fn protected(&self) -> (PathBuf, PathBuf) {
        let witness = self.directory.path().join("witness");
        std::fs::create_dir_all(&witness).unwrap();
        let path = self.directory.path().join("protected.toml");
        volume_config::write(&path, config(&self.root(), Some(&witness))).unwrap();
        (path, witness)
    }
}

/// `inspect`, `check` and `check --deep` read the volume without changing
/// it and say that they read it read-only.
fn read_only_commands(fixture: &Fixture) {
    let config = fixture.config();
    let config = config.to_str().unwrap();
    let before = tree(&fixture.root());

    let inspect = maki(&["volume", "inspect", config]);
    succeeded("inspect", &inspect);
    assert!(
        String::from_utf8_lossy(&inspect.stdout).contains("uuid:"),
        "{}",
        text(&inspect)
    );
    let check = maki(&["check", config]);
    succeeded("check", &check);
    let report = String::from_utf8_lossy(&check.stdout);
    assert!(
        report.contains("warning: read-only check: ") && report.ends_with("check passed\n"),
        "{}",
        text(&check)
    );
    let deep = maki(&["check", config, "--deep"]);
    succeeded("check --deep", &deep);
    let report = String::from_utf8_lossy(&deep.stdout);
    assert!(
        report.contains("warning: read-only check: ")
            && report.contains("info: deep check verdict: unproven\n")
            && !report.contains("verdict: clean")
            && report.ends_with("check passed\n"),
        "{}",
        text(&deep)
    );
    assert_eq!(
        tree(&fixture.root()),
        before,
        "a read-only command changed the backing"
    );
}

/// A rollback-protected configuration whose backing root or witness
/// directory cannot be written is refused, naming the directory, before
/// anything is opened.
fn protected_refused(config: &Path, directory: &Path, setting: &str) {
    for args in [
        &["volume", "inspect", config.to_str().unwrap()][..],
        &["check", config.to_str().unwrap()],
        &["check", config.to_str().unwrap(), "--deep"],
    ] {
        let output = maki(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {}", text(&output));
        let expected = format!(
            "{} (`{setting}`) cannot be written by this process, and a rollback-protected \
             backing cannot be checked or inspected read-only",
            directory.display()
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&expected),
            "{args:?}: {}",
            text(&output)
        );
    }
}

#[test]
fn check_and_inspect_read_a_tree_they_may_not_write() {
    let fixture = Fixture::new();
    set_modes(&fixture.root(), 0o400, 0o500);
    let result = std::panic::catch_unwind(|| read_only_commands(&fixture));
    set_modes(&fixture.root(), 0o600, 0o700);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    // With write access back, the deep check is the writable one again.
    let deep = maki(&["check", fixture.config().to_str().unwrap(), "--deep"]);
    succeeded("writable check --deep", &deep);
    let report = String::from_utf8_lossy(&deep.stdout);
    assert!(
        report.contains("info: deep check verdict: clean\n") && !report.contains("read-only"),
        "{}",
        text(&deep)
    );
}

#[test]
fn a_protected_backing_it_cannot_write_is_refused_with_the_reason() {
    let fixture = Fixture::new();
    let (config, witness) = fixture.protected();
    let root = fixture.root();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = std::panic::catch_unwind(|| protected_refused(&config, &root, "backing.root"));
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    std::fs::set_permissions(&witness, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = std::panic::catch_unwind(|| {
        protected_refused(
            &config,
            &witness,
            "backing.rollback_protection.witness_root",
        )
    });
    std::fs::set_permissions(&witness, std::fs::Permissions::from_mode(0o700)).unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

/// A protected root is never read as a plain one because its configuration
/// stanza went missing: the read-only open refuses it as the writable one
/// does.
#[test]
fn a_protected_root_without_its_configuration_is_refused_read_only_too() {
    let fixture = Fixture::new();
    std::fs::write(fixture.root().join("rollback.format"), b"").unwrap();
    let config = fixture.config();
    let config = config.to_str().unwrap();
    let refused = || {
        for args in [
            &["volume", "inspect", config][..],
            &["check", config],
            &["check", config, "--deep"],
        ] {
            let output = maki(args);
            assert_eq!(output.status.code(), Some(1), "{args:?}: {}", text(&output));
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("protected backing requires [backing.rollback_protection]"),
                "{args:?}: {}",
                text(&output)
            );
        }
    };
    refused();
    set_modes(&fixture.root(), 0o400, 0o500);
    let result = std::panic::catch_unwind(refused);
    set_modes(&fixture.root(), 0o600, 0o700);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
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
fn check_and_inspect_read_a_backing_on_a_read_only_mount() {
    if std::env::var_os(MOUNT_CHILD).is_some() {
        let fixture = Fixture::new();
        let (protected, _) = fixture.protected();
        let _mounted = bind_read_only(&fixture.root());
        let error = std::fs::OpenOptions::new()
            .write(true)
            .open(fixture.root().join("superblock.a"))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
        read_only_commands(&fixture);
        protected_refused(&protected, &fixture.root(), "backing.root");
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
