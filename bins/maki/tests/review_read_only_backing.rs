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
//! `clean`). A rollback-protected backing whose backing root or witness
//! directory cannot be written was refused, since opening it rewrites its
//! authenticated state and the witness record. It is now read through a
//! read-only view too: the same authentication, shared locks, nothing
//! written in either directory, and the verdict `unproven`; a damaged page,
//! a manifest the witness does not select and a backing in use are still
//! refused.
//!
//! Root ignores mode bits, so a root run drops CAP_DAC_OVERRIDE from the
//! command's bounding set before it starts. The read-only mount needs a
//! private mount namespace, which needs root: without it that case prints
//! why it is skipped.
#![cfg(target_os = "linux")]

#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

#[path = "support/short_dir.rs"]
mod short_dir;

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

/// An entry with its mode, its bytes if it is a file, and its modification
/// time.
type Entry = (PathBuf, u32, Option<Vec<u8>>, SystemTime);

/// Every entry below `root` with its mode, its bytes if it is a file, and
/// its modification time, which a rewrite of identical bytes and a created
/// or removed entry (in its directory) change.
fn tree(root: &Path) -> Vec<Entry> {
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
}

/// A rollback-protected volume created by `maki volume create`, its witness
/// directory on another filesystem.
struct Protected {
    directory: tempfile::TempDir,
    witness_parent: tempfile::TempDir,
}

impl Protected {
    /// `None`, after a notice, without a second filesystem for the witness.
    fn new() -> Option<Self> {
        let directory = tempfile::tempdir().unwrap();
        let witness_parent = other_filesystem::tempdir(directory.path())?;
        let protected = Self {
            directory,
            witness_parent,
        };
        volume_config::write(
            protected.config(),
            config(&protected.root(), Some(&protected.witness())),
        )
        .unwrap();
        succeeded(
            "create",
            &maki(&["volume", "create", protected.config().to_str().unwrap()]),
        );
        Some(protected)
    }

    fn root(&self) -> PathBuf {
        self.directory.path().join("volume")
    }

    fn witness(&self) -> PathBuf {
        self.witness_parent.path().join("witness")
    }

    fn config(&self) -> PathBuf {
        self.directory.path().join("protected.toml")
    }

    /// Set the modes of the backing root and of the witness directory (not
    /// of what they hold), run `run`, and give both their `0700` back.
    fn with_modes(&self, root: u32, witness: u32, run: impl FnOnce()) {
        let set = |root, witness| {
            std::fs::set_permissions(self.root(), std::fs::Permissions::from_mode(root)).unwrap();
            std::fs::set_permissions(self.witness(), std::fs::Permissions::from_mode(witness))
                .unwrap();
        };
        set(root, witness);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
        set(0o700, 0o700);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    /// A rollback-protected volume, made as [`Self::new`] makes one, that
    /// holds data written through the daemon's NBD adapter (what the nbdkit
    /// plugin's callbacks call): eight units in two shards, checkpointed
    /// into their slots before a clean detach. Its configuration names a key
    /// file, for the adapter in this process, and a control socket of its
    /// own; the commands load neither.
    fn with_data() -> Option<(Self, tempfile::TempDir)> {
        let directory = tempfile::tempdir().unwrap();
        let witness_parent = other_filesystem::tempdir(directory.path())?;
        let protected = Self {
            directory,
            witness_parent,
        };
        let key = protected.directory.path().join("volume.key");
        std::fs::write(&key, KEY_HEX).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let sockets = short_dir::tempdir().unwrap();
        volume_config::write(
            protected.config(),
            config(&protected.root(), Some(&protected.witness())).replace(
                r#"key = { source = "env", name = "read-only-backing-key" }"#,
                &format!(
                    "key = {{ source = \"file\", name = {} }}",
                    serde_json::to_string(key.to_str().unwrap()).unwrap()
                ),
            ) + &format!(
                "[control]\nsocket = {}\n",
                serde_json::to_string(sockets.path().join("c.sock").to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        succeeded(
            "create",
            &maki(&["volume", "create", protected.config().to_str().unwrap()]),
        );
        let adapter =
            maki_nbdkit::adapter::NbdAdapter::open_config(protected.config().to_str().unwrap())
                .unwrap();
        for (index, unit) in [0u64, 1, 2, 3, 2048, 2049, 2050, 2051]
            .into_iter()
            .enumerate()
        {
            adapter
                .pwrite(&[index as u8 + 1; 4096], unit * 4096, false)
                .unwrap();
        }
        adapter.flush().unwrap();
        adapter.checkpoint().unwrap();
        adapter.shutdown().unwrap();
        Some((protected, sockets))
    }

    /// The arena slot that holds page `page` of the file `name` in the
    /// manifest the witness selects.
    fn arena_slot(&self, name: &str, page: u64) -> u64 {
        let (_, manifest, _) = self.newest_manifest();
        let id = manifest["entries"][name]["File"].as_u64().unwrap();
        manifest["files"][id.to_string()]["pages"][page.to_string()]["slot"]
            .as_u64()
            .unwrap()
    }

    /// The manifest slot the witness selects, which holds the newest
    /// generation, with the manifest it holds, and the other slot's index.
    fn newest_manifest(&self) -> (usize, serde_json::Value, usize) {
        let (newest, manifest) = (0..2)
            .filter_map(|index| {
                let bytes =
                    std::fs::read(self.root().join(format!("rollback.manifest.{index}"))).unwrap();
                let len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
                let manifest: serde_json::Value =
                    serde_json::from_slice(bytes.get(8..8 + len)?).ok()?;
                Some((index, manifest))
            })
            .max_by_key(|(_, manifest)| manifest["generation"].as_u64().unwrap())
            .expect("a manifest");
        (newest, manifest, 1 - newest)
    }
}

/// `inspect`, `check` and `check --deep` read the volume of `config`
/// without changing anything in `directories` and say that they read it
/// read-only.
fn read_only_commands(config: &Path, directories: &[PathBuf]) {
    let config = config.to_str().unwrap();
    let trees = || {
        directories
            .iter()
            .map(|path| tree(path))
            .collect::<Vec<_>>()
    };
    let before = trees();

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
    assert_eq!(trees(), before, "a read-only command changed the backing");
}

/// `inspect`, `check` and `check --deep` of `config` each fail with an
/// error that contains `expected`, and change nothing in `directories`.
fn refused(config: &Path, directories: &[PathBuf], expected: &str) {
    let trees = || {
        directories
            .iter()
            .map(|path| tree(path))
            .collect::<Vec<_>>()
    };
    let before = trees();
    for args in [
        &["volume", "inspect", config.to_str().unwrap()][..],
        &["check", config.to_str().unwrap()],
        &["check", config.to_str().unwrap(), "--deep"],
    ] {
        let output = maki(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {}", text(&output));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{args:?}: {}",
            text(&output)
        );
    }
    assert_eq!(trees(), before, "a refused command changed the backing");
}

#[test]
fn check_and_inspect_read_a_tree_they_may_not_write() {
    let fixture = Fixture::new();
    set_modes(&fixture.root(), 0o400, 0o500);
    let result =
        std::panic::catch_unwind(|| read_only_commands(&fixture.config(), &[fixture.root()]));
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

/// A rollback-protected backing whose backing root, witness directory or
/// both this process may not write is read through a view that writes
/// neither: it was refused. Where both can be written the commands take
/// the writable path, as before.
#[test]
fn a_protected_backing_it_cannot_write_is_checked_read_only() {
    let Some(protected) = Protected::new() else {
        return;
    };
    let directories = [protected.root(), protected.witness()];
    for (root, witness) in [(0o500, 0o700), (0o700, 0o500), (0o500, 0o500)] {
        protected.with_modes(root, witness, || {
            read_only_commands(&protected.config(), &directories)
        });
    }
    let deep = maki(&["check", protected.config().to_str().unwrap(), "--deep"]);
    succeeded("writable check --deep", &deep);
    let report = String::from_utf8_lossy(&deep.stdout);
    assert!(
        report.contains("info: deep check verdict: clean\n") && !report.contains("read-only"),
        "{}",
        text(&deep)
    );
}

/// The read-only view authenticates every committed page, as opening the
/// backing to write does: a damaged one fails every command.
#[test]
fn a_damaged_page_of_a_protected_backing_it_cannot_write_is_an_error() {
    let Some(protected) = Protected::new() else {
        return;
    };
    let (_, manifest, _) = protected.newest_manifest();
    let slot = manifest["files"]
        .as_object()
        .unwrap()
        .values()
        .find_map(|node| node["pages"].as_object().unwrap().values().next())
        .expect("a committed page")["slot"]
        .as_u64()
        .unwrap();
    let arena = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(protected.root().join("rollback.arena"))
        .unwrap();
    use std::os::unix::fs::FileExt;
    let mut byte = [0];
    arena.read_exact_at(&mut byte, slot * 4096).unwrap();
    arena.write_all_at(&[byte[0] ^ 1], slot * 4096).unwrap();
    drop(arena);
    protected.with_modes(0o500, 0o500, || {
        refused(
            &protected.config(),
            &[protected.root(), protected.witness()],
            "rollback arena page authentication failed",
        )
    });
}

/// Only the manifest the witness selects is read: with the newest slot
/// rolled back to the older manifest, which is valid and canonical, every
/// command fails.
#[test]
fn a_protected_backing_whose_witness_selects_no_manifest_in_it_is_an_error() {
    let Some(protected) = Protected::new() else {
        return;
    };
    let (newest, _, older) = protected.newest_manifest();
    std::fs::copy(
        protected.root().join(format!("rollback.manifest.{older}")),
        protected.root().join(format!("rollback.manifest.{newest}")),
    )
    .unwrap();
    protected.with_modes(0o500, 0o500, || {
        refused(
            &protected.config(),
            &[protected.root(), protected.witness()],
            "no exact witnessed manifest",
        )
    });
}

/// The read-only view takes the locks a writer holds, shared: a backing
/// that a writer has open (an attached volume) is refused, and so is one
/// whose lock file is missing, which the view cannot create.
#[test]
fn a_protected_backing_in_use_or_without_its_lock_is_refused_read_only() {
    let Some(protected) = Protected::new() else {
        return;
    };
    let directories = [protected.root(), protected.witness()];
    let writer =
        maki_backing::RollbackBacking::open(&protected.root(), &protected.witness()).unwrap();
    protected.with_modes(0o500, 0o500, || {
        refused(
            &protected.config(),
            &directories,
            "rollback.lock is held by another process",
        )
    });
    drop(writer);
    std::fs::remove_file(protected.root().join("rollback.lock")).unwrap();
    protected.with_modes(0o500, 0o500, || {
        refused(
            &protected.config(),
            &directories,
            "rollback.lock is missing, and a read-only open cannot create it",
        )
    });
}

/// What the commands refuse once the writable open has opened the pair,
/// they refuse after the read-only open too: a configured capacity that is
/// not the stored one.
#[test]
fn a_protected_backing_of_another_capacity_is_refused_read_only_too() {
    let Some(protected) = Protected::new() else {
        return;
    };
    let other = protected.directory.path().join("other-capacity.toml");
    volume_config::write(
        &other,
        config(&protected.root(), Some(&protected.witness()))
            .replace("capacity = \"8MiB\"", "capacity = \"12MiB\""),
    )
    .unwrap();
    protected.with_modes(0o500, 0o500, || {
        refused(
            &other,
            &[protected.root(), protected.witness()],
            "protected backing capacity mismatch: configuration 12582912, stored 8388608",
        )
    });
}

/// A pair whose creation stopped after its witness anchor holds no volume:
/// read-only too, the commands say so and name what continues it.
#[test]
fn an_unfinished_protected_creation_is_named_read_only_too() {
    let directory = tempfile::tempdir().unwrap();
    let Some(witness_parent) = other_filesystem::tempdir(directory.path()) else {
        return;
    };
    let protected = Protected {
        directory,
        witness_parent,
    };
    drop(
        maki_backing::RollbackBacking::create(&protected.root(), &protected.witness(), 8 << 20)
            .unwrap(),
    );
    volume_config::write(
        protected.config(),
        config(&protected.root(), Some(&protected.witness())),
    )
    .unwrap();
    protected.with_modes(0o500, 0o500, || {
        refused(
            &protected.config(),
            &[protected.root(), protected.witness()],
            "this volume's creation did not complete",
        )
    });
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
        let mounted = bind_read_only(&fixture.root());
        let error = std::fs::OpenOptions::new()
            .write(true)
            .open(fixture.root().join("superblock.a"))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
        read_only_commands(&fixture.config(), &[fixture.root()]);
        drop(mounted);
        // A rollback-protected backing whose root, witness directory or
        // both are mounted read-only is read through its read-only view.
        let Some(protected) = Protected::new() else {
            return;
        };
        let directories = [protected.root(), protected.witness()];
        for (root, witness) in [(true, false), (false, true), (true, true)] {
            let _root = root.then(|| bind_read_only(&protected.root()));
            let _witness = witness.then(|| bind_read_only(&protected.witness()));
            read_only_commands(&protected.config(), &directories);
        }
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

/// A rollback-protected volume that holds data the daemon's NBD adapter
/// wrote, read through the read-only view: the deep check reads every
/// allocated slot and finds them intact, and neither directory changes.
#[test]
fn a_protected_volume_holding_data_is_checked_read_only() {
    let Some((protected, _sockets)) = Protected::with_data() else {
        return;
    };
    protected.with_modes(0o500, 0o500, || {
        read_only_commands(
            &protected.config(),
            &[protected.root(), protected.witness()],
        );
        let deep = maki(&["check", protected.config().to_str().unwrap(), "--deep"]);
        succeeded("check --deep", &deep);
        assert!(
            String::from_utf8_lossy(&deep.stdout).contains("info: slots: 8 allocated, 0 invalid"),
            "{}",
            text(&deep)
        );
    });
}

/// A data slot that does not hold what the engine wrote is an error of the
/// read-only deep check: here a ciphertext byte of unit 0 changed through
/// the backing itself, so that every page still authenticates and only the
/// slot's own checksum finds it. A changed arena page of a data slot fails
/// the authentication of every command.
#[test]
fn a_damaged_data_slot_of_a_protected_volume_is_an_error_read_only() {
    let Some((protected, _sockets)) = Protected::with_data() else {
        return;
    };
    let shard = maki_format::layout::shard_data(0);
    {
        let backing =
            maki_backing::RollbackBacking::open(&protected.root(), &protected.witness()).unwrap();
        use maki_backing::Backing;
        let file = backing.open(&shard, false).unwrap();
        let at = u64::from(maki_format::slot::SLOT_HEADER_SIZE) + 7;
        let mut byte = [0];
        file.read_at(at, &mut byte).unwrap();
        file.write_at(at, &[byte[0] ^ 1]).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("data").unwrap();
        backing.sync_dir("").unwrap();
    }
    let directories = [protected.root(), protected.witness()];
    protected.with_modes(0o500, 0o500, || {
        let before: Vec<_> = directories.iter().map(|path| tree(path)).collect();
        let deep = maki(&["check", protected.config().to_str().unwrap(), "--deep"]);
        let report = String::from_utf8_lossy(&deep.stdout);
        assert_eq!(deep.status.code(), Some(1), "{}", text(&deep));
        assert!(
            report.contains("warning: read-only check: ")
                && report.contains("ERROR: slot: ")
                && report.contains("1 invalid (0 recoverable by journal replay, 1 unrecoverable)")
                && report.ends_with("check FAILED\n"),
            "{}",
            text(&deep)
        );
        let after: Vec<_> = directories.iter().map(|path| tree(path)).collect();
        assert_eq!(
            after, before,
            "the read-only deep check changed the backing"
        );
    });
    let slot = protected.arena_slot(&shard, 0);
    let arena = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(protected.root().join("rollback.arena"))
        .unwrap();
    use std::os::unix::fs::FileExt;
    let mut byte = [0];
    arena.read_exact_at(&mut byte, slot * 4096 + 100).unwrap();
    arena
        .write_all_at(&[byte[0] ^ 1], slot * 4096 + 100)
        .unwrap();
    drop(arena);
    protected.with_modes(0o500, 0o500, || {
        refused(
            &protected.config(),
            &directories,
            "rollback arena page authentication failed",
        )
    });
}

/// `maki check` of a protected volume, read read-only, compares the
/// configuration with the superblock as attach does: one that attach
/// refuses fails the check, naming the setting and both values, and
/// changes nothing.
#[test]
fn a_mismatched_configuration_fails_a_read_only_check_of_a_protected_volume() {
    let Some(protected) = Protected::new() else {
        return;
    };
    let other = protected.directory.path().join("other-identity.toml");
    volume_config::write(
        &other,
        config(&protected.root(), Some(&protected.witness())).replace(
            r#"crypto_compatibility_id = "local-aes-gcm-siv-v1""#,
            r#"crypto_compatibility_id = "local-aes-gcm-siv-v2""#,
        ),
    )
    .unwrap();
    let directories = [protected.root(), protected.witness()];
    protected.with_modes(0o500, 0o500, || {
        let before: Vec<_> = directories.iter().map(|path| tree(path)).collect();
        for args in [
            &["check", other.to_str().unwrap()][..],
            &["check", other.to_str().unwrap(), "--deep"],
        ] {
            let output = maki(args);
            let report = String::from_utf8_lossy(&output.stdout);
            assert_eq!(output.status.code(), Some(1), "{args:?}: {}", text(&output));
            assert!(
                report.contains("warning: read-only check: ")
                    && report.contains(
                        "ERROR: configuration mismatch: crypto.crypto_compatibility_id is \
                         \"local-aes-gcm-siv-v2\" in the configuration, the volume has \
                         \"local-aes-gcm-siv-v1\"; attach refuses this configuration\n"
                    )
                    && report.ends_with("check FAILED\n"),
                "{args:?}: {}",
                text(&output)
            );
        }
        let after: Vec<_> = directories.iter().map(|path| tree(path)).collect();
        assert_eq!(after, before, "a read-only check changed the backing");
    });
}
