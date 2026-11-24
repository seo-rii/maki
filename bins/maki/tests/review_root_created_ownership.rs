//! A volume and its local rollback witness belong to the daemon user. An
//! offline command an operator runs as root (`maki check --deep`, `maki
//! volume inspect`) recreates a lock file or an inactive manifest slot that
//! a restore or copy dropped; the daemon must still be able to open the
//! volume afterwards, with no hand-back. A root `maki volume create` into
//! directories the daemon user owns leaves nothing to hand back either; one
//! that has to create the volume directory itself says what to hand back.
//! Running a command as another user needs root: without it these tests
//! print why they are skipped.
#![cfg(target_os = "linux")]

#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Stands in for the daemon user. Distinct uid and gid, neither root's.
const DAEMON: (u32, u32) = (65534, 65533);

fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn skip_unless_root(test: &str) -> bool {
    if running_as_root() {
        return false;
    }
    eprintln!("{test}: skipped: running maki as another user needs root");
    true
}

fn maki(args: &[&str], user: Option<(u32, u32)>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki"));
    command.args(args).env(
        "MAKI_CREDENTIAL_ROOT_CREATED_OWNERSHIP_KEY",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    );
    if let Some((uid, gid)) = user {
        command.uid(uid).gid(gid);
    }
    command.output().expect("spawn maki")
}

fn succeeded(what: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{what} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn warnings(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| line.starts_with("warning: "))
        .map(str::to_owned)
        .collect()
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
name = "root-created-ownership"
max_virtual_size = "16MiB"
shard_logical_size = "8MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "root-created-ownership-key" }}
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

struct Fixture {
    directory: tempfile::TempDir,
    witness_parent: Option<tempfile::TempDir>,
}

impl Fixture {
    /// Temporary directories root owns, as `tempfile` creates them, and the
    /// configuration. Neither the backing root nor the witness exists.
    /// `None` when a rollback fixture finds no second filesystem.
    fn bare(rollback: bool) -> Option<Self> {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let witness_parent = if rollback {
            Some(other_filesystem::reachable_tempdir(directory.path())?)
        } else {
            None
        };
        let fixture = Self {
            directory,
            witness_parent,
        };
        volume_config::write(
            fixture.config(),
            config(&fixture.root(), fixture.witness().as_deref()),
        )
        .unwrap();
        Some(fixture)
    }

    /// The backing root and witness directory created for the daemon user,
    /// as the guides do before `maki volume create`.
    fn for_daemon(rollback: bool) -> Option<Self> {
        let fixture = Self::bare(rollback)?;
        let mut directories = vec![fixture.directory.path().to_path_buf(), fixture.root()];
        if let (Some(parent), Some(witness)) = (&fixture.witness_parent, fixture.witness()) {
            directories.extend([parent.path().to_path_buf(), witness]);
        }
        for directory in directories {
            fs::create_dir_all(&directory).unwrap();
            std::os::unix::fs::chown(&directory, Some(DAEMON.0), Some(DAEMON.1)).unwrap();
        }
        Some(fixture)
    }

    fn root(&self) -> PathBuf {
        self.directory.path().join("volume")
    }

    fn witness(&self) -> Option<PathBuf> {
        self.witness_parent
            .as_ref()
            .map(|parent| parent.path().join("witness"))
    }

    fn config(&self) -> PathBuf {
        self.directory.path().join("volume.toml")
    }

    /// Entries in the backing root and witness directory the daemon user
    /// does not own.
    fn foreign(&self) -> Vec<String> {
        let mut out = Vec::new();
        foreign(&self.root(), DAEMON, &mut out);
        if let Some(witness) = self.witness() {
            foreign(&witness, DAEMON, &mut out);
        }
        out
    }
}

/// Entries below `path` (itself included) not owned by `owner`.
fn foreign(path: &Path, owner: (u32, u32), out: &mut Vec<String>) {
    let metadata = fs::symlink_metadata(path).unwrap();
    if (metadata.uid(), metadata.gid()) != owner {
        out.push(format!(
            "{} {}:{}",
            path.display(),
            metadata.uid(),
            metadata.gid()
        ));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            foreign(&entry.unwrap().path(), owner, out);
        }
    }
}

fn owner_of(path: &Path) -> (u32, u32) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.uid(), metadata.gid())
}

fn remove(paths: &[PathBuf]) {
    for path in paths {
        fs::remove_file(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    }
}

#[test]
fn root_deep_check_recreates_a_missing_volume_lock_for_the_daemon() {
    if skip_unless_root("root_deep_check_recreates_a_missing_volume_lock_for_the_daemon") {
        return;
    }
    let Some(fixture) = Fixture::for_daemon(false) else {
        return;
    };
    let config = fixture.config();
    let config = config.to_str().unwrap();
    succeeded(
        "daemon-user create",
        &maki(&["volume", "create", config], Some(DAEMON)),
    );
    // A restore that dropped the empty lock file.
    remove(&[fixture.root().join("volume.lock")]);

    succeeded("root deep check", &maki(&["check", config, "--deep"], None));
    assert_eq!(
        fixture.foreign(),
        Vec::<String>::new(),
        "root changed owners"
    );
    assert_eq!(
        fs::metadata(fixture.root().join("volume.lock"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    succeeded(
        "daemon-user deep check after root's",
        &maki(&["check", config, "--deep"], Some(DAEMON)),
    );
}

#[test]
fn root_inspect_and_check_recreate_missing_rollback_files_for_the_daemon() {
    if skip_unless_root("root_inspect_and_check_recreate_missing_rollback_files_for_the_daemon") {
        return;
    }
    let Some(fixture) = Fixture::for_daemon(true) else {
        return;
    };
    let config = fixture.config();
    let config = config.to_str().unwrap();
    succeeded(
        "daemon-user create",
        &maki(&["volume", "create", config], Some(DAEMON)),
    );
    // No locks and no inactive manifest slot: what a copy that drops empty
    // and sparse files leaves.
    let dropped = [
        fixture.root().join("rollback.lock"),
        fixture.root().join("rollback.manifest.1"),
        fixture.witness().unwrap().join("witness.lock"),
    ];
    for command in [
        &["volume", "inspect", config][..],
        &["check", config, "--deep"],
    ] {
        remove(&dropped);
        succeeded(&format!("root {command:?}"), &maki(command, None));
        assert_eq!(
            fixture.foreign(),
            Vec::<String>::new(),
            "root {command:?} changed owners"
        );
        succeeded(
            &format!("daemon-user deep check after root {command:?}"),
            &maki(&["check", config, "--deep"], Some(DAEMON)),
        );
    }
}

#[test]
fn root_create_into_daemon_owned_directories_leaves_nothing_to_hand_back() {
    if skip_unless_root("root_create_into_daemon_owned_directories_leaves_nothing_to_hand_back") {
        return;
    }
    for rollback in [false, true] {
        // Every file and directory is created inside the two directories
        // the daemon user owns.
        let Some(fixture) = Fixture::for_daemon(rollback) else {
            continue;
        };
        let config = fixture.config();
        let config = config.to_str().unwrap();
        let output = maki(&["volume", "create", config], None);
        succeeded(&format!("root create (rollback {rollback})"), &output);
        assert_eq!(
            warnings(&output),
            Vec::<String>::new(),
            "rollback {rollback}"
        );
        assert_eq!(
            fixture.foreign(),
            Vec::<String>::new(),
            "root kept entries (rollback {rollback})"
        );
        succeeded(
            &format!("daemon-user deep check after a root create (rollback {rollback})"),
            &maki(&["check", config, "--deep"], Some(DAEMON)),
        );
    }
}

#[test]
fn root_create_names_a_volume_directory_it_had_to_create() {
    if skip_unless_root("root_create_names_a_volume_directory_it_had_to_create") {
        return;
    }
    // The volume directory does not exist and its parent is root's (as
    // `/var/lib/maki` is): root creates it for itself, and the whole tree
    // is root's.
    let Some(fixture) = Fixture::bare(false) else {
        return;
    };
    let output = maki(
        &["volume", "create", fixture.config().to_str().unwrap()],
        None,
    );
    succeeded("root create", &output);
    let warnings = warnings(&output);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains(&format!("chown -R maki:maki {}", fixture.root().display())),
        "{warnings:?}"
    );
    assert_eq!(owner_of(&fixture.root()), (0, 0));
}
