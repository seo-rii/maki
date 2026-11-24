//! A local rollback-protected volume belongs to the daemon user, witness
//! included. The offline commands an operator runs as root (`maki check
//! --deep`, `maki volume inspect`) republish the witness anchor; they must
//! leave the daemon able to open it. A root `maki volume create` must name
//! the witness among the paths to hand back. Running a command as another
//! user needs root: without it these tests print why they are skipped.
#![cfg(target_os = "linux")]

#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
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
        "MAKI_CREDENTIAL_LOCAL_WITNESS_OWNER_KEY",
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

fn config(root: &Path, witness: &Path) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "local-witness-owner"
max_virtual_size = "16MiB"
shard_logical_size = "8MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "local-witness-owner-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = {}
journal_segment_size = "64KiB"
journal_max_bytes = "1MiB"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "64KiB"
[backing.rollback_protection]
witness_root = {}
capacity = "8MiB"
[nbd]
maximum_io = "64KiB"
"#,
        serde_json::to_string(root.to_str().unwrap()).unwrap(),
        serde_json::to_string(witness.to_str().unwrap()).unwrap()
    )
}

struct Fixture {
    directory: tempfile::TempDir,
    witness_parent: tempfile::TempDir,
}

impl Fixture {
    /// `None` when there is no second filesystem for the witness.
    fn new() -> Option<Self> {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let witness_parent = other_filesystem::reachable_tempdir(directory.path())?;
        let fixture = Self {
            directory,
            witness_parent,
        };
        volume_config::write(
            fixture.config(),
            config(&fixture.root(), &fixture.witness()),
        )
        .unwrap();
        Some(fixture)
    }

    fn root(&self) -> std::path::PathBuf {
        self.directory.path().join("volume")
    }

    fn witness(&self) -> std::path::PathBuf {
        self.witness_parent.path().join("witness")
    }

    fn config(&self) -> std::path::PathBuf {
        self.directory.path().join("volume.toml")
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

#[test]
fn root_offline_check_and_inspect_leave_the_daemon_able_to_open_its_witness() {
    if skip_unless_root("root_offline_check_and_inspect_leave_the_daemon_able_to_open_its_witness")
    {
        return;
    }
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let config = fixture.config();
    let config = config.to_str().unwrap();
    // The documented creation: directories the daemon user owns, then
    // `runuser -u maki -- maki volume create`.
    for directory in [fixture.directory.path(), fixture.witness_parent.path()] {
        std::os::unix::fs::chown(directory, Some(DAEMON.0), Some(DAEMON.1)).unwrap();
    }
    succeeded(
        "daemon-user create",
        &maki(&["volume", "create", config], Some(DAEMON)),
    );
    succeeded(
        "daemon-user inspect",
        &maki(&["volume", "inspect", config], Some(DAEMON)),
    );

    succeeded("root deep check", &maki(&["check", config, "--deep"], None));
    succeeded("root inspect", &maki(&["volume", "inspect", config], None));

    let mut changed = Vec::new();
    foreign(&fixture.root(), DAEMON, &mut changed);
    foreign(&fixture.witness(), DAEMON, &mut changed);
    assert_eq!(changed, Vec::<String>::new(), "root changed owners");
    succeeded(
        "daemon-user inspect after root's offline commands",
        &maki(&["volume", "inspect", config], Some(DAEMON)),
    );
    succeeded(
        "daemon-user deep check after root's offline commands",
        &maki(&["check", config, "--deep"], Some(DAEMON)),
    );
}

#[test]
fn root_create_names_the_rollback_witness_among_the_paths_to_hand_back() {
    if skip_unless_root("root_create_names_the_rollback_witness_among_the_paths_to_hand_back") {
        return;
    }
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let output = maki(
        &["volume", "create", fixture.config().to_str().unwrap()],
        None,
    );
    succeeded("root create", &output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let warning = stderr
        .lines()
        .find(|line| line.starts_with("warning: "))
        .unwrap_or_else(|| panic!("no ownership warning:\n{stderr}"));
    for path in [fixture.root(), fixture.witness()] {
        assert!(
            warning.contains(path.to_str().unwrap()),
            "warning does not name {}: {warning}",
            path.display()
        );
    }
}
