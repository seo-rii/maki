//! `maki volume create` on a local rollback-protected backing publishes the
//! witness anchor and then initializes the volume inside the backing. A
//! command that stopped between the two (killed, a power loss, a failure)
//! left a pair that `create` refused ("rollback enrollment requires empty
//! backing and witness directories") and that held no volume: the daemon,
//! `maki check` and `maki volume inspect` said only "no valid superblock",
//! and both directories had to be emptied by hand.
//!
//! Running `create` again continues such a pair, and the commands that need
//! a volume say that its creation did not complete and what continues it.
//! The interrupted commands run in child processes that a seccomp filter
//! kills at one system call, and in this process with a backing that stops
//! at one operation.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;
#[allow(dead_code)] // this target only kills
#[path = "../../maki-backing/tests/support/seccomp.rs"]
mod seccomp;

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::{Backing, BackingFile, RollbackBacking, VolumeLock};
use maki_format::superblock::{load_volume_superblock, Superblock};
use maki_format::{checker, init};
use maki_nbdkit::daemon::{build_backing, create_volume_from_config_str, parse_and_validate};

const CAPACITY: u64 = 8 * 1024 * 1024;
const XTS_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\
                       ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
const REFUSAL: &str = "rollback enrollment requires empty backing and witness directories";

struct Pair {
    directory: tempfile::TempDir,
    witness: tempfile::TempDir,
    raw: String,
}

impl Pair {
    /// A configuration for a new local rollback-protected volume, or `None`
    /// where there is no second filesystem for its witness (the test then
    /// says it is skipped).
    fn new() -> Option<Self> {
        let directory = tempfile::tempdir().unwrap();
        let witness = other_filesystem::tempdir(directory.path())?;
        let key = directory.path().join("key");
        std::fs::write(&key, XTS_KEY).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let raw = format!(
            r#"
config_schema_version = 1
[volume]
name = "interrupted-create"
max_virtual_size = "1MiB"
shard_logical_size = "128KiB"
device_block_size = 4096
crypto_unit_size = 4096
[crypto]
provider = "local-aes-xts"
crypto_compatibility_id = "interrupted-create-v1"
key = {{ source = "file", name = {:?} }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
[backing]
root = {:?}
slot_alignment = 4096
journal_segment_size = "64KiB"
journal_max_bytes = "1MiB"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "64KiB"
[backing.rollback_protection]
witness_root = {:?}
capacity = "8MiB"
[nbd]
minimum_io = 4096
preferred_io = 4096
maximum_io = "64KiB"
threads = 2
"#,
            key.display().to_string(),
            directory.path().join("volume").display().to_string(),
            witness.path().display().to_string(),
        );
        Some(Self {
            directory,
            witness,
            raw,
        })
    }

    fn root(&self) -> PathBuf {
        self.directory.path().join("volume")
    }

    /// The volume as the daemon, `maki check` and `maki volume inspect`
    /// open it.
    fn volume(&self) -> Result<Superblock, String> {
        let config = parse_and_validate(&self.raw).unwrap();
        let backing = build_backing(&config).map_err(|error| error.to_string())?;
        let superblock = load_volume_superblock(backing.as_ref())
            .map_err(|error| error.to_string())?
            .superblock;
        let report = checker::check_volume(backing.as_ref()).map_err(|error| error.to_string())?;
        assert!(report.ok(), "{:?}", report.errors);
        Ok(superblock)
    }

    /// Run `create` again: it continues the pair, the volume it reports is
    /// the one that opens, and nothing creates over it afterwards.
    fn create_again(&self, context: &str) {
        let created = create_volume_from_config_str(&self.raw).unwrap_or_else(|error| {
            panic!(
                "{context}: an interrupted creation is stranded: create: {error}; open: {:?}",
                self.volume().err()
            )
        });
        let opened = self
            .volume()
            .unwrap_or_else(|error| panic!("{context}: {error}"));
        assert_eq!(opened.volume_uuid, created.volume_uuid, "{context}");
        let again = create_volume_from_config_str(&self.raw).unwrap_err();
        assert!(again.to_string().contains(REFUSAL), "{context}: {again}");
        assert_eq!(self.volume().unwrap().volume_uuid, created.volume_uuid);
    }
}

const STEP: &str = "MAKI_INTERRUPTED_VOLUME_CREATE_STEP";
const CONFIG: &str = "MAKI_INTERRUPTED_VOLUME_CREATE_CONFIG";
/// Exit status of a step that could not arrange its interruption.
const UNAVAILABLE: i32 = 77;

/// The interrupted command, in the child process.
fn child() {
    let (Some(step), Some(config)) = (std::env::var_os(STEP), std::env::var_os(CONFIG)) else {
        return;
    };
    let length = match step.to_str().unwrap() {
        // The rollback layer stores the volume's files in pages: the first
        // page it writes belongs to the volume's initialization, after the
        // witness anchor was published.
        "killed at the volume's first page" => 4096,
        // A commit publishes its manifest and then that manifest's length,
        // in eight bytes: the first one is the volume's first commit.
        "killed publishing the volume's first commit" => 8,
        other => panic!("unknown step {other}"),
    };
    if !seccomp::on(libc::SYS_pwrite64, Some(length), seccomp::KILLS) {
        std::process::exit(UNAVAILABLE);
    }
    let outcome = create_volume_from_config_str(&std::fs::read_to_string(config).unwrap());
    eprintln!(
        "create: {:?}",
        outcome.map(|superblock| superblock.volume_uuid)
    );
    std::process::exit(0);
}

/// Run `create` in a child process that is killed at `step`. `false`, with
/// the reason printed, where the interruption cannot be arranged.
fn killed(test: &str, step: &str, pair: &Pair) -> bool {
    let config = pair.directory.path().join("volume.toml");
    std::fs::write(&config, &pair.raw).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(STEP, step)
        .env(CONFIG, &config)
        .output()
        .unwrap();
    if output.status.code() == Some(UNAVAILABLE) {
        eprintln!("{test}: skipped: cannot arrange `{step}` in a child process");
        return false;
    }
    assert_eq!(output.status.signal(), Some(libc::SIGSYS), "{output:?}");
    true
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn create_killed_at_the_volumes_first_page_can_be_run_again() {
    child();
    let Some(pair) = Pair::new() else {
        return;
    };
    if !killed(
        "create_killed_at_the_volumes_first_page_can_be_run_again",
        "killed at the volume's first page",
        &pair,
    ) {
        return;
    }
    // The enrollment completed: the anchor is published.
    assert!(entries(pair.witness.path()).contains(&"anchor".to_string()));
    // Whatever needs the volume says what is there and what continues it.
    let refused = pair.volume().unwrap_err();
    assert!(
        refused.contains("no valid superblock")
            && refused.contains("did not complete")
            && refused.contains("maki volume create"),
        "{refused}"
    );
    pair.create_again("killed at the volume's first page");
}

#[test]
fn create_killed_while_it_publishes_the_volumes_first_commit_can_be_run_again() {
    child();
    let Some(pair) = Pair::new() else {
        return;
    };
    if !killed(
        "create_killed_while_it_publishes_the_volumes_first_commit_can_be_run_again",
        "killed publishing the volume's first commit",
        &pair,
    ) {
        return;
    }
    assert!(entries(pair.witness.path()).contains(&"anchor".to_string()));
    assert!(pair.volume().is_err());
    pair.create_again("killed publishing the volume's first commit");
}

/// A backing that fails every operation from the `left`-th on: the
/// volume's initialization stops there, as a process that died would.
struct Stopping {
    inner: RollbackBacking,
    left: AtomicUsize,
}

impl Stopping {
    fn step(&self) -> io::Result<()> {
        self.left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .map(drop)
            .map_err(|_| io::Error::other("stopped"))
    }
}

impl Backing for Stopping {
    fn open(&self, name: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        self.step()?;
        self.inner.open(name, create)
    }
    fn exists(&self, name: &str) -> io::Result<bool> {
        self.step()?;
        self.inner.exists(name)
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        self.step()?;
        self.inner.remove(name)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.step()?;
        self.inner.rename(from, to)
    }
    fn create_dir_all(&self, name: &str) -> io::Result<()> {
        self.step()?;
        self.inner.create_dir_all(name)
    }
    fn list(&self, name: &str) -> io::Result<Vec<String>> {
        self.step()?;
        self.inner.list(name)
    }
    fn sync_dir(&self, name: &str) -> io::Result<()> {
        self.step()?;
        self.inner.sync_dir(name)
    }
    fn try_lock(&self, name: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.step()?;
        self.inner.try_lock(name)
    }
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.inner.free_bytes()
    }
}

/// The volume's initialization stops before each of its operations on the
/// backing, on real directories. Exactly one command continues every such
/// pair: `create` until the superblock is committed, the daemon from then
/// on.
#[test]
fn create_stopped_at_any_step_of_the_volumes_initialization_is_continued() {
    let mut covered = 0;
    for stop in 0.. {
        let Some(pair) = Pair::new() else {
            return;
        };
        let config = parse_and_validate(&pair.raw).unwrap();
        let rollback = config.backing.rollback_protection.as_ref().unwrap();
        let outer =
            RollbackBacking::create(&pair.root(), Path::new(&rollback.witness_root), CAPACITY)
                .unwrap();
        let stopping = Stopping {
            inner: outer,
            left: AtomicUsize::new(stop),
        };
        let superblock = Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::new_v4(),
            provider_type: config.crypto.provider.clone(),
            crypto_compatibility_id: config.crypto.effective_compatibility_id(),
            key_identity: String::new(),
            geometry: config.geometry().unwrap(),
            format_version: maki_format::superblock::CRYPTO_FORMAT_VERSION,
            created_unix: 0,
        };
        let finished = init::create_volume(&stopping, superblock).is_ok();
        drop(stopping);
        if finished {
            break;
        }
        covered += 1;
        let context = format!("stopped before operation {stop}");
        match pair.volume() {
            Ok(existing) => {
                // The superblock was committed: the volume exists, and
                // `create` refuses it.
                let refused = create_volume_from_config_str(&pair.raw).unwrap_err();
                assert!(
                    refused.to_string().contains(REFUSAL),
                    "{context}: {refused}"
                );
                assert_eq!(pair.volume().unwrap().volume_uuid, existing.volume_uuid);
            }
            Err(_) => pair.create_again(&context),
        }
    }
    assert!(covered > 10, "{covered} cut points");
}
