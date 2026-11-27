//! A rollback-protected backing opened only to read
//! ([`ReadOnlyRollbackBacking`]), for the commands that check or inspect a
//! volume where they may not write.
//!
//! Opening a protected backing to write rewrites its authenticated state
//! and the witness record, takes its locks exclusively, and, for a remote
//! witness, claims a writer at the authority and forks a namespace. The
//! read-only open must authenticate exactly what the writable open
//! authenticates, change nothing in the backing root or the witness
//! directory (not even attempt to: a backing that would allow it records
//! every attempt), take the writer's locks shared, send a remote authority
//! nothing but inspections, and stop for good when the witness stops
//! selecting what it read.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;
#[path = "support/private_dir.rs"]
mod private_dir;

use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use maki_backing::remote_witness::{
    Action, Record, Request, Role, Rpc, SessionAuthorization, StateStore,
};
use maki_backing::{
    Backing, BackingFile, FileBacking, FileOwner, ReadOnlyRollbackBacking, RollbackBacking,
    VolumeLock,
};

const PAGE: u64 = 4096;
/// Three whole pages and part of a fourth, with a hole in the second.
const PAYLOAD_LEN: usize = 3 * PAGE as usize + 100;

fn payload() -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8 + 1).collect();
    bytes[PAGE as usize..2 * PAGE as usize].fill(0);
    bytes
}

/// Write the payload to `data/payload`, leaving its second page a hole,
/// and commit it.
fn write_payload(backing: &dyn Backing) {
    let bytes = payload();
    backing.create_dir_all("data").unwrap();
    let file = backing.open("data/payload", true).unwrap();
    file.write_at(0, &bytes[..PAGE as usize]).unwrap();
    file.write_at(2 * PAGE, &bytes[2 * PAGE as usize..])
        .unwrap();
    file.sync_data().unwrap();
    backing.open("volume.lock", true).unwrap();
    backing.sync_dir("data").unwrap();
    backing.sync_dir("").unwrap();
}

fn read_payload(backing: &dyn Backing) -> Vec<u8> {
    read_payload_result(backing).unwrap()
}

fn read_payload_result(backing: &dyn Backing) -> io::Result<Vec<u8>> {
    let file = backing.open("data/payload", false)?;
    let mut bytes = vec![0xff; file.len()? as usize];
    file.read_at(0, &mut bytes)?;
    Ok(bytes)
}

/// An entry with its mode, its bytes if it is a file, and its modification
/// time.
type Entry = (PathBuf, u32, Option<Vec<u8>>, SystemTime);

/// Every entry below `root`: a rewrite of identical bytes changes the
/// modification time, and a created or removed entry that of its directory.
fn tree(root: &Path) -> Vec<Entry> {
    use std::os::unix::fs::PermissionsExt;
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

fn refused<T>(result: io::Result<T>) {
    match result {
        Ok(_) => panic!("a change through the read-only view succeeded"),
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::ReadOnlyFilesystem, "{error}"),
    }
}

/// Every change through `backing` and through its file `name` is refused.
fn every_change_is_refused(backing: &dyn Backing, name: &str) {
    assert!(backing.is_read_only());
    refused(backing.open(name, true));
    refused(backing.open("new", true));
    refused(backing.remove(name));
    refused(backing.rename(name, "renamed"));
    refused(backing.create_dir_all("directory"));
    refused(backing.sync_dir(""));
    refused(backing.try_lock("volume.lock"));
    let file = backing.open(name, false).unwrap();
    refused(file.write_at(0, b"x"));
    refused(file.set_len(1));
    refused(file.allocate_range(0, PAGE));
    refused(file.punch_hole(0, PAGE));
    refused(file.sync_data());
    refused(file.sync_all());
}

/// A local protected backing and its witness directory, on two
/// filesystems; `None` (after a notice) without a second one.
struct Local {
    root: tempfile::TempDir,
    witness: tempfile::TempDir,
}

impl Local {
    /// A backing that holds the payload, closed again.
    fn new() -> Option<Self> {
        let root = tempfile::tempdir().unwrap();
        let witness = other_filesystem::tempdir(root.path())?;
        let backing = RollbackBacking::create(root.path(), witness.path(), 32 * PAGE).unwrap();
        write_payload(&backing);
        drop(backing);
        Some(Self { root, witness })
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn witness(&self) -> &Path {
        self.witness.path()
    }

    fn trees(&self) -> (Vec<Entry>, Vec<Entry>) {
        (tree(self.root()), tree(self.witness()))
    }

    fn open(&self) -> io::Result<ReadOnlyRollbackBacking> {
        ReadOnlyRollbackBacking::open(self.root(), self.witness())
    }
}

/// The newest manifest of the backing in `root` (the one a witness that
/// was advanced last selects), its slot's index, and the other slot's.
fn newest_manifest(root: &Path) -> (usize, serde_json::Value, usize) {
    let (newest, manifest) = (0..2)
        .filter_map(|index| {
            let bytes = std::fs::read(root.join(format!("rollback.manifest.{index}"))).unwrap();
            let len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
            let manifest: serde_json::Value =
                serde_json::from_slice(bytes.get(8..8 + len)?).ok()?;
            Some((index, manifest))
        })
        .max_by_key(|(_, manifest)| manifest["generation"].as_u64().unwrap())
        .unwrap();
    (newest, manifest, 1 - newest)
}

/// The arena slot of a page the newest manifest in `root` references.
fn committed_slot(root: &Path) -> u64 {
    let (_, manifest, _) = newest_manifest(root);
    manifest["files"]
        .as_object()
        .unwrap()
        .values()
        .find_map(|node| node["pages"].as_object().unwrap().values().next())
        .expect("a committed page")["slot"]
        .as_u64()
        .unwrap()
}

/// Flip the first byte of `slot` in the arena at `arena`.
fn flip(arena: &Path, slot: u64) {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(arena)
        .unwrap();
    let mut byte = [0];
    file.read_exact_at(&mut byte, slot * PAGE).unwrap();
    file.write_all_at(&[byte[0] ^ 1], slot * PAGE).unwrap();
}

#[test]
fn a_local_read_only_open_reads_what_was_committed_and_changes_nothing() {
    let Some(local) = Local::new() else {
        return;
    };
    let before = local.trees();
    let view = local.open().unwrap();
    assert_eq!(read_payload(&view), payload());
    assert_eq!(view.capacity().unwrap(), 32 * PAGE);
    assert_eq!(view.list("").unwrap(), ["data", "volume.lock"]);
    assert_eq!(view.list("data").unwrap(), ["payload"]);
    assert!(view.exists("data/payload").unwrap());
    assert!(!view.exists("data/missing").unwrap());
    assert!(!view.exists("missing/payload").unwrap());
    assert_eq!(
        view.open("data/missing", false).err().unwrap().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        view.open("data", false).err().unwrap().kind(),
        io::ErrorKind::IsADirectory
    );
    // Reading past the end fails as a writer's view fails.
    let file = view.open("data/payload", false).unwrap();
    let mut beyond = [0; 2];
    assert_eq!(
        file.read_at(PAYLOAD_LEN as u64 - 1, &mut beyond)
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert!(view.free_bytes().unwrap().unwrap() < 32 * PAGE);
    // The volume lock within it is admitted, and never created.
    drop(view.try_lock_shared_existing("volume.lock").unwrap());
    assert_eq!(
        view.try_lock_shared_existing("missing.lock")
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::NotFound
    );
    every_change_is_refused(&view, "data/payload");
    view.check_freshness().unwrap();
    assert_eq!(view.session_stopped(), None);
    // An open file keeps the view, and its locks, as a writer's file does.
    drop(view);
    assert_eq!(
        RollbackBacking::open(local.root(), local.witness())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    drop(file);
    assert_eq!(
        local.trees(),
        before,
        "the read-only open changed a directory"
    );
    // A writer opens it afterwards and finds the same state.
    let writer = RollbackBacking::open(local.root(), local.witness()).unwrap();
    assert_eq!(read_payload(&writer), payload());
}

/// The view takes the locks a writer holds exclusively for its session,
/// shared: it waits for no writer, keeps one out while it is open, and
/// admits another reader.
#[test]
fn a_local_read_only_open_excludes_a_writer_and_admits_a_reader() {
    let Some(local) = Local::new() else {
        return;
    };
    let view = local.open().unwrap();
    let second = local.open().unwrap();
    let error = RollbackBacking::open(local.root(), local.witness())
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
    // Each of the two locks a writer takes is held for as long as the view
    // is open.
    for (directory, lock) in [
        (local.root(), "rollback.lock"),
        (local.witness(), "witness.lock"),
    ] {
        let error = FileBacking::new(directory)
            .unwrap()
            .try_lock(lock)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{lock}: {error}");
    }
    drop((view, second));
    let writer = RollbackBacking::open(local.root(), local.witness()).unwrap();
    let error = local.open().err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
    assert!(
        error
            .to_string()
            .contains("rollback.lock is held by another process"),
        "{error}"
    );
    drop(writer);
    // The witness's own lock is taken shared too.
    let witness_lock = FileBacking::new(local.witness())
        .unwrap()
        .try_lock("witness.lock")
        .unwrap();
    let error = local.open().err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
    assert!(
        error
            .to_string()
            .contains("witness.lock is held by another process"),
        "{error}"
    );
    drop(witness_lock);
    local.open().unwrap();
}

/// A lock file the view cannot take is never created: the open is refused.
/// A witness directory that holds neither its lock nor its anchor (a
/// witness that is not mounted) is refused as one without its anchor.
#[test]
fn a_local_read_only_open_without_a_lock_file_is_refused_and_creates_none() {
    let Some(local) = Local::new() else {
        return;
    };
    for (directory, lock) in [
        (local.root(), "rollback.lock"),
        (local.witness(), "witness.lock"),
    ] {
        std::fs::remove_file(directory.join(lock)).unwrap();
        let error = local.open().err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
        assert!(
            error.to_string().contains(&format!(
                "{lock} is missing, and a read-only open cannot create it"
            )),
            "{error}"
        );
        assert!(!directory.join(lock).exists());
        std::fs::write(directory.join(lock), b"").unwrap();
    }
    local.open().unwrap();
    let anchor = std::fs::read(local.witness().join("anchor")).unwrap();
    std::fs::remove_file(local.witness().join("anchor")).unwrap();
    std::fs::remove_file(local.witness().join("witness.lock")).unwrap();
    let error = local.open().err().unwrap();
    assert!(
        error
            .to_string()
            .contains("the witness directory holds no anchor"),
        "{error}"
    );
    assert!(!local.witness().join("witness.lock").exists());
    std::fs::write(local.witness().join("anchor"), anchor).unwrap();
    std::fs::write(local.witness().join("witness.lock"), b"").unwrap();
    local.open().unwrap();
}

/// What the writable open refuses, the read-only open refuses with the same
/// error, and it changes nothing meanwhile.
#[test]
fn a_local_read_only_open_authenticates_what_a_writable_open_does() {
    let Some(local) = Local::new() else {
        return;
    };
    let root = local.root().to_path_buf();
    let slot = committed_slot(&root);
    let (newest, _, older) = newest_manifest(&root);
    let newest_slot = root.join(format!("rollback.manifest.{newest}"));
    let older_slot = root.join(format!("rollback.manifest.{older}"));
    type Damage = Box<dyn Fn(bool)>;
    let save = |path: PathBuf| {
        let bytes = std::fs::read(&path).unwrap();
        move || std::fs::write(&path, &bytes).unwrap()
    };
    let (arena, restore_arena) = (
        root.join("rollback.arena"),
        save(root.join("rollback.arena")),
    );
    let restore_newest = save(newest_slot.clone());
    let restore_edited = save(newest_slot.clone());
    let restore_marker = save(root.join("rollback.format"));
    let cases: Vec<(&str, Damage, &str)> = vec![
        (
            "a damaged committed page",
            Box::new({
                let arena = arena.clone();
                move |damage| {
                    if damage {
                        flip(&arena, slot)
                    } else {
                        restore_arena()
                    }
                }
            }),
            "rollback arena page authentication failed",
        ),
        (
            "the newest slot rolled back to the older manifest",
            Box::new({
                let (newest_slot, older_slot) = (newest_slot.clone(), older_slot.clone());
                move |damage| {
                    if damage {
                        std::fs::copy(&older_slot, &newest_slot).unwrap();
                    } else {
                        restore_newest()
                    }
                }
            }),
            "no exact witnessed manifest",
        ),
        (
            "a valid, canonical manifest of the witness's identity and generation that the \
             witness does not select",
            Box::new({
                let newest_slot = newest_slot.clone();
                move |damage| {
                    if damage {
                        // The payload's length one byte shorter: still a
                        // valid manifest, encoded canonically, of the same
                        // length, generation and identity.
                        let mut bytes = std::fs::read(&newest_slot).unwrap();
                        let from = format!("\"len\":{PAYLOAD_LEN},");
                        let to = format!("\"len\":{},", PAYLOAD_LEN - 1);
                        let at = bytes
                            .windows(from.len())
                            .position(|window| window == from.as_bytes())
                            .expect("the payload's length is in the slot");
                        bytes[at..at + to.len()].copy_from_slice(to.as_bytes());
                        std::fs::write(&newest_slot, bytes).unwrap();
                    } else {
                        restore_edited()
                    }
                }
            }),
            "no exact witnessed manifest",
        ),
        (
            "an arena of another size",
            Box::new({
                let arena = arena.clone();
                move |damage| {
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&arena)
                        .unwrap();
                    let len = file.metadata().unwrap().len();
                    file.set_len(if damage { len + PAGE } else { len - PAGE })
                        .unwrap();
                }
            }),
            "rollback arena size mismatch",
        ),
        (
            "a foreign format marker",
            Box::new({
                let marker = root.join("rollback.format");
                move |damage| {
                    if damage {
                        std::fs::write(&marker, b"MAKI-WITNESS-COW-V0\n").unwrap();
                    } else {
                        restore_marker()
                    }
                }
            }),
            "unsupported rollback format",
        ),
    ];
    for (case, damage, expected) in &cases {
        damage(true);
        let before = local.trees();
        let read_only = local.open().err().unwrap();
        assert_eq!(
            local.trees(),
            before,
            "{case}: the read-only open changed something"
        );
        let writable = RollbackBacking::open(local.root(), local.witness())
            .err()
            .unwrap();
        assert!(
            read_only.to_string().contains(expected),
            "{case}: {read_only}"
        );
        assert_eq!(read_only.to_string(), writable.to_string(), "{case}");
        assert_eq!(read_only.kind(), writable.kind(), "{case}");
        damage(false);
        assert_eq!(read_payload(&local.open().unwrap()), payload(), "{case}");
    }
}

/// Every read is authenticated again, and a page that changed after the
/// open stops the view for good, as it stops a writer's session.
#[test]
fn a_page_that_changes_after_a_read_only_open_stops_the_view() {
    let Some(local) = Local::new() else {
        return;
    };
    let view = local.open().unwrap();
    flip(
        &local.root().join("rollback.arena"),
        committed_slot(local.root()),
    );
    let file = view.open("data/payload", false).unwrap();
    let mut bytes = vec![0; PAYLOAD_LEN];
    let error = file.read_at(0, &mut bytes).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    assert!(view.session_stopped().is_some());
    assert!(view.list("").is_err());
    flip(
        &local.root().join("rollback.arena"),
        committed_slot(local.root()),
    );
    assert!(file.read_at(0, &mut bytes).is_err(), "a stopped view read");
}

/// Every operation first reads a local witness again, to ask whether it
/// still selects what the view read: a changed anchor stops the view for
/// good.
#[test]
fn a_witness_that_changes_after_a_read_only_open_stops_the_view() {
    let Some(local) = Local::new() else {
        return;
    };
    let view = local.open().unwrap();
    let anchor = local.witness().join("anchor");
    let bytes = std::fs::read(&anchor).unwrap();
    std::fs::write(&anchor, b"").unwrap();
    let error = view.list("").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    let error = view.check_freshness().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    std::fs::write(&anchor, &bytes).unwrap();
    assert!(view.session_stopped().is_some());
    assert!(view.open("data/payload", false).is_err());
}

/// A backing that records every change asked of it, and lets it happen,
/// and, in `accesses`, every lock, open, lookup, listing and read in order,
/// each named with `label`.
struct Recording {
    inner: Arc<dyn Backing>,
    changes: Arc<Mutex<Vec<String>>>,
    label: &'static str,
    accesses: Arc<Mutex<Vec<String>>>,
}

struct RecordingFile {
    inner: Arc<dyn BackingFile>,
    name: String,
    changes: Arc<Mutex<Vec<String>>>,
    accesses: Arc<Mutex<Vec<String>>>,
}

impl Recording {
    fn note(&self, change: String) {
        self.changes.lock().unwrap().push(change);
    }
    fn access(&self, what: &str, path: &str) {
        self.accesses
            .lock()
            .unwrap()
            .push(format!("{what} {}:{path}", self.label));
    }
}

impl RecordingFile {
    fn note(&self, change: &str) {
        self.changes
            .lock()
            .unwrap()
            .push(format!("{change} {}", self.name));
    }
}

impl BackingFile for RecordingFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.accesses
            .lock()
            .unwrap()
            .push(format!("read {}", self.name));
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.note("write_at");
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.note("set_len");
        self.inner.set_len(len)
    }
    fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
        self.note("allocate_range");
        self.inner.allocate_range(offset, len)
    }
    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        self.note("punch_hole");
        self.inner.punch_hole(offset, len)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        self.note("sync_data");
        self.inner.sync_data()
    }
    fn sync_all(&self) -> io::Result<()> {
        self.note("sync_all");
        self.inner.sync_all()
    }
    fn owner(&self) -> io::Result<Option<FileOwner>> {
        self.inner.owner()
    }
    fn set_owner(&self, owner: FileOwner) -> io::Result<()> {
        self.note("set_owner");
        self.inner.set_owner(owner)
    }
}

impl Backing for Recording {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        if create {
            self.note(format!("create {path}"));
        }
        self.access("open", path);
        Ok(Arc::new(RecordingFile {
            inner: self.inner.open(path, create)?,
            name: format!("{}:{path}", self.label),
            changes: self.changes.clone(),
            accesses: self.accesses.clone(),
        }))
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.access("exists", path);
        self.inner.exists(path)
    }
    fn remove(&self, path: &str) -> io::Result<()> {
        self.note(format!("remove {path}"));
        self.inner.remove(path)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.note(format!("rename {from} {to}"));
        self.inner.rename(from, to)
    }
    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.note(format!("create_dir_all {path}"));
        self.inner.create_dir_all(path)
    }
    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        self.access("list", dir);
        self.inner.list(dir)
    }
    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        self.note(format!("sync_dir {dir}"));
        self.inner.sync_dir(dir)
    }
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.note(format!("try_lock {path}"));
        self.inner.try_lock(path)
    }
    fn is_read_only(&self) -> bool {
        self.inner.is_read_only()
    }
    fn try_lock_shared_existing(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.access("lock", path);
        self.inner.try_lock_shared_existing(path)
    }
    fn directory_owner(&self, dir: &str) -> io::Result<Option<FileOwner>> {
        self.inner.directory_owner(dir)
    }
}

/// Over backings that would let it write, the view asks for no change at
/// all, in either directory, while it opens, reads and closes.
#[test]
fn a_local_read_only_open_asks_for_no_change_even_where_one_is_allowed() {
    let Some(local) = Local::new() else {
        return;
    };
    let changes = Arc::new(Mutex::new(Vec::new()));
    let accesses = Arc::new(Mutex::new(Vec::new()));
    let recording = |label, path: &Path| -> Arc<dyn Backing> {
        Arc::new(Recording {
            inner: Arc::new(FileBacking::new(path).unwrap()),
            changes: changes.clone(),
            label,
            accesses: accesses.clone(),
        })
    };
    let view = ReadOnlyRollbackBacking::open_on(
        recording("root", local.root()),
        recording("witness", local.witness()),
    )
    .unwrap();
    // Both locks are taken before anything in either directory is opened,
    // listed or read.
    let order = accesses.lock().unwrap().clone();
    assert_eq!(
        order[..2],
        ["lock root:rollback.lock", "lock witness:witness.lock"],
        "{order:?}"
    );
    assert!(order.iter().any(|access| access.starts_with("read ")));
    assert_eq!(read_payload(&view), payload());
    view.check_freshness().unwrap();
    drop(view);
    assert_eq!(*changes.lock().unwrap(), Vec::<String>::new());
    // The recording itself is sound: the writable open asks for changes.
    drop(
        RollbackBacking::open_on(
            recording("root", local.root()),
            recording("witness", local.witness()),
        )
        .unwrap(),
    );
    assert!(!changes.lock().unwrap().is_empty());
}

/// A lock file that is missing refuses the open before anything else in
/// either directory is read: with `witness.lock` missing and the format
/// marker foreign, the refusal is the lock's.
#[test]
fn a_local_read_only_open_refuses_a_missing_lock_before_it_reads_the_marker() {
    let Some(local) = Local::new() else {
        return;
    };
    std::fs::remove_file(local.witness().join("witness.lock")).unwrap();
    std::fs::write(
        local.root().join("rollback.format"),
        b"MAKI-WITNESS-COW-V0\n",
    )
    .unwrap();
    let error = local.open().err().unwrap();
    assert!(
        error
            .to_string()
            .contains("witness.lock is missing, and a read-only open cannot create it"),
        "{error}"
    );
}

/// A remote authority over a local state store that records the action of
/// every request it answers.
struct RecordingRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
    actions: Arc<Mutex<Vec<&'static str>>>,
    /// Set to `n`, an administrator takes the authority over, elsewhere,
    /// right after the `n`th inspection from now is answered.
    takeover_after: Mutex<Option<usize>>,
    /// Set, a release is lost before the authority sees it: what a writer
    /// that died leaves.
    lose_release: std::sync::atomic::AtomicBool,
}

fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Inspect => "inspect",
        Action::Claim => "claim",
        Action::Takeover => "takeover",
        Action::RecoverEnrollment => "recover-enrollment",
        Action::ClaimRestore { .. } => "claim-restore",
        Action::Activate { .. } => "activate",
        Action::Advance { .. } => "advance",
        Action::Release => "release",
    }
}

impl Rpc for RecordingRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.actions
            .lock()
            .unwrap()
            .push(action_name(&request.action));
        if request.action == Action::Release
            && self.lose_release.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "release lost",
            ));
        }
        let record = self.store.lock().unwrap().handle(self.role, request)?;
        if request.action == Action::Inspect {
            let mut countdown = self.takeover_after.lock().unwrap();
            if let Some(remaining) = countdown.as_mut() {
                *remaining -= 1;
                if *remaining == 0 {
                    *countdown = None;
                    self.store.lock().unwrap().handle(
                        Role::Admin,
                        &Request {
                            operation_id: *uuid::Uuid::new_v4().as_bytes(),
                            expected: Some(record.clone()),
                            action: Action::Takeover,
                            authorization: Some(SessionAuthorization::generate().unwrap()),
                        },
                    )?;
                }
            }
        }
        Ok(record)
    }
}

struct Remote {
    root: tempfile::TempDir,
    _state: tempfile::TempDir,
    writer: Arc<RecordingRpc>,
    admin: Arc<RecordingRpc>,
    actions: Arc<Mutex<Vec<&'static str>>>,
}

impl Remote {
    /// A remote backing that holds the payload, released again.
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = private_dir::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            StateStore::create(state.path(), [1; 16]).unwrap(),
        ));
        let actions = Arc::new(Mutex::new(Vec::new()));
        let rpc = |role| {
            Arc::new(RecordingRpc {
                store: store.clone(),
                role,
                actions: actions.clone(),
                takeover_after: Mutex::new(None),
                lose_release: std::sync::atomic::AtomicBool::new(false),
            })
        };
        let remote = Self {
            root,
            _state: state,
            writer: rpc(Role::Writer),
            admin: rpc(Role::Admin),
            actions,
        };
        let backing =
            RollbackBacking::create_remote(remote.root(), remote.writer.clone(), 32 * PAGE)
                .unwrap();
        write_payload(&backing);
        drop(backing);
        remote
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn record(&self) -> Record {
        self.writer
            .call(&Request {
                operation_id: *uuid::Uuid::new_v4().as_bytes(),
                expected: None,
                action: Action::Inspect,
                authorization: None,
            })
            .unwrap()
    }

    fn open(&self) -> io::Result<ReadOnlyRollbackBacking> {
        ReadOnlyRollbackBacking::open_remote(self.root(), self.writer.clone())
    }

    /// Forget the actions sent so far.
    fn clear(&self) {
        self.actions.lock().unwrap().clear();
    }

    /// The actions sent since the last [`Self::clear`]: inspections only.
    fn only_inspections(&self) {
        let actions = self.actions.lock().unwrap().clone();
        assert!(
            !actions.is_empty() && actions.iter().all(|action| *action == "inspect"),
            "{actions:?}"
        );
    }
}

#[test]
fn a_remote_read_only_open_sends_only_inspections_and_changes_nothing() {
    let remote = Remote::new();
    let record = remote.record();
    let before = tree(remote.root());
    remote.clear();
    let view = remote.open().unwrap();
    assert_eq!(read_payload(&view), payload());
    assert_eq!(view.capacity().unwrap(), 32 * PAGE);
    assert_eq!(view.list("").unwrap(), ["data", "volume.lock"]);
    drop(view.try_lock_shared_existing("volume.lock").unwrap());
    every_change_is_refused(&view, "data/payload");
    drop(view);
    remote.only_inspections();
    assert_eq!(remote.record(), record);
    assert_eq!(
        tree(remote.root()),
        before,
        "the read-only open changed the root"
    );
}

/// A live writer holds its namespace's lock: the view refuses to run
/// beside it, having sent only inspections. While the view is open, no
/// writer starts: the root's operation lock is held shared.
#[test]
fn a_remote_read_only_open_excludes_a_writer() {
    let remote = Remote::new();
    let writer = RollbackBacking::open_remote(remote.root(), remote.writer.clone()).unwrap();
    let record = remote.record();
    remote.clear();
    let error = remote.open().err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
    assert!(
        error
            .to_string()
            .contains("/rollback.lock is held by another process"),
        "{error}"
    );
    remote.only_inspections();
    assert_eq!(remote.record(), record);
    drop(writer);
    let record = remote.record();
    let view = remote.open().unwrap();
    let second = remote.open().unwrap();
    remote.clear();
    let error = RollbackBacking::open_remote(remote.root(), remote.writer.clone())
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
    assert_eq!(*remote.actions.lock().unwrap(), Vec::<&str>::new());
    assert_eq!(remote.record(), record);
    // The root's operation lock and the current namespace's lock are both
    // held for as long as the view is open.
    let namespace = record.current.unwrap().namespace;
    for lock in [
        "remote.operation.lock".to_string(),
        format!("{namespace}/rollback.lock"),
    ] {
        let error = FileBacking::new(remote.root())
            .unwrap()
            .try_lock(&lock)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{lock}: {error}");
    }
    drop((view, second));
    drop(RollbackBacking::open_remote(remote.root(), remote.writer.clone()).unwrap());
}

/// The view authenticates the authority's current generation where it is,
/// and every committed page of it.
#[test]
fn a_remote_read_only_open_authenticates_the_current_generation() {
    let remote = Remote::new();
    let current = remote.record().current.unwrap().namespace;
    let namespace = remote.root().join(&current);
    let arena = namespace.join("rollback.arena");
    let slot = committed_slot(&namespace);
    flip(&arena, slot);
    remote.clear();
    let error = remote.open().err().unwrap();
    assert!(
        error
            .to_string()
            .contains("rollback arena page authentication failed"),
        "{error}"
    );
    remote.only_inspections();
    flip(&arena, slot);
    remote.open().unwrap();
    // A root that does not hold the current generation is refused in the
    // words attach uses.
    let (newest, _, older) = newest_manifest(&namespace);
    let newest_slot = namespace.join(format!("rollback.manifest.{newest}"));
    let saved = std::fs::read(&newest_slot).unwrap();
    std::fs::copy(
        namespace.join(format!("rollback.manifest.{older}")),
        &newest_slot,
    )
    .unwrap();
    let error = remote.open().err().unwrap();
    assert!(
        error
            .to_string()
            .contains("this backing root does not hold the remote authority's current generation"),
        "{error}"
    );
    std::fs::write(&newest_slot, saved).unwrap();
    // The namespace's lock is taken before anything in the namespace is
    // read: with the lock and both manifest slots gone, the refusal is the
    // lock's. A root without the namespace is refused in attach's words.
    let slots = [0, 1].map(|index| namespace.join(format!("rollback.manifest.{index}")));
    let saved = slots.clone().map(|slot| std::fs::read(slot).unwrap());
    let lock = namespace.join("rollback.lock");
    std::fs::remove_file(&lock).unwrap();
    for slot in &slots {
        std::fs::remove_file(slot).unwrap();
    }
    let error = remote.open().err().unwrap();
    assert!(
        error.to_string().contains(&format!(
            "{current}/rollback.lock is missing, and a read-only open cannot create it"
        )),
        "{error}"
    );
    let moved = remote.root().join("elsewhere");
    std::fs::rename(&namespace, &moved).unwrap();
    let error = remote.open().err().unwrap();
    assert!(
        error
            .to_string()
            .contains("this backing root does not hold the remote authority's current generation"),
        "{error}"
    );
    std::fs::rename(&moved, &namespace).unwrap();
    std::fs::write(&lock, b"").unwrap();
    for (slot, bytes) in slots.iter().zip(saved) {
        std::fs::write(slot, bytes).unwrap();
    }
    remote.open().unwrap();
    // The operation lock and the namespace's lock are taken, never created.
    for lock in [
        "remote.operation.lock".to_string(),
        format!("{current}/rollback.lock"),
    ] {
        let path = remote.root().join(&lock);
        std::fs::remove_file(&path).unwrap();
        let error = remote.open().err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
        assert!(
            error.to_string().contains(&format!(
                "{lock} is missing, and a read-only open cannot create it"
            )),
            "{error}"
        );
        assert!(!path.exists());
        std::fs::write(&path, b"").unwrap();
    }
    remote.open().unwrap();
}

/// The authority is asked again when the view's user asks
/// (`check_freshness`, which a command calls before it reports), and a
/// record that changed (here an administrator's takeover, made elsewhere)
/// stops the view for good. What the view read before is the generation it
/// opened, authenticated page by page: the takeover changed nothing in the
/// root, which the view's locks keep every other operation out of.
#[test]
fn an_authority_that_changes_after_a_remote_read_only_open_stops_the_view() {
    let remote = Remote::new();
    let view = remote.open().unwrap();
    let record = remote.record();
    remote
        .admin
        .call(&Request {
            operation_id: *uuid::Uuid::new_v4().as_bytes(),
            expected: Some(record),
            action: Action::Takeover,
            authorization: Some(SessionAuthorization::generate().unwrap()),
        })
        .unwrap();
    assert_eq!(read_payload(&view), payload());
    let error = view.check_freshness().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    assert!(
        error
            .to_string()
            .contains("the remote authority changed after the backing was opened read-only"),
        "{error}"
    );
    assert!(view.session_stopped().is_some());
    assert!(view.open("data/payload", false).is_err());
    assert!(view.list("").is_err());
    assert!(view.check_freshness().is_err());
}

/// A remote view sends the authority two inspections while it opens and one
/// each time its user asks for freshness, however much it reads: a deep
/// check of a large volume sent one before every backing operation, each
/// over a connection of its own. A local witness is still read before every
/// operation.
#[test]
fn a_remote_read_only_view_asks_the_authority_only_when_asked() {
    let remote = Remote::new();
    remote.clear();
    let view = remote.open().unwrap();
    assert_eq!(*remote.actions.lock().unwrap(), ["inspect", "inspect"]);
    remote.clear();
    for _ in 0..10 {
        assert_eq!(read_payload(&view), payload());
        assert_eq!(view.list("").unwrap(), ["data", "volume.lock"]);
        assert!(view.exists("data/payload").unwrap());
        assert_eq!(view.capacity().unwrap(), 32 * PAGE);
        view.free_bytes().unwrap();
        drop(view.try_lock_shared_existing("volume.lock").unwrap());
    }
    assert_eq!(*remote.actions.lock().unwrap(), Vec::<&str>::new());
    view.check_freshness().unwrap();
    view.check_freshness().unwrap();
    assert_eq!(*remote.actions.lock().unwrap(), ["inspect", "inspect"]);
}

/// A writable open that is given a check runs it before it claims a writer,
/// over a view of the authority's current generation that reads only what
/// the check reads, every page authenticated, and changes nothing: what the
/// check refuses is refused with only the open's inspection sent, the
/// authority's record unchanged and nothing in the root changed. A check
/// that passes leaves the open to claim as before. It runs only where a
/// claim could be granted: an authority that is not released refuses the
/// claim, as it did, without the check.
#[test]
fn a_writable_remote_open_runs_its_check_before_the_claim() {
    let remote = Remote::new();
    let record = remote.record();
    let before = tree(remote.root());
    remote.clear();
    let error =
        RollbackBacking::open_remote_checked(remote.root(), remote.writer.clone(), |view| {
            assert_eq!(read_payload(view), payload());
            assert_eq!(view.capacity().unwrap(), 32 * PAGE);
            every_change_is_refused(view, "data/payload");
            view.check_freshness().unwrap();
            Err(io::Error::other("refused by the check"))
        })
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "refused by the check");
    assert_eq!(*remote.actions.lock().unwrap(), ["inspect"]);
    assert_eq!(remote.record(), record);
    assert_eq!(
        tree(remote.root()),
        before,
        "a refused open changed the root"
    );
    // A page that does not authenticate fails the check's read, before the
    // claim too.
    let namespace = remote
        .root()
        .join(record.current.as_ref().unwrap().namespace.clone());
    let slot = committed_slot(&namespace);
    flip(&namespace.join("rollback.arena"), slot);
    remote.clear();
    let error =
        RollbackBacking::open_remote_checked(remote.root(), remote.writer.clone(), |view| {
            read_payload_result(view).map(drop)
        })
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("rollback arena page authentication failed"),
        "{error}"
    );
    assert_eq!(*remote.actions.lock().unwrap(), ["inspect"]);
    assert_eq!(remote.record(), record);
    flip(&namespace.join("rollback.arena"), slot);

    let mut checked = false;
    remote.clear();
    let writer = RollbackBacking::open_remote_checked(remote.root(), remote.writer.clone(), |_| {
        checked = true;
        Ok::<_, io::Error>(())
    })
    .unwrap();
    assert!(checked);
    assert_eq!(
        remote.actions.lock().unwrap()[..3],
        ["inspect", "claim", "activate"]
    );
    assert_eq!(read_payload(&writer), payload());
    remote
        .writer
        .lose_release
        .store(true, std::sync::atomic::Ordering::SeqCst);
    drop(writer);
    let record = remote.record();
    remote.clear();
    let error = RollbackBacking::open_remote_checked(remote.root(), remote.writer.clone(), |_| {
        Err(io::Error::other(
            "the check ran against an occupied authority",
        ))
    })
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
    assert_eq!(*remote.actions.lock().unwrap(), ["inspect", "claim"]);
    assert_eq!(remote.record(), record);
}

/// The authority's record is read again once the view holds its locks: a
/// change in between (here a takeover made elsewhere right after the first
/// inspection) refuses the open, and the authority is sent nothing but
/// inspections.
#[test]
fn an_authority_that_changes_while_a_remote_read_only_open_locks_is_refused() {
    let remote = Remote::new();
    *remote.writer.takeover_after.lock().unwrap() = Some(1);
    remote.clear();
    let error = remote.open().err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
    assert!(
        error
            .to_string()
            .contains("the remote authority changed while the backing was opened read-only"),
        "{error}"
    );
    remote.only_inspections();
}

/// An authority left active by a writer that is gone (here its release was
/// lost; a writer that dies leaves the same) holds no lock in the root: the
/// view reads the current generation, and sends only inspections.
#[test]
fn a_remote_read_only_open_reads_an_active_authority_whose_writer_is_gone() {
    use maki_backing::remote_witness::Phase;
    let remote = Remote::new();
    let writer = RollbackBacking::open_remote(remote.root(), remote.writer.clone()).unwrap();
    remote
        .writer
        .lose_release
        .store(true, std::sync::atomic::Ordering::SeqCst);
    drop(writer);
    let record = remote.record();
    assert_eq!(record.phase, Phase::Active);
    remote.clear();
    let view = remote.open().unwrap();
    assert_eq!(read_payload(&view), payload());
    drop(view);
    remote.only_inspections();
    assert_eq!(remote.record(), record);
}
