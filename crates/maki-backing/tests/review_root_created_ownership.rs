//! A volume's backing root and its local rollback witness belong to the
//! daemon user. Offline commands run as root (`maki check --deep`,
//! `maki-check --deep`, `maki volume inspect`) take lock files and reserve
//! manifest slots there, and recreate them when a restore or a copy dropped
//! them. A file root creates in a directory another user owns must belong to
//! that user: a root-owned `0600` lock file or manifest slot locks the daemon
//! out of its own volume. Root never gives away an entry another user owns
//! or publishes a witness record another user put there, and a root-owned
//! directory keeps getting root-owned files. Changing an owner needs root:
//! without it these tests print why they are skipped (as in CI).
#![cfg(target_os = "linux")]

#[path = "support/private_dir.rs"]
mod private_dir;

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::witness::FileWitness;
use maki_backing::{Backing, FileBacking, RollbackBacking};

/// Stands in for the daemon user. Distinct uid and gid, neither root's.
const DAEMON: (u32, u32) = (65534, 65533);
/// Another unprivileged user.
const OTHER: (u32, u32) = (65532, 65531);

fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn skip_unless_root(test: &str) -> bool {
    if running_as_root() {
        return false;
    }
    eprintln!("{test}: skipped: files of another user need root");
    true
}

fn give(path: &Path, (uid, gid): (u32, u32)) {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid)).unwrap();
    if fs::symlink_metadata(path).unwrap().is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            give(&entry.unwrap().path(), (uid, gid));
        }
    }
}

/// (uid, gid) and permission bits of an entry.
fn owner(path: &Path) -> ((u32, u32), u32) {
    let metadata = fs::symlink_metadata(path).unwrap();
    ((metadata.uid(), metadata.gid()), metadata.mode() & 0o7777)
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

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_CHOWN: u32 = 0;
const CAP_DAC_READ_SEARCH: u32 = 2;

fn capabilities(set: Option<&[CapabilityData; 2]>) -> io::Result<[CapabilityData; 2]> {
    // pid 0 names the calling thread.
    let mut header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = set.copied().unwrap_or_default();
    let call = if set.is_some() {
        libc::SYS_capset
    } else {
        libc::SYS_capget
    };
    // SAFETY: both pointers reference live, correctly laid out structures
    // for the duration of the call; capget writes two data words.
    if unsafe { libc::syscall(call, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(data)
}

/// Clears `capability` from the calling thread's effective set until the
/// guard drops. Credentials are per thread (libtest runs each test on its
/// own thread), so concurrent tests keep theirs.
struct WithoutCapability([CapabilityData; 2]);

impl WithoutCapability {
    fn new(capability: u32) -> io::Result<Self> {
        let saved = capabilities(None)?;
        let mut reduced = saved;
        reduced[(capability / 32) as usize].effective &= !(1 << (capability % 32));
        capabilities(Some(&reduced))?;
        Ok(Self(saved))
    }
}

impl Drop for WithoutCapability {
    fn drop(&mut self) {
        let _ = capabilities(Some(&self.0));
    }
}

#[test]
fn root_creates_a_missing_file_for_the_owner_of_its_directory() {
    if skip_unless_root("root_creates_a_missing_file_for_the_owner_of_its_directory") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("journal")).unwrap();
    fs::create_dir(dir.path().join("root")).unwrap();
    give(dir.path(), DAEMON);
    give(&dir.path().join("journal"), OTHER);
    give(&dir.path().join("root"), (0, 0));
    let backing = FileBacking::new(dir.path()).unwrap();

    let lock = backing.try_lock("volume.lock").unwrap();
    assert_eq!(owner(&dir.path().join("volume.lock")), (DAEMON, 0o600));
    drop(lock);
    // Reacquiring opens the existing file.
    drop(backing.try_lock("volume.lock").unwrap());

    let file = backing.open("superblock.a", true).unwrap();
    file.write_at(0, b"bytes").unwrap();
    file.sync_data().unwrap();
    assert_eq!(owner(&dir.path().join("superblock.a")), (DAEMON, 0o600));
    // Each file belongs to its own directory's owner.
    backing.open("journal/seg-1", true).unwrap();
    assert_eq!(owner(&dir.path().join("journal/seg-1")), (OTHER, 0o600));
    // A directory root owns gets root's files, as before.
    backing.open("root/file", true).unwrap();
    assert_eq!(owner(&dir.path().join("root/file")), ((0, 0), 0o600));
    // Directories follow the same rule.
    backing.create_dir_all("data/sub").unwrap();
    backing.create_dir_all("root/sub").unwrap();
    assert_eq!(owner(&dir.path().join("data")), (DAEMON, 0o700));
    assert_eq!(owner(&dir.path().join("data/sub")), (DAEMON, 0o700));
    assert_eq!(owner(&dir.path().join("root/sub")), ((0, 0), 0o700));
    // A new backing root is its creator's: its parent is not the volume.
    let nested = dir.path().join("data/new-root");
    drop(FileBacking::new(&nested).unwrap());
    assert_eq!(owner(&nested).0, (0, 0));
    // Every created file still has exactly one link.
    for name in ["volume.lock", "superblock.a", "journal/seg-1", "root/file"] {
        assert_eq!(
            fs::metadata(dir.path().join(name)).unwrap().nlink(),
            1,
            "{name}"
        );
    }
}

#[test]
fn root_never_gives_away_a_file_it_did_not_create() {
    if skip_unless_root("root_never_gives_away_a_file_it_did_not_create") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // Files root left behind earlier, in a directory the daemon user owns.
    fs::write(dir.path().join("volume.lock"), b"").unwrap();
    fs::write(dir.path().join("superblock.a"), b"root's bytes").unwrap();
    std::os::unix::fs::chown(dir.path(), Some(DAEMON.0), Some(DAEMON.1)).unwrap();
    let backing = FileBacking::new(dir.path()).unwrap();

    drop(backing.try_lock("volume.lock").unwrap());
    let file = backing.open("superblock.a", true).unwrap();
    let mut bytes = [0; 12];
    file.read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"root's bytes");
    for name in ["volume.lock", "superblock.a"] {
        assert_eq!(owner(&dir.path().join(name)).0, (0, 0), "{name}");
    }
}

#[test]
fn a_refused_owner_change_creates_nothing() {
    if skip_unless_root("a_refused_owner_change_creates_nothing") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    give(dir.path(), DAEMON);
    let backing = FileBacking::new(dir.path()).unwrap();
    {
        // Root without CAP_CHOWN cannot give a file away.
        let _unprivileged = match WithoutCapability::new(CAP_CHOWN) {
            Ok(guard) => guard,
            Err(error) => {
                eprintln!("a_refused_owner_change_creates_nothing: skipped: cannot drop CAP_CHOWN ({error})");
                return;
            }
        };
        let error = match backing.try_lock("volume.lock") {
            Ok(_) => panic!("a lock the daemon cannot open was created"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        let error = match backing.open("rollback.manifest.1", true) {
            Ok(_) => panic!("a file the daemon cannot open was created"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        let error = backing.create_dir_all("journal").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    }
    // Not even an empty root-owned entry is left behind.
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn root_without_cap_dac_read_search_still_creates_for_the_owner() {
    if skip_unless_root("root_without_cap_dac_read_search_still_creates_for_the_owner") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    give(dir.path(), DAEMON);
    let backing = FileBacking::new(dir.path()).unwrap();
    let _restricted = match WithoutCapability::new(CAP_DAC_READ_SEARCH) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!(
                "root_without_cap_dac_read_search_still_creates_for_the_owner: skipped: cannot \
                 drop CAP_DAC_READ_SEARCH ({error})"
            );
            return;
        }
    };
    drop(backing.try_lock("volume.lock").unwrap());
    assert_eq!(owner(&dir.path().join("volume.lock")), (DAEMON, 0o600));
}

#[test]
fn root_reopen_recreates_missing_rollback_files_for_the_daemon() {
    if skip_unless_root("root_reopen_recreates_missing_rollback_files_for_the_daemon") {
        return;
    }
    // Explicit roots keep the witness on an independent filesystem.
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let witness = tempfile::tempdir_in("/dev/shm").unwrap();
    drop(RollbackBacking::create(root.path(), witness.path(), 8 * 4096).unwrap());
    give(root.path(), DAEMON);
    give(witness.path(), DAEMON);
    // What a restore or copy that drops empty and sparse files leaves: no
    // locks and no inactive manifest slot (slot 0 holds the manifest).
    for path in [
        root.path().join("rollback.lock"),
        root.path().join("rollback.manifest.1"),
        witness.path().join("witness.lock"),
    ] {
        fs::remove_file(path).unwrap();
    }

    let backing = RollbackBacking::open(root.path(), witness.path()).unwrap();
    let file = backing.open("data", true).unwrap();
    file.write_at(0, b"offline").unwrap();
    file.sync_data().unwrap();
    drop(file);
    drop(backing);

    let mut changed = Vec::new();
    foreign(root.path(), DAEMON, &mut changed);
    foreign(witness.path(), DAEMON, &mut changed);
    assert_eq!(
        changed,
        Vec::<String>::new(),
        "root left files the daemon cannot open"
    );
    for path in [
        root.path().join("rollback.lock"),
        root.path().join("rollback.manifest.1"),
        witness.path().join("witness.lock"),
        witness.path().join("anchor"),
    ] {
        assert_eq!(owner(&path), (DAEMON, 0o600), "{}", path.display());
    }
    drop(RollbackBacking::open(root.path(), witness.path()).unwrap());
}

#[test]
fn root_republish_returns_a_root_owned_anchor_to_the_directory_owner() {
    if skip_unless_root("root_republish_returns_a_root_owned_anchor_to_the_directory_owner") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    drop(FileWitness::create(dir.path(), *b"volume-identity!", [0x11; 32]).unwrap());
    give(dir.path(), DAEMON);
    // What a root run before the anchor kept its owner left behind.
    give(&dir.path().join("anchor"), (0, 0));

    drop(FileWitness::open(dir.path()).unwrap());
    assert_eq!(owner(&dir.path().join("anchor")), (DAEMON, 0o600));
}

#[test]
fn root_refuses_to_republish_an_anchor_its_directory_owner_does_not_own() {
    if skip_unless_root("root_refuses_to_republish_an_anchor_its_directory_owner_does_not_own") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    drop(FileWitness::create(dir.path(), *b"volume-identity!", [0x11; 32]).unwrap());
    give(dir.path(), DAEMON);
    give(&dir.path().join("anchor"), OTHER);

    let error = FileWitness::open(dir.path()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    assert!(error.to_string().contains("uid 65532"), "{error}");
    assert!(error.to_string().contains("uid 65534"), "{error}");
    // Nothing was given to either user.
    assert_eq!(owner(&dir.path().join("anchor")).0, OTHER);
    assert!(!dir.path().join("anchor.next").exists());
}

#[test]
fn root_never_publishes_a_temporary_record_another_user_put_in_the_witness() {
    if skip_unless_root("root_never_publishes_a_temporary_record_another_user_put_in_the_witness") {
        return;
    }
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    let dir = tempfile::tempdir().unwrap();
    drop(FileWitness::create(dir.path(), *b"volume-identity!", [0x11; 32]).unwrap());
    give(dir.path(), DAEMON);
    // A temporary record of another user, who keeps a writable descriptor.
    let planted = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.path().join("anchor.next"))
        .unwrap();
    std::os::unix::fs::fchown(&planted, Some(OTHER.0), Some(OTHER.1)).unwrap();

    drop(FileWitness::open(dir.path()).unwrap());
    let anchor = dir.path().join("anchor");
    assert_ne!(
        fs::metadata(&anchor).unwrap().ino(),
        planted.metadata().unwrap().ino(),
        "the other user's file was published as the anchor"
    );
    assert_eq!(owner(&anchor), (DAEMON, 0o600));
    // Their file was not given away.
    let metadata = planted.metadata().unwrap();
    assert_eq!((metadata.uid(), metadata.gid()), OTHER);
    // Their descriptor cannot rewrite the published anchor.
    let published = fs::read(&anchor).unwrap();
    planted.write_all_at(&[0xa5; 104], 0).unwrap();
    assert_eq!(fs::read(&anchor).unwrap(), published);
    drop(FileWitness::open(dir.path()).unwrap());
}

/// The authority in process, answering for one role.
struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
}

impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.store.lock().unwrap().handle(self.role, request)
    }
}

#[test]
fn root_takeover_and_reopen_create_the_writer_namespace_for_the_daemon() {
    if skip_unless_root("root_takeover_and_reopen_create_the_writer_namespace_for_the_daemon") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let state = private_dir::tempdir().unwrap();
    let store = Arc::new(Mutex::new(
        StateStore::create(state.path(), [1; 16]).unwrap(),
    ));
    let writer = Arc::new(LocalRpc {
        store: store.clone(),
        role: Role::Writer,
    });
    let admin = Arc::new(LocalRpc {
        store,
        role: Role::Admin,
    });
    let old = RollbackBacking::create_remote(root.path(), writer.clone(), 8 * 4096).unwrap();
    let file = old.open("payload", true).unwrap();
    file.write_at(0, b"daemon").unwrap();
    file.sync_data().unwrap();
    old.sync_dir("").unwrap();
    drop(file);
    give(root.path(), DAEMON);

    // What `maki volume takeover` does as root with the administrator
    // configuration: a new writer namespace, copied from the current one.
    let expected = admin
        .call(&Request {
            authorization: None,
            operation_id: [7; 16],
            expected: None,
            action: Action::Inspect,
        })
        .unwrap();
    let new = RollbackBacking::takeover_remote(root.path(), admin.clone(), &expected).unwrap();
    drop(new);
    drop(old);
    let mut changed = Vec::new();
    foreign(root.path(), DAEMON, &mut changed);
    assert_eq!(
        changed,
        Vec::<String>::new(),
        "takeover left root's entries"
    );

    // A writer opened as root forks a namespace the same way.
    drop(RollbackBacking::open_remote(root.path(), writer).unwrap());
    let mut changed = Vec::new();
    foreign(root.path(), DAEMON, &mut changed);
    assert_eq!(changed, Vec::<String>::new(), "reopen left root's entries");
}
