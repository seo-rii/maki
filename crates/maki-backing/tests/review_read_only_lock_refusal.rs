//! What the read-only rollback view tells an operator about a lock file it
//! does not find (`ReadOnlyRollbackBacking`, `shared_lock_refusal`).
//!
//! The view takes the locks that keep a writer out shared and never creates
//! them, so a missing one refuses the open. For a local root's
//! `rollback.lock` and the witness directory's `witness.lock` the refusal
//! says that opening the backing where it can be written recreates the file,
//! which is true. A remote root's `remote.operation.lock` is recreated so
//! too, but every operation that changes a remote root creates it, so a root
//! without it is either a live root whose file was removed or a copy made by
//! a tool that left lock files out, and opening a copy to write moves the
//! volume onto it: that refusal says so. A remote namespace's
//! `rollback.lock` is not recreated by any open: a writer creates the lock of
//! the namespace it forks before the authority names that namespace, and a
//! writable open of a remote root forks a new namespace instead of opening
//! the current one. The current namespace without its lock is therefore
//! what a copy of it looks like, a `maki volume snapshot` destination above
//! all, and a writable open of such a copy (attach) claims a writer at the
//! authority and moves the volume onto it: the volume's own root then no
//! longer holds the authority's current generation, until a snapshot of the
//! copy is restored onto it.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;
#[path = "support/private_dir.rs"]
mod private_dir;

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Phase, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, ReadOnlyRollbackBacking, RollbackBacking};

const PAGE: u64 = 4096;

/// What the refusal of a lock file that an open where the backing can be
/// written creates says about it.
const RECREATED: &str = "(opening the backing where it can be written recreates the file)";

/// The refusal of a root that does not hold the authority's current
/// generation.
const NOT_CURRENT: &str =
    "this backing root does not hold the remote authority's current generation";

/// An authority over a local state store, in one role.
struct Authority {
    store: Arc<Mutex<StateStore>>,
    role: Role,
}

impl Rpc for Authority {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.store.lock().unwrap().handle(self.role, request)
    }
}

/// A remote root that holds one committed file, released again.
struct Remote {
    root: tempfile::TempDir,
    _state: tempfile::TempDir,
    rpc: Arc<Authority>,
    admin: Arc<Authority>,
}

impl Remote {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = private_dir::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            StateStore::create(state.path(), [1; 16]).unwrap(),
        ));
        let rpc = Arc::new(Authority {
            store: store.clone(),
            role: Role::Writer,
        });
        let admin = Arc::new(Authority {
            store,
            role: Role::Admin,
        });
        let backing = RollbackBacking::create_remote(root.path(), rpc.clone(), 32 * PAGE).unwrap();
        write_payload(&backing, 0x42);
        drop(backing);
        Self {
            root,
            _state: state,
            rpc,
            admin,
        }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn record(&self) -> Record {
        self.rpc
            .call(&Request {
                operation_id: *uuid::Uuid::new_v4().as_bytes(),
                expected: None,
                action: Action::Inspect,
                authorization: None,
            })
            .unwrap()
    }

    /// The namespace the authority names as current.
    fn current(&self) -> String {
        self.record().current.unwrap().namespace
    }

    fn read_only(&self, root: &Path) -> io::Result<ReadOnlyRollbackBacking> {
        ReadOnlyRollbackBacking::open_remote(root, self.rpc.clone())
    }

    fn writable(&self, root: &Path) -> io::Result<RollbackBacking> {
        RollbackBacking::open_remote(root, self.rpc.clone())
    }
}

/// Fill the file `payload` with `byte` and commit it.
fn write_payload(backing: &dyn Backing, byte: u8) {
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, &[byte; PAGE as usize]).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
}

/// The first byte of the file `payload`.
fn payload(backing: &dyn Backing) -> u8 {
    let mut byte = [0];
    backing
        .open("payload", false)
        .unwrap()
        .read_at(0, &mut byte)
        .unwrap();
    byte[0]
}

/// The refusal of a missing namespace lock, checked: it names the lock, does
/// not send the operator to a writable open, says what the root probably
/// is, and that it must not be attached or opened to write.
fn namespace_lock_refusal(error: io::Error, namespace: &str) {
    let message = error.to_string();
    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{message}");
    assert!(
        message.contains(&format!(
            "{namespace}/rollback.lock is missing, and a read-only open cannot create it"
        )),
        "{message}"
    );
    assert!(!message.contains("recreates the file"), "{message}");
    for said in [
        "this root is probably not the volume's live root but a copy of its current namespace",
        "such as a `maki volume snapshot` destination",
        "do not attach it or open it to write",
        "move the volume onto this copy",
    ] {
        assert!(
            message.contains(said),
            "{said:?} is missing from: {message}"
        );
    }
}

/// The current namespace without its `rollback.lock` is refused, and the
/// refusal does not say that a writable open recreates the file: none does.
/// Attach's open of the root forks a new namespace, which gets a lock of its
/// own, and leaves the old one as it is.
#[test]
fn a_missing_namespace_lock_is_not_said_to_be_recreated_by_a_writable_open() {
    let remote = Remote::new();
    let current = remote.current();
    let lock = remote.root().join(&current).join("rollback.lock");
    std::fs::remove_file(&lock).unwrap();
    let error = remote.read_only(remote.root()).err().unwrap();
    namespace_lock_refusal(error, &current);
    assert!(!lock.exists());
    // What the refusal no longer says: a writable open does not recreate it.
    drop(remote.writable(remote.root()).unwrap());
    assert!(
        !lock.exists(),
        "a writable open recreated {current}/rollback.lock"
    );
    let forked = remote.current();
    assert_ne!(forked, current);
    assert!(remote.root().join(&forked).join("rollback.lock").is_file());
    remote.read_only(remote.root()).unwrap();
}

/// A snapshot destination holds the current namespace without its lock and
/// is refused so, telling the operator not to open it to write. The warning
/// is true: a writable open of the destination (what the refusal used to
/// suggest) succeeds and makes the copy the volume's root, and the volume's
/// own root is refused afterwards, by the read-only and the writable open,
/// as one that does not hold the authority's current generation.
#[test]
fn a_snapshot_destination_is_refused_with_the_warning_not_to_open_it_to_write() {
    let remote = Remote::new();
    let target = tempfile::tempdir().unwrap();
    let destination = target.path().join("snapshot");
    {
        let session = remote.writable(remote.root()).unwrap();
        session.snapshot_remote(&destination).unwrap();
    }
    let current = remote.current();
    assert!(destination.join(&current).is_dir());
    assert!(!destination.join(&current).join("rollback.lock").exists());
    let error = remote.read_only(&destination).err().unwrap();
    namespace_lock_refusal(error, &current);
    // The volume's own root is still read.
    remote.read_only(remote.root()).unwrap();
    // What the refusal warns of.
    drop(remote.writable(&destination).unwrap());
    let moved = remote.current();
    assert!(destination.join(&moved).join("rollback.lock").is_file());
    assert!(!remote.root().join(&moved).exists());
    let error = remote.read_only(remote.root()).err().unwrap();
    assert!(error.to_string().contains(NOT_CURRENT), "{error}");
    let error = remote.writable(remote.root()).err().unwrap();
    assert!(error.to_string().contains(NOT_CURRENT), "{error}");
}

/// What the volume's own root is once a writable open of a snapshot
/// destination has moved the volume onto the copy (what the operations and
/// remote witness guides say): attach and `maki volume snapshot` (the
/// writable open), `maki check` and `maki volume inspect` (the read-only
/// one), takeover and GC refuse it as one that does not hold the authority's
/// current generation. Restore does not: the root's `remote.enrollment`
/// binding identifies it. A snapshot of the copy restored onto it puts the
/// volume back, with what was written on the copy, and the copy is then
/// refused in turn.
#[test]
fn a_volume_moved_onto_a_snapshot_destination_is_restored_onto_its_own_root() {
    let remote = Remote::new();
    let target = tempfile::tempdir().unwrap();
    let (copy, back) = (target.path().join("copy"), target.path().join("back"));
    remote
        .writable(remote.root())
        .unwrap()
        .snapshot_remote(&copy)
        .unwrap();
    // The volume is opened to write on the copy, and written there.
    write_payload(&remote.writable(&copy).unwrap(), 0x43);
    assert_eq!(remote.record().phase, Phase::Released);
    let refused = |error: io::Error| assert!(error.to_string().contains(NOT_CURRENT), "{error}");
    refused(remote.read_only(remote.root()).err().unwrap());
    refused(remote.writable(remote.root()).err().unwrap());
    refused(
        RollbackBacking::takeover_remote(remote.root(), remote.admin.clone(), &remote.record())
            .err()
            .unwrap(),
    );
    refused(RollbackBacking::collect_remote(remote.root(), remote.rpc.as_ref()).unwrap_err());
    assert!(remote.root().join("remote.enrollment").is_file());
    assert!(!copy.join("remote.enrollment").exists());
    // The way back: a snapshot of the copy, which the authority now names,
    // restored onto the volume's own root.
    let descriptor = remote
        .writable(&copy)
        .unwrap()
        .snapshot_remote(&back)
        .unwrap();
    drop(
        RollbackBacking::restore_remote(
            remote.root(),
            &back,
            &descriptor,
            remote.admin.clone(),
            &remote.record(),
        )
        .unwrap(),
    );
    assert_eq!(payload(&remote.read_only(remote.root()).unwrap()), 0x43);
    assert_eq!(payload(&remote.writable(remote.root()).unwrap()), 0x43);
    refused(remote.read_only(&copy).err().unwrap());
}

/// Every operation that changes a remote root, its creation included,
/// creates `remote.operation.lock`, so a root without it is either a live
/// root whose file was removed or a copy made by a tool that left lock files
/// out. The refusal says that opening the root to write recreates the file
/// only of the live root, and not to attach a copy: a writable open of a
/// copy made without its lock files succeeds and moves the volume onto it.
#[test]
fn a_root_without_its_operation_lock_may_be_a_copy_and_is_not_sent_to_attach() {
    let remote = Remote::new();
    let lock = remote.root().join("remote.operation.lock");
    std::fs::remove_file(&lock).unwrap();
    operation_lock_refusal(remote.read_only(remote.root()).err().unwrap());
    // On the live root, a writable open recreates the file.
    drop(remote.writable(remote.root()).unwrap());
    assert!(lock.is_file());
    remote.read_only(remote.root()).unwrap();
    // A copy of the root made without its lock files is refused in the
    // same words, and a writable open of it moves the volume onto it.
    let copy = tempfile::tempdir().unwrap();
    copy_without_locks(remote.root(), copy.path());
    assert!(!copy.path().join("remote.operation.lock").exists());
    assert!(copy.path().join("remote.enrollment").is_file());
    operation_lock_refusal(remote.read_only(copy.path()).err().unwrap());
    drop(remote.writable(copy.path()).unwrap());
    let error = remote.read_only(remote.root()).err().unwrap();
    assert!(error.to_string().contains(NOT_CURRENT), "{error}");
}

/// The refusal of a missing operation lock, checked.
fn operation_lock_refusal(error: io::Error) {
    let message = error.to_string();
    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{message}");
    assert!(!message.contains(RECREATED), "{message}");
    for said in [
        "remote.operation.lock is missing, and a read-only open cannot create it",
        "this root is either the volume's live root with the file removed or a copy made by a \
         tool that left lock files out",
        "if it is the volume's live root, opening it where it can be written recreates the file",
        "do not attach a copy or open it to write",
        "move the volume onto the copy",
    ] {
        assert!(
            message.contains(said),
            "{said:?} is missing from: {message}"
        );
    }
}

/// Copy the tree `from` to `to`, leaving out every file whose name ends in
/// `.lock`, as a backup that excludes lock files does.
fn copy_without_locks(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_without_locks(&path, &target);
        } else if !entry.file_name().to_string_lossy().ends_with(".lock") {
            std::fs::copy(&path, &target).unwrap();
        }
    }
}

/// The local lock files keep their refusal: `RollbackBacking::open`
/// recreates a local root's `rollback.lock` and its witness directory's
/// `witness.lock`, which the refusal says.
#[test]
fn the_local_missing_locks_are_said_to_be_recreated_by_a_writable_open() {
    let root = tempfile::tempdir().unwrap();
    let Some(witness) = other_filesystem::tempdir(root.path()) else {
        return;
    };
    drop(RollbackBacking::create(root.path(), witness.path(), 32 * PAGE).unwrap());
    for (directory, lock) in [
        (root.path(), "rollback.lock"),
        (witness.path(), "witness.lock"),
    ] {
        std::fs::remove_file(directory.join(lock)).unwrap();
        let error = ReadOnlyRollbackBacking::open(root.path(), witness.path())
            .err()
            .unwrap();
        let message = error.to_string();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{message}");
        assert!(
            message.contains(&format!(
                "{lock} is missing, and a read-only open cannot create it"
            )) && message.contains(RECREATED)
                && !message.contains("snapshot"),
            "{message}"
        );
        drop(RollbackBacking::open(root.path(), witness.path()).unwrap());
        assert!(directory.join(lock).is_file(), "{lock}");
        ReadOnlyRollbackBacking::open(root.path(), witness.path()).unwrap();
    }
}
