//! What the read-only rollback view tells an operator about a lock file it
//! does not find (`ReadOnlyRollbackBacking`, `shared_lock_refusal`).
//!
//! The view takes the locks that keep a writer out shared and never creates
//! them, so a missing one refuses the open. For the root's `rollback.lock`,
//! the witness directory's `witness.lock` and a remote root's
//! `remote.operation.lock` the refusal says that opening the backing where it
//! can be written recreates the file, which is true. A remote namespace's
//! `rollback.lock` is not recreated by any open: a writer creates the lock of
//! the namespace it forks before the authority names that namespace, and a
//! writable open of a remote root forks a new namespace instead of opening
//! the current one. The current namespace without its lock is therefore
//! what a copy of it looks like, a `maki volume snapshot` destination above
//! all, and a writable open of such a copy (attach) claims a writer at the
//! authority and moves the volume onto it: the volume's own root then no
//! longer holds the authority's current generation.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;
#[path = "support/private_dir.rs"]
mod private_dir;

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, ReadOnlyRollbackBacking, RollbackBacking};

const PAGE: u64 = 4096;

/// What the refusal of a lock file that an open where the backing can be
/// written creates says about it.
const RECREATED: &str = "(opening the backing where it can be written recreates the file)";

/// An authority over a local state store, in the writer's role.
struct Authority {
    store: Mutex<StateStore>,
}

impl Rpc for Authority {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.store.lock().unwrap().handle(Role::Writer, request)
    }
}

/// A remote root that holds one committed file, released again.
struct Remote {
    root: tempfile::TempDir,
    _state: tempfile::TempDir,
    rpc: Arc<Authority>,
}

impl Remote {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = private_dir::tempdir().unwrap();
        let rpc = Arc::new(Authority {
            store: Mutex::new(StateStore::create(state.path(), [1; 16]).unwrap()),
        });
        let backing = RollbackBacking::create_remote(root.path(), rpc.clone(), 32 * PAGE).unwrap();
        let file = backing.open("payload", true).unwrap();
        file.write_at(0, &[0x42; PAGE as usize]).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        drop((file, backing));
        Self {
            root,
            _state: state,
            rpc,
        }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    /// The namespace the authority names as current.
    fn current(&self) -> String {
        let record = self
            .rpc
            .call(&Request {
                operation_id: *uuid::Uuid::new_v4().as_bytes(),
                expected: None,
                action: Action::Inspect,
                authorization: None,
            })
            .unwrap();
        record.current.unwrap().namespace
    }

    fn read_only(&self, root: &Path) -> io::Result<ReadOnlyRollbackBacking> {
        ReadOnlyRollbackBacking::open_remote(root, self.rpc.clone())
    }

    fn writable(&self, root: &Path) -> io::Result<RollbackBacking> {
        RollbackBacking::open_remote(root, self.rpc.clone())
    }
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
/// own root is refused afterwards, by every open, as one that does not hold
/// the authority's current generation.
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
    const NOT_CURRENT: &str =
        "this backing root does not hold the remote authority's current generation";
    let error = remote.read_only(remote.root()).err().unwrap();
    assert!(error.to_string().contains(NOT_CURRENT), "{error}");
    let error = remote.writable(remote.root()).err().unwrap();
    assert!(error.to_string().contains(NOT_CURRENT), "{error}");
}

/// The other lock files keep their refusal: an open where the backing can be
/// written recreates each of them, which the refusal says. A remote root's
/// operation lock is created by attach's open of the root; a local root's
/// `rollback.lock` and its witness directory's `witness.lock` by
/// `RollbackBacking::open`.
#[test]
fn the_other_missing_locks_are_said_to_be_recreated_by_a_writable_open() {
    let remote = Remote::new();
    let lock = remote.root().join("remote.operation.lock");
    std::fs::remove_file(&lock).unwrap();
    let error = remote.read_only(remote.root()).err().unwrap();
    let message = error.to_string();
    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{message}");
    assert!(
        message.contains("remote.operation.lock is missing, and a read-only open cannot create it")
            && message.contains(RECREATED)
            && !message.contains("snapshot"),
        "{message}"
    );
    drop(remote.writable(remote.root()).unwrap());
    assert!(lock.is_file());
    remote.read_only(remote.root()).unwrap();

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
