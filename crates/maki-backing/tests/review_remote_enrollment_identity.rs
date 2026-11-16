//! Enrollment recovery must prove that the configured backing root can belong
//! to the never-activated authority it resumes before it binds the root,
//! claims the authority or lets automatic GC reclaim anything. Roots written
//! by older binaries carry no `remote.enrollment` binding, so a missing
//! binding is no evidence that the root is unused (the restore form of this
//! is BUG-187, `review_remote_restore_identity.rs`).
#![cfg(target_os = "linux")]

use maki_backing::remote_witness::{
    namespace, Action, Phase, Record, Request, Role, Rpc, StateStore,
};
use maki_backing::{Backing, MemBacking, RollbackBacking};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const CAPACITY: u64 = 32 * 4096;

struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
    /// Apply a claim, then lose its reply (an interrupted enrollment).
    lose_claim: AtomicBool,
    /// Refuse an activation before the authority sees it, leaving the
    /// claimed namespace behind as an abandoned candidate.
    drop_activate: AtomicBool,
}

impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        if matches!(request.action, Action::Activate { .. })
            && self.drop_activate.load(Ordering::SeqCst)
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "activation never reached the authority",
            ));
        }
        let record = self.store.lock().unwrap().handle(self.role, request)?;
        if matches!(request.action, Action::Claim) && self.lose_claim.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "lost durable claim reply",
            ));
        }
        Ok(record)
    }
}

struct Authority {
    writer: Arc<LocalRpc>,
    admin: Arc<LocalRpc>,
}

impl Authority {
    fn new(identity: [u8; 16]) -> Self {
        let store = Arc::new(Mutex::new(
            StateStore::create_backing(Arc::new(MemBacking::new()), identity).unwrap(),
        ));
        let make = |role| {
            Arc::new(LocalRpc {
                store: store.clone(),
                role,
                lose_claim: AtomicBool::new(false),
                drop_activate: AtomicBool::new(false),
            })
        };
        Self {
            writer: make(Role::Writer),
            admin: make(Role::Admin),
        }
    }

    /// An activated, quiescent volume holding `payload`.
    fn activated(&self, root: &Path, payload: &[u8]) {
        let backing = RollbackBacking::create_remote(root, self.writer.clone(), CAPACITY).unwrap();
        let file = backing.open("payload", true).unwrap();
        file.write_at(0, payload).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
    }

    /// Initial enrollment whose claim reply was lost: never activated.
    fn interrupted(&self, root: &Path) -> Record {
        self.writer.lose_claim.store(true, Ordering::SeqCst);
        assert!(RollbackBacking::create_remote(root, self.writer.clone(), CAPACITY).is_err());
        self.writer.lose_claim.store(false, Ordering::SeqCst);
        let record = inspect(self.admin.as_ref());
        assert_eq!(record.phase, Phase::Claimed);
        assert!(record.current.is_none());
        record
    }

    /// Initial enrollment whose activation never reached the authority: the
    /// root keeps the claimed candidate namespace with its manifest.
    fn abandoned(&self, root: &Path) -> (Record, String) {
        self.writer.drop_activate.store(true, Ordering::SeqCst);
        assert!(RollbackBacking::create_remote(root, self.writer.clone(), CAPACITY).is_err());
        self.writer.drop_activate.store(false, Ordering::SeqCst);
        let record = inspect(self.admin.as_ref());
        assert_eq!(record.phase, Phase::Claimed);
        assert!(record.current.is_none());
        let candidate = namespace(record.fence, record.session);
        assert_eq!(namespaces(root), std::slice::from_ref(&candidate));
        (record, candidate)
    }
}

fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
        authorization: None,
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })
    .unwrap()
}

fn entries(root: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn namespaces(root: &Path) -> Vec<String> {
    entries(root)
        .into_iter()
        .filter(|name| name.starts_with("remote-"))
        .collect()
}

fn read(root: &Path, rpc: Arc<LocalRpc>) -> Vec<u8> {
    let backing = RollbackBacking::open_remote(root, rpc).unwrap();
    let file = backing.open("payload", false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

#[test]
fn recovery_refuses_a_foreign_legacy_root_before_binding_claim_or_gc() {
    // Volume B: activated and quiescent on a root written before the
    // supplementary binding existed.
    let b = Authority::new([2; 16]);
    let root_b = tempfile::tempdir().unwrap();
    b.activated(root_b.path(), b"volume B data");
    std::fs::remove_file(root_b.path().join("remote.enrollment")).unwrap();
    let b_before = inspect(b.writer.as_ref());
    let b_entries = entries(root_b.path());
    assert_eq!(
        namespaces(root_b.path()),
        [b_before.current.as_ref().unwrap().namespace.clone()]
    );

    // Volume A: initial enrollment interrupted, so it needs admin recovery.
    let a = Authority::new([1; 16]);
    let root_a = tempfile::tempdir().unwrap();
    let a_before = a.interrupted(root_a.path());

    // Every authority-side guard passes; only the configured root is B's.
    let outcome = RollbackBacking::recover_enrollment_remote(
        root_b.path(),
        a.admin.clone(),
        CAPACITY,
        &a_before,
    );
    assert!(
        outcome.is_err(),
        "enrollment recovery adopted a root holding another volume's data"
    );
    drop(outcome);
    assert_eq!(inspect(a.admin.as_ref()), a_before, "authority A changed");
    assert_eq!(inspect(b.writer.as_ref()), b_before, "authority B changed");
    assert_eq!(
        entries(root_b.path()),
        b_entries,
        "B's root gained a binding or namespace, or lost its data"
    );
    assert_eq!(read(root_b.path(), b.writer.clone()), b"volume B data");

    // A's own root still resumes.
    RollbackBacking::recover_enrollment_remote(root_a.path(), a.admin.clone(), CAPACITY, &a_before)
        .unwrap();
}

#[test]
fn recovery_refuses_another_volumes_namespace_beside_its_own_binding() {
    let b = Authority::new([2; 16]);
    let root_b = tempfile::tempdir().unwrap();
    b.activated(root_b.path(), b"volume B data");
    let b_namespace = inspect(b.writer.as_ref()).current.unwrap().namespace;

    let a = Authority::new([1; 16]);
    let root_a = tempfile::tempdir().unwrap();
    let a_before = a.interrupted(root_a.path());
    // A copy of B's namespace in A's root is no namespace A's never-activated
    // authority could have written, even though A's binding is present.
    copy_dir(
        &root_b.path().join(&b_namespace),
        &root_a.path().join(&b_namespace),
    );
    let a_entries = entries(root_a.path());
    assert!(RollbackBacking::recover_enrollment_remote(
        root_a.path(),
        a.admin.clone(),
        CAPACITY,
        &a_before
    )
    .is_err());
    assert_eq!(inspect(a.admin.as_ref()), a_before);
    assert_eq!(entries(root_a.path()), a_entries);
}

#[test]
fn recovery_refuses_a_retired_namespace_tombstone() {
    let a = Authority::new([1; 16]);
    let root = tempfile::tempdir().unwrap();
    let (before, candidate) = a.abandoned(root.path());
    // GC runs only after an activation, so a never-activated authority's
    // root never holds a tombstone; one proves another authority used it.
    std::fs::rename(
        root.path().join(&candidate),
        root.path().join(format!(".remote-gc-{candidate}")),
    )
    .unwrap();
    std::fs::remove_file(root.path().join("remote.enrollment")).unwrap();
    let before_entries = entries(root.path());
    assert!(RollbackBacking::recover_enrollment_remote(
        root.path(),
        a.admin.clone(),
        CAPACITY,
        &before
    )
    .is_err());
    assert_eq!(inspect(a.admin.as_ref()), before);
    assert_eq!(entries(root.path()), before_entries);
}

#[test]
fn own_abandoned_candidates_resume_and_are_retired_after_activation() {
    for torn in [false, true] {
        let a = Authority::new([1; 16]);
        let root = tempfile::tempdir().unwrap();
        let (first, abandoned) = a.abandoned(root.path());
        // A second recovery attempt that also never activated leaves a
        // lower-fence candidate the current claim no longer names.
        a.admin.drop_activate.store(true, Ordering::SeqCst);
        assert!(RollbackBacking::recover_enrollment_remote(
            root.path(),
            a.admin.clone(),
            CAPACITY,
            &first
        )
        .is_err());
        a.admin.drop_activate.store(false, Ordering::SeqCst);
        let second = inspect(a.admin.as_ref());
        assert_eq!(second.fence, first.fence + 1);
        assert!(second.current.is_none());
        let pending = namespace(second.fence, second.session);
        assert_eq!(
            namespaces(root.path()),
            [abandoned.clone(), pending.clone()]
        );
        let manifest = root.path().join(&abandoned).join("rollback.manifest.0");
        if torn {
            // A crash during that write can persist any subset of the
            // manifest's bytes; the rest still read as reserved zeroes.
            let mut bytes = std::fs::read(&manifest).unwrap();
            for byte in bytes.iter_mut().skip(3).step_by(5).take(40) {
                *byte = 0;
            }
            std::fs::write(&manifest, bytes).unwrap();
        }
        // Binaries older than the binding left marker-only roots.
        std::fs::remove_file(root.path().join("remote.enrollment")).unwrap();

        let resumed = RollbackBacking::recover_enrollment_remote(
            root.path(),
            a.admin.clone(),
            CAPACITY,
            &second,
        )
        .unwrap();
        let after = inspect(a.admin.as_ref());
        assert_eq!(after.fence, second.fence + 1);
        assert!(root.path().join("remote.enrollment").is_file());
        assert_eq!(
            namespaces(root.path()),
            [after.current.as_ref().unwrap().namespace.clone()],
            "automatic GC keeps only the activated namespace (torn: {torn})"
        );
        assert!(resumed.list("").unwrap().is_empty());
    }
}
