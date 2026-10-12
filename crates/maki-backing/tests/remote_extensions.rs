#![cfg(target_os = "linux")]
use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, FileBacking, RollbackBacking};
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
    lose: AtomicU8,
}
impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        let record = self.store.lock().unwrap().handle(self.role, request)?;
        let lost = matches!(
            (&request.action, self.lose.load(Ordering::SeqCst)),
            (Action::Claim, 1) | (Action::Activate { .. }, 2) | (Action::RecoverEnrollment, 3)
        );
        if lost {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "lost durable reply",
            ))
        } else {
            Ok(record)
        }
    }
}
struct Fixture {
    root: tempfile::TempDir,
    _authority: tempfile::TempDir,
    writer: Arc<LocalRpc>,
    admin: Arc<LocalRpc>,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let authority = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            StateStore::create(authority.path(), [1; 16]).unwrap(),
        ));
        let make = |role| {
            Arc::new(LocalRpc {
                store: store.clone(),
                role,
                lose: AtomicU8::new(0),
            })
        };
        Self {
            root,
            _authority: authority,
            writer: make(Role::Writer),
            admin: make(Role::Admin),
        }
    }
    fn create(&self) -> RollbackBacking {
        RollbackBacking::create_remote(self.root.path(), self.writer.clone(), 32 * 4096).unwrap()
    }
    fn interrupted(&self) -> Record {
        self.writer.lose.store(1, Ordering::SeqCst);
        assert!(
            RollbackBacking::create_remote(self.root.path(), self.writer.clone(), 32 * 4096)
                .is_err()
        );
        self.writer.lose.store(0, Ordering::SeqCst);
        inspect(self.writer.as_ref())
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
fn names(f: &Fixture) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(f.root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_owned())
        .filter(|name| name.starts_with("remote-"))
        .collect();
    names.sort();
    names
}

#[test]
fn automatic_gc_on_reopen_keeps_only_current_ciphertext_namespace() {
    let f = Fixture::new();
    let b = f.create();
    let file = b.open("ciphertext", true).unwrap();
    file.write_at(0, b"opaque").unwrap();
    file.sync_data().unwrap();
    b.sync_dir("").unwrap();
    drop(file);
    drop(b);
    let b = RollbackBacking::open_remote(f.root.path(), f.writer.clone()).unwrap();
    assert_eq!(
        names(&f),
        [inspect(f.writer.as_ref()).current.unwrap().namespace]
    );
    let mut bytes = [0; 6];
    b.open("ciphertext", false)
        .unwrap()
        .read_at(0, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"opaque");
}
#[test]
fn live_revoked_namespace_survives_until_its_last_handle_drops() {
    let f = Fixture::new();
    let old = f.create();
    let file = old.open("ciphertext", true).unwrap();
    let before = inspect(f.writer.as_ref());
    let next = RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &before).unwrap();
    assert_eq!(names(&f).len(), 2);
    assert!(old.check_freshness().is_err());
    drop(old);
    assert!(
        RollbackBacking::collect_remote(f.root.path(), f.writer.as_ref())
            .unwrap()
            .removed
            .is_empty()
    );
    drop(file);
    assert_eq!(
        RollbackBacking::collect_remote(f.root.path(), f.writer.as_ref())
            .unwrap()
            .removed
            .len(),
        1
    );
    assert_eq!(names(&f).len(), 1);
    drop(next);
}
#[test]
fn initial_enrollment_binding_is_durable_before_claim() {
    let f = Fixture::new();
    let expected = f.interrupted();
    assert!(expected.current.is_none());
    let bytes = std::fs::read(f.root.path().join("remote.enrollment")).unwrap();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[8..24], &[1; 16]);
    assert_eq!(
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        32 * 4096
    );
}
#[test]
fn interrupted_enrollment_resumes_same_identity_with_new_fence_and_session() {
    let f = Fixture::new();
    let before = f.interrupted();
    let b = RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before,
    )
    .unwrap();
    let after = inspect(f.writer.as_ref());
    assert_eq!(after.identity, before.identity);
    assert_eq!(after.fence, before.fence + 1);
    assert_ne!(after.session, before.session);
    assert_eq!(after.current.as_ref().unwrap().anchor.generation, 0);
    assert!(b.list("").unwrap().is_empty());
    drop(b);
    RollbackBacking::open_remote(f.root.path(), f.writer.clone()).unwrap();
}
#[test]
fn stale_approval_wrong_capacity_and_writer_role_cannot_resume() {
    let f = Fixture::new();
    let before = f.interrupted();
    assert!(RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        64 * 4096,
        &before
    )
    .is_err());
    assert_eq!(inspect(f.writer.as_ref()), before);
    assert!(RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.writer.clone(),
        32 * 4096,
        &before
    )
    .is_err());
    assert_eq!(inspect(f.writer.as_ref()), before);
    let b = RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before,
    )
    .unwrap();
    assert!(RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before
    )
    .is_err());
    assert!(b.check_freshness().is_ok());
}
#[test]
fn lost_activation_result_never_allows_an_empty_reset() {
    let f = Fixture::new();
    f.writer.lose.store(2, Ordering::SeqCst);
    assert!(RollbackBacking::create_remote(f.root.path(), f.writer.clone(), 32 * 4096).is_err());
    f.writer.lose.store(0, Ordering::SeqCst);
    let before = inspect(f.writer.as_ref());
    assert!(before.current.is_some());
    assert!(RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before
    )
    .is_err());
    assert_eq!(inspect(f.writer.as_ref()), before);
    RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &before).unwrap();
}
#[test]
fn legacy_marker_only_interruption_requires_explicit_admin_adoption() {
    let f = Fixture::new();
    std::fs::write(
        f.root.path().join("rollback.format"),
        b"MAKI-REMOTE-WITNESS-COW-V2\n",
    )
    .unwrap();
    let before = inspect(f.writer.as_ref());
    assert!(RollbackBacking::create_remote(f.root.path(), f.writer.clone(), 32 * 4096).is_err());
    let b = RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before,
    )
    .unwrap();
    assert_eq!(inspect(f.writer.as_ref()).identity, [1; 16]);
    assert!(f.root.path().join("remote.enrollment").is_file());
    drop(b);
}
#[test]
fn corrupt_binding_and_wrong_identity_never_change_authority() {
    let f = Fixture::new();
    let before = f.interrupted();
    let path = f.root.path().join("remote.enrollment");
    let original = std::fs::read(&path).unwrap();
    let mut broken = original.clone();
    broken[8] ^= 1;
    std::fs::write(&path, broken).unwrap();
    assert!(RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before
    )
    .is_err());
    assert_eq!(inspect(f.writer.as_ref()), before);
    std::fs::write(path, original).unwrap();
    let mut wrong = before.clone();
    wrong.identity = [2; 16];
    assert!(RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &wrong
    )
    .is_err());
    assert_eq!(inspect(f.writer.as_ref()), before);
}
#[test]
fn active_gc_operation_excludes_reopen_before_claim() {
    let f = Fixture::new();
    drop(f.create());
    let before = inspect(f.writer.as_ref());
    let disk = FileBacking::new(f.root.path()).unwrap();
    let guard = maki_backing::remote_gc::OperationGuard::acquire(&disk).unwrap();
    assert!(RollbackBacking::open_remote(f.root.path(), f.writer.clone()).is_err());
    assert_eq!(inspect(f.writer.as_ref()), before);
    drop(guard);
}

#[test]
fn abandoned_initial_candidate_is_retired_but_a_live_candidate_is_preserved() {
    let f = Fixture::new();
    let before = f.interrupted();
    let name = maki_backing::remote_witness::namespace(before.fence, before.session);
    let disk = FileBacking::new(f.root.path()).unwrap();
    disk.create_dir_all(&name).unwrap();
    for entry in ["rollback.arena", "rollback.manifest.0"] {
        let file = disk.open(&format!("{name}/{entry}"), true).unwrap();
        file.write_at(0, b"unfinished ciphertext").unwrap();
        file.sync_data().unwrap();
    }
    let lock = disk.try_lock(&format!("{name}/rollback.lock")).unwrap();
    disk.sync_dir(&name).unwrap();
    disk.sync_dir("").unwrap();
    let b = RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before,
    )
    .unwrap();
    assert!(disk.exists(&name).unwrap());
    let after = inspect(f.writer.as_ref());
    assert!(f
        .writer
        .call(&Request {
            authorization: None,
            operation_id: [33; 16],
            expected: Some(before),
            action: Action::Activate {
                descriptor: after.current.clone().unwrap()
            }
        })
        .is_err());
    assert_eq!(inspect(f.writer.as_ref()), after);
    drop(lock);
    assert_eq!(
        RollbackBacking::collect_remote(f.root.path(), f.writer.as_ref())
            .unwrap()
            .removed,
        [name]
    );
    assert!(b.check_freshness().is_ok());
}
#[test]
fn lost_recovery_result_requires_fresh_exact_approval_and_retries_same_identity() {
    let f = Fixture::new();
    let before = f.interrupted();
    f.admin.lose.store(3, Ordering::SeqCst);
    assert!(RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before
    )
    .is_err());
    f.admin.lose.store(0, Ordering::SeqCst);
    let claimed = inspect(f.writer.as_ref());
    assert_eq!(claimed.fence, before.fence + 1);
    assert!(claimed.current.is_none());
    assert!(RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before
    )
    .is_err());
    assert_eq!(inspect(f.writer.as_ref()), claimed);
    let b = RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &claimed,
    )
    .unwrap();
    let after = inspect(f.writer.as_ref());
    assert_eq!(after.identity, before.identity);
    assert_eq!(after.fence, claimed.fence + 1);
    assert!(b.check_freshness().is_ok());
}
#[test]
fn operation_guard_excludes_initial_recovery_before_authority_mutation() {
    let f = Fixture::new();
    let before = f.interrupted();
    let disk = FileBacking::new(f.root.path()).unwrap();
    let guard = maki_backing::remote_gc::OperationGuard::acquire(&disk).unwrap();
    assert!(RollbackBacking::recover_enrollment_remote(
        f.root.path(),
        f.admin.clone(),
        32 * 4096,
        &before
    )
    .is_err());
    assert_eq!(inspect(f.writer.as_ref()), before);
    drop(guard);
}
