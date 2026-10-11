#![cfg(target_os = "linux")]

use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, FileBacking, RollbackBacking};
use std::io;
use std::sync::{Arc, Mutex};

struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
}
impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.store.lock().unwrap().handle(self.role, request)
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
}
fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
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
