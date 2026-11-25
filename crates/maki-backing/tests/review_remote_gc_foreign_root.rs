//! `maki volume gc` pointed at a backing root that does not hold the
//! authority's current generation (a root restored to an earlier state, or
//! another volume's root) refuses before it deletes anything. Attach,
//! takeover and snapshot say what was found; GC must say the same, not
//! repeat the bare system error of the namespace it looked for.
#![cfg(target_os = "linux")]

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, MemBacking, RollbackBacking};

const CAPACITY: u64 = 32 * 4096;
const NOT_CURRENT: &str = "this backing root does not hold the remote authority's current \
                           generation";

struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
}

impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.store.lock().unwrap().handle(Role::Writer, request)
    }
}

fn authority() -> Arc<LocalRpc> {
    Arc::new(LocalRpc {
        store: Arc::new(Mutex::new(
            StateStore::create_backing(Arc::new(MemBacking::new()), [1; 16]).unwrap(),
        )),
    })
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

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn names(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// The refusal GC gives for `root`, which must name what it found and
/// leave the root as it was; attach must refuse it in the same words.
fn assert_refused_like_attach(root: &Path, rpc: Arc<LocalRpc>) {
    let before = names(root);
    let record = inspect(rpc.as_ref());
    let error = RollbackBacking::collect_remote(root, rpc.as_ref()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    let message = error.to_string();
    assert!(message.contains(NOT_CURRENT), "{message}");
    assert!(
        message.contains("check the witness address and backing root before retrying"),
        "{message}"
    );
    let attach = RollbackBacking::open_remote(root, rpc.clone())
        .err()
        .expect("attach refuses the same root");
    assert_eq!(message, attach.to_string());
    assert_eq!(names(root), before, "the refused commands changed the root");
    assert_eq!(
        inspect(rpc.as_ref()),
        record,
        "the refusal changed the authority"
    );
}

#[test]
fn gc_on_a_root_without_the_current_namespace_says_what_it_found() {
    let rpc = authority();
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("volume");
    drop(RollbackBacking::create_remote(&root, rpc.clone(), CAPACITY).unwrap());
    // The root as it was after creation, before the next attach moved the
    // authority to a new namespace (and its GC removed this one).
    let restored = base.path().join("restored");
    copy_tree(&root, &restored);
    drop(RollbackBacking::open_remote(&root, rpc.clone()).unwrap());
    let current = inspect(rpc.as_ref()).current.unwrap().namespace;
    assert!(!restored.join(&current).exists());
    // Control: the real root collects.
    RollbackBacking::collect_remote(&root, rpc.as_ref()).unwrap();

    assert_refused_like_attach(&restored, rpc);
}

#[test]
fn gc_on_a_root_whose_current_namespace_is_older_says_what_it_found() {
    let rpc = authority();
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("volume");
    let backing = RollbackBacking::create_remote(&root, rpc.clone(), CAPACITY).unwrap();
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, b"first").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
    // The same namespace, two commits behind: neither manifest slot of the
    // copy holds the generation the authority names.
    let restored = base.path().join("restored");
    copy_tree(&root, &restored);
    for version in [b"second", b"third!"] {
        file.write_at(0, version).unwrap();
        file.sync_data().unwrap();
    }
    drop((file, backing));
    let current = inspect(rpc.as_ref()).current.unwrap().namespace;
    assert!(restored.join(&current).is_dir());

    assert_refused_like_attach(&restored, rpc);
}
