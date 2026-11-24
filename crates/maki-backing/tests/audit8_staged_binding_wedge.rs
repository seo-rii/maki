//! Audit round 8 (long-seeds), finding F1, public-API half.
//!
//! The crash-model chain sweep (shadow copy of
//! `src/rollback/remote_creation_tests.rs`, seed 160709) reaches a backing
//! root that holds a staged binding (`remote.enrollment.next`) but no
//! published format marker: a `volume create` whose marker directory sync
//! failed, then `resume-enrollment` cut by a power loss after it staged the
//! binding, the crash keeping the staged file's name and losing the marker's
//! rename. This file shows, through the public API on a real filesystem,
//! what the documented commands answer for exactly that root: both refuse,
//! although nothing was published or claimed, and
//! docs/rollback-protection.md says of a root without `rollback.format`
//! "Nothing has to be removed by hand".
//!
//! Not part of the maintained suite. The first test FAILS on 956e354.
#![cfg(target_os = "linux")]

#[path = "support/private_dir.rs"]
mod private_dir;

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{
    Action, CanonicalState, Phase, Record, Request, Role, Rpc,
};
use maki_backing::RollbackBacking;

const CAPACITY: u64 = 16 * 4096;
const IDENTITY: [u8; 16] = [0x5a; 16];
const MARKER: &[u8] = b"MAKI-REMOTE-WITNESS-COW-V2\n";

struct Authority(Mutex<CanonicalState>);

struct RoleRpc(Arc<Authority>, Role);

impl Rpc for RoleRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        let mut state = self.0 .0.lock().unwrap();
        let next = state.apply(self.1, request)?;
        *state = next;
        Ok(state.record().clone())
    }
}

/// A never-claimed authority, as its writer and its administrator see it.
fn authority() -> (Arc<dyn Rpc>, Arc<dyn Rpc>) {
    let authority = Arc::new(Authority(Mutex::new(
        CanonicalState::initial(IDENTITY).unwrap(),
    )));
    (
        Arc::new(RoleRpc(authority.clone(), Role::Writer)),
        Arc::new(RoleRpc(authority, Role::Admin)),
    )
}

fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
        operation_id: [0; 16],
        expected: None,
        action: Action::Inspect,
        authorization: None,
    })
    .unwrap()
}

fn entries(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// What an operator can run after an interrupted creation, against the
/// authority that creation never reached (the helper of
/// `review_interrupted_enrollment.rs`): `volume create`, and if that is
/// refused `volume resume-enrollment`. Returns the refusals when neither
/// completes the enrollment.
fn documented_commands(root: &Path) -> Vec<String> {
    let (writer, admin) = authority();
    let mut refusals = Vec::new();
    match RollbackBacking::create_remote(root, writer, CAPACITY) {
        Ok(_) => return Vec::new(),
        Err(error) => refusals.push(format!("volume create: {error}")),
    }
    let record = inspect(admin.as_ref());
    assert!(record.current.is_none() && record.fence == 0);
    match RollbackBacking::recover_enrollment_remote(root, admin.clone(), CAPACITY, &record) {
        Ok(_) => {}
        Err(error) => {
            refusals.push(format!("volume resume-enrollment: {error}"));
            return refusals;
        }
    }
    assert_eq!(inspect(admin.as_ref()).phase, Phase::Released);
    Vec::new()
}

/// The bytes a creation for this identity and capacity writes as its
/// binding, taken from a creation that completed in another root.
fn binding_bytes(dir: &Path) -> Vec<u8> {
    let root = dir.join("reference");
    let (writer, _) = authority();
    drop(RollbackBacking::create_remote(&root, writer, CAPACITY).unwrap());
    assert_eq!(std::fs::read(root.join("rollback.format")).unwrap(), MARKER);
    std::fs::read(root.join("remote.enrollment")).unwrap()
}

/// The root the crash leaves: both locks, the staged marker (its rename was
/// lost) and the staged binding.
fn wedged_root(dir: &Path, binding: &[u8]) -> std::path::PathBuf {
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    for lock in ["remote.enroll.lock", "remote.operation.lock"] {
        std::fs::write(root.join(lock), b"").unwrap();
    }
    std::fs::write(root.join("rollback.format.next"), MARKER).unwrap();
    std::fs::write(root.join("remote.enrollment.next"), binding).unwrap();
    root
}

#[test]
fn audit8_a_staged_binding_without_a_marker_is_continued_by_a_documented_command() {
    for (what, staged) in [("complete", true), ("empty", false)] {
        let dir = private_dir::tempdir().unwrap();
        let binding = if staged {
            binding_bytes(dir.path())
        } else {
            Vec::new()
        };
        let root = wedged_root(dir.path(), &binding);
        let before = entries(&root);
        let refusals = documented_commands(&root);
        println!("AUDIT8 {what} staged binding, root {before:?}: {refusals:?}");
        assert!(
            refusals.is_empty(),
            "a root that published and claimed nothing ({before:?}, {what} staged binding) is \
             refused by both documented commands: {refusals:?}"
        );
    }
}

/// Controls: the same root without the staged binding is continued by
/// `volume create`, and so is the wedged root once the staged binding is
/// removed by hand.
#[test]
fn audit8_control_the_root_continues_once_the_staged_binding_is_removed() {
    let dir = private_dir::tempdir().unwrap();
    let binding = binding_bytes(dir.path());
    let root = wedged_root(dir.path(), &binding);
    assert!(!documented_commands(&root).is_empty());
    std::fs::remove_file(root.join("remote.enrollment.next")).unwrap();
    assert_eq!(documented_commands(&root), Vec::<String>::new());
    assert!(entries(&root).contains(&"rollback.format".to_string()));
}
