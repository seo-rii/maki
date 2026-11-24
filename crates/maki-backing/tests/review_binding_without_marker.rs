//! A remote `volume create` publishes its format marker and then its
//! binding, and asks the authority for a claim only once both are durable.
//! Enrollment recovery, which continues a root whose marker is readable,
//! wrote the binding without first making the marker's *name* durable: after
//! a creation whose directory sync had failed, a power loss during recovery
//! could keep the binding, staged (`remote.enrollment.next`) or published
//! (`remote.enrollment`), and lose the marker. Such a root published nothing
//! a creation may not write again and claimed nothing, and both documented
//! commands refused it: `volume create` because it was not empty,
//! `volume resume-enrollment` because it had no marker.
//!
//! `volume create` continues it, as it continues every root without a
//! marker. The staged binding is never read. A published binding is accepted
//! only when it is the one this creation would write, for the identity of an
//! authority that never activated and the capacity asked for; any other is
//! refused and left as it is, and so is the root under an authority that was
//! claimed or activated.
#![cfg(target_os = "linux")]

#[path = "support/private_dir.rs"]
mod private_dir;

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{
    namespace, Action, CanonicalState, Phase, Record, Request, Role, Rpc, SessionAuthorization,
};
use maki_backing::RollbackBacking;

const CAPACITY: u64 = 16 * 4096;
const IDENTITY: [u8; 16] = [0x5a; 16];
const MARKER: &[u8] = b"MAKI-REMOTE-WITNESS-COW-V2\n";
const STAGED_MARKER: &str = "rollback.format.next";
const BINDING: &str = "remote.enrollment";
const STAGED_BINDING: &str = "remote.enrollment.next";

const NOT_EMPTY: &str = "remote enrollment requires an empty backing";
const OCCUPIED: &str = "remote witness already enrolled or occupied";
const CREATE_AGAIN: &str = "create the volume again";
const ANOTHER_CREATION: &str = "binding of an interrupted creation for another authority";

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
fn authority_of(identity: [u8; 16]) -> (Arc<dyn Rpc>, Arc<dyn Rpc>) {
    let authority = Arc::new(Authority(Mutex::new(
        CanonicalState::initial(identity).unwrap(),
    )));
    (
        Arc::new(RoleRpc(authority.clone(), Role::Writer)),
        Arc::new(RoleRpc(authority, Role::Admin)),
    )
}

fn authority() -> (Arc<dyn Rpc>, Arc<dyn Rpc>) {
    authority_of(IDENTITY)
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

/// Every entry of the root with its bytes; a directory has none.
fn contents(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = entry
                .file_type()
                .unwrap()
                .is_file()
                .then(|| std::fs::read(entry.path()).unwrap());
            (entry.file_name().into_string().unwrap(), bytes)
        })
        .collect()
}

/// The bytes a creation writes as its binding for `identity` and `capacity`,
/// from a creation that completed in a root of its own.
fn binding_of(identity: [u8; 16], capacity: u64) -> Vec<u8> {
    let dir = private_dir::tempdir().unwrap();
    let root = dir.path().join("reference");
    let (writer, _) = authority_of(identity);
    drop(RollbackBacking::create_remote(&root, writer, capacity).unwrap());
    assert_eq!(std::fs::read(root.join("rollback.format")).unwrap(), MARKER);
    std::fs::read(root.join(BINDING)).unwrap()
}

fn binding() -> Vec<u8> {
    binding_of(IDENTITY, CAPACITY)
}

/// A root as a creation leaves it once it holds both root locks, with the
/// given files beside them.
fn root_with(dir: &Path, files: &[(&str, &[u8])]) -> PathBuf {
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    for lock in ["remote.enroll.lock", "remote.operation.lock"] {
        std::fs::write(root.join(lock), b"").unwrap();
    }
    for (name, bytes) in files {
        std::fs::write(root.join(name), bytes).unwrap();
    }
    root
}

/// The root holds this identity's durable enrollment and nothing staged,
/// and the authority activated it.
fn assert_enrolled(root: &Path, admin: &dyn Rpc, context: &str) {
    let found = contents(root);
    assert_eq!(
        found["rollback.format"].as_deref(),
        Some(MARKER),
        "{context}"
    );
    assert_eq!(found[BINDING].as_deref(), Some(&binding()[..]), "{context}");
    assert!(
        !found.contains_key(STAGED_MARKER) && !found.contains_key(STAGED_BINDING),
        "{context}: {:?}",
        found.keys()
    );
    let record = inspect(admin);
    assert_eq!(record.identity, IDENTITY, "{context}");
    assert!(record.current.is_some(), "{context}: {record:?}");
}

/// Enrollment recovery, approved for the authority as it is now, refuses
/// the root with `message` and changes neither the root nor the authority.
fn assert_recovery_refuses(root: &Path, admin: &Arc<dyn Rpc>, message: &str, context: &str) {
    let before = contents(root);
    let record = inspect(admin.as_ref());
    let error = RollbackBacking::recover_enrollment_remote(root, admin.clone(), CAPACITY, &record)
        .err()
        .unwrap_or_else(|| panic!("{context}: enrollment recovery continued the root"));
    assert!(
        error.to_string().contains(message),
        "{context}: volume resume-enrollment: {error}"
    );
    assert_eq!(contents(root), before, "{context}");
    assert_eq!(inspect(admin.as_ref()), record, "{context}");
}

/// `volume create` refuses the root with `message` and changes neither the
/// root nor the authority.
fn assert_create_refuses(
    root: &Path,
    writer: &Arc<dyn Rpc>,
    admin: &Arc<dyn Rpc>,
    message: &str,
    context: &str,
) {
    let before = contents(root);
    let record = inspect(admin.as_ref());
    let error = RollbackBacking::create_remote(root, writer.clone(), CAPACITY)
        .err()
        .unwrap_or_else(|| panic!("{context}: volume create continued the root"));
    assert!(
        error.to_string().contains(message),
        "{context}: volume create: {error}"
    );
    assert_eq!(contents(root), before, "{context}");
    assert_eq!(inspect(admin.as_ref()), record, "{context}");
}

/// Files of a root, by name.
type Files<'a> = Vec<(&'a str, &'a [u8])>;

/// What a power loss can leave of the marker when it loses its rename.
fn markers() -> [(&'static str, Files<'static>); 3] {
    [
        ("the staged marker", vec![(STAGED_MARKER, MARKER)]),
        ("no marker", vec![]),
        ("an unwritten marker", vec![("rollback.format", b"")]),
    ]
}

#[test]
fn create_continues_a_staged_binding_left_without_a_marker() {
    let complete = binding();
    let staged: [(&str, &[u8]); 3] = [
        ("complete", &complete),
        ("empty", b""),
        ("torn", &complete[..20]),
    ];
    for (marker, files) in markers() {
        for (what, bytes) in staged {
            let context = format!("a staged binding ({what}) beside {marker}");
            let plant = || {
                let dir = private_dir::tempdir().unwrap();
                let mut files = files.clone();
                files.push((STAGED_BINDING, bytes));
                let root = root_with(dir.path(), &files);
                (dir, root)
            };
            // Enrollment recovery has no marker to continue from, and says
            // which command does.
            let (_dir, root) = plant();
            let (_, admin) = authority();
            assert_recovery_refuses(&root, &admin, CREATE_AGAIN, &context);

            let (_dir, root) = plant();
            let (writer, admin) = authority();
            RollbackBacking::create_remote(&root, writer, CAPACITY)
                .map(drop)
                .unwrap_or_else(|error| panic!("{context}: volume create: {error}"));
            assert_enrolled(&root, admin.as_ref(), &context);
        }
    }
}

#[test]
fn create_continues_its_own_binding_published_without_a_marker() {
    let complete = binding();
    for (marker, files) in markers() {
        let context = format!("this creation's binding beside {marker}");
        let plant = || {
            let dir = private_dir::tempdir().unwrap();
            let mut files = files.clone();
            files.push((BINDING, &complete));
            let root = root_with(dir.path(), &files);
            (dir, root)
        };
        let (_dir, root) = plant();
        let (_, admin) = authority();
        assert_recovery_refuses(&root, &admin, CREATE_AGAIN, &context);

        let (_dir, root) = plant();
        let (writer, admin) = authority();
        RollbackBacking::create_remote(&root, writer, CAPACITY)
            .map(drop)
            .unwrap_or_else(|error| panic!("{context}: volume create: {error}"));
        assert_enrolled(&root, admin.as_ref(), &context);
    }
}

/// Nothing reads the staged binding, whoever wrote it: the binding that is
/// published is the one for the authority's identity and the capacity asked
/// for, through creation and through enrollment recovery alike.
#[test]
fn a_planted_staged_binding_is_never_read() {
    let foreign = binding_of([0xa7; 16], 64 * 4096);
    assert_ne!(foreign, binding());
    let large = vec![0xff; 1 << 20];
    let planted: [(&str, &[u8]); 3] = [
        ("another volume's binding", &foreign),
        ("64 bytes of noise", &[0x3c; 64]),
        ("a megabyte", &large),
    ];
    for (what, bytes) in planted {
        let dir = private_dir::tempdir().unwrap();
        let root = root_with(
            dir.path(),
            &[(STAGED_MARKER, MARKER), (STAGED_BINDING, bytes)],
        );
        let (writer, admin) = authority();
        RollbackBacking::create_remote(&root, writer, CAPACITY)
            .map(drop)
            .unwrap_or_else(|error| panic!("{what}: volume create: {error}"));
        assert_enrolled(&root, admin.as_ref(), what);

        let dir = private_dir::tempdir().unwrap();
        let root = root_with(
            dir.path(),
            &[("rollback.format", MARKER), (STAGED_BINDING, bytes)],
        );
        let (_, admin) = authority();
        let record = inspect(admin.as_ref());
        RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record)
            .map(drop)
            .unwrap_or_else(|error| panic!("{what}: volume resume-enrollment: {error}"));
        assert_enrolled(&root, admin.as_ref(), what);
    }
}

/// A staged binding that is a link is not written through.
#[test]
fn a_staged_binding_that_is_a_link_leaves_its_target_alone() {
    let dir = private_dir::tempdir().unwrap();
    let outside = dir.path().join("outside");
    std::fs::write(&outside, b"not a binding").unwrap();
    let root = root_with(dir.path(), &[(STAGED_MARKER, MARKER)]);
    std::os::unix::fs::symlink(&outside, root.join(STAGED_BINDING)).unwrap();
    let (writer, admin) = authority();
    match RollbackBacking::create_remote(&root, writer, CAPACITY) {
        Ok(_) => assert_enrolled(&root, admin.as_ref(), "a linked staged binding"),
        Err(_) => assert!(inspect(admin.as_ref()).current.is_none()),
    }
    assert_eq!(std::fs::read(&outside).unwrap(), b"not a binding");
}

/// A binding for another authority or another capacity is not this
/// creation's: both commands refuse it, say what continues it, and leave the
/// root and the authority as they are.
#[test]
fn control_a_binding_for_another_authority_or_capacity_is_refused_and_left() {
    let others = [
        ("another authority", binding_of([0xa7; 16], CAPACITY)),
        ("another capacity", binding_of(IDENTITY, 64 * 4096)),
    ];
    for (marker, files) in markers() {
        for (what, other) in &others {
            let context = format!("a binding for {what} beside {marker}");
            let dir = private_dir::tempdir().unwrap();
            let mut files = files.clone();
            files.push((BINDING, other));
            let root = root_with(dir.path(), &files);
            let (writer, admin) = authority();
            assert_create_refuses(&root, &writer, &admin, ANOTHER_CREATION, &context);
            assert_recovery_refuses(&root, &admin, ANOTHER_CREATION, &context);
            assert_eq!(inspect(admin.as_ref()).phase, Phase::Released);
        }
    }
}

/// A binding that cannot be read cannot be told from a damaged one. It is
/// never written over, and recovery does not send the root to creation.
#[test]
fn control_an_unreadable_binding_without_a_marker_is_refused_and_left() {
    let complete = binding();
    let mut changed = complete.clone();
    changed[40] ^= 1;
    let mut longer = complete.clone();
    longer.push(0);
    let unreadable: [(&str, &[u8]); 4] = [
        ("empty", b""),
        ("torn", &complete[..32]),
        ("changed", &changed),
        ("longer", &longer),
    ];
    for (what, bytes) in unreadable {
        let context = format!("a binding that is {what}");
        let dir = private_dir::tempdir().unwrap();
        let root = root_with(dir.path(), &[(STAGED_MARKER, MARKER), (BINDING, bytes)]);
        let (writer, admin) = authority();
        assert_create_refuses(&root, &writer, &admin, NOT_EMPTY, &context);
        let before = contents(&root);
        let record = inspect(admin.as_ref());
        let error =
            RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record)
                .err()
                .unwrap();
        assert!(
            !error.to_string().contains(CREATE_AGAIN),
            "{context}: {error}"
        );
        assert_eq!(contents(&root), before, "{context}");
        assert_eq!(inspect(admin.as_ref()), record, "{context}");
    }
}

/// Nor is anything else under the binding's name read as one.
#[test]
fn control_a_directory_under_the_binding_s_name_is_refused_and_left() {
    let dir = private_dir::tempdir().unwrap();
    let root = root_with(dir.path(), &[(STAGED_MARKER, MARKER)]);
    std::fs::create_dir(root.join(BINDING)).unwrap();
    let (writer, admin) = authority();
    assert_create_refuses(&root, &writer, &admin, NOT_EMPTY, "a directory");
    let before = contents(&root);
    let record = inspect(admin.as_ref());
    let error = RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record)
        .err()
        .unwrap();
    assert!(!error.to_string().contains(CREATE_AGAIN), "{error}");
    assert_eq!(contents(&root), before);
}

/// The binding names an authority, and says nothing about what that
/// authority has done since. Under one that was activated, by a creation
/// that completed elsewhere, or claimed, neither command continues a root
/// without a marker, even with the very binding that authority's creation
/// writes.
#[test]
fn control_no_root_without_a_marker_is_continued_once_the_authority_was_claimed_or_activated() {
    let complete = binding();
    let left: [(&str, Files<'_>); 3] = [
        (
            "a staged binding",
            vec![(STAGED_MARKER, MARKER), (STAGED_BINDING, &complete)],
        ),
        (
            "its binding beside the staged marker",
            vec![(STAGED_MARKER, MARKER), (BINDING, &complete)],
        ),
        ("its binding alone", vec![(BINDING, &complete)]),
    ];
    for (what, files) in &left {
        // Activated.
        let dir = private_dir::tempdir().unwrap();
        let root = root_with(dir.path(), files);
        let (writer, admin) = authority();
        drop(
            RollbackBacking::create_remote(&dir.path().join("elsewhere"), writer.clone(), CAPACITY)
                .unwrap(),
        );
        assert!(inspect(admin.as_ref()).current.is_some());
        let context = format!("{what}, activated authority");
        assert_create_refuses(&root, &writer, &admin, OCCUPIED, &context);
        assert_recovery_refuses(
            &root,
            &admin,
            "cannot recover enrollment after its first activation",
            &context,
        );

        // Claimed and never activated.
        let dir = private_dir::tempdir().unwrap();
        let root = root_with(dir.path(), files);
        let (writer, admin) = authority();
        let claimed = writer
            .call(&Request {
                operation_id: [1; 16],
                expected: Some(inspect(admin.as_ref())),
                action: Action::Claim,
                authorization: Some(SessionAuthorization::from_bytes([9; 32])),
            })
            .unwrap();
        assert_eq!(claimed.phase, Phase::Claimed);
        let context = format!("{what}, claimed authority");
        assert_create_refuses(&root, &writer, &admin, OCCUPIED, &context);
        let before = contents(&root);
        let error =
            RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &claimed)
                .err()
                .unwrap_or_else(|| panic!("{context}: enrollment recovery continued the root"));
        assert!(
            !error.to_string().contains(CREATE_AGAIN),
            "{context}: {error}"
        );
        assert_eq!(contents(&root), before, "{context}");
        assert_eq!(inspect(admin.as_ref()), claimed, "{context}");
    }
}

/// Only a root that holds nothing else is an interrupted creation: beside a
/// namespace, a tombstone or any other entry, the binding changes nothing.
#[test]
fn control_a_binding_beside_anything_else_is_not_an_interrupted_creation() {
    let complete = binding();
    let mut session = [0; 16];
    session[15] = 1;
    let stale = namespace(1, session);
    type Plant = Box<dyn Fn(&Path)>;
    let beside: [(&str, Plant); 3] = [
        (
            "a namespace",
            Box::new({
                let stale = stale.clone();
                move |root| std::fs::create_dir(root.join(&stale)).unwrap()
            }),
        ),
        (
            "a tombstone",
            Box::new(move |root| {
                std::fs::create_dir(root.join(format!(".remote-gc-{stale}"))).unwrap()
            }),
        ),
        (
            "another file",
            Box::new(|root| std::fs::write(root.join("notes"), b"operator").unwrap()),
        ),
    ];
    for name in [BINDING, STAGED_BINDING] {
        for (what, plant) in &beside {
            let context = format!("{name} beside {what}");
            let dir = private_dir::tempdir().unwrap();
            let root = root_with(dir.path(), &[(STAGED_MARKER, MARKER), (name, &complete)]);
            plant(&root);
            let (writer, admin) = authority();
            assert_create_refuses(&root, &writer, &admin, NOT_EMPTY, &context);
            let before = contents(&root);
            let record = inspect(admin.as_ref());
            let error =
                RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record)
                    .err()
                    .unwrap();
            assert!(
                !error.to_string().contains(CREATE_AGAIN),
                "{context}: {error}"
            );
            assert_eq!(contents(&root), before, "{context}");
        }
    }
}

/// A snapshot has no binding of its own: its destination stays as strict as
/// it was.
#[test]
fn control_a_snapshot_destination_that_holds_a_binding_is_refused() {
    let complete = binding();
    for name in [BINDING, STAGED_BINDING] {
        let dir = private_dir::tempdir().unwrap();
        let root = root_with(dir.path(), &[(STAGED_MARKER, MARKER), (name, &complete)]);
        let before = contents(&root);
        let error = RollbackBacking::check_snapshot_destination(&root)
            .err()
            .unwrap_or_else(|| panic!("a snapshot destination holding {name} was accepted"));
        assert_eq!(error.to_string(), NOT_EMPTY);
        assert_eq!(contents(&root), before);
    }
}
