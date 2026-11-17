//! A remote rollback root is a plain directory: anyone who can write it can
//! add an entry whose name is not UTF-8. Maki never creates such a name (a
//! namespace, a tombstone and every root file it writes are ASCII), so GC
//! must treat it like any other unknown entry: keep it, report it under
//! `skipped_unrecognized` and go on scanning. Failing the whole scan on it
//! stopped every later pass, and the automatic pass after each activation
//! swallows that error, so retired namespaces (each a full arena) piled up.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::remote_gc::OperationGuard;
use maki_backing::remote_witness::{
    namespace, Action, Descriptor, Phase, Record, Request, Role, Rpc, StateStore,
};
use maki_backing::witness::Anchor;
use maki_backing::{Backing, FileBacking, MemBacking, RollbackBacking};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct EmptyManifest {
    format: u32,
    identity: [u8; 16],
    generation: u64,
    capacity: u64,
    next_id: u64,
    entries: BTreeMap<String, String>,
    files: BTreeMap<u64, String>,
}

struct Inspector(Record);

impl Rpc for Inspector {
    fn call(&self, request: &Request) -> io::Result<Record> {
        assert_eq!(request.action, Action::Inspect);
        assert!(request.expected.is_none());
        Ok(self.0.clone())
    }
}

fn session(fence: u64) -> [u8; 16] {
    let mut bytes = [1; 16];
    bytes[..8].copy_from_slice(&fence.to_le_bytes());
    bytes
}

/// A remote root whose authority's current namespace (fence 5000) holds an
/// exact empty generation.
fn fixture() -> (tempfile::TempDir, FileBacking, Inspector) {
    let root = tempfile::tempdir().unwrap();
    let disk = FileBacking::new(root.path()).unwrap();
    let marker = disk.open("rollback.format", true).unwrap();
    marker.write_at(0, b"MAKI-REMOTE-WITNESS-COW-V2\n").unwrap();
    marker.sync_data().unwrap();
    let fence = 5000;
    let name = namespace(fence, session(fence));
    disk.create_dir_all(&name).unwrap();
    let bytes = serde_json::to_vec(&EmptyManifest {
        format: 1,
        identity: [1; 16],
        generation: 7,
        capacity: 4096,
        next_id: 1,
        entries: BTreeMap::new(),
        files: BTreeMap::new(),
    })
    .unwrap();
    let mut hash = Sha256::new();
    hash.update(b"maki.rollback.manifest.v1\0");
    hash.update(&bytes);
    for file in [
        "rollback.arena",
        "rollback.manifest.0",
        "rollback.manifest.1",
        "rollback.lock",
    ] {
        let data = disk.open(&format!("{name}/{file}"), true).unwrap();
        if file == "rollback.arena" {
            data.set_len(8192).unwrap();
        } else if file.starts_with("rollback.manifest.") {
            data.set_len((8 << 20) + 256).unwrap();
            data.write_at(0, &(bytes.len() as u64).to_le_bytes())
                .unwrap();
            data.write_at(8, &bytes).unwrap();
        }
        data.sync_data().unwrap();
    }
    disk.sync_dir(&name).unwrap();
    disk.sync_dir("").unwrap();
    let record = Record {
        identity: [1; 16],
        current: Some(Descriptor {
            anchor: Anchor {
                identity: [1; 16],
                generation: 7,
                root: hash.finalize().into(),
            },
            epoch: 0,
            namespace: name,
        }),
        fence,
        session: session(fence),
        phase: Phase::Active,
        restore_source: None,
        last_operation: [7; 16],
    };
    record.validate().unwrap();
    (root, disk, Inspector(record))
}

/// A quiescent lower-fence fork: GC retires it.
fn abandoned_fork(disk: &FileBacking, fence: u64) -> String {
    let name = namespace(fence, session(fence));
    disk.create_dir_all(&name).unwrap();
    drop(disk.open(&format!("{name}/rollback.lock"), true).unwrap());
    name
}

fn lossy(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn root_names(root: &Path) -> Vec<OsString> {
    let mut names: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    names
}

fn namespaces(root: &Path) -> Vec<String> {
    root_names(root)
        .into_iter()
        .filter(|name| name.as_bytes().starts_with(b"remote-"))
        .map(|name| name.into_string().unwrap())
        .collect()
}

#[test]
fn non_utf8_root_entries_are_reported_and_kept_while_gc_reclaims() {
    let (root, disk, authority) = fixture();
    let old = abandoned_fork(&disk, 1);
    let directory = b"stray-\xff".as_slice();
    let file = b"\xc3(note".as_slice();
    std::fs::create_dir(root.path().join(OsStr::from_bytes(directory))).unwrap();
    std::fs::write(root.path().join(OsStr::from_bytes(file)), b"operator").unwrap();

    let guard = OperationGuard::acquire(&disk).unwrap();
    let report = guard.collect(&authority).unwrap();
    assert_eq!(report.removed, std::slice::from_ref(&old));
    assert_eq!(report.counts.removed, 1);
    assert!(!disk.exists(&old).unwrap());
    let mut unrecognized = report.skipped_unrecognized.clone();
    unrecognized.sort();
    let mut expected = vec![lossy(directory), lossy(file)];
    expected.sort();
    assert_eq!(unrecognized, expected);
    assert_eq!(report.counts.skipped_unrecognized, 2);
    assert!(!report.details_truncated);
    // Never deleted, and a later pass reports them again.
    assert!(root.path().join(OsStr::from_bytes(directory)).is_dir());
    assert_eq!(
        std::fs::read(root.path().join(OsStr::from_bytes(file))).unwrap(),
        b"operator"
    );
    let again = guard.collect(&authority).unwrap();
    assert_eq!(again.counts.removed, 0);
    assert_eq!(again.counts.skipped_unrecognized, 2);
}

#[test]
fn non_utf8_names_across_pages_are_each_counted_once() {
    let (root, disk, authority) = fixture();
    // 4,100 such names sort before every namespace and fill the first page.
    for index in 0..4100 {
        let mut name = b"foreign-\xff-".to_vec();
        name.extend_from_slice(format!("{index:04}").as_bytes());
        std::fs::write(root.path().join(OsString::from_vec(name)), b"").unwrap();
    }
    let old = abandoned_fork(&disk, 1);
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&authority)
        .unwrap();
    assert_eq!(report.removed, std::slice::from_ref(&old));
    assert!(!disk.exists(&old).unwrap());
    assert_eq!(report.counts.skipped_unrecognized, 4100);
    assert_eq!(report.skipped_unrecognized.len(), 4096);
    assert_eq!(
        report.skipped_unrecognized.first().unwrap(),
        &lossy(b"foreign-\xff-0000")
    );
    assert_eq!(
        report.skipped_unrecognized.last().unwrap(),
        &lossy(b"foreign-\xff-4095")
    );
    assert!(report.details_truncated);
    assert_eq!(root_names(root.path()).len(), 4103);
}

/// Retirement must show that a namespace holds only its known files. One it
/// cannot even name keeps the namespace (the scan inside a namespace fails
/// closed); this passes before and after root entries became tolerated.
#[test]
fn control_a_non_utf8_entry_inside_a_retired_namespace_keeps_it() {
    let (root, disk, authority) = fixture();
    let old = abandoned_fork(&disk, 1);
    disk.open(&format!("{old}/rollback.arena"), true).unwrap();
    std::fs::write(
        root.path().join(&old).join(OsStr::from_bytes(b"\xffnote")),
        b"",
    )
    .unwrap();
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&authority)
        .unwrap();
    assert!(report.removed.is_empty());
    assert_eq!(report.skipped_unrecognized, std::slice::from_ref(&old));
    assert!(disk.exists(&format!("{old}/rollback.arena")).unwrap());
    assert!(disk.exists(&format!("{old}/rollback.lock")).unwrap());
}

const CAPACITY: u64 = 32 * 4096;

struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
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
        self.store.lock().unwrap().handle(self.role, request)
    }
}

fn authority() -> (Arc<LocalRpc>, Arc<LocalRpc>) {
    let store = Arc::new(Mutex::new(
        StateStore::create_backing(Arc::new(MemBacking::new()), [1; 16]).unwrap(),
    ));
    let make = |role| {
        Arc::new(LocalRpc {
            store: store.clone(),
            role,
            drop_activate: AtomicBool::new(false),
        })
    };
    (make(Role::Writer), make(Role::Admin))
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

#[test]
fn activation_retires_its_predecessor_past_a_non_utf8_root_entry() {
    let (writer, _) = authority();
    let root = tempfile::tempdir().unwrap();
    let first = RollbackBacking::create_remote(root.path(), writer.clone(), CAPACITY).unwrap();
    let file = first.open("payload", true).unwrap();
    file.write_at(0, b"kept").unwrap();
    file.sync_data().unwrap();
    first.sync_dir("").unwrap();
    drop((file, first));
    let stray = root.path().join(OsStr::from_bytes(b"lost-\xfe"));
    std::fs::create_dir(&stray).unwrap();

    for _ in 0..3 {
        let backing = RollbackBacking::open_remote(root.path(), writer.clone()).unwrap();
        let current = inspect(writer.as_ref()).current.unwrap().namespace;
        // The automatic pass retired every predecessor arena.
        assert_eq!(namespaces(root.path()), [current]);
        let mut bytes = [0; 4];
        backing
            .open("payload", false)
            .unwrap()
            .read_at(0, &mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"kept");
    }
    assert!(stray.is_dir());
}

#[test]
fn enrollment_recovery_keeps_a_non_utf8_root_entry() {
    let (writer, admin) = authority();
    let root = tempfile::tempdir().unwrap();
    writer.drop_activate.store(true, Ordering::SeqCst);
    assert!(RollbackBacking::create_remote(root.path(), writer.clone(), CAPACITY).is_err());
    let expected = inspect(admin.as_ref());
    assert_eq!(expected.phase, Phase::Claimed);
    assert!(expected.current.is_none());
    let abandoned = namespace(expected.fence, expected.session);
    assert_eq!(namespaces(root.path()), std::slice::from_ref(&abandoned));
    // A name Maki cannot have written is not remote state of any volume.
    // It sorts before the namespaces, so the GC pass must step past it.
    let stray = root.path().join(OsStr::from_bytes(b"lost-\x80"));
    std::fs::write(&stray, b"operator").unwrap();

    let resumed =
        RollbackBacking::recover_enrollment_remote(root.path(), admin.clone(), CAPACITY, &expected)
            .unwrap();
    let after = inspect(admin.as_ref());
    assert_eq!(after.fence, expected.fence + 1);
    assert_eq!(
        namespaces(root.path()),
        [after.current.unwrap().namespace],
        "automatic GC retires the examined candidate"
    );
    assert!(resumed.list("").unwrap().is_empty());
    assert_eq!(std::fs::read(&stray).unwrap(), b"operator");
}
