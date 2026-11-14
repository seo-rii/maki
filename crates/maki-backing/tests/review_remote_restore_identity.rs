#![cfg(target_os = "linux")]

use maki_backing::remote_witness::{
    Action, Descriptor, Phase, Record, Request, Role, Rpc, StateStore,
};
use maki_backing::{Backing, MemBacking, RollbackBacking};
use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

struct LocalRpc(Mutex<StateStore>);

impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.0.lock().unwrap().handle(Role::Admin, request)
    }
}

fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
        authorization: None,
    })
    .unwrap()
}

fn entries(root: &Path) -> Vec<OsString> {
    let mut names: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    names
}

fn read(backing: &RollbackBacking) -> Vec<u8> {
    let file = backing.open("payload", false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

struct Fixture {
    root: tempfile::TempDir,
    rpc: Arc<LocalRpc>,
}

impl Fixture {
    fn new(identity: [u8; 16], payload: &[u8]) -> Self {
        Self::with_capacity(identity, payload, 4096)
    }

    fn with_capacity(identity: [u8; 16], payload: &[u8], capacity: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        let rpc = Arc::new(LocalRpc(Mutex::new(
            StateStore::create_backing(Arc::new(MemBacking::new()), identity).unwrap(),
        )));
        let backing = RollbackBacking::create_remote(root.path(), rpc.clone(), capacity).unwrap();
        let file = backing.open("payload", true).unwrap();
        file.write_at(0, payload).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        assert_eq!(read(&backing), payload);
        drop(file);
        drop(backing);
        assert_eq!(inspect(rpc.as_ref()).phase, Phase::Released);
        Self { root, rpc }
    }

    fn snapshot(&self) -> (tempfile::TempDir, Descriptor, Record) {
        let backing = RollbackBacking::open_remote(self.root.path(), self.rpc.clone()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = backing.snapshot_remote(directory.path()).unwrap();
        drop(backing);
        let expected = inspect(self.rpc.as_ref());
        assert_eq!(expected.phase, Phase::Released);
        (directory, source, expected)
    }

    fn damage_current(&self, record: &Record) {
        let namespace = self
            .root
            .path()
            .join(&record.current.as_ref().unwrap().namespace);
        for name in ["rollback.manifest.0", "rollback.manifest.1"] {
            std::fs::write(namespace.join(name), b"damaged current manifest").unwrap();
        }
        assert!(RollbackBacking::open_remote(self.root.path(), self.rpc.clone()).is_err());
        assert_eq!(inspect(self.rpc.as_ref()), *record);
    }
}

#[test]
fn restore_refuses_foreign_target_before_claim_or_gc() {
    let a = Fixture::new([0xA1; 16], b"approved A backup");
    let b = Fixture::new([0xB2; 16], b"unrelated B data");
    let approved_a = inspect(a.rpc.as_ref());
    let original_b = inspect(b.rpc.as_ref());
    assert_ne!(approved_a.identity, original_b.identity);
    let source = approved_a.current.as_ref().unwrap();
    let original_b_namespace = b
        .root
        .path()
        .join(&original_b.current.as_ref().unwrap().namespace);
    let b_entries = entries(b.root.path());
    let b_enrollment = std::fs::read(b.root.path().join("remote.enrollment")).unwrap();

    // The approved source and authority both belong to A. Only the target
    // path is wrong, as when an administrator copies another volume's config.
    let outcome = RollbackBacking::restore_remote(
        b.root.path(),
        a.root.path(),
        source,
        a.rpc.clone(),
        &approved_a,
    );
    assert!(
        outcome.is_err(),
        "restore must refuse a target enrolled to a distinct identity"
    );
    assert_eq!(inspect(a.rpc.as_ref()), approved_a);
    assert_eq!(inspect(b.rpc.as_ref()), original_b);
    assert!(original_b_namespace.exists());
    assert_eq!(entries(b.root.path()), b_entries);
    assert_eq!(
        std::fs::read(b.root.path().join("remote.enrollment")).unwrap(),
        b_enrollment
    );
    let reopened = RollbackBacking::open_remote(b.root.path(), b.rpc.clone()).unwrap();
    assert_eq!(read(&reopened), b"unrelated B data");
}

#[test]
fn wrong_source_identity_is_refused_without_touching_target() {
    let a = Fixture::new([0xA1; 16], b"A source");
    let b = Fixture::new([0xB2; 16], b"B target");
    let a_before = inspect(a.rpc.as_ref());
    let b_before = inspect(b.rpc.as_ref());
    let b_entries = entries(b.root.path());
    let source = a_before.current.as_ref().unwrap();
    assert!(RollbackBacking::restore_remote(
        b.root.path(),
        a.root.path(),
        source,
        b.rpc.clone(),
        &b_before,
    )
    .is_err());
    assert_eq!(inspect(a.rpc.as_ref()), a_before);
    assert_eq!(inspect(b.rpc.as_ref()), b_before);
    assert_eq!(entries(b.root.path()), b_entries);
}

#[test]
fn restore_refuses_snapshot_capacity_that_disagrees_with_target_enrollment() {
    let a = Fixture::with_capacity([0xA1; 16], b"larger snapshot", 8192);
    let b = Fixture::with_capacity([0xA1; 16], b"smaller target", 4096);
    let a_before = inspect(a.rpc.as_ref());
    let b_before = inspect(b.rpc.as_ref());
    let b_entries = entries(b.root.path());
    assert_eq!(a_before.identity, b_before.identity);
    assert!(RollbackBacking::restore_remote(
        b.root.path(),
        a.root.path(),
        a_before.current.as_ref().unwrap(),
        b.rpc.clone(),
        &b_before,
    )
    .is_err());
    assert_eq!(inspect(a.rpc.as_ref()), a_before);
    assert_eq!(inspect(b.rpc.as_ref()), b_before);
    assert_eq!(entries(b.root.path()), b_entries);
    let reopened = RollbackBacking::open_remote(b.root.path(), b.rpc.clone()).unwrap();
    assert_eq!(read(&reopened), b"smaller target");
}

#[test]
fn enrolled_target_can_restore_when_both_current_manifests_are_damaged() {
    let fixture = Fixture::new([0xA1; 16], b"approved snapshot");
    let (backup, source, expected) = fixture.snapshot();
    let enrollment = std::fs::read(fixture.root.path().join("remote.enrollment")).unwrap();
    fixture.damage_current(&expected);
    let restored = RollbackBacking::restore_remote(
        fixture.root.path(),
        backup.path(),
        &source,
        fixture.rpc.clone(),
        &expected,
    )
    .unwrap();
    assert_eq!(read(&restored), b"approved snapshot");
    let after = inspect(fixture.rpc.as_ref());
    let current = after.current.as_ref().unwrap();
    let old = expected.current.as_ref().unwrap();
    assert_eq!(after.identity, expected.identity);
    assert_eq!(after.fence, expected.fence + 1);
    assert_eq!(current.epoch, old.epoch + 1);
    assert_eq!(current.anchor.generation, old.anchor.generation + 1);
    assert_eq!(
        std::fs::read(fixture.root.path().join("remote.enrollment")).unwrap(),
        enrollment
    );
}

#[test]
fn missing_enrollment_uses_intact_exact_current_identity() {
    let fixture = Fixture::new([0xA1; 16], b"legacy snapshot");
    let (backup, source, expected) = fixture.snapshot();
    let enrollment = fixture.root.path().join("remote.enrollment");
    std::fs::remove_file(&enrollment).unwrap();
    let restored = RollbackBacking::restore_remote(
        fixture.root.path(),
        backup.path(),
        &source,
        fixture.rpc.clone(),
        &expected,
    )
    .unwrap();
    assert_eq!(read(&restored), b"legacy snapshot");
    assert_eq!(inspect(fixture.rpc.as_ref()).fence, expected.fence + 1);
    assert!(!enrollment.exists());
}

#[test]
fn missing_enrollment_and_damaged_current_are_refused_before_claim() {
    let fixture = Fixture::new([0xA1; 16], b"approved snapshot");
    let (backup, source, expected) = fixture.snapshot();
    let enrollment = fixture.root.path().join("remote.enrollment");
    std::fs::remove_file(&enrollment).unwrap();
    fixture.damage_current(&expected);
    let before = entries(fixture.root.path());
    assert!(RollbackBacking::restore_remote(
        fixture.root.path(),
        backup.path(),
        &source,
        fixture.rpc.clone(),
        &expected,
    )
    .is_err());
    assert_eq!(inspect(fixture.rpc.as_ref()), expected);
    assert_eq!(entries(fixture.root.path()), before);
    assert!(!enrollment.exists());
}

#[test]
fn corrupt_enrollment_is_refused_even_with_intact_current() {
    let fixture = Fixture::new([0xA1; 16], b"approved snapshot");
    let (backup, source, expected) = fixture.snapshot();
    let enrollment = fixture.root.path().join("remote.enrollment");
    let mut damaged = std::fs::read(&enrollment).unwrap();
    damaged[0] ^= 1;
    std::fs::write(&enrollment, &damaged).unwrap();
    let before = entries(fixture.root.path());
    assert!(RollbackBacking::restore_remote(
        fixture.root.path(),
        backup.path(),
        &source,
        fixture.rpc.clone(),
        &expected,
    )
    .is_err());
    assert_eq!(inspect(fixture.rpc.as_ref()), expected);
    assert_eq!(entries(fixture.root.path()), before);
    assert_eq!(std::fs::read(enrollment).unwrap(), damaged);
}
