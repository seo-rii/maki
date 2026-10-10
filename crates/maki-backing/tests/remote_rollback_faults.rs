//! Format and enrollment-failure boundaries of the remote namespace format.
#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::fs::symlink;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Phase, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, RollbackBacking};
use sha2::{Digest, Sha256};

const CAPACITY: u64 = 32 * 4096;

#[derive(Clone, Copy)]
enum LostReply {
    Claim,
    Activate,
}
struct RoleRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
    lost_reply: Mutex<Option<LostReply>>,
}
impl Rpc for RoleRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        let record = self.store.lock().unwrap().handle(self.role, request)?;
        let lose = matches!(
            (*self.lost_reply.lock().unwrap(), &request.action),
            (Some(LostReply::Claim), Action::Claim)
                | (Some(LostReply::Activate), Action::Activate { .. })
        );
        if lose {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "simulated lost durable response",
            ))
        } else {
            Ok(record)
        }
    }
}
struct Fixture {
    root: tempfile::TempDir,
    _authority: tempfile::TempDir,
    writer: Arc<RoleRpc>,
    admin: Arc<RoleRpc>,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let authority = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            StateStore::create(authority.path(), [1; 16]).unwrap(),
        ));
        let writer = Arc::new(RoleRpc {
            store: store.clone(),
            role: Role::Writer,
            lost_reply: Mutex::new(None),
        });
        let admin = Arc::new(RoleRpc {
            store,
            role: Role::Admin,
            lost_reply: Mutex::new(None),
        });
        Self {
            root,
            _authority: authority,
            writer,
            admin,
        }
    }
    fn create(&self) -> RollbackBacking {
        RollbackBacking::create_remote(self.root.path(), self.writer.clone(), CAPACITY).unwrap()
    }
    fn current(&self) -> Record {
        self.admin
            .call(&Request {
                operation_id: [0; 16],
                expected: None,
                action: Action::Inspect,
            })
            .unwrap()
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn remote_v2_marker_and_initial_manifest_have_fixed_golden_vectors() {
    let f = Fixture::new();
    let b = f.create();
    let marker = std::fs::read(f.root.path().join("rollback.format")).unwrap();
    assert_eq!(marker, b"MAKI-REMOTE-WITNESS-COW-V2\n");
    assert_eq!(
        hex(&Sha256::digest(&marker)),
        "123165c4784ed2c1b683b7ed02459041d486faa8958062cd5204db0019921356"
    );
    let descriptor = f.current().current.unwrap();
    assert_eq!(
        hex(&descriptor.anchor.root),
        "dfac7d8b5d8f94e9160b14e07d270364220d0de003d3e8eb69a7b068faaa3d8c"
    );
    assert_eq!(descriptor.anchor.generation, 0);
    assert_eq!(descriptor.epoch, 0);
    let path = f
        .root
        .path()
        .join(&descriptor.namespace)
        .join("rollback.manifest.0");
    let bytes = std::fs::read(path).unwrap();
    let length = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
    let manifest = std::str::from_utf8(&bytes[8..8 + length]).unwrap();
    assert!(manifest.starts_with("{\"format\":1,\"identity\":[1,1,1,"));
    assert_eq!(b.list("").unwrap(), Vec::<String>::new());
}

#[test]
fn two_lost_claim_replies_leave_unactivated_claim_that_normal_attach_cannot_override() {
    let f = Fixture::new();
    *f.writer.lost_reply.lock().unwrap() = Some(LostReply::Claim);
    assert!(RollbackBacking::create_remote(f.root.path(), f.writer.clone(), CAPACITY).is_err());
    let pending = f.current();
    assert_eq!(pending.phase, Phase::Claimed);
    assert!(pending.current.is_none());
    assert_eq!(pending.fence, 1, "exact retry cannot create a second claim");
    *f.writer.lost_reply.lock().unwrap() = None;
    assert!(RollbackBacking::create_remote(f.root.path(), f.writer.clone(), CAPACITY).is_err());
    assert!(RollbackBacking::open_remote(f.root.path(), f.writer.clone()).is_err());
    assert_eq!(f.current(), pending);
    // Ordinary takeover has no authenticated manifest to clone. Enrollment
    // recovery must be an explicit administrator operation, never a fallback.
    assert!(RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &pending).is_err());
    assert!(f.current().current.is_none());
}

#[test]
fn two_lost_activation_replies_preserve_published_root_for_admin_takeover() {
    let f = Fixture::new();
    *f.writer.lost_reply.lock().unwrap() = Some(LostReply::Activate);
    assert!(RollbackBacking::create_remote(f.root.path(), f.writer.clone(), CAPACITY).is_err());
    let committed = f.current();
    assert_eq!(committed.phase, Phase::Active);
    assert!(committed.current.is_some());
    *f.writer.lost_reply.lock().unwrap() = None;
    let recovered =
        RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &committed).unwrap();
    let current = f.current();
    assert_eq!(
        current.current.as_ref().unwrap().anchor,
        committed.current.as_ref().unwrap().anchor
    );
    assert_ne!(
        current.current.as_ref().unwrap().namespace,
        committed.current.as_ref().unwrap().namespace
    );
    assert!(recovered.list("").unwrap().is_empty());
}

#[test]
fn damaged_or_local_format_marker_is_refused_before_a_remote_claim() {
    for marker in [
        b"MAKI-WITNESS-COW-V1\n".as_slice(),
        b"MAKI-REMOTE-WITNESS-COW-V3\n",
        b"MAKI-REMOTE-WITNESS-COW-V2\nextra",
    ] {
        let f = Fixture::new();
        drop(f.create());
        let before = f.current();
        std::fs::write(f.root.path().join("rollback.format"), marker).unwrap();
        assert!(RollbackBacking::open_remote(f.root.path(), f.writer.clone()).is_err());
        assert_eq!(f.current(), before);
    }
}

#[test]
fn symlinked_marker_and_namespace_cannot_redirect_the_authorized_backing() {
    for entry in ["rollback.format", "namespace"] {
        let f = Fixture::new();
        drop(f.create());
        let before = f.current();
        let outside = tempfile::tempdir().unwrap();
        let name = if entry == "namespace" {
            before.current.as_ref().unwrap().namespace.as_str()
        } else {
            entry
        };
        let original = f.root.path().join(name);
        let moved = outside.path().join("original");
        std::fs::rename(&original, &moved).unwrap();
        symlink(&moved, &original).unwrap();
        let sentinel = outside.path().join("sentinel");
        std::fs::write(&sentinel, b"untouched").unwrap();
        assert!(RollbackBacking::open_remote(f.root.path(), f.writer.clone()).is_err());
        assert_eq!(f.current().current, before.current);
        assert_eq!(std::fs::read(sentinel).unwrap(), b"untouched");
    }
}

#[test]
fn truncated_or_extended_arena_rejects_exact_witness_root_without_rewinding_it() {
    for delta in [-1i64, 1] {
        let f = Fixture::new();
        drop(f.create());
        let before = f.current();
        let path = f
            .root
            .path()
            .join(&before.current.as_ref().unwrap().namespace)
            .join("rollback.arena");
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_len((CAPACITY as i64 * 2 + delta) as u64).unwrap();
        file.sync_all().unwrap();
        assert!(RollbackBacking::open_remote(f.root.path(), f.writer.clone()).is_err());
        let after = f.current();
        assert_eq!(after.current, before.current);
        assert_eq!(after.phase, Phase::Claimed);
    }
}

#[test]
fn both_manifest_lengths_corrupt_fail_closed_even_when_old_generation_exists() {
    use std::os::unix::fs::FileExt;
    let f = Fixture::new();
    let b = f.create();
    let file = b.open("payload", true).unwrap();
    file.write_at(0, b"durable").unwrap();
    file.sync_data().unwrap();
    b.sync_dir("").unwrap();
    drop((file, b));
    let before = f.current();
    let namespace = f
        .root
        .path()
        .join(&before.current.as_ref().unwrap().namespace);
    for name in ["rollback.manifest.0", "rollback.manifest.1"] {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(namespace.join(name))
            .unwrap();
        file.write_all_at(&u64::MAX.to_le_bytes(), 0).unwrap();
        file.sync_all().unwrap();
    }
    assert!(RollbackBacking::open_remote(f.root.path(), f.writer.clone()).is_err());
    assert_eq!(f.current().current, before.current);
}
