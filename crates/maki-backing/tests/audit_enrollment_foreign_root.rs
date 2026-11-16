//! Audit probe: initial-enrollment recovery does not prove that the target
//! backing root belongs to the never-activated authority it is resuming.
//!
//! BUG-187 fixed the same class for restore ("the approved backup proves the
//! source, not the target directory"): a root that holds another volume's
//! activated data must be refused before the authority changes or GC can
//! mistake the foreign namespaces for retired candidates. Enrollment recovery
//! creates the missing `remote.enrollment` binding for any marker-only root
//! (legacy roots written by older binaries have no binding) and then runs the
//! automatic GC pass, which retires every lower-fence namespace it recognizes.
#![cfg(target_os = "linux")]

use maki_backing::remote_witness::{Action, Phase, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, RollbackBacking};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const CAPACITY: u64 = 32 * 4096;

struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
    lose_claim: AtomicBool,
}

impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
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
    _dir: tempfile::TempDir,
    writer: Arc<LocalRpc>,
    admin: Arc<LocalRpc>,
}

impl Authority {
    fn new(identity: [u8; 16]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            StateStore::create(dir.path(), identity).unwrap(),
        ));
        let make = |role| {
            Arc::new(LocalRpc {
                store: store.clone(),
                role,
                lose_claim: AtomicBool::new(false),
            })
        };
        Self {
            _dir: dir,
            writer: make(Role::Writer),
            admin: make(Role::Admin),
        }
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

fn namespaces(root: &std::path::Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("remote-"))
        .collect();
    names.sort();
    names
}

#[test]
fn enrollment_recovery_into_a_foreign_legacy_root_retires_the_other_volumes_data() {
    // Volume B: an activated, quiescent remote volume with durable data.
    let b = Authority::new([2; 16]);
    let root_b = tempfile::tempdir().unwrap();
    {
        let backing =
            RollbackBacking::create_remote(root_b.path(), b.writer.clone(), CAPACITY).unwrap();
        let file = backing.open("payload", true).unwrap();
        file.write_at(0, b"volume B data").unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
    }
    // Older binaries never wrote the supplementary binding; such legacy
    // activated roots are explicitly supported by restore and GC.
    std::fs::remove_file(root_b.path().join("remote.enrollment")).unwrap();
    let b_before = inspect(b.writer.as_ref());
    let b_namespace = b_before.current.as_ref().unwrap().namespace.clone();
    assert_eq!(namespaces(root_b.path()), [b_namespace.clone()]);

    // Volume A: its own initial enrollment was interrupted (claim reply lost
    // twice), so the authority is never-activated and needs admin recovery.
    let a = Authority::new([1; 16]);
    let root_a = tempfile::tempdir().unwrap();
    a.writer.lose_claim.store(true, Ordering::SeqCst);
    assert!(RollbackBacking::create_remote(root_a.path(), a.writer.clone(), CAPACITY).is_err());
    a.writer.lose_claim.store(false, Ordering::SeqCst);
    let a_before = inspect(a.admin.as_ref());
    assert_eq!(a_before.phase, Phase::Claimed);
    assert!(a_before.current.is_none());

    // The administrator configuration names the wrong backing root (B's).
    // The approved authority record is exact and never activated, so every
    // authority-side guard passes. The target root is never authenticated.
    let result = RollbackBacking::recover_enrollment_remote(
        root_b.path(),
        a.admin.clone(),
        CAPACITY,
        &a_before,
    );
    let accepted = result.is_ok();
    drop(result);

    let survivors = namespaces(root_b.path());
    let binding = std::fs::read(root_b.path().join("remote.enrollment")).ok();
    eprintln!(
        "recovery accepted: {accepted}; namespaces in B's root now: {survivors:?}; \
         B's namespace present: {}; binding identity: {:?}",
        survivors.contains(&b_namespace),
        binding.as_ref().map(|bytes| bytes[8..24].to_vec())
    );
    // Secure behaviour: a root that holds another volume's activated data is
    // refused before the authority or the root changes, and nothing of B's is
    // ever deleted.
    assert!(
        survivors.contains(&b_namespace),
        "enrollment recovery's automatic GC retired volume B's only namespace"
    );
    assert!(
        !accepted,
        "enrollment recovery adopted a root holding another volume's data"
    );
}
