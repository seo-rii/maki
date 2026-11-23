//! Audit round 5 (remote-admin-crash): an initial remote enrollment that is
//! interrupted before its format marker holds its bytes leaves a backing root
//! that no documented procedure accepts. Not part of the maintained suite.
//!
//! `create_remote` creates `rollback.format`, then writes it. A process death
//! between the two (SIGKILL here, delivered by strace at the first
//! `pwrite64`), a power loss whose journal kept the name but not the data, or
//! simply a failed write (ENOSPC, EDQUOT, EIO: injected here as ENOSPC)
//! leaves an empty marker. The authority was never claimed (fence 0), so
//! nothing is lost, but:
//!
//! - `maki volume create` (`create_remote`) refuses: "remote enrollment
//!   requires an empty backing";
//! - `maki volume resume-enrollment <cfg> 0 <uuid>`
//!   (`recover_enrollment_remote`), the documented way to continue an
//!   interrupted enrollment, refuses: "not a remote rollback backing".
//!
//! The tests assert that one of the two documented procedures completes the
//! enrollment, so they FAIL on the audited tree.

#![cfg(target_os = "linux")]

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, CanonicalState, Record, Request, Role, Rpc, StateStore};
use maki_backing::RollbackBacking;

const CAPACITY: u64 = 16 * 4096;
const IDENTITY: [u8; 16] = [0x5A; 16];

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

/// What an operator can run next: `volume create`, then `resume-enrollment`
/// with the inspected (never-activated) record.
fn documented_procedures(root: &Path) -> Vec<String> {
    let (writer, admin) = authority();
    let mut refusals = Vec::new();
    match RollbackBacking::create_remote(root, writer, CAPACITY) {
        Ok(_) => return refusals,
        Err(error) => refusals.push(format!("volume create: {error}")),
    }
    let record = inspect(admin.as_ref());
    assert!(record.current.is_none() && record.fence == 0);
    match RollbackBacking::recover_enrollment_remote(root, admin, CAPACITY, &record) {
        Ok(_) => return Vec::new(),
        Err(error) => refusals.push(format!("volume resume-enrollment: {error}")),
    }
    refusals
}

/// The traced child: one `volume create` against an untouched authority.
#[test]
fn audit5_enrollment_child() {
    let Ok(root) = std::env::var("AUDIT5_ENROLL_ROOT") else {
        return;
    };
    let (writer, _) = authority();
    let outcome = RollbackBacking::create_remote(Path::new(&root), writer, CAPACITY);
    // An injected failed write: report it and let the parent continue.
    eprintln!("child create_remote: {:?}", outcome.as_ref().err());
    std::process::exit(if outcome.is_ok() { 0 } else { 3 });
}

fn run_child(root: &Path, inject: &str) -> std::process::ExitStatus {
    std::process::Command::new("strace")
        .args(["-f", "-o", "/dev/null", "-e", "trace=pwrite64", "-e"])
        .arg(format!("inject=pwrite64:{inject}:when=1"))
        .arg(std::env::current_exe().unwrap())
        .args(["audit5_enrollment_child", "--exact", "--nocapture", "--test-threads=1"])
        .env("AUDIT5_ENROLL_ROOT", root)
        .status()
        .expect("strace is required")
}

#[test]
fn create_killed_before_the_marker_is_written_can_be_completed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let status = run_child(&root, "signal=SIGKILL");
    assert!(!status.success(), "the child must have been killed");
    let marker = std::fs::metadata(root.join("rollback.format")).expect("marker was created");
    assert_eq!(marker.len(), 0, "killed between create and write");
    let refusals = documented_procedures(&root);
    assert!(
        refusals.is_empty(),
        "an enrollment killed before its marker was written is stranded: {refusals:?}"
    );
}

#[test]
fn create_whose_marker_write_failed_can_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    // The process is not killed: the write fails once, as on a full disk.
    let status = run_child(&root, "error=ENOSPC");
    assert_eq!(status.code(), Some(3), "create must have failed with ENOSPC");
    let refusals = documented_procedures(&root);
    assert!(
        refusals.is_empty(),
        "after one failed marker write (ENOSPC) the root is stranded: {refusals:?}"
    );
}

/// The traced child of the witness test: one `maki-witness init`.
#[test]
fn audit5_witness_init_child() {
    let Ok(dir) = std::env::var("AUDIT5_WITNESS_DIR") else {
        return;
    };
    let outcome = StateStore::create(Path::new(&dir), IDENTITY).map(|_| ());
    eprintln!("child StateStore::create: {:?}", outcome.as_ref().err());
    std::process::exit(if outcome.is_ok() { 0 } else { 3 });
}

/// The witness side of the same class: `maki-witness init` whose first
/// state write fails (ENOSPC injected at the `pwrite64` of `remote.next`;
/// a kill anywhere between the sentinel and the rename leaves the same
/// files). The empty `remote.state` sentinel is deliberate (an interrupted
/// enrollment must not be silently usable), but then `init` refuses
/// ("already enrolled") and `serve` refuses (invalid length), and the service
/// guide names no way to continue.
#[test]
fn witness_init_interrupted_after_its_sentinel_can_be_completed() {
    let dir = tempfile::tempdir().unwrap();
    let status = std::process::Command::new("strace")
        .args(["-f", "-o", "/dev/null", "-e", "trace=pwrite64", "-e"])
        .arg("inject=pwrite64:error=ENOSPC:when=1")
        .arg(std::env::current_exe().unwrap())
        .args(["audit5_witness_init_child", "--exact", "--nocapture", "--test-threads=1"])
        .env("AUDIT5_WITNESS_DIR", dir.path())
        .status()
        .expect("strace is required");
    assert_eq!(status.code(), Some(3), "init must have failed with ENOSPC");
    assert_eq!(
        std::fs::metadata(dir.path().join("remote.state")).unwrap().len(),
        0,
        "the failed init left its empty sentinel"
    );
    let init = StateStore::create(dir.path(), IDENTITY).map(|_| ());
    let serve = StateStore::open(dir.path()).map(|_| ());
    assert!(
        init.is_ok() || serve.is_ok(),
        "interrupted witness init is stranded: init: {:?}; serve: {:?}",
        init.err().map(|e| e.to_string()),
        serve.err().map(|e| e.to_string())
    );
}

/// Control: the same cut one file later (the `remote.enrollment` binding
/// created but empty) has the exit the guide documents: quarantine the
/// damaged binding and resume.
#[test]
fn control_an_empty_binding_resumes_after_the_documented_quarantine() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("rollback.format"), b"MAKI-REMOTE-WITNESS-COW-V2\n").unwrap();
    std::fs::write(root.join("remote.enrollment"), b"").unwrap();
    let (_, admin) = authority();
    let record = inspect(admin.as_ref());
    let refused =
        RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record);
    assert!(refused.is_err(), "a truncated binding is refused, as documented");
    std::fs::rename(root.join("remote.enrollment"), dir.path().join("quarantined")).unwrap();
    RollbackBacking::recover_enrollment_remote(&root, admin, CAPACITY, &record)
        .expect("resume after quarantining the binding");
}
