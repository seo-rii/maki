//! A remote `volume create` writes its format marker into the backing root
//! before anything else. A creation that is killed, loses power or fails
//! while it does so (a full disk, a quota, an I/O error) has claimed nothing
//! from the authority, so nothing is lost. It must also leave a root that a
//! documented command continues: `volume create` again while the marker is
//! not published, `volume resume-enrollment` once it is. A root holding a
//! marker that was created and never written is neither kind, and both
//! commands refused it.
//!
//! `maki-witness init` has the same shape on the authority's side: an
//! initialization that is cut or fails before its first record is published
//! must be one the operator can simply run again. What it must never do is
//! stand in for an enrolled authority: an empty `remote.state`, which is
//! what a truncated state file of an enrolled authority looks like, is
//! refused by `init` and by `serve`, and left as it is.
//!
//! The interrupted commands run in child processes: one is killed by a
//! seccomp filter at its first file write, the other has every file write
//! refused by a zero file-size limit.
#![cfg(target_os = "linux")]

use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{
    namespace, Action, CanonicalState, Phase, Record, Request, Role, Rpc, SessionAuthorization,
    StateStore,
};
use maki_backing::{Backing, RollbackBacking};

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

/// A root as a creation leaves it once it holds both root locks.
fn locked_root(dir: &Path) -> std::path::PathBuf {
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    for lock in ["remote.enroll.lock", "remote.operation.lock"] {
        std::fs::write(root.join(lock), b"").unwrap();
    }
    root
}

/// Run what an operator can run after an interrupted creation, against the
/// authority that creation never reached: `volume create`, and if that is
/// refused `volume resume-enrollment` with the inspected record. Returns
/// the refusals when neither completes the enrollment.
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

const STEP: &str = "MAKI_INTERRUPTED_ENROLLMENT_STEP";
const PATH: &str = "MAKI_INTERRUPTED_ENROLLMENT_PATH";
/// Exit status of a step whose command returned an error.
const FAILED: i32 = 3;
/// Exit status of a step that could not arrange its interruption.
const UNAVAILABLE: i32 = 77;

/// Kill this process at its first positional file write. False where
/// seccomp filters are unavailable.
fn die_at_the_first_file_write() -> bool {
    let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let filter = [
        // seccomp_data.nr
        statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
        statement(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::SYS_pwrite64 as u32,
            0,
            1,
        ),
        statement(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_KILL_PROCESS,
            0,
            0,
        ),
        statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: both calls affect only this thread, which runs the command;
    // the program outlives them.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            ) == 0
    }
}

/// Make every write that would grow a file fail (EFBIG), as on a full
/// disk: a zero file-size limit for this process, with the signal that
/// accompanies it ignored. Pipes, such as the test's output, are unaffected.
fn refuse_file_writes() -> bool {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain libc calls with valid arguments.
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN) != libc::SIG_ERR
            && libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == 0
    }
}

/// The interrupted command, in the child process. Never returns.
fn step(step: &str, path: &Path) -> ! {
    let (command, interruption) = step.split_once(' ').unwrap();
    let arranged = match interruption {
        "killed" => die_at_the_first_file_write(),
        "refused" => refuse_file_writes(),
        other => panic!("unknown interruption {other}"),
    };
    if !arranged {
        std::process::exit(UNAVAILABLE);
    }
    let outcome = match command {
        "create" => RollbackBacking::create_remote(path, authority().0, CAPACITY).map(drop),
        "init" => StateStore::create(path, IDENTITY).map(drop),
        other => panic!("unknown command {other}"),
    };
    eprintln!("{command}: {outcome:?}");
    std::process::exit(if outcome.is_ok() { 0 } else { FAILED });
}

/// Run `step` on `path` in a child process that re-enters `test`. `None`,
/// with the reason printed, where the interruption cannot be arranged.
fn interrupted(test: &str, step: &str, path: &Path) -> Option<std::process::Output> {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(STEP, step)
        .env(PATH, path)
        .output()
        .unwrap();
    if output.status.code() == Some(UNAVAILABLE) {
        eprintln!("{test}: skipped: cannot arrange `{step}` in a child process");
        return None;
    }
    Some(output)
}

/// The child half of a test that interrupts a command.
fn child() {
    if let (Some(name), Some(path)) = (std::env::var_os(STEP), std::env::var_os(PATH)) {
        step(name.to_str().unwrap(), Path::new(&path));
    }
}

#[test]
fn create_killed_before_the_marker_is_written_can_be_completed() {
    use std::os::unix::process::ExitStatusExt;
    child();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let Some(killed) = interrupted(
        "create_killed_before_the_marker_is_written_can_be_completed",
        "create killed",
        &root,
    ) else {
        return;
    };
    assert_eq!(killed.status.signal(), Some(libc::SIGSYS), "{killed:?}");
    // It held both root locks and was about to write the marker.
    let left = entries(&root);
    assert!(
        left.iter().any(|name| name == "remote.enroll.lock")
            && left.iter().any(|name| name == "remote.operation.lock"),
        "{left:?}"
    );
    // The marker it was writing is not under its published name.
    assert!(
        !left.iter().any(|name| name == "rollback.format"),
        "{left:?}"
    );
    let refusals = documented_commands(&root);
    assert!(
        refusals.is_empty(),
        "a creation killed before its marker was written is stranded with {left:?}: {refusals:?}"
    );
    assert_eq!(std::fs::read(root.join("rollback.format")).unwrap(), MARKER);
    assert!(!root.join("rollback.format.next").exists());
}

#[test]
fn create_whose_marker_write_failed_can_be_retried() {
    child();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let Some(failed) = interrupted(
        "create_whose_marker_write_failed_can_be_retried",
        "create refused",
        &root,
    ) else {
        return;
    };
    assert_eq!(failed.status.code(), Some(FAILED), "{failed:?}");
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("File too large"),
        "the marker write must have failed: {failed:?}"
    );
    let left = entries(&root);
    // The failed command removed the marker it could not write.
    assert_eq!(left, ["remote.enroll.lock", "remote.operation.lock"]);
    let refusals = documented_commands(&root);
    assert!(
        refusals.is_empty(),
        "after one failed marker write the root is stranded with {left:?}: {refusals:?}"
    );
    assert_eq!(std::fs::read(root.join("rollback.format")).unwrap(), MARKER);
}

/// A marker that is empty, or a torn copy (each byte the marker's or zero),
/// is what a release that wrote the marker in place left when it was cut
/// there. With nothing beside it but the root locks, no creation published
/// anything in this root: `create` completes it like an empty directory.
#[test]
fn create_completes_a_root_whose_marker_was_created_and_never_written() {
    let mut torn = MARKER.to_vec();
    torn[9..].fill(0);
    for unwritten in [&[][..], &MARKER[..5], &[0; 27][..], &torn[..]] {
        let dir = tempfile::tempdir().unwrap();
        let root = locked_root(dir.path());
        std::fs::write(root.join("rollback.format"), unwritten).unwrap();
        let (writer, admin) = authority();
        let created = RollbackBacking::create_remote(&root, writer.clone(), CAPACITY)
            .unwrap_or_else(|error| panic!("marker {unwritten:?}: {error}"));
        let file = created.open("payload", true).unwrap();
        file.write_at(0, b"kept").unwrap();
        file.sync_data().unwrap();
        created.sync_dir("").unwrap();
        drop((file, created));
        assert_eq!(std::fs::read(root.join("rollback.format")).unwrap(), MARKER);
        // An ordinary volume from here on.
        let record = inspect(admin.as_ref());
        assert_eq!((record.fence, record.phase), (1, Phase::Released));
        let reopened = RollbackBacking::open_remote(&root, writer).unwrap();
        let mut bytes = [0; 4];
        reopened
            .open("payload", false)
            .unwrap()
            .read_at(0, &mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"kept");
    }
}

/// A creation stages the marker as `rollback.format.next` and renames it
/// into place once it is synced. Whatever an interrupted creation left
/// under that name is written again, never published as it is.
#[test]
fn create_completes_a_root_that_holds_only_a_staged_marker() {
    assert!(RollbackBacking::owns_host_entry(
        "rollback.format.next",
        true
    ));
    for staged in [&[][..], &MARKER[..11], b"anything else at all, and longer"] {
        let dir = tempfile::tempdir().unwrap();
        let root = locked_root(dir.path());
        std::fs::write(root.join("rollback.format.next"), staged).unwrap();
        let (writer, _) = authority();
        RollbackBacking::create_remote(&root, writer, CAPACITY)
            .unwrap_or_else(|error| panic!("staged {staged:?}: {error}"));
        assert_eq!(std::fs::read(root.join("rollback.format")).unwrap(), MARKER);
        assert!(!root.join("rollback.format.next").exists());
    }
}

/// Enrollment recovery continues a published root. For one whose creation
/// stopped earlier it says which command does, and changes nothing.
#[test]
fn enrollment_recovery_sends_an_unpublished_root_back_to_creation() {
    type Plant = fn(&Path);
    let unpublished: [Plant; 3] = [
        |_| {},
        |root| std::fs::write(root.join("rollback.format.next"), b"").unwrap(),
        |root| std::fs::write(root.join("rollback.format"), b"").unwrap(),
    ];
    for plant in unpublished {
        let dir = tempfile::tempdir().unwrap();
        let root = locked_root(dir.path());
        plant(&root);
        let before = entries(&root);
        let (_, admin) = authority();
        let record = inspect(admin.as_ref());
        let error =
            RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record)
                .err()
                .unwrap();
        assert!(
            error.to_string().contains("create the volume again"),
            "{before:?}: {error}"
        );
        assert_eq!(entries(&root), before);
        assert_eq!(inspect(admin.as_ref()), record);
    }
    // Anything else keeps its own refusal: a root that holds more than an
    // interrupted creation leaves,
    let dir = tempfile::tempdir().unwrap();
    let root = locked_root(dir.path());
    std::fs::write(root.join("rollback.format"), b"").unwrap();
    std::fs::write(root.join("notes"), b"operator").unwrap();
    let (_, admin) = authority();
    let record = inspect(admin.as_ref());
    let error = RollbackBacking::recover_enrollment_remote(&root, admin, CAPACITY, &record)
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "not a remote rollback backing");
    // and a root without a marker under an authority that is claimed, which
    // no creation that stopped before its marker can have done.
    let dir = tempfile::tempdir().unwrap();
    let root = locked_root(dir.path());
    std::fs::write(root.join("rollback.format"), b"").unwrap();
    let (writer, admin) = authority();
    let released = inspect(admin.as_ref());
    let claimed = writer
        .call(&Request {
            operation_id: [1; 16],
            expected: Some(released),
            action: Action::Claim,
            authorization: Some(
                maki_backing::remote_witness::SessionAuthorization::from_bytes([9; 32]),
            ),
        })
        .unwrap();
    assert_eq!(claimed.phase, Phase::Claimed);
    let error =
        RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &claimed)
            .err()
            .unwrap();
    assert_eq!(error.to_string(), "not a remote rollback backing");
    assert_eq!(inspect(admin.as_ref()), claimed);
}

/// Once the marker is published the root is a remote backing whose
/// enrollment is in progress: `create` refuses it, and enrollment recovery,
/// which the administrator approves, continues it.
#[test]
fn control_a_published_marker_is_continued_by_enrollment_recovery_only() {
    let dir = tempfile::tempdir().unwrap();
    let root = locked_root(dir.path());
    std::fs::write(root.join("rollback.format"), MARKER).unwrap();
    let (writer, admin) = authority();
    let error = RollbackBacking::create_remote(&root, writer, CAPACITY)
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "remote enrollment requires an empty backing"
    );
    let record = inspect(admin.as_ref());
    assert_eq!(record.fence, 0);
    RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record).unwrap();
    assert_eq!(inspect(admin.as_ref()).fence, 1);
}

/// One file later the creation writes the binding. Cut there, it leaves a
/// published marker and an unwritten binding: enrollment recovery refuses
/// the binding rather than write over it, and continues once the operator
/// has moved it out of the root.
#[test]
fn control_an_unwritten_binding_is_quarantined_before_enrollment_recovery_continues() {
    let dir = tempfile::tempdir().unwrap();
    let root = locked_root(dir.path());
    std::fs::write(root.join("rollback.format"), MARKER).unwrap();
    std::fs::write(root.join("remote.enrollment"), b"").unwrap();
    let (writer, admin) = authority();
    assert!(RollbackBacking::create_remote(&root, writer, CAPACITY).is_err());
    let record = inspect(admin.as_ref());
    let error = RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record)
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "invalid enrollment metadata length");
    assert_eq!(inspect(admin.as_ref()), record);
    std::fs::rename(
        root.join("remote.enrollment"),
        dir.path().join("remote.enrollment.kept"),
    )
    .unwrap();
    RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record).unwrap();
    assert_eq!(inspect(admin.as_ref()).fence, 1);
    assert_eq!(
        std::fs::metadata(root.join("remote.enrollment"))
            .unwrap()
            .len(),
        64
    );
}

/// Only a root that holds nothing else is an interrupted creation. An
/// unwritten marker beside a namespace, a binding or any other entry, and a
/// marker holding anything but a torn copy, are refused and left as they
/// are: neither is something this creation may write over.
#[test]
fn control_create_refuses_an_unwritten_marker_that_is_not_alone_and_a_foreign_marker() {
    let mut session = [0; 16];
    session[15] = 1;
    let stale = namespace(1, session);
    type Plant = Box<dyn Fn(&Path)>;
    let beside: [(&str, Plant); 4] = [
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
            "a binding",
            Box::new(|root| std::fs::write(root.join("remote.enrollment"), b"").unwrap()),
        ),
        (
            "another file",
            Box::new(|root| std::fs::write(root.join("notes"), b"operator").unwrap()),
        ),
    ];
    for (what, plant) in &beside {
        let dir = tempfile::tempdir().unwrap();
        let root = locked_root(dir.path());
        std::fs::write(root.join("rollback.format"), b"").unwrap();
        plant(&root);
        let before = entries(&root);
        let (writer, admin) = authority();
        let error = RollbackBacking::create_remote(&root, writer, CAPACITY)
            .err()
            .unwrap_or_else(|| panic!("an unwritten marker beside {what} was accepted"));
        assert_eq!(
            error.to_string(),
            "remote enrollment requires an empty backing"
        );
        assert_eq!(entries(&root), before, "{what}");
        assert_eq!(std::fs::read(root.join("rollback.format")).unwrap(), b"");
        assert_eq!(inspect(admin.as_ref()).fence, 0, "{what}");
    }
    let mut changed = MARKER.to_vec();
    changed[3] ^= 1;
    let mut longer = MARKER.to_vec();
    longer.push(0);
    for foreign in [
        b"MAKI-ROLLBACK-COW-V1\n".to_vec(),
        changed,
        longer,
        vec![0; 28],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = locked_root(dir.path());
        std::fs::write(root.join("rollback.format"), &foreign).unwrap();
        let (writer, admin) = authority();
        assert!(
            RollbackBacking::create_remote(&root, writer, CAPACITY).is_err(),
            "{foreign:?}"
        );
        assert_eq!(
            std::fs::read(root.join("rollback.format")).unwrap(),
            foreign
        );
        assert_eq!(inspect(admin.as_ref()).fence, 0);
    }
}

/// A snapshot initializes its target the same way, so a target an
/// interrupted snapshot left with an unwritten marker can be reused.
#[test]
fn snapshot_reuses_a_target_whose_marker_was_never_written() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, _) = authority();
    let backing =
        RollbackBacking::create_remote(&dir.path().join("volume"), writer, CAPACITY).unwrap();
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, b"kept").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
    let target = locked_root(dir.path());
    std::fs::write(target.join("rollback.format"), b"").unwrap();
    RollbackBacking::check_snapshot_destination(&target).unwrap();
    let descriptor = backing.snapshot_remote(&target).unwrap();
    assert_eq!(
        std::fs::read(target.join("rollback.format")).unwrap(),
        MARKER
    );
    assert!(target.join(&descriptor.namespace).is_dir());
}

fn inspect_store(store: &mut StateStore) -> Record {
    store
        .handle(
            Role::Admin,
            &Request {
                operation_id: [0; 16],
                expected: None,
                action: Action::Inspect,
                authorization: None,
            },
        )
        .unwrap()
}

/// Run `maki-witness init` again after an interrupted one and serve the
/// result: the initial record of the identity, exactly once.
fn init_again_and_serve(state: &Path, left: &[String]) {
    let again = StateStore::create(state, IDENTITY).map(drop);
    let served = StateStore::open(state);
    assert!(
        again.is_ok() && served.is_ok(),
        "an interrupted init is stranded with {left:?}: init: {:?}; serve: {:?}",
        again.err().map(|error| error.to_string()),
        served.err().map(|error| error.to_string())
    );
    let record = inspect_store(&mut served.unwrap());
    assert_eq!(
        (record.identity, record.fence, record.phase),
        (IDENTITY, 0, Phase::Released)
    );
    assert!(record.current.is_none());
    assert_eq!(
        StateStore::create(state, IDENTITY).err().unwrap().kind(),
        io::ErrorKind::AlreadyExists
    );
}

#[test]
fn witness_init_killed_before_its_state_is_written_can_be_run_again() {
    use std::os::unix::process::ExitStatusExt;
    child();
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("authority");
    let Some(killed) = interrupted(
        "witness_init_killed_before_its_state_is_written_can_be_run_again",
        "init killed",
        &state,
    ) else {
        return;
    };
    assert_eq!(killed.status.signal(), Some(libc::SIGSYS), "{killed:?}");
    let left = entries(&state);
    assert!(left.iter().any(|name| name == "remote.lock"), "{left:?}");
    // Nothing was published under the state's name, and `serve` says so.
    assert!(!left.iter().any(|name| name == "remote.state"), "{left:?}");
    let unserved = StateStore::open(&state).err().unwrap();
    assert_eq!(unserved.kind(), io::ErrorKind::NotFound);
    assert!(
        unserved.to_string().contains("is not initialized"),
        "{unserved}"
    );
    init_again_and_serve(&state, &left);
}

#[test]
fn witness_init_whose_state_write_failed_can_be_run_again() {
    child();
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("authority");
    let Some(failed) = interrupted(
        "witness_init_whose_state_write_failed_can_be_run_again",
        "init refused",
        &state,
    ) else {
        return;
    };
    assert_eq!(failed.status.code(), Some(FAILED), "{failed:?}");
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("File too large"),
        "the state write must have failed: {failed:?}"
    );
    let left = entries(&state);
    init_again_and_serve(&state, &left);
}

/// An empty `remote.state` can be an initialization that stopped after
/// creating the file (releases that created it before writing it) or an
/// enrolled authority whose state was truncated. The two cannot be told
/// apart, so neither command replaces it: both name the two causes and the
/// only safe way out, and the directory stays as it was.
#[test]
fn an_empty_witness_state_is_refused_with_its_causes_and_the_way_out() {
    let dir = tempfile::tempdir().unwrap();
    drop(StateStore::create(dir.path(), IDENTITY).unwrap());
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(dir.path().join("remote.state"))
        .unwrap();
    let before = entries(dir.path());
    let refused = [
        (
            "init",
            StateStore::create(dir.path(), IDENTITY).map(drop),
            io::ErrorKind::AlreadyExists,
        ),
        (
            "serve",
            StateStore::open(dir.path()).map(drop),
            io::ErrorKind::InvalidData,
        ),
    ];
    for (command, outcome, kind) in refused {
        let error = outcome
            .err()
            .unwrap_or_else(|| panic!("{command} accepted it"));
        assert_eq!(error.kind(), kind, "{command}: {error}");
        let text = error.to_string();
        assert!(
            text.contains("remote.state is empty")
                && text.contains("did not complete")
                && text.contains("lost its state")
                && text.contains("never been served")
                && text.contains("remove remote.state"),
            "{command}: {text}"
        );
    }
    assert_eq!(entries(dir.path()), before);
    assert_eq!(
        std::fs::metadata(dir.path().join("remote.state"))
            .unwrap()
            .len(),
        0
    );
}

/// The safety side of the same state: an authority that has accepted a
/// claim and whose state file is then truncated is never initialized again
/// by rerunning `init`, which would reset its fence to zero.
#[test]
fn control_an_enrolled_authority_whose_state_was_truncated_is_never_initialized_again() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), IDENTITY).unwrap();
    let expected = inspect_store(&mut store);
    let claimed = store
        .handle(
            Role::Writer,
            &Request {
                operation_id: [1; 16],
                expected: Some(expected),
                action: Action::Claim,
                authorization: Some(SessionAuthorization::from_bytes([9; 32])),
            },
        )
        .unwrap();
    assert_eq!(claimed.fence, 1);
    drop(store);
    let state = dir.path().join("remote.state");
    let published = std::fs::read(&state).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&state)
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            StateStore::create(dir.path(), IDENTITY)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(StateStore::open(dir.path()).is_err());
        assert_eq!(std::fs::metadata(&state).unwrap().len(), 0);
    }
    // Only the authority's own bytes bring it back, at its own fence.
    std::fs::write(&state, &published).unwrap();
    assert_eq!(
        inspect_store(&mut StateStore::open(dir.path()).unwrap()),
        claimed
    );
}

/// `remote.next` is never state. Whatever a failed or killed initialization
/// left there, the next one writes its own record over it.
#[test]
fn control_init_writes_over_a_staged_state_left_behind() {
    use std::os::unix::fs::PermissionsExt;
    for staged in [&[][..], b"MAKIRW02 and then not a record at all"] {
        let dir = tempfile::tempdir().unwrap();
        let next = dir.path().join("remote.next");
        std::fs::write(&next, staged).unwrap();
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(StateStore::open(dir.path()).is_err());
        let mut store = StateStore::create(dir.path(), IDENTITY).unwrap();
        assert_eq!(inspect_store(&mut store).fence, 0);
        drop(store);
        assert!(!next.exists());
        assert_eq!(
            inspect_store(&mut StateStore::open(dir.path()).unwrap()).identity,
            IDENTITY
        );
    }
}

/// Why the way out of an empty state file cannot make a rollback
/// acceptable even when it is taken by mistake: an authority initialized
/// again starts without a current root, and nothing accepts a backing that
/// holds a volume's data for it.
#[test]
fn control_an_authority_initialized_again_accepts_none_of_the_existing_backing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let (writer, _) = authority();
    let backing = RollbackBacking::create_remote(&root, writer, CAPACITY).unwrap();
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, b"kept").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
    drop((file, backing));
    let before = entries(&root);

    // The same identity, initialized again.
    let (writer, admin) = authority();
    let record = inspect(admin.as_ref());
    assert!(record.current.is_none() && record.fence == 0);
    assert!(RollbackBacking::open_remote(&root, writer.clone()).is_err());
    assert!(RollbackBacking::takeover_remote(&root, admin.clone(), &record).is_err());
    assert!(
        RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &record)
            .is_err()
    );
    assert!(RollbackBacking::create_remote(&root, writer, CAPACITY).is_err());
    assert_eq!(inspect(admin.as_ref()), record);
    assert_eq!(entries(&root), before);
}
