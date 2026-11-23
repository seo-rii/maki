//! Remote GC retires stale writer namespaces one at a time, in name order,
//! which is fence order. A stale namespace it cannot open or examine must be
//! kept, reported with the reason and stepped past. Ending the pass there
//! leaves every higher-fence namespace on disk, each a full arena, and the
//! automatic pass after an activation discards the error, so attaching keeps
//! succeeding while the backing fills.
//!
//! Two such namespaces: one the daemon user may not open (a `takeover` run as
//! root that dies between creating the new namespace directory and giving it
//! to the daemon user leaves it root's, `0700`), and one holding a directory
//! where a namespace file belongs, which anyone who can write the root can
//! make. Only a candidate that could not be examined is skipped: a pass
//! still ends when it cannot authenticate the current namespace, and a
//! retired namespace whose lifetime lock cannot be opened keeps its files.
#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use maki_backing::remote_gc::GcUnreadable;
use maki_backing::remote_witness::{
    namespace, Action, CanonicalState, Record, Request, Role, Rpc, StateStore,
};
use maki_backing::{Backing, MemBacking, RollbackBacking};

const CAPACITY: u64 = 16 * 4096;
const IDENTITY: [u8; 16] = [0x6c; 16];

struct LocalRpc(Mutex<StateStore>);

impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.0.lock().unwrap().handle(Role::Writer, request)
    }
}

fn authority() -> Arc<dyn Rpc> {
    Arc::new(LocalRpc(Mutex::new(
        StateStore::create_backing(Arc::new(MemBacking::new()), IDENTITY).unwrap(),
    )))
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

fn commit(backing: &RollbackBacking, tag: &[u8]) {
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, tag).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
}

/// A fence-1 namespace name that sorts before the one `create_remote`
/// makes, whose session is random: GC reaches it first.
fn first_stale_name() -> String {
    let mut session = [0; 16];
    session[15] = 1;
    namespace(1, session)
}

/// Root entries whose name starts with `prefix`, sorted.
fn entries(root: &Path, prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(prefix))
        .collect();
    names.sort();
    names
}

fn namespaces(root: &Path) -> Vec<String> {
    entries(root, "remote-0")
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_DAC_OVERRIDE: u32 = 1;
const CAP_DAC_READ_SEARCH: u32 = 2;

fn capabilities(set: Option<&[CapabilityData; 2]>) -> io::Result<[CapabilityData; 2]> {
    // pid 0 names the calling thread.
    let mut header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = set.copied().unwrap_or_default();
    let call = if set.is_some() {
        libc::SYS_capset
    } else {
        libc::SYS_capget
    };
    // SAFETY: both pointers reference live, correctly laid out structures
    // for the duration of the call; capget writes two data words.
    if unsafe { libc::syscall(call, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(data)
}

/// Makes file modes apply to the calling thread until the guard drops, by
/// clearing the capabilities that let root ignore them. Credentials are per
/// thread (libtest runs each test on its own thread), so concurrent tests
/// keep theirs; an unprivileged user has nothing to clear.
struct ModesApply([CapabilityData; 2]);

impl ModesApply {
    /// `None`, with the reason printed, where `closed` can still be opened.
    fn unless_openable(test: &str, closed: &Path) -> Option<Self> {
        let guard = capabilities(None).and_then(|saved| {
            let mut reduced = saved;
            for capability in [CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH] {
                reduced[(capability / 32) as usize].effective &= !(1 << (capability % 32));
            }
            capabilities(Some(&reduced))?;
            Ok(Self(saved))
        });
        match guard {
            Ok(guard) if std::fs::File::open(closed).is_err() => Some(guard),
            Ok(_) => {
                eprintln!("{test}: skipped: {} can still be opened", closed.display());
                None
            }
            Err(error) => {
                eprintln!("{test}: skipped: cannot clear capabilities ({error})");
                None
            }
        }
    }
}

impl Drop for ModesApply {
    fn drop(&mut self) {
        let _ = capabilities(Some(&self.0));
    }
}

#[test]
fn gc_reclaims_past_a_namespace_it_may_not_open() {
    let writer = authority();
    let root = tempfile::tempdir().unwrap();
    let created = RollbackBacking::create_remote(root.path(), writer.clone(), CAPACITY).unwrap();
    commit(&created, b"created");
    drop(created);
    // What an interrupted root-run takeover leaves the daemon user: an
    // empty namespace directory it may not open.
    let closed = first_stale_name();
    std::fs::create_dir(root.path().join(&closed)).unwrap();
    set_mode(&root.path().join(&closed), 0o000);
    let Some(modes) = ModesApply::unless_openable(
        "gc_reclaims_past_a_namespace_it_may_not_open",
        &root.path().join(&closed),
    ) else {
        return;
    };

    for _ in 0..3 {
        let backing = RollbackBacking::open_remote(root.path(), writer.clone()).unwrap();
        let current = inspect(writer.as_ref()).current.unwrap().namespace;
        assert_eq!(
            namespaces(root.path()),
            [closed.clone(), current],
            "the automatic pass must retire each predecessor past the closed namespace"
        );
        commit(&backing, b"attached");
    }
    let report = RollbackBacking::collect_remote(root.path(), writer.as_ref())
        .expect("a namespace GC may not open must not end the pass");
    assert!(report.removed.is_empty());
    assert_eq!(report.counts.removed, 0);
    assert_eq!(namespaces(root.path()).len(), 2);
    assert!(root.path().join(&closed).is_dir());
    // Reported with the step and the OS error, apart from the entries GC
    // does not recognize.
    assert_eq!(
        report.skipped_unreadable,
        [GcUnreadable {
            name: closed.clone(),
            error: "opening the namespace directory: Permission denied (os error 13)".into(),
        }]
    );
    assert_eq!(report.counts.skipped_unreadable, 1);
    assert!(report.skipped_unrecognized.is_empty());
    assert!(!report.details_truncated);

    drop(modes);
    set_mode(&root.path().join(&closed), 0o700);
}

#[test]
fn gc_reclaims_past_a_namespace_holding_a_directory_named_like_its_arena() {
    let writer = authority();
    let root = tempfile::tempdir().unwrap();
    let created = RollbackBacking::create_remote(root.path(), writer.clone(), CAPACITY).unwrap();
    commit(&created, b"created");
    drop(created);
    // A quiescent stale namespace whose arena cannot be opened as a file.
    let odd = first_stale_name();
    std::fs::create_dir(root.path().join(&odd)).unwrap();
    std::fs::write(root.path().join(&odd).join("rollback.lock"), b"").unwrap();
    std::fs::create_dir(root.path().join(&odd).join("rollback.arena")).unwrap();

    for _ in 0..3 {
        let backing = RollbackBacking::open_remote(root.path(), writer.clone()).unwrap();
        let current = inspect(writer.as_ref()).current.unwrap().namespace;
        assert_eq!(
            namespaces(root.path()),
            [odd.clone(), current],
            "the automatic pass must retire each predecessor past the odd namespace"
        );
        commit(&backing, b"attached");
    }
    let report = RollbackBacking::collect_remote(root.path(), writer.as_ref())
        .expect("a namespace GC cannot examine must not end the pass");
    assert!(report.removed.is_empty());
    assert_eq!(namespaces(root.path()).len(), 2);
    assert_eq!(
        report.skipped_unreadable,
        [GcUnreadable {
            name: odd.clone(),
            error: "opening rollback.arena: Is a directory (os error 21)".into(),
        }]
    );
    assert_eq!(report.counts.skipped_unreadable, 1);
    // Kept exactly as it was, under its own name.
    assert!(root.path().join(&odd).join("rollback.arena").is_dir());
    assert!(root.path().join(&odd).join("rollback.lock").is_file());
    assert!(entries(root.path(), ".remote-gc-").is_empty());
}

/// A tombstone proves that a namespace was retired, not that the handles
/// of its last writer are gone: only its lifetime lock does. A lock file GC
/// cannot open is not a free lock.
#[test]
fn a_retired_namespace_whose_lock_cannot_be_opened_keeps_its_files() {
    let writer = authority();
    let root = tempfile::tempdir().unwrap();
    let created = RollbackBacking::create_remote(root.path(), writer.clone(), CAPACITY).unwrap();
    commit(&created, b"created");
    drop(created);
    // Sorts before every namespace, so each pass reaches it first.
    let retired = root
        .path()
        .join(format!(".remote-gc-{}", first_stale_name()));
    std::fs::create_dir(&retired).unwrap();
    std::fs::write(retired.join("rollback.arena"), b"ciphertext").unwrap();
    std::fs::write(retired.join("rollback.lock"), b"").unwrap();
    set_mode(&retired.join("rollback.lock"), 0o000);
    let Some(modes) = ModesApply::unless_openable(
        "a_retired_namespace_whose_lock_cannot_be_opened_keeps_its_files",
        &retired.join("rollback.lock"),
    ) else {
        return;
    };

    let backing = RollbackBacking::open_remote(root.path(), writer.clone()).unwrap();
    let current = inspect(writer.as_ref()).current.unwrap().namespace;
    assert_eq!(
        namespaces(root.path()),
        [current],
        "the automatic pass must retire the predecessor past the tombstone"
    );
    drop(backing);
    let report = RollbackBacking::collect_remote(root.path(), writer.as_ref())
        .expect("a tombstone GC cannot examine must not end the pass");
    assert!(report.removed.is_empty());
    assert_eq!(
        report.skipped_unreadable,
        [GcUnreadable {
            name: format!(".remote-gc-{}", first_stale_name()),
            error: "opening rollback.lock: Permission denied (os error 13)".into(),
        }]
    );
    assert_eq!(
        std::fs::read(retired.join("rollback.arena")).unwrap(),
        b"ciphertext"
    );
    assert!(retired.join("rollback.lock").is_file());

    drop(modes);
    set_mode(&retired.join("rollback.lock"), 0o600);
}

/// What GC may delete is decided against the authority's current
/// generation, which it reads from the current namespace. That one being
/// unreadable is not a candidate to step past: nothing is retired.
#[test]
fn control_gc_refuses_a_root_whose_current_namespace_it_cannot_open() {
    let writer = authority();
    let root = tempfile::tempdir().unwrap();
    let created = RollbackBacking::create_remote(root.path(), writer.clone(), CAPACITY).unwrap();
    commit(&created, b"created");
    drop(created);
    drop(RollbackBacking::open_remote(root.path(), writer.clone()).unwrap());
    let current = inspect(writer.as_ref()).current.unwrap().namespace;
    assert_eq!(namespaces(root.path()), std::slice::from_ref(&current));
    // A quiescent abandoned fork, which a pass retires.
    let stale = first_stale_name();
    std::fs::create_dir(root.path().join(&stale)).unwrap();
    std::fs::write(root.path().join(&stale).join("rollback.lock"), b"").unwrap();
    set_mode(&root.path().join(&current), 0o000);
    let Some(modes) = ModesApply::unless_openable(
        "control_gc_refuses_a_root_whose_current_namespace_it_cannot_open",
        &root.path().join(&current),
    ) else {
        return;
    };

    let error = RollbackBacking::collect_remote(root.path(), writer.as_ref()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(root.path().join(&stale).join("rollback.lock").is_file());

    drop(modes);
    set_mode(&root.path().join(&current), 0o700);
    let report = RollbackBacking::collect_remote(root.path(), writer.as_ref()).unwrap();
    assert_eq!(report.removed, [stale]);
}

/// Every event logged in this test process, with the thread that logged it.
static EVENTS: Mutex<Vec<(std::thread::ThreadId, String)>> = Mutex::new(Vec::new());

/// The events the calling thread logs while `run` runs, each as its level,
/// target and fields in one line. The subscriber is installed once for the
/// whole process: one scoped to a thread can miss an event whose callsite
/// another test's thread reached first, without a subscriber.
fn logged<T>(run: impl FnOnce() -> T) -> (T, Vec<String>) {
    use std::fmt::Write;
    use tracing::field::{Field, Visit};
    use tracing::span;

    struct Line(String);
    impl Visit for Line {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            write!(self.0, " {}={value:?}", field.name()).unwrap();
        }
    }
    struct Capture;
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let metadata = event.metadata();
            let mut line = Line(format!("{} {}", metadata.level(), metadata.target()));
            event.record(&mut line);
            EVENTS
                .lock()
                .unwrap()
                .push((std::thread::current().id(), line.0));
        }
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
    }
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| tracing::subscriber::set_global_default(Capture).unwrap());
    let mine = || -> Vec<String> {
        let me = std::thread::current().id();
        let events = EVENTS.lock().unwrap();
        let mine = events.iter().filter(|(thread, _)| *thread == me);
        mine.map(|(_, line)| line.clone()).collect()
    };
    let before = mine().len();
    let result = run();
    (result, mine().split_off(before))
}

/// Nothing but the log reports the automatic pass after an activation, and
/// the activation succeeds whatever that pass could do.
#[test]
fn the_automatic_pass_logs_the_namespaces_it_could_not_examine() {
    let writer = authority();
    let root = tempfile::tempdir().unwrap();
    let created = RollbackBacking::create_remote(root.path(), writer.clone(), CAPACITY).unwrap();
    commit(&created, b"created");
    drop(created);
    // Without anything it cannot examine, the pass logs nothing.
    let (backing, events) =
        logged(|| RollbackBacking::open_remote(root.path(), writer.clone()).unwrap());
    assert_eq!(events, Vec::<String>::new());
    drop(backing);

    let odd = first_stale_name();
    std::fs::create_dir(root.path().join(&odd)).unwrap();
    std::fs::write(root.path().join(&odd).join("rollback.lock"), b"").unwrap();
    std::fs::create_dir(root.path().join(&odd).join("rollback.arena")).unwrap();
    let (backing, events) =
        logged(|| RollbackBacking::open_remote(root.path(), writer.clone()).unwrap());
    commit(&backing, b"attached");
    assert_eq!(events.len(), 1, "{events:#?}");
    assert!(
        events[0].starts_with("WARN maki_backing::rollback::remote ")
            && events[0].contains("automatic remote GC kept retired writer namespaces")
            && events[0].contains("count=1")
            && events[0].contains(&format!("namespace={odd}"))
            && events[0].contains("error=opening rollback.arena: Is a directory (os error 21)"),
        "{events:#?}"
    );
}

/// The authority of a writer whose activation was accepted, and which then
/// stops answering.
struct AnswersUntilActive {
    inner: Arc<dyn Rpc>,
    active: std::sync::atomic::AtomicBool,
}

impl Rpc for AnswersUntilActive {
    fn call(&self, request: &Request) -> io::Result<Record> {
        use std::sync::atomic::Ordering;
        if self.active.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the authority did not answer",
            ));
        }
        let record = self.inner.call(request)?;
        if matches!(request.action, Action::Activate { .. }) {
            self.active.store(true, Ordering::SeqCst);
        }
        Ok(record)
    }
}

#[test]
fn the_automatic_pass_logs_why_it_did_not_complete() {
    let writer = authority();
    let root = tempfile::tempdir().unwrap();
    let created = RollbackBacking::create_remote(root.path(), writer.clone(), CAPACITY).unwrap();
    commit(&created, b"created");
    drop(created);
    let predecessor = namespaces(root.path());
    let unanswered: Arc<dyn Rpc> = Arc::new(AnswersUntilActive {
        inner: writer.clone(),
        active: false.into(),
    });
    let (backing, events) = logged(|| RollbackBacking::open_remote(root.path(), unanswered));
    // The activation was accepted; only reclamation is postponed.
    let backing = backing.unwrap();
    assert_eq!(namespaces(root.path()).len(), 2);
    assert!(namespaces(root.path()).contains(&predecessor[0]));
    assert_eq!(events.len(), 1, "{events:#?}");
    assert!(
        events[0].starts_with("WARN maki_backing::rollback::remote ")
            && events[0].contains("automatic remote GC did not complete")
            && events[0].contains("error=the authority did not answer"),
        "{events:#?}"
    );
    // Its writer session cannot be released through this authority either.
    drop(backing);
}

const STEP: &str = "MAKI_GC_UNREADABLE_STEP";
const TOP: &str = "MAKI_GC_UNREADABLE_TOP";
const KILLED_TAKEOVER: &str =
    "gc_as_the_daemon_reclaims_past_the_namespace_a_killed_root_takeover_left";
/// Stands in for the daemon user. Distinct uid and gid, neither root's.
const DAEMON: (u32, u32) = (65534, 65533);
/// Exit status of a step that could not install its seccomp filter.
const NO_SECCOMP: i32 = 77;

/// The authority of the steps below, which run as different users in
/// separate processes: its state is one file that each of them may replace.
struct FileAuthority {
    path: PathBuf,
    role: Role,
}

impl Rpc for FileAuthority {
    fn call(&self, request: &Request) -> io::Result<Record> {
        let state = CanonicalState::decode(&std::fs::read(&self.path)?)?;
        let next = state.apply(self.role, request)?;
        if next != state {
            let staged = self.path.with_extension("next");
            std::fs::write(&staged, next.encode()?)?;
            set_mode(&staged, 0o666);
            std::fs::rename(&staged, &self.path)?;
        }
        Ok(next.record().clone())
    }
}

/// Kill this process at its first `fchown`: a root-run takeover creates the
/// new namespace directory and then gives it to the daemon user with that
/// call. False where seccomp filters are unavailable.
fn die_at_fchown() -> bool {
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
            libc::SYS_fchown as u32,
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
    // SAFETY: both calls affect only this thread, which runs the takeover;
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

/// One command of the volume's life, in the process and as the user the
/// test chose for it.
fn step(top: &Path, step: &str) {
    let root = top.join("root");
    let rpc = |role| -> Arc<dyn Rpc> {
        Arc::new(FileAuthority {
            path: top.join("authority/state"),
            role,
        })
    };
    match step {
        "probe" => {}
        // `maki volume create` and a daemon start and clean stop.
        "create" => {
            let backing =
                RollbackBacking::create_remote(&root, rpc(Role::Writer), CAPACITY).unwrap();
            commit(&backing, b"created");
        }
        "attach" => {
            let backing = RollbackBacking::open_remote(&root, rpc(Role::Writer)).unwrap();
            commit(&backing, b"attached");
        }
        // `maki volume takeover` with the administrator configuration.
        "takeover" | "killed-takeover" => {
            if step == "killed-takeover" && !die_at_fchown() {
                std::process::exit(NO_SECCOMP);
            }
            let admin = rpc(Role::Admin);
            let before = inspect(admin.as_ref());
            drop(RollbackBacking::takeover_remote(&root, admin, &before).unwrap());
        }
        // `maki volume gc`.
        "gc" => match RollbackBacking::collect_remote(&root, rpc(Role::Writer).as_ref()) {
            Ok(report) => {
                println!("gc: removed {}", report.counts.removed);
                for skipped in &report.skipped_unreadable {
                    println!("gc: unreadable {}: {}", skipped.name, skipped.error);
                }
            }
            Err(error) => println!("gc: failed: {error}"),
        },
        other => panic!("unknown step {other}"),
    }
}

fn run(top: &Path, step: &str, as_daemon: bool) -> io::Result<Output> {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            KILLED_TAKEOVER,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(STEP, step)
        .env(TOP, top);
    if as_daemon {
        command.uid(DAEMON.0).gid(DAEMON.1);
    }
    command.output()
}

fn must(top: &Path, step: &str, as_daemon: bool) -> String {
    let output = run(top, step, as_daemon).unwrap();
    assert!(
        output.status.success(),
        "{step} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The takeover, restore and enrollment-recovery commands run as root with
/// the administrator key and create the new writer namespace for the daemon
/// user: `mkdirat`, then `fchown`. Killed in between, the takeover leaves an
/// empty root-owned `0700` namespace directory. The rerun completes, and
/// from then on the daemon user's GC meets a lower-fence namespace it may
/// not open before every predecessor it has to retire.
#[test]
fn gc_as_the_daemon_reclaims_past_the_namespace_a_killed_root_takeover_left() {
    if let (Some(name), Some(top)) = (std::env::var_os(STEP), std::env::var_os(TOP)) {
        return step(Path::new(&top), name.to_str().unwrap());
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("{KILLED_TAKEOVER}: skipped: acting as root and as the daemon user needs root");
        return;
    }
    let top = tempfile::tempdir().unwrap();
    set_mode(top.path(), 0o755);
    // The daemon user's backing root, as `install -d -o maki -g maki -m 0700`.
    let root = top.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::os::unix::fs::chown(&root, Some(DAEMON.0), Some(DAEMON.1)).unwrap();
    set_mode(&root, 0o700);
    let authority = top.path().join("authority");
    std::fs::create_dir(&authority).unwrap();
    set_mode(&authority, 0o777);
    std::fs::write(
        authority.join("state"),
        CanonicalState::initial(IDENTITY).unwrap().encode().unwrap(),
    )
    .unwrap();
    set_mode(&authority.join("state"), 0o666);
    match run(top.path(), "probe", true) {
        Ok(output) if output.status.success() => {}
        failed => {
            eprintln!(
                "{KILLED_TAKEOVER}: skipped: cannot run this test binary as uid {} ({failed:?})",
                DAEMON.0
            );
            return;
        }
    }

    must(top.path(), "create", true);
    let killed = run(top.path(), "killed-takeover", false).unwrap();
    if killed.status.code() == Some(NO_SECCOMP) {
        eprintln!("{KILLED_TAKEOVER}: skipped: seccomp filters are unavailable");
        return;
    }
    assert_eq!(
        killed.status.signal(),
        Some(libc::SIGSYS),
        "the takeover must die at its fchown: {killed:?}"
    );
    let leftover: Vec<String> = namespaces(&root)
        .into_iter()
        .filter(|name| std::fs::metadata(root.join(name)).unwrap().uid() == 0)
        .collect();
    assert_eq!(leftover.len(), 1, "{leftover:?}");
    let metadata = std::fs::metadata(root.join(&leftover[0])).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    assert_eq!(
        std::fs::read_dir(root.join(&leftover[0])).unwrap().count(),
        0
    );

    // The administrator runs the takeover again, and the daemon starts and
    // stops three times. Every command succeeds.
    must(top.path(), "takeover", false);
    for _ in 0..3 {
        must(top.path(), "attach", true);
    }
    let gc = must(top.path(), "gc", true);
    let left = namespaces(&root);
    assert!(
        gc.contains("gc: removed") && left.len() == 2,
        "only the current namespace and the leftover may remain: {left:#?}\n{gc}"
    );
    assert!(left.contains(&leftover[0]));
    // The daemon user is told which entry it could not examine and why.
    assert!(
        gc.contains(&format!(
            "gc: unreadable {}: opening the namespace directory: Permission denied",
            leftover[0]
        )),
        "{gc}"
    );
}
