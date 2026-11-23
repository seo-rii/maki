//! Audit round 5 (remote-admin-crash): crash-image replay of the REMOTE
//! rollback mode's volume host. Not part of the maintained suite.
//!
//! Remote mode writes its physical root through the concrete `FileBacking`,
//! so `CrashableBacking` cannot host it. This harness records what the real
//! code does instead (the approach of ALICE / CrashMonkey):
//!
//! 1. A child (this test binary re-executed under `strace -f -y -xx`) runs a
//!    scripted volume life cycle with the real `RollbackBacking` remote
//!    entry points (create, attach, commits, takeover, snapshot, restore,
//!    GC, enrollment recovery) against an in-process authority built on the
//!    real `CanonicalState` state machine. Every authority mutation and every
//!    oracle event is a marker syscall, so its position in the trace is exact.
//! 2. The parent parses the trace into filesystem operations and replays
//!    them into a model that keeps, for every file and directory, the
//!    volatile (page cache) and the durable (fsynced) state.
//! 3. For a cut after every operation it materializes crash images on tmpfs:
//!    `All` (process death: everything written is still there), `Synced`
//!    (power loss: only fsynced bytes and directory entries), and seeded
//!    `Random` images (any prefix of a directory's unsynced entry changes,
//!    any subset of a file's unsynced writes, torn at 512 bytes). The
//!    authority is the state it had at the cut: the cut right after an
//!    authority marker is "the mutation applied, its reply never arrived".
//! 4. Every legal continuation then runs on the real code in this process:
//!    administrator takeover (+ a commit, release, GC, ordinary attach), an
//!    ordinary attach, GC first, restore of an approved snapshot, and for a
//!    never-activated authority `create` or enrollment recovery.
//!
//! Oracle: an enrolled authority's current generation must always be
//! recoverable (takeover succeeds and the files hash to what the last
//! acknowledged or in-flight sync wrote); an ordinary attach must work
//! exactly when the authority is released; an unenrolled root must be
//! completed by `create` or by enrollment recovery (a state that both refuse
//! is reported as a strand).
//!
//! `AUDIT5_PLANT=<class>` removes one class of fsync from the *model*
//! (`arena`, `manifest`, `nsdir`, `root`, `marker`, `enrollment`,
//! `snapjson`) or corrupts the expected view (`view`), to show the oracle
//! fails when the code would not sync.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{
    Action, CanonicalState, Descriptor, Phase, Record, Request, Role, Rpc,
};
use maki_backing::{Backing, FileBacking, RollbackBacking};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PAGE: u64 = 4096;
const CAPACITY: u64 = 16 * PAGE;
const IDENTITY: [u8; 16] = [0xA5; 16];
const FILES: [(&str, u64); 3] = [("data/a", 3), ("data/b", 3), ("meta", 2)];

type View = BTreeMap<String, String>;

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn view_of(files: &BTreeMap<String, Vec<u8>>) -> View {
    files
        .iter()
        .map(|(name, bytes)| (name.clone(), sha(bytes)))
        .collect()
}

// ---------------------------------------------------------------------------
// The authority: the real state machine, with trace markers in the child.

#[derive(Serialize, Deserialize, Clone, Debug)]
enum Event {
    /// The authority now holds this encoded `CanonicalState`.
    Authority(Vec<u8>),
    Step(String),
    /// A call that may commit follows. `view` is what the durable files
    /// hash to if it commits (only for plain `sync_data` commits).
    Intent {
        view: Option<View>,
    },
    /// The call returned success; `root` is the authority's current root.
    Ack {
        root: Option<Vec<u8>>,
        view: View,
    },
    /// The snapshot command completed and its descriptor was "approved".
    Snapshot {
        descriptor: Descriptor,
        view: View,
    },
}

struct Recorder {
    marks: PathBuf,
    events: Mutex<Vec<Event>>,
}

impl Recorder {
    fn mark(&self, event: Event) {
        let mut events = self.events.lock().unwrap();
        // One syscall whose path names the event index.
        std::fs::create_dir(self.marks.join(events.len().to_string())).unwrap();
        events.push(event);
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    /// The request never reaches the authority.
    Unreachable,
    /// The authority applies it; the reply never arrives.
    LostReply,
}

struct Authority {
    state: Mutex<CanonicalState>,
    recorder: Option<Arc<Recorder>>,
    /// A writer that died does not release.
    release_blocked: AtomicBool,
    /// Fault for every request of this action name from now on.
    fault: Mutex<(String, Fault)>,
    mutations: AtomicUsize,
}

impl Authority {
    fn new(state: CanonicalState, recorder: Option<Arc<Recorder>>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(state),
            recorder,
            release_blocked: AtomicBool::new(false),
            fault: Mutex::new((String::new(), Fault::None)),
            mutations: AtomicUsize::new(0),
        })
    }
    fn record(&self) -> Record {
        self.state.lock().unwrap().record().clone()
    }
    fn root(&self) -> Option<Vec<u8>> {
        self.record().current.map(|c| c.anchor.root.to_vec())
    }
    fn rpc(self: &Arc<Self>, role: Role) -> Arc<dyn Rpc> {
        Arc::new(RoleRpc {
            authority: self.clone(),
            role,
        })
    }
}

fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Inspect => "inspect",
        Action::Claim => "claim",
        Action::Takeover => "takeover",
        Action::RecoverEnrollment => "recover",
        Action::ClaimRestore { .. } => "claim_restore",
        Action::Activate { .. } => "activate",
        Action::Advance { .. } => "advance",
        Action::Release => "release",
    }
}

struct RoleRpc {
    authority: Arc<Authority>,
    role: Role,
}

impl Rpc for RoleRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        let name = action_name(&request.action);
        if name == "release" && self.authority.release_blocked.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "writer died"));
        }
        let fault = {
            let fault = self.authority.fault.lock().unwrap();
            if fault.0 == name {
                fault.1
            } else {
                Fault::None
            }
        };
        if fault == Fault::Unreachable {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "unreachable"));
        }
        let mut state = self.authority.state.lock().unwrap();
        let next = state.apply(self.role, request)?;
        if next != *state {
            *state = next;
            self.authority.mutations.fetch_add(1, Ordering::SeqCst);
            if let Some(recorder) = &self.authority.recorder {
                recorder.mark(Event::Authority(state.encode().unwrap()));
            }
        }
        if fault == Fault::LostReply {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "lost reply"));
        }
        Ok(state.record().clone())
    }
}

fn inspect(rpc: &dyn Rpc) -> io::Result<Record> {
    rpc.call(&Request {
        operation_id: [0; 16],
        expected: None,
        action: Action::Inspect,
        authorization: None,
    })
}

// ---------------------------------------------------------------------------
// Workload shared by the child (recording) and the parent (continuations).

fn pattern(counter: u64, len: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(0xA5A5_0000 + counter);
    (0..len).map(|_| rng.random()).collect()
}

fn read_all(backing: &dyn Backing) -> io::Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    for (name, pages) in FILES {
        let file = backing.open(name, false)?;
        let len = file.len()?;
        if len != pages * PAGE {
            return Err(io::Error::other(format!("{name}: length {len}")));
        }
        let mut bytes = vec![0; len as usize];
        file.read_at(0, &mut bytes)?;
        files.insert(name.to_string(), bytes);
    }
    Ok(files)
}

struct Script {
    top: PathBuf,
    authority: Arc<Authority>,
    recorder: Arc<Recorder>,
    durable: BTreeMap<String, Vec<u8>>,
    counter: u64,
}

impl Script {
    fn root(&self) -> PathBuf {
        self.top.join("fs/root")
    }
    fn snap(&self) -> PathBuf {
        self.top.join("fs/snap")
    }
    fn step(&self, name: &str) {
        self.recorder.mark(Event::Step(name.into()));
    }
    fn ack(&self) {
        self.recorder.mark(Event::Ack {
            root: self.authority.root(),
            view: view_of(&self.durable),
        });
    }
    fn setup(&mut self, backing: &dyn Backing) {
        self.recorder.mark(Event::Intent { view: None });
        backing.create_dir_all("data").unwrap();
        for (name, pages) in FILES {
            let file = backing.open(name, true).unwrap();
            file.allocate_range(0, pages * PAGE).unwrap();
            file.sync_data().unwrap();
            self.durable
                .insert(name.to_string(), vec![0; (pages * PAGE) as usize]);
        }
        backing.sync_dir("data").unwrap();
        backing.sync_dir("").unwrap();
        self.ack();
    }
    /// One write and its durable barrier, as a FLUSH would do.
    fn round(&mut self, backing: &dyn Backing) {
        let (name, pages) = FILES[(self.counter % 3) as usize];
        let file = backing.open(name, false).unwrap();
        let (offset, len) = match self.counter % 4 {
            // A whole page, two pages, and partial pages (read-modify-write).
            0 => (((self.counter / 3) % pages) * PAGE, PAGE as usize),
            1 => (0, 2 * PAGE as usize),
            2 => (PAGE + 100, 1000),
            _ => ((pages - 1) * PAGE + 4000, 96),
        };
        let data = pattern(self.counter, len);
        file.write_at(offset, &data).unwrap();
        let mut candidate = self.durable.clone();
        candidate.get_mut(name).unwrap()[offset as usize..offset as usize + len]
            .copy_from_slice(&data);
        self.recorder.mark(Event::Intent {
            view: Some(view_of(&candidate)),
        });
        file.sync_data().unwrap();
        self.durable = candidate;
        self.ack();
        self.counter += 1;
    }
    fn verify(&self, backing: &dyn Backing) {
        assert_eq!(
            view_of(&read_all(backing).unwrap()),
            view_of(&self.durable),
            "child: reopened content differs"
        );
    }
    /// The daemon dies: nothing is released.
    fn die(&self, backing: RollbackBacking) {
        self.authority.release_blocked.store(true, Ordering::SeqCst);
        drop(backing);
        self.authority.release_blocked.store(false, Ordering::SeqCst);
    }
    fn takeover(&self) {
        let admin = self.authority.rpc(Role::Admin);
        let before = inspect(admin.as_ref()).unwrap();
        let backing = RollbackBacking::takeover_remote(&self.root(), admin.clone(), &before).unwrap();
        drop(backing);
        let after = inspect(admin.as_ref()).unwrap();
        assert_eq!(after.phase, Phase::Released);
        assert_eq!(after.fence, before.fence + 1);
    }
}

/// `maki volume snapshot`, as `bins/maki/src/main.rs` sequences it.
fn snapshot_command(root: &Path, target: &Path, writer: Arc<dyn Rpc>) -> io::Result<Descriptor> {
    RollbackBacking::check_snapshot_destination(target)?;
    let backing = RollbackBacking::open_remote(root, writer.clone())?;
    let descriptor = backing.snapshot_remote(target)?;
    let bytes = serde_json::to_vec(&descriptor).map_err(io::Error::other)?;
    let disk = FileBacking::new(target)?;
    let _lock = disk.try_lock("snapshot.lock")?;
    if disk.exists("snapshot.json")? {
        return Err(io::Error::other("snapshot descriptor already exists"));
    }
    let file = disk.open("snapshot.json", true)?;
    file.write_at(0, &bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_data()?;
    disk.sync_dir("")?;
    drop(backing);
    let released = inspect(writer.as_ref())?;
    if released.phase != Phase::Released || released.current.as_ref() != Some(&descriptor) {
        return Err(io::Error::other("release not confirmed"));
    }
    Ok(descriptor)
}

/// `read_snapshot` of `bins/maki/src/main.rs`.
fn read_snapshot(directory: &Path) -> io::Result<Descriptor> {
    let disk = FileBacking::read_only(directory)?;
    let file = disk.open("snapshot.json", false)?;
    let length = file.len()?;
    if length == 0 || length > 64 * 1024 {
        return Err(io::Error::other("invalid snapshot descriptor size"));
    }
    let mut bytes = vec![0; length as usize];
    file.read_at(0, &mut bytes)?;
    let descriptor: Descriptor =
        serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid descriptor"))?;
    descriptor.validate()?;
    if serde_json::to_vec(&descriptor).map_err(io::Error::other)? != bytes {
        return Err(io::Error::other("descriptor not canonical"));
    }
    Ok(descriptor)
}

fn run_child(scenario: &str, top: &Path) {
    let recorder = Arc::new(Recorder {
        marks: top.join("meta/marks"),
        events: Mutex::new(Vec::new()),
    });
    let authority = Authority::new(
        CanonicalState::initial(IDENTITY).unwrap(),
        Some(recorder.clone()),
    );
    let writer = authority.rpc(Role::Writer);
    let admin = authority.rpc(Role::Admin);
    let mut script = Script {
        top: top.to_path_buf(),
        authority: authority.clone(),
        recorder: recorder.clone(),
        durable: BTreeMap::new(),
        counter: 0,
    };
    let root = script.root();
    match scenario {
        "lifecycle" => {
            script.step("create");
            let backing = RollbackBacking::create_remote(&root, writer.clone(), CAPACITY).unwrap();
            script.setup(&backing);
            script.round(&backing);
            script.round(&backing);
            script.step("release");
            drop(backing);
            script.step("attach2");
            let backing = RollbackBacking::open_remote(&root, writer.clone()).unwrap();
            script.verify(&backing);
            for _ in 0..3 {
                script.round(&backing);
            }
            script.step("daemon-dies");
            script.die(backing);
            script.step("takeover");
            script.takeover();
            script.step("snapshot");
            let descriptor = snapshot_command(&root, &script.snap(), writer.clone()).unwrap();
            recorder.mark(Event::Snapshot {
                descriptor: descriptor.clone(),
                view: view_of(&script.durable),
            });
            let snapshot_files = script.durable.clone();
            script.step("attach3");
            let backing = RollbackBacking::open_remote(&root, writer.clone()).unwrap();
            script.verify(&backing);
            for _ in 0..3 {
                script.round(&backing);
            }
            script.step("daemon-dies-2");
            script.die(backing);
            script.step("takeover2");
            script.takeover();
            script.step("restore");
            let before = inspect(admin.as_ref()).unwrap();
            let source = read_snapshot(&script.snap()).unwrap();
            assert_eq!(source, descriptor);
            recorder.mark(Event::Intent {
                view: Some(view_of(&snapshot_files)),
            });
            let backing = RollbackBacking::restore_remote(
                &root,
                &script.snap(),
                &source,
                admin.clone(),
                &before,
            )
            .unwrap();
            script.durable = snapshot_files;
            script.ack();
            drop(backing);
            script.step("attach4");
            let backing = RollbackBacking::open_remote(&root, writer.clone()).unwrap();
            script.verify(&backing);
            script.round(&backing);
            script.round(&backing);
            script.step("release4");
            drop(backing);
            script.step("gc");
            RollbackBacking::collect_remote(&root, writer.as_ref()).unwrap();
        }
        // The authority applies the first claim and every reply is lost,
        // then the administrator resumes the enrollment.
        "enroll-claim-lost" | "enroll-unreachable" | "enroll-activate-lost" => {
            script.step("create-fails");
            let (action, fault) = match scenario {
                "enroll-claim-lost" => ("claim", Fault::LostReply),
                "enroll-unreachable" => ("claim", Fault::Unreachable),
                _ => ("activate", Fault::LostReply),
            };
            *authority.fault.lock().unwrap() = (action.into(), fault);
            assert!(RollbackBacking::create_remote(&root, writer.clone(), CAPACITY).is_err());
            *authority.fault.lock().unwrap() = (String::new(), Fault::None);
            let before = inspect(admin.as_ref()).unwrap();
            if scenario == "enroll-activate-lost" {
                // The descriptor activated: ordinary exact-current takeover.
                assert!(before.current.is_some());
                script.step("takeover");
                script.takeover();
                script.step("attach");
                let backing = RollbackBacking::open_remote(&root, writer.clone()).unwrap();
                script.setup(&backing);
                script.round(&backing);
                drop(backing);
            } else {
                script.step("resume");
                let backing = RollbackBacking::recover_enrollment_remote(
                    &root,
                    admin.clone(),
                    CAPACITY,
                    &before,
                )
                .unwrap();
                script.setup(&backing);
                script.round(&backing);
                script.step("release");
                drop(backing);
                // A second interrupted recovery, then a third that completes.
            }
            script.step("gc");
            RollbackBacking::collect_remote(&root, writer.as_ref()).unwrap();
        }
        // Enrollment recovery is itself interrupted after its claim.
        "enroll-resume-twice" => {
            script.step("create-fails");
            *authority.fault.lock().unwrap() = ("claim".into(), Fault::LostReply);
            assert!(RollbackBacking::create_remote(&root, writer.clone(), CAPACITY).is_err());
            script.step("resume-fails");
            *authority.fault.lock().unwrap() = ("activate".into(), Fault::Unreachable);
            let before = inspect(admin.as_ref()).unwrap();
            assert!(RollbackBacking::recover_enrollment_remote(
                &root,
                admin.clone(),
                CAPACITY,
                &before
            )
            .is_err());
            *authority.fault.lock().unwrap() = (String::new(), Fault::None);
            script.step("resume");
            let before = inspect(admin.as_ref()).unwrap();
            let backing =
                RollbackBacking::recover_enrollment_remote(&root, admin.clone(), CAPACITY, &before)
                    .unwrap();
            script.setup(&backing);
            script.round(&backing);
            script.step("release");
            drop(backing);
        }
        // Administrative operations that themselves fail part-way, so later
        // cuts start from several stale namespaces and from the Claimed and
        // RestoreClaimed phases.
        "messy" => {
            let set_fault = |action: &str, fault: Fault| {
                *authority.fault.lock().unwrap() = (action.into(), fault);
            };
            script.step("create");
            let backing = RollbackBacking::create_remote(&root, writer.clone(), CAPACITY).unwrap();
            script.setup(&backing);
            script.round(&backing);
            drop(backing);
            script.step("snapshot");
            let descriptor = snapshot_command(&root, &script.snap(), writer.clone()).unwrap();
            recorder.mark(Event::Snapshot {
                descriptor: descriptor.clone(),
                view: view_of(&script.durable),
            });
            let snapshot_files = script.durable.clone();
            script.step("attach");
            let backing = RollbackBacking::open_remote(&root, writer.clone()).unwrap();
            script.round(&backing);
            script.round(&backing);
            script.step("daemon-dies");
            script.die(backing);
            script.step("takeover-activate-reply-lost");
            set_fault("activate", Fault::LostReply);
            let before = inspect(admin.as_ref()).unwrap();
            assert!(RollbackBacking::takeover_remote(&root, admin.clone(), &before).is_err());
            script.step("takeover-activate-unreachable");
            set_fault("activate", Fault::Unreachable);
            let before = inspect(admin.as_ref()).unwrap();
            assert!(RollbackBacking::takeover_remote(&root, admin.clone(), &before).is_err());
            script.step("restore-activate-unreachable");
            let before = inspect(admin.as_ref()).unwrap();
            assert!(RollbackBacking::restore_remote(
                &root,
                &script.snap(),
                &descriptor,
                admin.clone(),
                &before
            )
            .is_err());
            set_fault("", Fault::None);
            script.step("gc-while-restore-claimed");
            RollbackBacking::collect_remote(&root, writer.as_ref()).unwrap();
            script.step("restore-claim-reply-lost");
            set_fault("claim_restore", Fault::LostReply);
            let before = inspect(admin.as_ref()).unwrap();
            assert!(RollbackBacking::restore_remote(
                &root,
                &script.snap(),
                &descriptor,
                admin.clone(),
                &before
            )
            .is_err());
            set_fault("", Fault::None);
            script.step("takeover");
            script.takeover();
            script.step("attach2");
            let backing = RollbackBacking::open_remote(&root, writer.clone()).unwrap();
            script.verify(&backing);
            script.round(&backing);
            script.step("daemon-dies-2");
            script.die(backing);
            script.step("restore");
            let before = inspect(admin.as_ref()).unwrap();
            recorder.mark(Event::Intent {
                view: Some(view_of(&snapshot_files)),
            });
            let backing = RollbackBacking::restore_remote(
                &root,
                &script.snap(),
                &descriptor,
                admin.clone(),
                &before,
            )
            .unwrap();
            script.durable = snapshot_files;
            script.ack();
            drop(backing);
            script.step("attach3");
            let backing = RollbackBacking::open_remote(&root, writer.clone()).unwrap();
            script.verify(&backing);
            script.round(&backing);
            drop(backing);
            script.step("gc");
            RollbackBacking::collect_remote(&root, writer.as_ref()).unwrap();
        }
        // Local witness mode: the witness directory is on the same host
        // and loses its unsynced state in the same power loss.
        "local" => {
            let wit = top.join("fs/wit");
            script.step("create");
            let backing = RollbackBacking::create(&root, &wit, CAPACITY).unwrap();
            script.step("created");
            script.setup(&backing);
            for _ in 0..3 {
                script.round(&backing);
            }
            script.step("close");
            drop(backing);
            script.step("open2");
            let backing = RollbackBacking::open(&root, &wit).unwrap();
            script.verify(&backing);
            for _ in 0..3 {
                script.round(&backing);
            }
            script.step("close2");
            drop(backing);
            // A leftover `anchor.next` (a publication that failed before its
            // rename): #344 unlinks it before writing the next record.
            {
                let disk = FileBacking::new(&wit).unwrap();
                let file = disk.open("anchor.next", true).unwrap();
                file.write_at(0, &[0x5A; 104]).unwrap();
                file.sync_data().unwrap();
                disk.sync_dir("").unwrap();
            }
            script.step("open3-leftover-temporary");
            let backing = RollbackBacking::open(&root, &wit).unwrap();
            script.verify(&backing);
            for _ in 0..3 {
                script.round(&backing);
            }
            drop(backing);
        }
        other => panic!("unknown scenario {other}"),
    }
    let events = recorder.events.lock().unwrap();
    std::fs::write(
        top.join("meta/events.json"),
        serde_json::to_vec(&*events).unwrap(),
    )
    .unwrap();
}

/// Entry point of the traced child; a no-op in an ordinary test run.
#[test]
fn audit5_child() {
    let (Ok(scenario), Ok(top)) = (std::env::var("AUDIT5_CHILD"), std::env::var("AUDIT5_TOP"))
    else {
        return;
    };
    run_child(&scenario, Path::new(&top));
}

// ---------------------------------------------------------------------------
// Trace parsing.

#[derive(Debug, Clone)]
enum Op {
    Mark(usize),
    Create(String),
    Mkdir(String),
    Unlink(String),
    Rename(String, String),
    Write(String, u64, Vec<u8>),
    Truncate(String, u64),
    Allocate(String, u64),
    Sync(String),
}

/// strace -xx prints every byte of a string or path as \xNN; anything else
/// (a pipe or socket label) is not a path.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4);
    let mut at = 0;
    while at < bytes.len() {
        if at + 4 > bytes.len() || bytes[at] != b'\\' || bytes[at + 1] != b'x' {
            return None;
        }
        out.push(u8::from_str_radix(&text[at + 2..at + 4], 16).ok()?);
        at += 4;
    }
    Some(out)
}

fn split_args(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut quoted = false;
    let mut current = String::new();
    for ch in args.chars() {
        match ch {
            '"' => quoted = !quoted,
            '<' | '{' | '[' if !quoted => depth += 1,
            '>' | '}' | ']' if !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => {
                out.push(current.trim().to_string());
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

/// The path strace -y attached to a descriptor argument.
fn fd_path(arg: &str) -> Option<String> {
    let start = arg.find('<')?;
    let end = arg.rfind('>')?;
    String::from_utf8(unhex(&arg[start + 1..end])?).ok()
}

fn quoted(arg: &str) -> Vec<u8> {
    let start = arg.find('"').expect("string argument");
    let end = arg.rfind('"').unwrap();
    assert!(
        !arg[end..].contains("..."),
        "truncated string in trace; raise -s"
    );
    unhex(&arg[start + 1..end]).expect("hex-escaped string")
}

fn join(dir: &str, name: &[u8]) -> String {
    let name = String::from_utf8(name.to_vec()).unwrap();
    if name.starts_with('/') {
        name
    } else {
        format!("{dir}/{name}")
    }
}

fn parse_trace(trace: &str, top: &str) -> Vec<Op> {
    let tracked = format!("{top}/fs");
    let marks = format!("{top}/meta/marks/");
    let mut pending: HashMap<String, String> = HashMap::new();
    let mut ops = Vec::new();
    for line in trace.lines() {
        let Some((pid, rest)) = line.split_once(' ') else {
            continue;
        };
        let rest = rest.trim_start();
        let call = if let Some(prefix) = rest.strip_suffix(" <unfinished ...>") {
            pending.insert(pid.to_string(), prefix.to_string());
            continue;
        } else if let Some(resumed) = rest.strip_prefix("<... ") {
            let (_, tail) = resumed.split_once(" resumed>").expect("resumed line");
            let Some(prefix) = pending.remove(pid) else {
                continue;
            };
            format!("{prefix}{tail}")
        } else {
            rest.to_string()
        };
        if call.starts_with("---") || call.starts_with("+++") {
            continue;
        }
        let Some(open) = call.find('(') else { continue };
        let Some(close) = call.rfind(") = ") else {
            continue;
        };
        let name = &call[..open];
        let result = call[close + 4..].trim();
        if result.starts_with('-') || result.starts_with('?') {
            continue;
        }
        let args = split_args(&call[open + 1..close]);
        let inside = |path: &str| path == tracked || path.starts_with(&format!("{tracked}/"));
        match name {
            "mkdir" => {
                let path = String::from_utf8(quoted(&args[0])).unwrap();
                if let Some(index) = path.strip_prefix(&marks) {
                    ops.push(Op::Mark(index.parse().unwrap()));
                } else {
                    assert!(!inside(&path), "unexpected mkdir {path}");
                }
            }
            "mkdirat" => {
                let path = join(&fd_path(&args[0]).unwrap_or_default(), &quoted(&args[1]));
                if let Some(index) = path.strip_prefix(&marks) {
                    ops.push(Op::Mark(index.parse().unwrap()));
                } else if inside(&path) {
                    ops.push(Op::Mkdir(path));
                }
            }
            "openat" => {
                if !args[2].contains("O_CREAT") {
                    continue;
                }
                assert!(
                    !args[2].contains("O_TRUNC") || !fd_path(result).is_some_and(|p| inside(&p)),
                    "unexpected O_TRUNC in the tracked tree"
                );
                let path = fd_path(result).expect("opened path");
                if inside(&path) {
                    ops.push(Op::Create(path));
                }
            }
            "unlinkat" => {
                let path = join(&fd_path(&args[0]).unwrap_or_default(), &quoted(&args[1]));
                if inside(&path) {
                    ops.push(Op::Unlink(path));
                }
            }
            "renameat" | "renameat2" => {
                let from = join(&fd_path(&args[0]).unwrap_or_default(), &quoted(&args[1]));
                let to = join(&fd_path(&args[2]).unwrap_or_default(), &quoted(&args[3]));
                if inside(&from) || inside(&to) {
                    ops.push(Op::Rename(from, to));
                }
            }
            "pwrite64" => {
                let Some(path) = fd_path(&args[0]) else {
                    continue;
                };
                if inside(&path) {
                    let written: usize = result
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let mut data = quoted(&args[1]);
                    data.truncate(written);
                    ops.push(Op::Write(path, args[3].parse().unwrap(), data));
                }
            }
            "ftruncate" => {
                let Some(path) = fd_path(&args[0]) else {
                    continue;
                };
                if inside(&path) {
                    ops.push(Op::Truncate(path, args[1].parse().unwrap()));
                }
            }
            "fallocate" => {
                let Some(path) = fd_path(&args[0]) else {
                    continue;
                };
                if inside(&path) {
                    assert_eq!(args[1], "0", "unexpected fallocate mode");
                    let offset: u64 = args[2].parse().unwrap();
                    let len: u64 = args[3].parse().unwrap();
                    ops.push(Op::Allocate(path, offset + len));
                }
            }
            "fsync" | "fdatasync" => {
                let Some(path) = fd_path(&args[0]) else {
                    continue;
                };
                if inside(&path) {
                    ops.push(Op::Sync(path));
                }
            }
            // Anything else that could change the tracked tree is a hole in
            // the model: fail loudly instead of replaying a wrong image.
            "write" | "writev" | "pwritev" | "pwritev2" | "fchown" | "fchmod"
            | "sync_file_range" => {
                if let Some(path) = fd_path(&args[0]) {
                    assert!(!inside(&path), "unmodelled {name} on {path}");
                }
            }
            "open" | "creat" | "unlink" | "rename" | "link" | "linkat" | "symlink"
            | "symlinkat" | "truncate" | "fchownat" => {
                assert!(
                    !call.contains(&hexed(&tracked)),
                    "unmodelled {name} in the tracked tree: {call:.200}"
                );
            }
            _ => {}
        }
    }
    ops
}

fn hexed(text: &str) -> String {
    text.bytes().map(|b| format!("\\x{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// The filesystem model: volatile and durable state of every object.

#[derive(Clone, Default, PartialEq, Debug)]
struct Content {
    len: u64,
    pages: BTreeMap<u64, Vec<u8>>,
}

impl Content {
    fn write(&mut self, offset: u64, data: &[u8]) {
        let mut at = 0usize;
        while at < data.len() {
            let position = offset + at as u64;
            let page = position / PAGE;
            let start = (position % PAGE) as usize;
            let count = (PAGE as usize - start).min(data.len() - at);
            let bytes = self
                .pages
                .entry(page)
                .or_insert_with(|| vec![0; PAGE as usize]);
            bytes[start..start + count].copy_from_slice(&data[at..at + count]);
            at += count;
        }
        self.len = self.len.max(offset + data.len() as u64);
    }
    fn set_len(&mut self, len: u64) {
        if len < self.len {
            self.pages.retain(|page, _| *page * PAGE < len);
            if len % PAGE != 0 {
                if let Some(bytes) = self.pages.get_mut(&(len / PAGE)) {
                    bytes[(len % PAGE) as usize..].fill(0);
                }
            }
        }
        self.len = len;
    }
}

#[derive(Clone, Debug)]
enum DirOp {
    Link(String, usize),
    Unlink(String),
    Rename(String, String),
}

#[derive(Clone, Debug)]
enum FileOp {
    Write(u64, Vec<u8>),
    Truncate(u64),
    Extend(u64),
}

enum Node {
    Dir {
        vol: BTreeMap<String, usize>,
        dur: BTreeMap<String, usize>,
        pending: Vec<DirOp>,
    },
    File {
        vol: Content,
        dur: Content,
        pending: Vec<FileOp>,
    },
}

fn apply_dir(entries: &mut BTreeMap<String, usize>, op: &DirOp) {
    match op {
        DirOp::Link(name, id) => {
            entries.insert(name.clone(), *id);
        }
        DirOp::Unlink(name) => {
            entries.remove(name);
        }
        DirOp::Rename(from, to) => {
            if let Some(id) = entries.remove(from) {
                entries.insert(to.clone(), id);
            }
        }
    }
}

fn apply_file(content: &mut Content, op: &FileOp) {
    match op {
        FileOp::Write(offset, data) => content.write(*offset, data),
        FileOp::Truncate(len) => content.set_len(*len),
        FileOp::Extend(end) => {
            if *end > content.len {
                content.set_len(*end);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Model {
    /// Process death: the page cache survives.
    All,
    /// Power loss: only what an fsync covered.
    Synced,
    /// Power loss: a seeded choice among the unsynced effects.
    Random(u64),
}

enum Item {
    Dir,
    File(Content),
}

struct Fs {
    top_fs: String,
    nodes: Vec<Node>,
    /// A class of fsync the planted bug "forgets".
    plant: String,
    /// Operations on paths the model does not know (unlinked files).
    unknown: usize,
}

impl Fs {
    fn new(top: &str, plant: &str) -> Self {
        let mut fs = Self {
            top_fs: format!("{top}/fs"),
            nodes: Vec::new(),
            plant: plant.to_string(),
            unknown: 0,
        };
        // `fs` and the operator-created `fs/root` exist durably.
        let root = Node::Dir {
            vol: BTreeMap::new(),
            dur: BTreeMap::new(),
            pending: Vec::new(),
        };
        fs.nodes.push(Node::Dir {
            vol: BTreeMap::from([("root".to_string(), 1)]),
            dur: BTreeMap::from([("root".to_string(), 1)]),
            pending: Vec::new(),
        });
        fs.nodes.push(root);
        fs
    }

    /// The local-mode witness directory: another filesystem, created by
    /// the operator before the volume.
    fn with_witness(mut self) -> Self {
        let id = self.nodes.len();
        self.nodes.push(Node::Dir {
            vol: BTreeMap::new(),
            dur: BTreeMap::new(),
            pending: Vec::new(),
        });
        if let Node::Dir { vol, dur, .. } = &mut self.nodes[0] {
            vol.insert("wit".to_string(), id);
            dur.insert("wit".to_string(), id);
        }
        self
    }

    fn lookup(&self, path: &str) -> Option<usize> {
        let relative = path.strip_prefix(&self.top_fs)?;
        let mut node = 0;
        for part in relative.split('/').filter(|part| !part.is_empty()) {
            match &self.nodes[node] {
                Node::Dir { vol, .. } => node = *vol.get(part)?,
                Node::File { .. } => return None,
            }
        }
        Some(node)
    }

    fn parent(&self, path: &str) -> Option<(usize, String)> {
        let (dir, name) = path.rsplit_once('/')?;
        Some((self.lookup(dir)?, name.to_string()))
    }

    fn dir_op(&mut self, dir: usize, op: DirOp) {
        if let Node::Dir { vol, pending, .. } = &mut self.nodes[dir] {
            apply_dir(vol, &op);
            pending.push(op);
        } else {
            panic!("directory operation on a file");
        }
    }

    fn file_op(&mut self, path: &str, op: FileOp) {
        match self.lookup(path) {
            Some(id) => {
                if let Node::File { vol, pending, .. } = &mut self.nodes[id] {
                    apply_file(vol, &op);
                    pending.push(op);
                } else {
                    panic!("file operation on a directory: {path}");
                }
            }
            None => self.unknown += 1,
        }
    }

    fn forgets(&self, path: &str, is_dir: bool) -> bool {
        let name = path.rsplit('/').next().unwrap_or("");
        let in_snapshot = path.contains("/fs/snap");
        match self.plant.as_str() {
            "arena" => name == "rollback.arena" && !in_snapshot,
            "manifest" => name.starts_with("rollback.manifest.") && !in_snapshot,
            "nsdir" => is_dir && name.starts_with("remote-") && !in_snapshot,
            "root" => is_dir && path.ends_with("/fs/root"),
            "marker" => name == "rollback.format" && !in_snapshot,
            "enrollment" => name == "remote.enrollment",
            "snapjson" => name == "snapshot.json",
            "snaparena" => name == "rollback.arena" && in_snapshot,
            "anchor" => name == "anchor.next",
            "witdir" => is_dir && path.ends_with("/fs/wit"),
            _ => false,
        }
    }

    fn apply(&mut self, op: &Op) {
        match op {
            Op::Mark(_) => {}
            Op::Create(path) => {
                if self.lookup(path).is_none() {
                    let (dir, name) = self.parent(path).expect("parent of created file");
                    let id = self.nodes.len();
                    self.nodes.push(Node::File {
                        vol: Content::default(),
                        dur: Content::default(),
                        pending: Vec::new(),
                    });
                    self.dir_op(dir, DirOp::Link(name, id));
                }
            }
            Op::Mkdir(path) => {
                let (dir, name) = self.parent(path).expect("parent of created directory");
                let id = self.nodes.len();
                self.nodes.push(Node::Dir {
                    vol: BTreeMap::new(),
                    dur: BTreeMap::new(),
                    pending: Vec::new(),
                });
                self.dir_op(dir, DirOp::Link(name, id));
            }
            Op::Unlink(path) => {
                let (dir, name) = self.parent(path).expect("parent of unlinked entry");
                self.dir_op(dir, DirOp::Unlink(name));
            }
            Op::Rename(from, to) => {
                let (dir, from) = self.parent(from).expect("rename source");
                let (target, to) = self.parent(to).expect("rename target");
                assert_eq!(dir, target, "cross-directory rename is not modelled");
                self.dir_op(dir, DirOp::Rename(from, to));
            }
            Op::Write(path, offset, data) => self.file_op(path, FileOp::Write(*offset, data.clone())),
            Op::Truncate(path, len) => self.file_op(path, FileOp::Truncate(*len)),
            Op::Allocate(path, end) => self.file_op(path, FileOp::Extend(*end)),
            Op::Sync(path) => {
                let Some(id) = self.lookup(path) else {
                    self.unknown += 1;
                    return;
                };
                let is_dir = matches!(self.nodes[id], Node::Dir { .. });
                if self.forgets(path, is_dir) {
                    return;
                }
                match &mut self.nodes[id] {
                    Node::Dir { vol, dur, pending } => {
                        *dur = vol.clone();
                        pending.clear();
                    }
                    Node::File { vol, dur, pending } => {
                        *dur = vol.clone();
                        pending.clear();
                    }
                }
            }
        }
    }

    fn has_pending(&self) -> bool {
        self.nodes.iter().any(|node| match node {
            Node::Dir { pending, .. } => !pending.is_empty(),
            Node::File { pending, .. } => !pending.is_empty(),
        })
    }

    fn image(&self, model: Model) -> BTreeMap<String, Item> {
        let mut rng = match model {
            Model::Random(seed) => Some(StdRng::seed_from_u64(seed)),
            _ => None,
        };
        let mut out = BTreeMap::new();
        self.walk(0, String::new(), model, &mut rng, &mut out);
        out
    }

    fn walk(
        &self,
        id: usize,
        prefix: String,
        model: Model,
        rng: &mut Option<StdRng>,
        out: &mut BTreeMap<String, Item>,
    ) {
        let Node::Dir { vol, dur, pending } = &self.nodes[id] else {
            unreachable!()
        };
        let entries = match model {
            Model::All => vol.clone(),
            Model::Synced => dur.clone(),
            Model::Random(_) => {
                // Metadata is journalled in order: a prefix persists.
                let rng = rng.as_mut().unwrap();
                let keep = rng.random_range(0..=pending.len());
                let mut entries = dur.clone();
                for op in &pending[..keep] {
                    apply_dir(&mut entries, op);
                }
                entries
            }
        };
        for (name, child) in entries {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            match &self.nodes[child] {
                Node::Dir { .. } => {
                    out.insert(path.clone(), Item::Dir);
                    self.walk(child, path, model, rng, out);
                }
                Node::File { vol, dur, pending } => {
                    let content = match model {
                        Model::All => vol.clone(),
                        Model::Synced => dur.clone(),
                        Model::Random(_) => {
                            let rng = rng.as_mut().unwrap();
                            let mut content = dur.clone();
                            for op in pending {
                                if !rng.random_bool(0.5) {
                                    continue;
                                }
                                match op {
                                    // Data writes tear at sector boundaries.
                                    FileOp::Write(offset, data) if rng.random_bool(0.3) => {
                                        let sectors = data.len() / 512;
                                        let keep = rng.random_range(0..=sectors) * 512;
                                        if keep > 0 {
                                            content.write(*offset, &data[..keep]);
                                        }
                                    }
                                    op => apply_file(&mut content, op),
                                }
                            }
                            content
                        }
                    };
                    out.insert(path, Item::File(content));
                }
            }
        }
    }
}

fn clear(dir: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            // `wit` may be a mount point: empty it, keep it.
            if entry.file_name() == "wit" {
                clear(&entry.path());
            } else {
                std::fs::remove_dir_all(entry.path()).unwrap();
            }
        } else {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
}

fn materialize(image: &BTreeMap<String, Item>, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    clear(dest);
    // BTreeMap order lists a directory before its children.
    for (path, item) in image {
        let target = dest.join(path);
        match item {
            Item::Dir => std::fs::create_dir_all(&target).unwrap(),
            Item::File(content) => {
                use std::os::unix::fs::FileExt;
                let file = std::fs::File::create(&target).unwrap();
                file.set_len(content.len).unwrap();
                for (page, bytes) in &content.pages {
                    let offset = page * PAGE;
                    if offset >= content.len || bytes.iter().all(|b| *b == 0) {
                        continue;
                    }
                    let count = (content.len - offset).min(PAGE) as usize;
                    file.write_all_at(&bytes[..count], offset).unwrap();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Continuations on a crash image.

#[derive(Clone, Default)]
struct Context {
    step: String,
    /// What the files must hash to, if known for this cut.
    view: Option<View>,
    snapshot: Option<(Descriptor, View)>,
}

fn probe_write(backing: &dyn Backing) -> io::Result<()> {
    let file = backing.open("probe", true)?;
    file.write_at(0, b"audit5 probe")?;
    file.sync_data()?;
    backing.sync_dir("")
}

fn probe_read(backing: &dyn Backing) -> io::Result<()> {
    let file = backing.open("probe", false)?;
    let mut bytes = [0; 12];
    file.read_at(0, &mut bytes)?;
    if &bytes != b"audit5 probe" {
        return Err(io::Error::other("probe content lost"));
    }
    Ok(())
}

fn check_view(backing: &dyn Backing, view: &Option<View>) -> io::Result<()> {
    if let Some(view) = view {
        let actual = view_of(&read_all(backing)?);
        if actual != *view {
            return Err(io::Error::other(format!(
                "CONTENT MISMATCH: files differ from the acknowledged view: {:?}",
                actual
                    .iter()
                    .filter(|(name, hash)| view.get(*name) != Some(hash))
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>()
            )));
        }
    }
    Ok(())
}

/// After any successful recovery: commit, release, GC and attach again.
fn settle(
    root: &Path,
    authority: &Arc<Authority>,
    backing: RollbackBacking,
    view: &Option<View>,
) -> io::Result<()> {
    let writer = authority.rpc(Role::Writer);
    check_view(&backing, view).map_err(|e| io::Error::other(format!("verify: {e}")))?;
    probe_write(&backing).map_err(|e| io::Error::other(format!("first commit: {e}")))?;
    drop(backing);
    let record = authority.record();
    if record.phase != Phase::Released {
        return Err(io::Error::other("not released after drop"));
    }
    RollbackBacking::collect_remote(root, writer.as_ref())
        .map_err(|e| io::Error::other(format!("gc after recovery: {e}")))?;
    let backing = RollbackBacking::open_remote(root, writer.clone())
        .map_err(|e| io::Error::other(format!("attach after recovery: {e}")))?;
    check_view(&backing, view).map_err(|e| io::Error::other(format!("verify 2: {e}")))?;
    probe_read(&backing).map_err(|e| io::Error::other(format!("probe: {e}")))?;
    drop(backing);
    // Nothing may stay unreclaimable: after one more pass, with every
    // lifetime lock free, only the current namespace holds files. (A
    // namespace directory whose creation was cut before its lock file
    // existed stays, empty, as `skipped_unrecognized`.)
    RollbackBacking::collect_remote(root, writer.as_ref())
        .map_err(|e| io::Error::other(format!("final gc: {e}")))?;
    let current = authority.record().current.map(|c| c.namespace);
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.contains("remote-0") || Some(&name) == current.as_ref() {
            continue;
        }
        let files: Vec<_> = std::fs::read_dir(entry.path())?
            .map(|file| file.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        if !files.is_empty() {
            return Err(io::Error::other(format!(
                "LEAK: GC never reclaims a stale namespace holding {files:?}"
            )));
        }
    }
    Ok(())
}

fn continuations(
    work: &Path,
    image: &BTreeMap<String, Item>,
    state: &CanonicalState,
    context: &Context,
) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    let root = work.join("root");
    let snap = work.join("snap");
    let record = state.record().clone();
    let fresh = || {
        materialize(image, work);
        Authority::new(state.clone(), None)
    };
    if record.current.is_some() {
        // Administrator takeover must always recover the current generation.
        let authority = fresh();
        let admin = authority.rpc(Role::Admin);
        let outcome = RollbackBacking::takeover_remote(&root, admin, &record)
            .map_err(|e| io::Error::other(format!("takeover: {e}")))
            .and_then(|backing| settle(&root, &authority, backing, &context.view));
        if let Err(error) = outcome {
            violations.push(("takeover".into(), error.to_string()));
        }
        // An ordinary attach works exactly when the authority is released.
        let authority = fresh();
        let writer = authority.rpc(Role::Writer);
        match RollbackBacking::open_remote(&root, writer) {
            Ok(backing) => {
                if record.phase != Phase::Released {
                    violations.push(("attach".into(), "attached over an unreleased writer".into()));
                } else if let Err(error) = settle(&root, &authority, backing, &context.view) {
                    violations.push(("attach".into(), error.to_string()));
                }
            }
            Err(error) => {
                if record.phase == Phase::Released {
                    violations.push(("attach".into(), format!("released but refused: {error}")));
                } else if authority.record() != record {
                    violations.push(("attach".into(), "refused attach changed the authority".into()));
                }
            }
        }
        // GC first (any outcome), then takeover.
        let authority = fresh();
        let _ = RollbackBacking::collect_remote(&root, authority.rpc(Role::Writer).as_ref());
        let outcome = RollbackBacking::takeover_remote(&root, authority.rpc(Role::Admin), &record)
            .map_err(|e| io::Error::other(format!("takeover: {e}")))
            .and_then(|backing| settle(&root, &authority, backing, &context.view));
        if let Err(error) = outcome {
            violations.push(("gc+takeover".into(), error.to_string()));
        }
        // An approved snapshot must restore from now on.
        if let Some((descriptor, view)) = &context.snapshot {
            let authority = fresh();
            let outcome = read_snapshot(&snap)
                .map_err(|e| io::Error::other(format!("read snapshot.json: {e}")))
                .and_then(|source| {
                    if source != *descriptor {
                        return Err(io::Error::other("snapshot.json differs from approval"));
                    }
                    RollbackBacking::restore_remote(
                        &root,
                        &snap,
                        &source,
                        authority.rpc(Role::Admin),
                        &record,
                    )
                    .map_err(|e| io::Error::other(format!("restore: {e}")))
                })
                .and_then(|backing| settle(&root, &authority, backing, &Some(view.clone())));
            if let Err(error) = outcome {
                violations.push(("restore".into(), error.to_string()));
            }
        }
    } else {
        // Never activated: `create` on an untouched root, or resume.
        let mut errors = Vec::new();
        let mut done = false;
        if record.fence == 0 {
            let authority = fresh();
            match RollbackBacking::create_remote(&root, authority.rpc(Role::Writer), CAPACITY) {
                Ok(backing) => {
                    done = true;
                    if let Err(error) = settle(&root, &authority, backing, &None) {
                        violations.push(("create".into(), error.to_string()));
                    }
                }
                Err(error) => errors.push(format!("create: {error}")),
            }
        }
        if !done {
            let authority = fresh();
            match RollbackBacking::recover_enrollment_remote(
                &root,
                authority.rpc(Role::Admin),
                CAPACITY,
                &record,
            ) {
                Ok(backing) => {
                    done = true;
                    if let Err(error) = settle(&root, &authority, backing, &None) {
                        violations.push(("resume".into(), error.to_string()));
                    }
                }
                Err(error) => errors.push(format!("resume: {error}")),
            }
        }
        if !done {
            // A strand of a never-claimed authority is the known finding;
            // one after a claim would be a new one.
            let label = if record.fence == 0 {
                "STRAND"
            } else {
                "STRAND-AFTER-CLAIM"
            };
            violations.push((label.into(), errors.join(" | ")));
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// The sweep.

struct Recording {
    top: PathBuf,
    ops: Vec<Op>,
    events: Vec<Event>,
}

fn record_trace(scenario: &str) -> Recording {
    let top = PathBuf::from(format!(
        "/dev/shm/audit5-rac-{}-{scenario}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&top);
    std::fs::create_dir_all(top.join("fs/root")).unwrap();
    std::fs::create_dir_all(top.join("meta/marks")).unwrap();
    if scenario.starts_with("local") {
        // Local mode refuses a witness on the backing's filesystem.
        for dir in ["fs/wit", "work/wit"] {
            std::fs::create_dir_all(top.join(dir)).unwrap();
            let mounted = std::process::Command::new("mount")
                .args(["-t", "tmpfs", "-o", "size=64m", "none"])
                .arg(top.join(dir))
                .status()
                .expect("mount");
            assert!(mounted.success(), "mounting a tmpfs needs root");
        }
    }
    let trace = top.join("meta/trace");
    let status = std::process::Command::new("strace")
        .args(["-f", "-y", "-xx", "-s", "1048576", "-o"])
        .arg(&trace)
        .args([
            "-e",
            "trace=open,openat,creat,mkdir,mkdirat,unlink,unlinkat,rename,renameat,renameat2,\
             link,linkat,symlink,symlinkat,pwrite64,pwritev,pwritev2,write,writev,ftruncate,\
             truncate,fallocate,fsync,fdatasync,sync_file_range,fchown,fchownat,fchmod",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["audit5_child", "--exact", "--nocapture", "--test-threads=1"])
        .env("AUDIT5_CHILD", scenario)
        .env("AUDIT5_TOP", &top)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("strace is required");
    assert!(status.success(), "traced child failed for {scenario}");
    let top_text = top.to_str().unwrap();
    let ops = parse_trace(&std::fs::read_to_string(&trace).unwrap(), top_text);
    let events: Vec<Event> =
        serde_json::from_slice(&std::fs::read(top.join("meta/events.json")).unwrap()).unwrap();
    let marks = ops.iter().filter(|op| matches!(op, Op::Mark(_))).count();
    assert_eq!(marks, events.len(), "every event has one marker in the trace");
    Recording { top, ops, events }
}

#[derive(Default)]
struct Report {
    cuts: usize,
    images: usize,
    groups: BTreeMap<(String, String, String), (usize, Vec<String>)>,
}

fn describe(op: Option<&Op>) -> String {
    match op {
        None => "start".into(),
        Some(Op::Write(path, offset, data)) => {
            format!("Write({}, {offset}, {} bytes)", short(path), data.len())
        }
        Some(Op::Create(path)) => format!("Create({})", short(path)),
        Some(Op::Mkdir(path)) => format!("Mkdir({})", short(path)),
        Some(Op::Unlink(path)) => format!("Unlink({})", short(path)),
        Some(Op::Rename(from, to)) => format!("Rename({}, {})", short(from), short(to)),
        Some(Op::Truncate(path, len)) => format!("Truncate({}, {len})", short(path)),
        Some(Op::Allocate(path, end)) => format!("Allocate({}, {end})", short(path)),
        Some(Op::Sync(path)) => format!("Sync({})", short(path)),
        Some(Op::Mark(index)) => format!("Mark({index})"),
    }
}

fn short(path: &str) -> String {
    let tail = path.split("/fs/").nth(1).unwrap_or(path);
    // remote-<fence>-<session>: keep the fence.
    tail.split('/')
        .map(|part| {
            if part.starts_with("remote-") && part.len() == 56 {
                format!("ns{}", u64::from_str_radix(&part[7..23], 16).unwrap())
            } else if part.starts_with(".remote-gc-remote-") {
                format!("tomb{}", u64::from_str_radix(&part[18..34], 16).unwrap())
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn sweep(scenario: &str, random_images: u64, plant: &str) -> Report {
    let recording = record_trace(scenario);
    let top = recording.top.to_str().unwrap().to_string();
    let mut fs = Fs::new(&top, plant);
    let mut state = CanonicalState::initial(IDENTITY).unwrap();
    let mut context = Context::default();
    let mut acked: HashMap<Vec<u8>, View> = HashMap::new();
    let mut intent: Option<View> = None;
    let mut report = Report::default();
    let work = recording.top.join("work");
    let only: Option<usize> = std::env::var("AUDIT5_ONLY_CUT")
        .ok()
        .and_then(|v| v.parse().ok());
    let stride: usize = std::env::var("AUDIT5_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    for cut in 0..=recording.ops.len() {
        if cut > 0 {
            let op = &recording.ops[cut - 1];
            fs.apply(op);
            if let Op::Mark(index) = op {
                match &recording.events[*index] {
                    Event::Authority(bytes) => state = CanonicalState::decode(bytes).unwrap(),
                    Event::Step(name) => context.step = name.clone(),
                    Event::Intent { view } => intent = view.clone(),
                    Event::Ack { root, view } => {
                        intent = None;
                        if let Some(root) = root {
                            acked.insert(root.clone(), view.clone());
                        }
                    }
                    Event::Snapshot { descriptor, view } => {
                        context.snapshot = Some((descriptor.clone(), view.clone()))
                    }
                }
                // Only an authority change makes a new crash state.
                if !matches!(recording.events[*index], Event::Authority(_)) {
                    continue;
                }
            }
        }
        if only.is_some_and(|only| only != cut) || cut % stride != 0 {
            continue;
        }
        // What the current root must hold: the acknowledged view of that
        // root, or the in-flight sync's candidate.
        context.view = state
            .record()
            .current
            .as_ref()
            .and_then(|current| acked.get(current.anchor.root.as_slice()).cloned())
            .or_else(|| intent.clone());
        if plant == "view" {
            if let Some(view) = &mut context.view {
                view.insert("meta".into(), "planted".into());
            }
        }
        report.cuts += 1;
        let mut models = vec![Model::All];
        if fs.has_pending() {
            models.push(Model::Synced);
            models.extend((0..random_images).map(|n| Model::Random(seed_base() + cut as u64 * 1000 + n)));
        }
        for model in models {
            report.images += 1;
            let image = fs.image(model);
            let found = continuations(&work, &image, &state, &context);
            for (variant, error) in found {
                let kind = match model {
                    Model::All => "process-death",
                    Model::Synced => "power-loss(synced-only)",
                    Model::Random(_) => "power-loss(random)",
                };
                let group = report
                    .groups
                    .entry((variant, kind.to_string(), error))
                    .or_default();
                group.0 += 1;
                if group.1.len() < 4 {
                    group.1.push(format!(
                        "cut {cut} in step '{}' after {} [{model:?}] authority fence {} {:?}",
                        context.step,
                        describe(cut.checked_sub(1).map(|i| &recording.ops[i])),
                        state.record().fence,
                        state.record().phase,
                    ));
                }
            }
        }
    }
    assert_eq!(fs.unknown, 0, "operations on paths the model lost track of");
    if std::env::var("AUDIT5_KEEP").is_err() {
        let _ = std::fs::remove_dir_all(&recording.top);
    }
    println!(
        "audit5 {scenario} plant='{plant}': {} ops, {} cuts, {} crash images, {} violation groups",
        recording.ops.len(),
        report.cuts,
        report.images,
        report.groups.len()
    );
    for ((variant, kind, error), (count, examples)) in &report.groups {
        println!("  [{variant}] {kind} x{count}: {error}");
        for example in examples {
            println!("      {example}");
        }
    }
    report
}

fn seed_base() -> u64 {
    std::env::var("AUDIT5_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        * 1_000_000
}

fn random_images() -> u64 {
    std::env::var("AUDIT5_RANDOM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2)
}

fn run(scenario: &str) {
    let plant = std::env::var("AUDIT5_PLANT").unwrap_or_default();
    let report = sweep(scenario, random_images(), &plant);
    if std::env::var("AUDIT5_REPORT_ONLY").is_err() {
        // The strands of a never-claimed authority (fence 0) whose initial
        // `create` was cut before its marker or binding held its bytes are
        // reported separately (audit5_interrupted_enrollment.rs). Everything
        // else must hold; AUDIT5_STRICT=1 fails on those strands too.
        let strict = std::env::var("AUDIT5_STRICT").is_ok();
        let unexpected: Vec<_> = report
            .groups
            .keys()
            .filter(|(variant, _, _)| strict || variant != "STRAND")
            .collect();
        assert!(
            unexpected.is_empty(),
            "{} violation groups (see output): {unexpected:#?}",
            unexpected.len()
        );
    }
}

#[test]
#[ignore = "audit sweep: needs strace and /dev/shm"]
fn audit5_lifecycle_crash_images() {
    run("lifecycle");
}

#[test]
#[ignore = "audit sweep: needs strace and /dev/shm"]
fn audit5_enrollment_claim_lost_crash_images() {
    run("enroll-claim-lost");
}

#[test]
#[ignore = "audit sweep: needs strace and /dev/shm"]
fn audit5_enrollment_unreachable_crash_images() {
    run("enroll-unreachable");
}

#[test]
#[ignore = "audit sweep: needs strace and /dev/shm"]
fn audit5_enrollment_activate_lost_crash_images() {
    run("enroll-activate-lost");
}

#[test]
#[ignore = "audit sweep: needs strace and /dev/shm"]
fn audit5_enrollment_resume_twice_crash_images() {
    run("enroll-resume-twice");
}

#[test]
#[ignore = "audit sweep: needs strace and /dev/shm"]
fn audit5_messy_admin_crash_images() {
    run("messy");
}

// ---------------------------------------------------------------------------
// Local witness mode: backing and witness lose power together.

fn local_continuation(
    work: &Path,
    image: &BTreeMap<String, Item>,
    allowed: &[View],
    check_content: bool,
) -> Result<(), String> {
    materialize(image, work);
    let root = work.join("root");
    let wit = work.join("wit");
    let backing = RollbackBacking::open(&root, &wit).map_err(|e| format!("open: {e}"))?;
    if check_content {
        let actual = view_of(&read_all(&backing).map_err(|e| format!("read: {e}"))?);
        if !allowed.contains(&actual) {
            return Err("CONTENT MISMATCH: neither the acknowledged nor the in-flight view".into());
        }
    }
    probe_write(&backing).map_err(|e| format!("commit after recovery: {e}"))?;
    drop(backing);
    let backing = RollbackBacking::open(&root, &wit).map_err(|e| format!("reopen: {e}"))?;
    probe_read(&backing).map_err(|e| format!("probe: {e}"))?;
    Ok(())
}

#[test]
#[ignore = "audit sweep: needs strace, root (tmpfs mounts) and /dev/shm"]
fn audit5_local_witness_crash_images() {
    let plant = std::env::var("AUDIT5_PLANT").unwrap_or_default();
    let recording = record_trace("local");
    let top = recording.top.to_str().unwrap().to_string();
    let mut fs = Fs::new(&top, &plant).with_witness();
    let work = recording.top.join("work");
    let mut step = String::new();
    let mut created = false;
    let mut acked: Option<View> = None;
    let mut intent: Option<View> = None;
    let mut settled = false;
    let (mut cuts, mut images, mut window) = (0, 0, 0);
    let mut groups: BTreeMap<(String, String), (usize, Vec<String>)> = BTreeMap::new();
    for cut in 0..=recording.ops.len() {
        if cut > 0 {
            let op = &recording.ops[cut - 1];
            fs.apply(op);
            if let Op::Mark(index) = op {
                match &recording.events[*index] {
                    Event::Step(name) => {
                        step = name.clone();
                        created |= name == "created";
                    }
                    Event::Intent { view } => {
                        intent = view.clone();
                        settled = false;
                    }
                    Event::Ack { view, .. } => {
                        acked = Some(view.clone());
                        intent = None;
                        settled = true;
                    }
                    _ => {}
                }
                continue;
            }
        }
        if !created {
            // A create cut short leaves non-empty directories; the guide
            // requires both to be empty for creation.
            window += 1;
            continue;
        }
        cuts += 1;
        let allowed: Vec<View> = acked.iter().chain(intent.iter()).cloned().collect();
        let mut models = vec![Model::All];
        if fs.has_pending() {
            models.push(Model::Synced);
            models.extend((0..random_images()).map(|n| Model::Random(seed_base() + cut as u64 * 1000 + n)));
        }
        for model in models {
            images += 1;
            if let Err(error) = local_continuation(&work, &fs.image(model), &allowed, settled || intent.is_some()) {
                let kind = match model {
                    Model::All => "process-death",
                    Model::Synced => "power-loss(synced-only)",
                    Model::Random(_) => "power-loss(random)",
                };
                let group = groups.entry((kind.to_string(), error)).or_default();
                group.0 += 1;
                if group.1.len() < 4 {
                    group.1.push(format!(
                        "cut {cut} in step '{step}' after {} [{model:?}]",
                        describe(cut.checked_sub(1).map(|i| &recording.ops[i]))
                    ));
                }
            }
        }
    }
    assert_eq!(fs.unknown, 0, "operations on paths the model lost track of");
    for dir in ["fs/wit", "work/wit"] {
        let _ = std::process::Command::new("umount")
            .arg(recording.top.join(dir))
            .status();
    }
    if std::env::var("AUDIT5_KEEP").is_err() {
        let _ = std::fs::remove_dir_all(&recording.top);
    }
    println!(
        "audit5 local plant='{plant}': {} ops, {cuts} cuts after create ({window} inside it), \
         {images} crash images, {} violation groups",
        recording.ops.len(),
        groups.len()
    );
    for ((kind, error), (count, examples)) in &groups {
        println!("  {kind} x{count}: {error}");
        for example in examples {
            println!("      {example}");
        }
    }
    if std::env::var("AUDIT5_REPORT_ONLY").is_err() {
        assert!(groups.is_empty(), "{} violation groups", groups.len());
    }
}
