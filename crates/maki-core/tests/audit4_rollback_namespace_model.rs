//! Audit round 4 (rollback-witness): a model-based sweep of the rewritten
//! `RollbackBacking` state machine, below the engine. Not part of the
//! maintained suite.
//!
//! Round 4 rewrote about 500 lines of `rollback.rs` for speed: committed
//! reservation totals (#205), hole-only punch walks (#209), sparse read fills
//! and logical-file locks (#216), a cached unlinked-identity set (#230),
//! clean `sync_data` / `sync_dir` skips (#242), a `possibly_dirty` set
//! (#276) and identity-bound locks (#319). Each optimisation removes a
//! commit or a recomputation that used to be unconditional. This sweep drives
//! several files, a directory, renames, unlinks, open/unlinked handles and
//! locks against an independent POSIX-style oracle:
//!
//! - working view: what every handle reads (exact bytes and length),
//! - durable view: a file's bytes as of its last `sync_data`, a directory's
//!   names as of its last `sync_dir` (a reservation that adds pages may also
//!   persist a zero-filled longer EOF, never unsynced bytes),
//! - `free_bytes` = capacity minus the durable reservations of every identity
//!   that still has a name or an open handle or lock.
//!
//! A restart (drop + reopen; for the rollback backing the only crash an
//! in-process test can produce) must show exactly the durable view. Local
//! mode can block the witness publication (a directory at `anchor.next`);
//! remote mode runs the in-process `StateStore` of the remote tests on a
//! `CrashableBacking` process view, with unavailable / lost-reply RPCs,
//! witness-host power losses while the writer is live, and process deaths
//! without a release (then the documented administrator takeover). An
//! operation that stops the session leaves either its pre- or post-state.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::remote_witness::{Action, Phase, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, BackingFile, RollbackBacking, VolumeLock};
use maki_test_support::CrashableBacking;

const PAGE: usize = 4096;

// ---------------------------------------------------------------------------
// Oracle

#[derive(Clone, Debug, Default, PartialEq)]
struct Img {
    bytes: Vec<u8>,
    reserved: BTreeSet<usize>,
}

impl Img {
    fn reserve(&mut self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        let end = offset + len;
        self.reserved.extend(offset / PAGE..end.div_ceil(PAGE));
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
        }
    }
    fn write(&mut self, offset: usize, data: &[u8]) {
        self.reserve(offset, data.len());
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
    }
    fn set_len(&mut self, len: usize) {
        self.bytes.resize(len, 0);
        self.reserved.retain(|page| *page < len.div_ceil(PAGE));
    }
    fn punch(&mut self, offset: usize, len: usize) {
        let end = (offset + len).min(self.bytes.len());
        if offset >= end {
            return;
        }
        self.bytes[offset..end].fill(0);
        self.reserved.retain(|page| {
            let start = *page * PAGE;
            offset > start || offset + len < start + PAGE
        });
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Ent {
    Dir,
    File(u64),
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Model {
    w_entries: BTreeMap<String, Ent>,
    d_entries: BTreeMap<String, Ent>,
    w: BTreeMap<u64, Img>,
    d: BTreeMap<u64, Img>,
    next: u64,
}

fn parent(name: &str) -> &str {
    name.rsplit_once('/').map_or("", |(p, _)| p)
}

impl Model {
    fn dir_exists(&self, dir: &str) -> bool {
        dir.is_empty() || self.w_entries.get(dir) == Some(&Ent::Dir)
    }
    fn file(&self, name: &str) -> Option<u64> {
        match self.w_entries.get(name) {
            Some(Ent::File(id)) => Some(*id),
            _ => None,
        }
    }
    fn create(&mut self, name: &str) -> u64 {
        if let Some(id) = self.file(name) {
            return id;
        }
        self.next += 1;
        let id = self.next;
        self.w.insert(id, Img::default());
        self.w_entries.insert(name.to_string(), Ent::File(id));
        id
    }
    fn retained(&self, open: &BTreeSet<u64>) -> BTreeSet<u64> {
        let mut ids: BTreeSet<u64> = open.clone();
        for entry in self.w_entries.values().chain(self.d_entries.values()) {
            if let Ent::File(id) = entry {
                ids.insert(*id);
            }
        }
        ids
    }
    fn prune(&mut self, open: &BTreeSet<u64>) {
        let keep = self.retained(open);
        self.w.retain(|id, _| keep.contains(id));
        self.d.retain(|id, _| keep.contains(id));
    }
    fn reserved_pages(&self) -> usize {
        self.d.values().map(|img| img.reserved.len()).sum()
    }
    /// `Ok(true)` = committed a reservation, `Ok(false)` = covered.
    fn reserve(
        &mut self,
        id: u64,
        offset: usize,
        len: usize,
        cap_pages: usize,
        open: &BTreeSet<u64>,
    ) -> Result<bool, ()> {
        if len == 0 {
            return Ok(false);
        }
        let range = offset / PAGE..(offset + len).div_ceil(PAGE);
        if range.len() > cap_pages {
            return Err(());
        }
        self.prune(open);
        let durable = self.d.get(&id);
        let additional = range
            .clone()
            .filter(|page| !durable.is_some_and(|img| img.reserved.contains(page)))
            .count();
        if additional > cap_pages - self.reserved_pages() {
            return Err(());
        }
        if additional != 0 {
            self.d.entry(id).or_default().reserve(offset, len);
        }
        self.w.get_mut(&id).unwrap().reserve(offset, len);
        Ok(additional != 0)
    }
    fn sync_dir(&mut self, dir: &str) {
        self.d_entries.retain(|name, _| parent(name) != dir);
        let children: Vec<(String, Ent)> = self
            .w_entries
            .iter()
            .filter(|(name, _)| parent(name) == dir)
            .map(|(n, e)| (n.clone(), e.clone()))
            .collect();
        for (name, entry) in children {
            if let Ent::File(id) = entry {
                self.d.entry(id).or_default();
            }
            self.d_entries.insert(name, entry);
        }
        let mut ancestor = dir;
        while !ancestor.is_empty() {
            self.d_entries.insert(ancestor.to_string(), Ent::Dir);
            ancestor = parent(ancestor);
        }
    }
    fn restart(&mut self) {
        self.w_entries = self.d_entries.clone();
        self.prune(&BTreeSet::new());
        self.w = self.d.clone();
    }
    fn check_invariants(&self) {
        for (id, img) in &self.w {
            let durable = self.d.get(id).map(|d| &d.reserved);
            for page in &img.reserved {
                assert!(
                    durable.is_some_and(|d| d.contains(page)),
                    "MODEL: working reservation {id}/{page} not durable"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// In-process remote witness (as in maki-backing/tests/remote_rollback.rs)

struct RpcFaults {
    injected: AtomicU32,
    unavailable: AtomicU32,
    lost_reply: AtomicU32,
    no_release: AtomicBool,
    rng: Mutex<StdRng>,
}

struct FakeRpc {
    store: Arc<Mutex<Option<StateStore>>>,
    role: Role,
    f: Arc<RpcFaults>,
}

impl Rpc for FakeRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        let release = matches!(request.action, Action::Release);
        if release && self.f.no_release.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "audit: process died before its release",
            ));
        }
        let unavailable = self.f.unavailable.load(Ordering::SeqCst);
        if unavailable > 0 && self.f.rng.lock().random_range(0..1000) < unavailable {
            self.f.injected.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "audit: witness unavailable",
            ));
        }
        let record = {
            let mut store = self.store.lock();
            let store = store
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused, "witness down"))?;
            store.handle(self.role, request)?
        };
        let lost = self.f.lost_reply.load(Ordering::SeqCst);
        if !matches!(request.action, Action::Inspect)
            && lost > 0
            && self.f.rng.lock().random_range(0..1000) < lost
        {
            self.f.injected.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "audit: reply lost after durable commit",
            ));
        }
        Ok(record)
    }
}

fn inspect(rpc: &dyn Rpc) -> io::Result<Record> {
    rpc.call(&Request {
        authorization: None,
        operation_id: *Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })
}

// ---------------------------------------------------------------------------
// World

struct World {
    remote: bool,
    root: tempfile::TempDir,
    wdir: tempfile::TempDir,
    machine: CrashableBacking,
    store: Arc<Mutex<Option<StateStore>>>,
    writer: Arc<FakeRpc>,
    admin: Arc<FakeRpc>,
    rpcf: Arc<RpcFaults>,
    capacity: u64,
    /// Admin snapshots: (directory, approved descriptor, durable model).
    snapshots: Vec<(
        tempfile::TempDir,
        maki_backing::remote_witness::Descriptor,
        Model,
    )>,
    /// An old copy of the whole backing root (a rogue rollback).
    stash: Option<tempfile::TempDir>,
}

/// In-process copy: forking `cp` from a multi-threaded test process lets the
/// child inherit (and briefly hold) another test thread's flock descriptors.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

impl World {
    fn new(remote: bool, seed: u64, capacity: u64) -> Self {
        let machine = CrashableBacking::new().with_tearing(64);
        let store = Arc::new(Mutex::new(None));
        if remote {
            *store.lock() = Some(
                StateStore::create_backing(machine.process() as Arc<dyn Backing>, [9; 16]).unwrap(),
            );
        }
        let rpcf = Arc::new(RpcFaults {
            injected: AtomicU32::new(0),
            unavailable: AtomicU32::new(0),
            lost_reply: AtomicU32::new(0),
            no_release: AtomicBool::new(false),
            rng: Mutex::new(StdRng::seed_from_u64(seed ^ 0x77)),
        });
        let rpc = |role| {
            Arc::new(FakeRpc {
                store: store.clone(),
                role,
                f: rpcf.clone(),
            })
        };
        Self {
            remote,
            root: tempfile::tempdir().unwrap(),
            wdir: tempfile::tempdir_in("/dev/shm").unwrap(),
            writer: rpc(Role::Writer),
            admin: rpc(Role::Admin),
            machine,
            store,
            rpcf,
            capacity,
            snapshots: Vec::new(),
            stash: None,
        }
    }
    fn create(&self) -> RollbackBacking {
        if self.remote {
            RollbackBacking::create_remote(self.root.path(), self.writer.clone(), self.capacity)
                .unwrap()
        } else {
            RollbackBacking::create(self.root.path(), self.wdir.path(), self.capacity).unwrap()
        }
    }
    fn open(&self, log: &mut Vec<String>) -> Result<RollbackBacking, String> {
        if !self.remote {
            return RollbackBacking::open(self.root.path(), self.wdir.path())
                .map_err(|e| format!("local open: {e}"));
        }
        let first = match RollbackBacking::open_remote(self.root.path(), self.writer.clone()) {
            Ok(b) => return Ok(b),
            Err(e) => e,
        };
        let record = inspect(self.admin.as_ref()).map_err(|e| format!("inspect: {e}"))?;
        if record.phase == Phase::Released {
            return Err(format!("open_remote refused a released authority: {first}"));
        }
        log.push(format!(
            "   open refused ({first}); takeover from {:?}",
            record.phase
        ));
        RollbackBacking::takeover_remote(self.root.path(), self.admin.clone(), &record)
            .map_err(|e| format!("takeover after refused open ({first}): {e}"))
    }
    fn witness_power_loss(&self, rng: &mut StdRng) -> Result<(), String> {
        let mut store = self.store.lock();
        *store = None;
        if rng.random_bool(0.3) {
            self.machine.crash_all_lost();
        } else {
            self.machine.crash(rng);
        }
        *store = Some(
            StateStore::open_backing(self.machine.process() as Arc<dyn Backing>)
                .map_err(|e| format!("WITNESS-REOPEN: {e}"))?,
        );
        Ok(())
    }
}

const ROOT_NAMES: [&str; 3] = ["a", "b", "c"];
const DIR_NAMES: [&str; 2] = ["d/x", "d/y"];

fn pick_name(rng: &mut StdRng) -> &'static str {
    if rng.random_bool(0.6) {
        ROOT_NAMES[rng.random_range(0..ROOT_NAMES.len())]
    } else {
        DIR_NAMES[rng.random_range(0..DIR_NAMES.len())]
    }
}

fn sibling(rng: &mut StdRng, name: &str) -> &'static str {
    if parent(name).is_empty() {
        ROOT_NAMES[rng.random_range(0..ROOT_NAMES.len())]
    } else {
        DIR_NAMES[rng.random_range(0..DIR_NAMES.len())]
    }
}

struct Live {
    backing: Option<RollbackBacking>,
    handles: Vec<(Arc<dyn BackingFile>, u64)>,
    locks: Vec<(Box<dyn VolumeLock>, u64)>,
}

impl Live {
    fn open_ids(&self) -> BTreeSet<u64> {
        self.handles
            .iter()
            .map(|(_, id)| *id)
            .chain(self.locks.iter().map(|(_, id)| *id))
            .collect()
    }
    fn b(&self) -> &RollbackBacking {
        self.backing.as_ref().unwrap()
    }
}

fn verify_durable(backing: &RollbackBacking, model: &Model, cap: u64) -> Result<(), String> {
    for dir in ["", "d"] {
        let expected: Vec<String> = model
            .d_entries
            .keys()
            .filter(|name| parent(name) == dir)
            .map(|name| name.rsplit('/').next().unwrap().to_string())
            .collect();
        let exists = dir.is_empty() || model.d_entries.get(dir) == Some(&Ent::Dir);
        match backing.list(dir) {
            Ok(names) if exists => {
                if names != expected {
                    return Err(format!(
                        "RESTART-NAMES: list({dir:?}) = {names:?}, durable model {expected:?}"
                    ));
                }
            }
            Ok(names) => {
                return Err(format!(
                    "RESTART-NAMES: list({dir:?}) = {names:?} but the directory was never synced"
                ))
            }
            Err(e) if !exists => {
                let _ = e;
            }
            Err(e) => return Err(format!("RESTART-LIST: {dir:?}: {e}")),
        }
    }
    for (name, entry) in &model.d_entries {
        let Ent::File(id) = entry else { continue };
        let want = &model.d[id];
        let file = backing
            .open(name, false)
            .map_err(|e| format!("RESTART-OPEN: {name}: {e}"))?;
        let len = file.len().map_err(|e| format!("RESTART-LEN: {e}"))?;
        if len != want.bytes.len() as u64 {
            return Err(format!(
                "RESTART-LENGTH: {name}: {len} bytes, durable model {}",
                want.bytes.len()
            ));
        }
        let mut got = vec![0; len as usize];
        file.read_at(0, &mut got)
            .map_err(|e| format!("RESTART-READ: {name}: {e}"))?;
        if got != want.bytes {
            let at = got.iter().zip(&want.bytes).position(|(a, b)| a != b);
            return Err(format!(
                "RESTART-CONTENT: {name}: first difference at byte {at:?}"
            ));
        }
    }
    let free = backing
        .free_bytes()
        .map_err(|e| format!("RESTART-FREE: {e}"))?;
    let expected = cap - (model.reserved_pages() * PAGE) as u64;
    if free != Some(expected) {
        return Err(format!(
            "RESTART-FREE-SPACE: free_bytes {free:?}, model {expected}"
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Local,
    LocalBlock,
    Remote,
    RemoteFaults,
    RemoteAdmin,
}

fn run_seed(mode: Mode, seed: u64, steps: usize) -> Result<BTreeMap<&'static str, u64>, String> {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA4);
    let cap_pages = [4usize, 8, 16][rng.random_range(0..3)];
    let cap = (cap_pages * PAGE) as u64;
    let remote = matches!(mode, Mode::Remote | Mode::RemoteFaults | Mode::RemoteAdmin);
    let mut world = World::new(remote, seed, cap);
    let mut log: Vec<String> = Vec::new();
    let mut stats: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut model = Model::default();
    let mut live = Live {
        backing: Some(if mode == Mode::RemoteAdmin && rng.random_bool(0.3) {
            // Interrupted enrollment: every mutation reply is lost after the
            // authority committed it, so creation fails; the documented
            // resume-enrollment (never activated) or takeover recovers it.
            world.rpcf.lost_reply.store(1000, Ordering::SeqCst);
            let created =
                RollbackBacking::create_remote(world.root.path(), world.writer.clone(), cap);
            world.rpcf.lost_reply.store(0, Ordering::SeqCst);
            match created {
                Ok(b) => b,
                Err(e) => {
                    let record = inspect(world.admin.as_ref()).unwrap();
                    log.push(format!("create failed ({e}); authority {:?}", record.phase));
                    *stats.entry("resumed-enrollments").or_default() += 1;
                    let resumed = if record.current.is_none() {
                        RollbackBacking::recover_enrollment_remote(
                            world.root.path(),
                            world.admin.clone(),
                            cap,
                            &record,
                        )
                    } else {
                        RollbackBacking::takeover_remote(
                            world.root.path(),
                            world.admin.clone(),
                            &record,
                        )
                    };
                    match resumed {
                        Ok(b) => {
                            if let Err(t) = verify_durable(&b, &Model::default(), cap) {
                                return Err(format!("RESUMED-ENROLLMENT-STATE: {t} seed {seed}"));
                            }
                            b
                        }
                        Err(e) => {
                            return Err(format!(
                                "RESUME-ENROLLMENT-REFUSED: {e} (authority {record:?}) seed {seed}"
                            ))
                        }
                    }
                }
            }
        } else {
            world.create()
        }),
        handles: Vec::new(),
        locks: Vec::new(),
    };
    let max_off = cap_pages * PAGE + PAGE;
    let planted = std::env::var("AUDIT_PLANT").is_ok();

    macro_rules! fail {
        ($($t:tt)*) => {{
            let tail = log.len().saturating_sub(120);
            return Err(format!(
                "{}\nmode {mode:?} seed {seed} cap_pages {cap_pages}\n  {}",
                format!($($t)*),
                log[tail..].join("\n  ")
            ));
        }};
    }

    for step in 0..steps {
        let faults = matches!(mode, Mode::RemoteFaults | Mode::RemoteAdmin) && rng.random_bool(0.5);
        world
            .rpcf
            .unavailable
            .store(if faults { 30 } else { 0 }, Ordering::SeqCst);
        world
            .rpcf
            .lost_reply
            .store(if remote { 80 } else { 0 }, Ordering::SeqCst);
        let block = mode == Mode::LocalBlock && rng.random_range(0..100) < 6;
        if block {
            std::fs::create_dir(world.wdir.path().join("anchor.next")).unwrap();
        }
        let pre = model.clone();
        let mut post = model.clone();
        let open = live.open_ids();
        let mut roll = rng.random_range(0..100);
        if (12..=61).contains(&roll) || (82..=85).contains(&roll) {
            if live.handles.is_empty() {
                roll = 0;
            }
        }
        if (89..=90).contains(&roll) && live.locks.is_empty() {
            roll = 86;
        }
        if roll == 94 && !remote {
            roll = 91;
        }
        if roll >= 95 && rng.random_bool(0.5) {
            roll = 91;
        }
        if (95..=97).contains(&roll) && mode != Mode::RemoteAdmin {
            roll = 98;
        }
        if roll == 96 && world.snapshots.is_empty() {
            roll = 95;
        }
        let injected_before = world.rpcf.injected.load(Ordering::SeqCst);
        // Whether the oracle predicts a namespace refusal for this operation.
        let mut expect_fail = false;
        // Outcome expected by the oracle: Ok(()) or an expected error kind.
        let (label, outcome): (String, Result<(), io::Error>) = match roll {
            // open / create
            0..=11 => {
                let name = pick_name(&mut rng);
                let create = rng.random_bool(0.7);
                let r = live.b().open(name, create);
                let label = format!("open {name} create={create}");
                let expect_ok =
                    post.dir_exists(parent(name)) && (create || post.file(name).is_some());
                expect_fail = !expect_ok;
                match r {
                    Ok(file) => {
                        if !expect_ok {
                            fail!("UNEXPECTED-OPEN: {label} succeeded");
                        }
                        let id = post.create(name);
                        live.handles.push((file, id));
                        (label, Ok(()))
                    }
                    Err(e) => (label, Err(e)),
                }
            }
            // write
            12..=33 if !live.handles.is_empty() => {
                let i = rng.random_range(0..live.handles.len());
                let id = live.handles[i].1;
                let offset = rng.random_range(0..max_off);
                let len = rng.random_range(1..=PAGE * 2 + 13);
                let data: Vec<u8> = (0..len).map(|_| rng.random::<u8>() | 1).collect();
                let label = format!("write #{id} @{offset}+{len}");
                let r = live.handles[i].0.write_at(offset as u64, &data);
                match post.reserve(id, offset, len, cap_pages, &open) {
                    Ok(_) => {
                        post.w.get_mut(&id).unwrap().write(offset, &data);
                        (label, r)
                    }
                    Err(()) => match r {
                        Err(e) if e.raw_os_error() == Some(28) => {
                            *stats.entry("enospc").or_default() += 1;
                            (label, Ok(()))
                        }
                        Ok(()) => fail!("ENOSPC-MISMATCH: {label} succeeded, model has no space"),
                        Err(e) => (label, Err(e)),
                    },
                }
            }
            34..=38 if !live.handles.is_empty() => {
                let i = rng.random_range(0..live.handles.len());
                let id = live.handles[i].1;
                let offset = rng.random_range(0..max_off);
                let len = rng.random_range(0..PAGE * 3);
                let label = format!("allocate #{id} @{offset}+{len}");
                let r = live.handles[i].0.allocate_range(offset as u64, len as u64);
                match post.reserve(id, offset, len, cap_pages, &open) {
                    Ok(_) => (label, r),
                    Err(()) => match r {
                        Err(e) if e.raw_os_error() == Some(28) => {
                            *stats.entry("enospc").or_default() += 1;
                            (label, Ok(()))
                        }
                        Ok(()) => fail!("ENOSPC-MISMATCH: {label} succeeded, model has no space"),
                        Err(e) => (label, Err(e)),
                    },
                }
            }
            39..=44 if !live.handles.is_empty() => {
                let i = rng.random_range(0..live.handles.len());
                let id = live.handles[i].1;
                let len = rng.random_range(0..max_off);
                let label = format!("set_len #{id} {len}");
                let r = live.handles[i].0.set_len(len as u64);
                post.w.get_mut(&id).unwrap().set_len(len);
                (label, r)
            }
            45..=49 if !live.handles.is_empty() => {
                let i = rng.random_range(0..live.handles.len());
                let id = live.handles[i].1;
                let offset = rng.random_range(0..max_off);
                let len = rng.random_range(0..PAGE * 3);
                let label = format!("punch #{id} @{offset}+{len}");
                let r = live.handles[i].0.punch_hole(offset as u64, len as u64);
                post.w.get_mut(&id).unwrap().punch(offset, len);
                (label, r)
            }
            50..=61 if !live.handles.is_empty() => {
                let i = rng.random_range(0..live.handles.len());
                let id = live.handles[i].1;
                let label = format!("sync_data #{id}");
                let r = live.handles[i].0.sync_data();
                let img = post.w[&id].clone();
                // Oracle self-test: a model that forgets some barriers must fail.
                if !(planted && rng.random_bool(0.2)) {
                    post.d.insert(id, img);
                }
                (label, r)
            }
            62..=69 => {
                let dir = if rng.random_bool(0.6) { "" } else { "d" };
                let label = format!("sync_dir {dir:?}");
                let r = live.b().sync_dir(dir);
                expect_fail = !post.dir_exists(dir);
                if post.dir_exists(dir) {
                    post.sync_dir(dir);
                } else if r.is_ok() {
                    fail!("UNEXPECTED: {label} succeeded on a missing directory");
                }
                (label, r)
            }
            70..=74 => {
                let name = pick_name(&mut rng);
                let label = format!("remove {name}");
                let r = live.b().remove(name);
                expect_fail = post.file(name).is_none();
                if post.file(name).is_some() {
                    post.w_entries.remove(name);
                } else if r.is_ok() {
                    fail!("UNEXPECTED: {label} succeeded on a missing file");
                }
                (label, r)
            }
            75..=79 => {
                let from = pick_name(&mut rng);
                let to = sibling(&mut rng, from);
                let label = format!("rename {from} -> {to}");
                let r = live.b().rename(from, to);
                expect_fail = post.file(from).is_none();
                if let Some(id) = post.file(from) {
                    post.w_entries.remove(from);
                    post.w_entries.insert(to.to_string(), Ent::File(id));
                } else if r.is_ok() {
                    fail!("UNEXPECTED: {label} succeeded on a missing file");
                }
                (label, r)
            }
            80..=81 => {
                let r = live.b().create_dir_all("d");
                post.w_entries.insert("d".into(), Ent::Dir);
                ("mkdir d".into(), r)
            }
            82..=85 if !live.handles.is_empty() => {
                let i = rng.random_range(0..live.handles.len());
                let (_, id) = live.handles.swap_remove(i);
                (format!("close #{id}"), Ok(()))
            }
            86..=88 => {
                let name = pick_name(&mut rng);
                let label = format!("try_lock {name}");
                let r = live.b().try_lock(name);
                expect_fail = !post.dir_exists(parent(name));
                let held = post
                    .file(name)
                    .is_some_and(|id| live.locks.iter().any(|(_, l)| *l == id));
                match r {
                    Ok(lock) => {
                        if held {
                            fail!("LOCK-IDENTITY: {label} acquired a held lock");
                        }
                        if !post.dir_exists(parent(name)) {
                            fail!("UNEXPECTED: {label} in a missing directory");
                        }
                        let id = post.create(name);
                        live.locks.push((lock, id));
                        (label, Ok(()))
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock && held => (label, Ok(())),
                    Err(e) => (label, Err(e)),
                }
            }
            89..=90 if !live.locks.is_empty() => {
                let i = rng.random_range(0..live.locks.len());
                let (_, id) = live.locks.swap_remove(i);
                (format!("unlock #{id}"), Ok(()))
            }
            91..=93 => {
                // Reads through every handle and a space query.
                let mut result = Ok(());
                for (file, id) in &live.handles {
                    let want = &post.w[id];
                    match file.len() {
                        Ok(len) if len == want.bytes.len() as u64 => {}
                        Ok(len) => {
                            fail!("LIVE-LENGTH: #{id} {len} bytes, model {}", want.bytes.len())
                        }
                        Err(e) => {
                            result = Err(e);
                            break;
                        }
                    }
                    let mut got = vec![0; want.bytes.len()];
                    if let Err(e) = file.read_at(0, &mut got) {
                        result = Err(e);
                        break;
                    }
                    if got != want.bytes {
                        fail!("LIVE-CONTENT: #{id} differs from the working model");
                    }
                }
                if result.is_ok() {
                    post.prune(&open);
                    match live.b().free_bytes() {
                        Ok(free) => {
                            let expected = cap - (post.reserved_pages() * PAGE) as u64;
                            if free != Some(expected) {
                                fail!("LIVE-FREE-SPACE: free_bytes {free:?}, model {expected}");
                            }
                        }
                        Err(e) => result = Err(e),
                    }
                }
                if result.is_ok() {
                    for dir in ["", "d"] {
                        if !post.dir_exists(dir) {
                            continue;
                        }
                        let expected: Vec<String> = post
                            .w_entries
                            .keys()
                            .filter(|name| parent(name) == dir)
                            .map(|name| name.rsplit('/').next().unwrap().to_string())
                            .collect();
                        match live.b().list(dir) {
                            Ok(names) if names == expected => {}
                            Ok(names) => {
                                fail!("LIVE-NAMES: list({dir:?}) {names:?} vs {expected:?}")
                            }
                            Err(e) => {
                                result = Err(e);
                                break;
                            }
                        }
                    }
                }
                ("check live".into(), result)
            }
            94 if remote => {
                if let Err(t) = world.witness_power_loss(&mut rng) {
                    fail!("{t}");
                }
                *stats.entry("witness-power-loss-live").or_default() += 1;
                ("witness host power loss".into(), Ok(()))
            }
            95 => {
                let dir = tempfile::tempdir().unwrap();
                let target = dir.path().join("snap");
                match live.b().snapshot_remote(&target) {
                    Ok(descriptor) => {
                        let mut image = post.clone();
                        image.restart();
                        world.snapshots.push((dir, descriptor, image));
                        if world.snapshots.len() > 3 {
                            world.snapshots.remove(0);
                        }
                        *stats.entry("snapshots").or_default() += 1;
                        ("snapshot".into(), Ok(()))
                    }
                    Err(e) => ("snapshot".into(), Err(e)),
                }
            }
            96 => {
                let pick = rng.random_range(0..world.snapshots.len());
                let (snap_path, descriptor, image) = {
                    let (dir, d, m) = &world.snapshots[pick];
                    (dir.path().join("snap"), d.clone(), m.clone())
                };
                live.handles.clear();
                live.locks.clear();
                live.backing = None;
                let mut restored = None;
                for attempt in 0..4 {
                    let record = match inspect(world.admin.as_ref()) {
                        Ok(r) => r,
                        Err(e) => {
                            log.push(format!("{step}: restore inspect failed: {e}"));
                            continue;
                        }
                    };
                    let before = world.rpcf.injected.load(Ordering::SeqCst);
                    match RollbackBacking::restore_remote(
                        world.root.path(),
                        &snap_path,
                        &descriptor,
                        world.admin.clone(),
                        &record,
                    ) {
                        Ok(b) => {
                            restored = Some(b);
                            break;
                        }
                        Err(e) => {
                            log.push(format!("{step}: restore attempt {attempt} -> ERR {e}"));
                            if world.rpcf.injected.load(Ordering::SeqCst) == before {
                                fail!("RESTORE-REFUSED: snapshot {pick}: {e}");
                            }
                        }
                    }
                }
                world.rpcf.unavailable.store(0, Ordering::SeqCst);
                world.rpcf.lost_reply.store(0, Ordering::SeqCst);
                let (backing, candidates) = match restored {
                    Some(b) => (b, vec![image.clone()]),
                    None => match world.open(&mut log) {
                        Ok(b) => {
                            let mut old = pre.clone();
                            old.restart();
                            (b, vec![old, image.clone()])
                        }
                        Err(t) => fail!("REOPEN-AFTER-RESTORE: {t}"),
                    },
                };
                let mut errors = Vec::new();
                let mut chosen = None;
                for candidate in candidates {
                    match verify_durable(&backing, &candidate, cap) {
                        Ok(()) => {
                            chosen = Some(candidate);
                            break;
                        }
                        Err(t) => errors.push(t),
                    }
                }
                match chosen {
                    Some(c) => post = c,
                    None => fail!("RESTORE-STATE: {}", errors.join("\n   or ")),
                }
                live.backing = Some(backing);
                *stats.entry("restores").or_default() += 1;
                ("restore".into(), Ok(()))
            }
            97 => {
                let r = RollbackBacking::collect_remote(world.root.path(), world.admin.as_ref());
                match r {
                    Ok(report) => {
                        *stats.entry("gc-removed").or_default() += report.counts.removed;
                        if report.counts.skipped_unrecognized != 0 {
                            fail!("GC-UNRECOGNIZED: {report:?}");
                        }
                        ("gc".into(), Ok(()))
                    }
                    Err(e) => ("gc".into(), Err(e)),
                }
            }
            _ => ("restart".into(), Err(io::Error::other("restart"))),
        };
        if block {
            let _ = std::fs::remove_dir(world.wdir.path().join("anchor.next"));
        }
        let restart = label == "restart";
        let stopped = match &outcome {
            Ok(()) => {
                log.push(format!("{step}: {label} -> ok"));
                model = post.clone();
                false
            }
            Err(e) if restart => {
                let _ = e;
                false
            }
            Err(e) => {
                log.push(format!("{step}: {label} -> ERR {e}"));
                // Expected refusals of the oracle (a missing file or dir).
                let benign = expect_fail
                    && matches!(
                        e.kind(),
                        io::ErrorKind::NotFound
                            | io::ErrorKind::NotADirectory
                            | io::ErrorKind::IsADirectory
                    );
                let injected = world.rpcf.injected.load(Ordering::SeqCst) != injected_before;
                if benign {
                    false
                } else {
                    // A real failure: only injected faults may cause one, and
                    // then the session either refused before any change or
                    // stopped (pre- or post-state durable).
                    world.rpcf.unavailable.store(0, Ordering::SeqCst);
                    world.rpcf.lost_reply.store(0, Ordering::SeqCst);
                    let poisoned = live.b().check_freshness().is_err();
                    if !block && !injected {
                        fail!("UNEXPECTED-FAILURE: {label}: {e}");
                    }
                    if poisoned {
                        *stats.entry("stopped").or_default() += 1;
                        true
                    } else {
                        // Refused before any change.
                        *stats.entry("refused").or_default() += 1;
                        model = pre.clone();
                        false
                    }
                }
            }
        };
        model.check_invariants();
        if restart || stopped {
            world.rpcf.unavailable.store(0, Ordering::SeqCst);
            world.rpcf.lost_reply.store(0, Ordering::SeqCst);
            let no_release = remote && rng.random_bool(0.3);
            world.rpcf.no_release.store(no_release, Ordering::SeqCst);
            live.handles.clear();
            live.locks.clear();
            live.backing = None;
            world.rpcf.no_release.store(false, Ordering::SeqCst);
            if remote && rng.random_bool(0.2) {
                if let Err(t) = world.witness_power_loss(&mut rng) {
                    fail!("{t}");
                }
            }
            log.push(format!(
                "{step}: == restart (stopped={stopped}, release={})",
                !no_release
            ));
            if mode != Mode::LocalBlock && rng.random_bool(0.12) {
                if world.stash.is_none() || rng.random_bool(0.3) {
                    let stash = tempfile::tempdir().unwrap();
                    copy_tree(world.root.path(), stash.path());
                    world.stash = Some(stash);
                    log.push(format!("{step}: == stash a copy of the root"));
                } else {
                    // Put an older copy of the whole root back and open it.
                    let aside = tempfile::tempdir().unwrap();
                    let aside_root = aside.path().join("root");
                    std::fs::rename(world.root.path(), &aside_root).unwrap();
                    std::fs::create_dir(world.root.path()).unwrap();
                    copy_tree(world.stash.as_ref().unwrap().path(), world.root.path());
                    let authority = remote.then(|| inspect(world.admin.as_ref()).unwrap());
                    let opened = world.open(&mut log);
                    let mut keep_rogue = false;
                    match opened {
                        Err(t) => {
                            log.push(format!("{step}: == old root refused ({t})"));
                            *stats.entry("rollback-refused").or_default() += 1;
                            if let Some(before) = authority {
                                let after = inspect(world.admin.as_ref()).unwrap();
                                if after != before {
                                    fail!(
                                        "ROLLBACK-CHANGED-AUTHORITY: a refused old root changed \
                                         the authority: {before:?} -> {after:?}"
                                    );
                                }
                            }
                        }
                        Ok(b) => {
                            log.push(format!("{step}: == old root ACCEPTED"));
                            *stats.entry("rollback-accepted").or_default() += 1;
                            let mut errors = Vec::new();
                            let mut matched = false;
                            let mut candidates = vec![model.clone()];
                            if stopped {
                                candidates = vec![pre.clone(), post.clone()];
                            }
                            for mut candidate in candidates {
                                candidate.restart();
                                match verify_durable(&b, &candidate, cap) {
                                    Ok(()) => matched = true,
                                    Err(t) => errors.push(t),
                                }
                            }
                            if !matched {
                                fail!("ROLLBACK-SERVED: {}", errors.join("\n   or "));
                            }
                            drop(b);
                            keep_rogue = true;
                        }
                    }
                    if !keep_rogue {
                        std::fs::remove_dir_all(world.root.path()).unwrap();
                        std::fs::rename(&aside_root, world.root.path()).unwrap();
                    }
                }
            }
            if mode == Mode::RemoteAdmin && rng.random_bool(0.2) {
                if let Err(e) =
                    RollbackBacking::collect_remote(world.root.path(), world.admin.as_ref())
                {
                    log.push(format!("{step}: offline gc -> ERR {e}"));
                }
            }
            let backing = match world.open(&mut log) {
                Ok(b) => b,
                Err(t) => fail!("REOPEN-REFUSED: {t}"),
            };
            let mut candidates = vec![model.clone()];
            if stopped {
                candidates = vec![pre.clone(), post.clone()];
            }
            let mut errors = Vec::new();
            let mut chosen = None;
            for mut candidate in candidates {
                candidate.restart();
                match verify_durable(&backing, &candidate, cap) {
                    Ok(()) => {
                        chosen = Some(candidate);
                        break;
                    }
                    Err(t) => errors.push(t),
                }
            }
            match chosen {
                Some(c) => model = c,
                None => fail!("{}", errors.join("\n   or ")),
            }
            live.backing = Some(backing);
            *stats.entry("restarts").or_default() += 1;
        }
        *stats.entry("steps").or_default() += 1;
    }
    Ok(stats)
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn sweep(mode: Mode) {
    let budget = Duration::from_secs(env_or("AUDIT_BUDGET_SECS", 20));
    let start = env_or("AUDIT_SEED_START", 0);
    let count = env_or("AUDIT_SEED_COUNT", 200);
    let steps = env_or("AUDIT_STEPS", 300) as usize;
    let started = Instant::now();
    let mut totals: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut run = 0;
    for seed in start..start + count {
        if started.elapsed() > budget {
            break;
        }
        run += 1;
        match run_seed(mode, seed, steps) {
            Ok(stats) => {
                for (k, v) in stats {
                    *totals.entry(k).or_default() += v;
                }
            }
            Err(text) => {
                println!(
                    "AUDIT-FAIL mode={mode:?} seed={seed} class={}",
                    text.split(':').next().unwrap_or("?")
                );
                failures.push((seed, text));
            }
        }
    }
    println!(
        "AUDIT-SWEEP mode={mode:?} seeds={start}..{} run={run} failures={} elapsed={:.0}s {totals:?}",
        start + run,
        failures.len(),
        started.elapsed().as_secs_f64()
    );
    if let Some((seed, text)) = failures.first() {
        panic!("{} failure(s); first seed {seed}:\n{text}", failures.len());
    }
}

#[test]
fn audit4_rollback_model_local() {
    sweep(Mode::Local);
}

#[test]
fn audit4_rollback_model_local_witness_block() {
    sweep(Mode::LocalBlock);
}

#[test]
fn audit4_rollback_model_remote() {
    sweep(Mode::Remote);
}

#[test]
fn audit4_rollback_model_remote_faults() {
    sweep(Mode::RemoteFaults);
}

#[test]
fn audit4_rollback_model_remote_admin() {
    sweep(Mode::RemoteAdmin);
}
