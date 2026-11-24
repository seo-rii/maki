//! Round 9 (r8-storage): verbatim copy of round 8's `audit8_sweep_rollback.rs` from the dev branch,
//! re-run on the merged tree (1d4c7ea). Only this header was added.
//!
//! Audit round 2: the engine on rollback-protected backings (local witness
//! and the in-process remote witness of `maki-backing`'s remote tests) under
//! crash/fault sweeps. Not part of the maintained suite.
//!
//! The rollback backing keeps unsynced bytes in a process-local working view,
//! so a process restart is the only crash an in-process test can produce for
//! it (its private `open_backing` crash hook is not reachable from here): a
//! restart drops everything the engine did not sync. Around it the sweep
//! injects, between the engine and the backing, transient failures of every
//! mutation (fail before, short write, sync that persisted but reports EIO),
//! process deaths at a random mutation, cancelled requests, and for the
//! remote witness: unavailable authority, lost replies after a durable
//! commit, a process that dies without releasing its session (attach then
//! needs the documented administrator takeover) and power losses of the
//! witness host's own state directory (a `CrashableBacking`).
//!
//! Oracle: after any restart the volume attaches (or refuses only for a
//! documented reason, which is then resolved as documented) and every unit
//! shows a value the durability model allows; whatever an attach serves is
//! pinned and must survive the next restart.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::remote_witness::{Action, Phase, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, BackingFile, RollbackBacking, VolumeLock};
use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_core::error::CoreError;
use maki_core::volume::VolumeOptions;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ReferenceBlockModel};

// ---------------------------------------------------------------------------
// Processes and cancellation (as in audit2_sweep_engine.rs)

struct Proc {
    rt: Option<tokio::runtime::Runtime>,
}

impl Proc {
    fn new() -> Self {
        Self {
            rt: Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap(),
            ),
        }
    }
    async fn run<T: Send + 'static>(&self, fut: impl Future<Output = T> + Send + 'static) -> T {
        match self.rt.as_ref().unwrap().handle().spawn(fut).await {
            Ok(v) => v,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => panic!("PROCESS-TASK: {e}"),
        }
    }
    fn kill(mut self) {
        let rt = self.rt.take().unwrap();
        std::thread::spawn(move || rt.shutdown_timeout(Duration::from_secs(60)))
            .join()
            .unwrap();
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

struct CancelAfterPolls<F> {
    inner: Option<Pin<Box<F>>>,
    left: u32,
}

impl<F: Future> Future for CancelAfterPolls<F> {
    type Output = Option<F::Output>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.inner.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Ready(v) => {
                this.inner = None;
                Poll::Ready(Some(v))
            }
            Poll::Pending => {
                this.left = this.left.saturating_sub(1);
                if this.left == 0 {
                    this.inner = None;
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Faults between the engine and the rollback backing

struct Faults {
    /// Transient faults are live.
    enabled: AtomicBool,
    /// A process death: every mutation fails from now on.
    dead: AtomicBool,
    /// Mutations left before a death; negative = not armed.
    countdown: AtomicI64,
    permille: u32,
    mutations: AtomicU64,
    rng: Mutex<StdRng>,
    log: Arc<Mutex<Vec<String>>>,
}

enum SyncFault {
    None,
    /// Fails without reaching the backing (the syscall never ran).
    Before,
    /// Reached the backing (committed) and then reported EIO.
    Lie,
}

impl Faults {
    fn gate(&self, what: &str) -> io::Result<()> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(io::Error::other("audit: process is dead"));
        }
        self.mutations.fetch_add(1, Ordering::SeqCst);
        let left = self.countdown.load(Ordering::SeqCst);
        if left >= 0 {
            if left <= 1 {
                self.dead.store(true, Ordering::SeqCst);
                self.log.lock().push(format!("      !! DEATH at {what}"));
                return Err(io::Error::other("audit: process died"));
            }
            self.countdown.store(left - 1, Ordering::SeqCst);
        }
        Ok(())
    }
    fn roll(&self) -> bool {
        self.enabled.load(Ordering::SeqCst) && self.rng.lock().random_range(0..1000) < self.permille
    }
    fn mutation(&self, what: &str) -> io::Result<()> {
        self.gate(what)?;
        if self.roll() {
            self.log.lock().push(format!("      ! fault {what}"));
            return Err(io::Error::other("audit: injected failure"));
        }
        Ok(())
    }
    fn sync(&self, what: &str) -> io::Result<SyncFault> {
        self.gate(what)?;
        if self.roll() {
            if self.rng.lock().random_bool(0.5) {
                self.log.lock().push(format!("      ! fault {what}"));
                return Ok(SyncFault::Before);
            }
            self.log.lock().push(format!("      ! lying {what}"));
            return Ok(SyncFault::Lie);
        }
        Ok(SyncFault::None)
    }
    fn partial(&self, len: usize) -> Option<usize> {
        (len > 1 && self.roll()).then(|| self.rng.lock().random_range(0..len))
    }
}

struct Faulty {
    inner: Arc<dyn Backing>,
    f: Arc<Faults>,
}

struct FaultyFile {
    inner: Arc<dyn BackingFile>,
    path: String,
    f: Arc<Faults>,
}

impl BackingFile for FaultyFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.f
            .mutation(&format!("write {} @{offset}+{}", self.path, data.len()))?;
        if let Some(keep) = self.f.partial(data.len()) {
            self.f.log.lock().push(format!(
                "      ! short write {keep}/{} {}",
                data.len(),
                self.path
            ));
            self.inner.write_at(offset, &data[..keep])?;
            return Err(io::Error::other("audit: short write"));
        }
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.f.mutation(&format!("set_len {} {len}", self.path))?;
        self.inner.set_len(len)
    }
    fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
        self.f.mutation(&format!("allocate {}", self.path))?;
        self.inner.allocate_range(offset, len)
    }
    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        self.f.mutation(&format!("punch {}", self.path))?;
        self.inner.punch_hole(offset, len)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        match self.f.sync(&format!("sync {}", self.path))? {
            SyncFault::None => self.inner.sync_data(),
            SyncFault::Before => Err(io::Error::other("audit: sync failed")),
            SyncFault::Lie => {
                self.inner.sync_data()?;
                Err(io::Error::other(
                    "audit: sync persisted but reported failure",
                ))
            }
        }
    }
    fn sync_all(&self) -> io::Result<()> {
        match self.f.sync(&format!("sync_all {}", self.path))? {
            SyncFault::None => self.inner.sync_all(),
            SyncFault::Before => Err(io::Error::other("audit: sync failed")),
            SyncFault::Lie => {
                self.inner.sync_all()?;
                Err(io::Error::other(
                    "audit: sync persisted but reported failure",
                ))
            }
        }
    }
}

impl Backing for Faulty {
    fn check_freshness(&self) -> io::Result<()> {
        self.inner.check_freshness()
    }
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        if create {
            self.f.mutation(&format!("open+create {path}"))?;
        }
        let inner = self.inner.open(path, create)?;
        Ok(Arc::new(FaultyFile {
            inner,
            path: path.to_string(),
            f: self.f.clone(),
        }))
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.inner.exists(path)
    }
    fn remove(&self, path: &str) -> io::Result<()> {
        self.f.mutation(&format!("remove {path}"))?;
        self.inner.remove(path)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.f.mutation(&format!("rename {from} -> {to}"))?;
        self.inner.rename(from, to)
    }
    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.f.mutation(&format!("mkdir {path}"))?;
        self.inner.create_dir_all(path)
    }
    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        self.inner.list(dir)
    }
    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        match self.f.sync(&format!("sync_dir {dir:?}"))? {
            SyncFault::None => self.inner.sync_dir(dir),
            SyncFault::Before => Err(io::Error::other("audit: dir sync failed")),
            SyncFault::Lie => {
                self.inner.sync_dir(dir)?;
                Err(io::Error::other(
                    "audit: dir sync persisted but reported failure",
                ))
            }
        }
    }
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(path)
    }
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.inner.free_bytes()
    }
}

// ---------------------------------------------------------------------------
// The in-process remote witness (as in maki-backing/tests/remote_rollback.rs)

struct RpcFaults {
    enabled: AtomicBool,
    unavailable: u32,
    lost_reply: u32,
    /// The process died: its Release is never sent.
    no_release: AtomicBool,
    rng: Mutex<StdRng>,
    log: Arc<Mutex<Vec<String>>>,
}

struct FakeRpc {
    store: Arc<Mutex<Option<StateStore>>>,
    role: Role,
    f: Arc<RpcFaults>,
}

impl Rpc for FakeRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        let name = match &request.action {
            Action::Inspect => "inspect",
            Action::Claim => "claim",
            Action::Takeover => "takeover",
            Action::Activate { .. } => "activate",
            Action::Advance { .. } => "advance",
            Action::Release => "release",
            _ => "other",
        };
        if self.f.no_release.load(Ordering::SeqCst) && name == "release" {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "audit: the process died before its release",
            ));
        }
        let live = self.f.enabled.load(Ordering::SeqCst);
        if live && self.f.rng.lock().random_range(0..1000) < self.f.unavailable {
            self.f
                .log
                .lock()
                .push(format!("      ! witness unavailable for {name}"));
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
        if live && name != "inspect" && self.f.rng.lock().random_range(0..1000) < self.f.lost_reply
        {
            self.f
                .log
                .lock()
                .push(format!("      ! witness reply lost after commit of {name}"));
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
// Configuration

#[derive(Clone, Debug)]
struct Cfg {
    remote: bool,
    unit: u32,
    device_units: u64,
    units_per_shard: u64,
    segment_size: u64,
    journal_max_bytes: u64,
    max_pending_bytes: u64,
    max_overlay_entries: u64,
    discard: bool,
    worker: bool,
    /// Permille of engine-to-backing mutations failing (fault cycles).
    permille: u32,
    witness_unavailable: u32,
    witness_lost_reply: u32,
    cancel_pct: u32,
    death_pct: u32,
}

fn cfg_for(name: &str, seed: u64) -> Cfg {
    let mut r = StdRng::seed_from_u64(seed ^ 0x0110_BAC4);
    let unit = [512u32, 512, 1024, 4096][r.random_range(0..4)];
    let rec = 32 + unit as u64 + 8;
    let device_units = r.random_range(4..=24u64);
    let per_segment = r.random_range(1..=4u64);
    let segment_size = 48 + per_segment * rec;
    Cfg {
        remote: name.starts_with("remote"),
        unit,
        device_units,
        units_per_shard: [1u64, 3, 8][r.random_range(0..3)].min(device_units),
        segment_size,
        journal_max_bytes: 3 * segment_size + 5 * rec + 7 * 48,
        max_pending_bytes: rec * r.random_range(1..=3u64),
        max_overlay_entries: if r.random_bool(0.5) { 0 } else { 6 },
        discard: r.random_bool(0.6),
        worker: r.random_bool(0.5),
        permille: if name.ends_with("faults") { 25 } else { 0 },
        witness_unavailable: if name.ends_with("faults") && name.starts_with("remote") {
            8
        } else {
            0
        },
        witness_lost_reply: if name.starts_with("remote") { 60 } else { 0 },
        cancel_pct: 15,
        death_pct: 40,
    }
}

impl Cfg {
    fn superblock(&self) -> Superblock {
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xA0D2_B000 + self.unit as u128),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                512,
                self.unit,
                512,
                self.unit + 8,
                self.device_units * self.unit as u64,
                self.units_per_shard * self.unit as u64,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        }
    }
    fn options(&self) -> EngineOptions {
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: self.segment_size,
            },
            limits: EngineLimits {
                max_request_bytes: 4 * self.unit as u64,
                max_overlay_entries: self.max_overlay_entries,
                ..EngineLimits::default()
            },
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: if self.worker {
                    self.segment_size.max(160)
                } else {
                    u64::MAX
                },
                journal_max_bytes: self.journal_max_bytes,
                max_pending_bytes: self.max_pending_bytes,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
            },
            ..EngineOptions::default()
        }
    }
}

const CAPACITY: u64 = 2 << 20;

struct World {
    cfg: Cfg,
    root: tempfile::TempDir,
    /// The local witness lives on another filesystem (tmpfs).
    wdir: tempfile::TempDir,
    store_backing: Arc<CrashableBacking>,
    store: Arc<Mutex<Option<StateStore>>>,
    writer: Arc<FakeRpc>,
    admin: Arc<FakeRpc>,
    rpcf: Arc<RpcFaults>,
    log: Arc<Mutex<Vec<String>>>,
}

impl World {
    fn new(cfg: Cfg, seed: u64, log: Arc<Mutex<Vec<String>>>) -> Self {
        let store_backing = Arc::new(CrashableBacking::new().with_tearing(64));
        let store = Arc::new(Mutex::new(None));
        if cfg.remote {
            *store.lock() = Some(
                StateStore::create_backing(store_backing.process() as Arc<dyn Backing>, [7; 16])
                    .unwrap(),
            );
        }
        let rpcf = Arc::new(RpcFaults {
            enabled: AtomicBool::new(false),
            unavailable: cfg.witness_unavailable,
            lost_reply: cfg.witness_lost_reply,
            no_release: AtomicBool::new(false),
            rng: Mutex::new(StdRng::seed_from_u64(seed ^ 0x5157)),
            log: log.clone(),
        });
        let rpc = |role| {
            Arc::new(FakeRpc {
                store: store.clone(),
                role,
                f: rpcf.clone(),
            })
        };
        Self {
            root: tempfile::tempdir().unwrap(),
            wdir: tempfile::tempdir_in("/dev/shm").unwrap(),
            writer: rpc(Role::Writer),
            admin: rpc(Role::Admin),
            store_backing,
            store,
            rpcf,
            cfg,
            log,
        }
    }

    fn create(&self) -> RollbackBacking {
        if self.cfg.remote {
            RollbackBacking::create_remote(self.root.path(), self.writer.clone(), CAPACITY).unwrap()
        } else {
            RollbackBacking::create(self.root.path(), self.wdir.path(), CAPACITY).unwrap()
        }
    }

    /// Reopen after a restart. The only documented refusal is an occupied
    /// remote authority (a crash or an ambiguous response), resolved by the
    /// documented exact-current administrator takeover.
    fn open(&self, stats: &Stats) -> Result<RollbackBacking, String> {
        if !self.cfg.remote {
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
        self.log.lock().push(format!(
            "   open_remote refused ({first}); phase {:?} -> administrator takeover",
            record.phase
        ));
        stats.bump("takeovers");
        RollbackBacking::takeover_remote(self.root.path(), self.admin.clone(), &record)
            .map_err(|e| format!("takeover after refused open ({first}): {e}"))
    }

    /// The witness host loses power and restarts its authority.
    fn witness_power_loss(&self, rng: &mut StdRng) -> Result<(), String> {
        let mut store = self.store.lock();
        *store = None;
        if rng.random_bool(0.3) {
            self.store_backing.crash_all_lost();
        } else {
            self.store_backing.crash(rng);
        }
        *store = Some(
            StateStore::open_backing(self.store_backing.process() as Arc<dyn Backing>)
                .map_err(|e| format!("WITNESS-REOPEN: {e}"))?,
        );
        Ok(())
    }
}

#[derive(Default)]
struct Stats {
    counters: Mutex<BTreeMap<String, u64>>,
}

impl Stats {
    fn bump(&self, key: &str) {
        *self.counters.lock().entry(key.to_string()).or_default() += 1;
    }
    fn render(&self) -> String {
        self.counters
            .lock()
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn pattern(stamp: u32, offset: u64, len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            let o = (offset + i) as u32;
            let x = stamp.wrapping_mul(0x9E37_79B1) ^ o.wrapping_mul(0x85EB_CA6B);
            let x = (x ^ (x >> 15)).wrapping_mul(0x2545_F491);
            ((x >> 24) as u8) | 1
        })
        .collect()
}

#[derive(Clone)]
enum Req {
    Write {
        offset: u64,
        data: Vec<u8>,
        fua: bool,
    },
    Trim {
        offset: u64,
        len: usize,
        fua: bool,
    },
    Flush,
    Checkpoint,
}

async fn issue(
    proc: &Proc,
    engine: &Engine,
    req: Req,
    cut: Option<u32>,
) -> Option<Result<(), CoreError>> {
    let e = engine.clone();
    proc.run(async move {
        let fut = async {
            match req {
                Req::Write { offset, data, fua } => e.write(offset, &data, fua).await,
                Req::Trim { offset, len, fua } => e.trim(offset, len, fua).await,
                Req::Flush => e.flush().await,
                Req::Checkpoint => e.checkpoint().await.map(|_| ()),
            }
        };
        match cut {
            None => Some(fut.await),
            Some(n) => {
                CancelAfterPolls {
                    inner: Some(Box::pin(fut)),
                    left: n,
                }
                .await
            }
        }
    })
    .await
}

async fn read_unit(
    proc: &Proc,
    engine: &Engine,
    unit: u64,
    size: usize,
) -> Result<Vec<u8>, CoreError> {
    let e = engine.clone();
    proc.run(async move { e.read(unit * size as u64, size).await })
        .await
}

async fn settle(proc: &Proc, engine: &Engine) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let e = engine.clone();
        let s = proc.run(async move { e.stats().await }).await;
        if s.admission_slots == 0 && s.active_requests == 0 {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "SETTLE-HANG: admission_slots={}",
                s.admission_slots
            ));
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn run_seed(name: &str, seed: u64, cycles: usize, stats: Arc<Stats>) {
    let cfg = cfg_for(name, seed);
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let say = |t: String| log.lock().push(t);
    let history = || {
        let lines = log.lock();
        let skip = lines.len().saturating_sub(300);
        format!(
            "cfg {name} seed {seed} {cfg:?}\n  {}",
            lines[skip..].join("\n  ")
        )
    };
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9) ^ 0x0110);
    let world = World::new(cfg.clone(), seed, log.clone());
    let faults = Arc::new(Faults {
        enabled: AtomicBool::new(false),
        dead: AtomicBool::new(false),
        countdown: AtomicI64::new(-1),
        permille: cfg.permille,
        mutations: AtomicU64::new(0),
        rng: Mutex::new(StdRng::seed_from_u64(seed ^ 0xFA17)),
        log: log.clone(),
    });
    let rb = Arc::new(world.create());
    let wrap = |rb: &Arc<RollbackBacking>| -> Arc<dyn Backing> {
        Arc::new(Faulty {
            inner: rb.clone() as Arc<dyn Backing>,
            f: faults.clone(),
        })
    };
    {
        let backing = wrap(&rb);
        if cfg.discard {
            init::create_volume_with_discard(backing.as_ref(), cfg.superblock()).unwrap();
        } else {
            init::create_volume(backing.as_ref(), cfg.superblock()).unwrap();
        }
    }
    let unit = cfg.unit as u64;
    let usize_unit = cfg.unit as usize;
    let mut model = ReferenceBlockModel::new(usize_unit, cfg.device_units);
    let zeros = vec![0u8; usize_unit];
    let mut stamp = 0u32;
    let mut rb = Some(rb);
    let mut workload_mutations = 60u64;
    let mut snapshot: Option<tempfile::TempDir> = None;

    for cycle in 0..cycles {
        let b = rb.take().expect("open backing");
        let proc = Proc::new();
        let attach = {
            let (backing, options, u) = (wrap(&b), cfg.options(), cfg.unit);
            proc.run(async move {
                Engine::attach(backing, Arc::new(FakeCryptoProvider::new(u)), options).await
            })
            .await
        };
        let engine = match attach {
            Ok(engine) => engine,
            Err(e) => panic!("ATTACH-REFUSED: {e}\n{}", history()),
        };
        // Pin what this attach serves.
        let mut maybe: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
        for u in 0..cfg.device_units {
            let actual = match read_unit(&proc, &engine, u, usize_unit).await {
                Ok(v) => v,
                Err(e) => panic!("READ-AFTER-RECOVERY: unit {u}: {e}\n{}", history()),
            };
            if let Err(v) = model.crash_adopt(u, &actual) {
                panic!("ORACLE: {v}\n{}", history());
            }
        }
        stats.bump("attaches-checked");

        let faulty = cfg.permille > 0 && rng.random_bool(0.6);
        let death = rng.random_range(0..100) < cfg.death_pct;
        faults.enabled.store(faulty && !death, Ordering::SeqCst);
        world
            .rpcf
            .enabled
            .store(rng.random_bool(0.7), Ordering::SeqCst);
        if death {
            faults.countdown.store(
                rng.random_range(1..=workload_mutations.max(8)) as i64,
                Ordering::SeqCst,
            );
        }
        say(format!("-- cycle {cycle} faults={faulty} death={death}"));
        let before = faults.mutations.load(Ordering::SeqCst);
        let mut stopped = false;
        for _ in 0..rng.random_range(5..30) {
            stats.bump("ops");
            if cfg.remote && rng.random_range(0..100) < 4 {
                // The witness host loses power while this writer is active:
                // its session must survive (nothing it was told is lost).
                if let Err(t) = world.witness_power_loss(&mut rng) {
                    panic!("{t}\n{}", history());
                }
                say("== witness host power loss (writer active)".into());
                stats.bump("witness-power-losses-live");
            }
            let roll = rng.random_range(0..100);
            let cut = (rng.random_range(0..100) < cfg.cancel_pct).then(|| rng.random_range(1..=12));
            let (req, images): (Req, Vec<(u64, Vec<u8>)>) = match roll {
                0..=54 => {
                    let count = rng.random_range(1..=3u64.min(cfg.device_units));
                    let first = rng.random_range(0..=cfg.device_units - count);
                    let fua = rng.random_bool(0.3);
                    stamp += 1;
                    let data = pattern(stamp, first * unit, (count * unit) as usize);
                    let images = (0..count)
                        .map(|i| {
                            (
                                first + i,
                                data[(i * unit) as usize..((i + 1) * unit) as usize].to_vec(),
                            )
                        })
                        .collect();
                    (
                        Req::Write {
                            offset: first * unit,
                            data,
                            fua,
                        },
                        images,
                    )
                }
                55..=66 if cfg.discard => {
                    let count = rng.random_range(1..=3u64.min(cfg.device_units));
                    let first = rng.random_range(0..=cfg.device_units - count);
                    let fua = rng.random_bool(0.3);
                    (
                        Req::Trim {
                            offset: first * unit,
                            len: (count * unit) as usize,
                            fua,
                        },
                        (first..first + count).map(|u| (u, zeros.clone())).collect(),
                    )
                }
                55..=84 => (Req::Flush, Vec::new()),
                _ => (Req::Checkpoint, Vec::new()),
            };
            let fua = matches!(
                req,
                Req::Write { fua: true, .. } | Req::Trim { fua: true, .. }
            );
            let flush = matches!(req, Req::Flush);
            let label = match &req {
                Req::Write { offset, data, fua } => {
                    format!("write off {offset} len {} fua={fua}", data.len())
                }
                Req::Trim { offset, len, fua } => format!("trim off {offset} len {len} fua={fua}"),
                Req::Flush => "flush".into(),
                Req::Checkpoint => "checkpoint".into(),
            };
            let result = issue(&proc, &engine, req, cut).await;
            say(format!(
                "{label} cut={cut:?} -> {}",
                match &result {
                    None => "CANCELLED".to_string(),
                    Some(Ok(())) => "ok".into(),
                    Some(Err(e)) => format!("ERR {e}"),
                }
            ));
            match result {
                Some(Ok(())) => {
                    for (u, image) in &images {
                        if fua {
                            model.write_fua(*u, image);
                        } else {
                            model.write(*u, image);
                        }
                    }
                    if flush {
                        model.flush();
                    }
                }
                outcome => {
                    let failed = outcome.is_some();
                    if failed {
                        stats.bump("failed-requests");
                    } else {
                        stats.bump("cancelled-requests");
                    }
                    let live = faults.enabled.load(Ordering::SeqCst)
                        || world.rpcf.enabled.load(Ordering::SeqCst)
                        || faults.dead.load(Ordering::SeqCst);
                    if failed && !live {
                        panic!(
                            "UNEXPECTED-FAILURE: {label} failed without faults\n{}",
                            history()
                        );
                    }
                    if !failed {
                        let was = faults.enabled.swap(false, Ordering::SeqCst);
                        let rpc_was = world.rpcf.enabled.swap(false, Ordering::SeqCst);
                        if let Err(t) = settle(&proc, &engine).await {
                            panic!("{t}\n{}", history());
                        }
                        faults.enabled.store(was, Ordering::SeqCst);
                        world.rpcf.enabled.store(rpc_was, Ordering::SeqCst);
                    }
                    // Resolve by reading back, faults off; a session the
                    // rollback layer stopped (or a dead process) cannot be
                    // read: its units stay undecided until the restart.
                    let was = faults.enabled.swap(false, Ordering::SeqCst);
                    let rpc_was = world.rpcf.enabled.swap(false, Ordering::SeqCst);
                    let mut unreadable = faults.dead.load(Ordering::SeqCst);
                    if !unreadable {
                        for (u, image) in &images {
                            match read_unit(&proc, &engine, *u, usize_unit).await {
                                Ok(actual) if actual == *image => {
                                    if actual != model.read(*u) {
                                        model.write(*u, &actual);
                                    }
                                }
                                Ok(actual) => assert!(
                                    actual == model.read(*u),
                                    "LIVE-FOREIGN: unit {u} after {label}\n{}",
                                    history()
                                ),
                                Err(e) => {
                                    say(format!("      read-back of unit {u} failed: {e}"));
                                    if !live {
                                        panic!(
                                            "LIVE-READ-FAILED: unit {u} after a cancelled {label}: {e}\n{}",
                                            history()
                                        );
                                    }
                                    unreadable = true;
                                    break;
                                }
                            }
                        }
                    }
                    faults.enabled.store(was, Ordering::SeqCst);
                    world.rpcf.enabled.store(rpc_was, Ordering::SeqCst);
                    if unreadable {
                        for (u, image) in &images {
                            maybe.entry(*u).or_default().push(image.clone());
                        }
                        stats.bump("stopped-sessions");
                        stopped = true;
                    }
                }
            }
            if stopped || faults.dead.load(Ordering::SeqCst) {
                break;
            }
        }
        if !death {
            workload_mutations = (faults.mutations.load(Ordering::SeqCst) - before).max(8);
        }
        // The process dies; sometimes without sending its release.
        faults.enabled.store(false, Ordering::SeqCst);
        world.rpcf.enabled.store(false, Ordering::SeqCst);
        faults.dead.store(true, Ordering::SeqCst);
        let no_release = cfg.remote && rng.random_bool(0.3);
        world.rpcf.no_release.store(no_release, Ordering::SeqCst);
        drop(engine);
        proc.kill();
        assert_eq!(
            Arc::strong_count(&b),
            1,
            "HARNESS: the rollback backing outlived its process\n{}",
            history()
        );
        drop(b);
        world.rpcf.no_release.store(false, Ordering::SeqCst);
        faults.dead.store(false, Ordering::SeqCst);
        faults.countdown.store(-1, Ordering::SeqCst);
        say(format!("== restart (release sent: {})", !no_release));
        stats.bump("restarts");
        if cfg.remote && rng.random_bool(0.3) {
            if let Err(t) = world.witness_power_loss(&mut rng) {
                panic!("{t}\n{}", history());
            }
            say("== witness host power loss".into());
            stats.bump("witness-power-losses");
        }
        // An offline deep check of the reopened backing must be read-only
        // and clean.
        if rng.random_bool(0.25) {
            let b = match world.open(&stats) {
                Ok(b) => Arc::new(b),
                Err(t) => panic!("ATTACH-REFUSED (check): {t}\n{}", history()),
            };
            let before = faults.mutations.load(Ordering::SeqCst);
            let report = maki_core::check::deep_check(wrap(&b), cfg.segment_size);
            if faults.mutations.load(Ordering::SeqCst) != before {
                panic!(
                    "CHECK-MUTATED: deep check mutated the backing\n{}",
                    history()
                );
            }
            match report {
                Ok(r) if !r.errors.is_empty() => {
                    panic!("CHECK-FALSE-POSITIVE: {:?}\n{}", r.errors, history())
                }
                Ok(_) => stats.bump("checks"),
                Err(e) => panic!("CHECK-ERROR: {e}\n{}", history()),
            }
            drop(b);
        }
        // Rollback attempt: restore an older copy of the whole backing root
        // (taken at an earlier restart). The witness has advanced since, so
        // the backing must refuse it, or serve nothing older than the model.
        if snapshot.is_none() && rng.random_bool(0.2) {
            let snap = tempfile::tempdir().unwrap();
            copy_tree(world.root.path(), snap.path());
            snapshot = Some(snap);
            say("== snapshot of the backing root taken".into());
        } else if snapshot.is_some() && rng.random_bool(0.4) {
            let snap = snapshot.take().unwrap();
            let aside = tempfile::tempdir().unwrap();
            let aside_root = aside.path().join("root");
            std::fs::rename(world.root.path(), &aside_root).unwrap();
            copy_tree(snap.path(), world.root.path());
            match world.open(&stats) {
                Err(t) => {
                    say(format!("== old root restored: refused ({t})"));
                    stats.bump("rollback-refused");
                }
                Ok(b) => {
                    say("== old root restored: ACCEPTED".into());
                    stats.bump("rollback-accepted");
                    let b = Arc::new(b);
                    let p = Proc::new();
                    let attach = {
                        let (backing, options, u) = (wrap(&b), cfg.options(), cfg.unit);
                        p.run(async move {
                            Engine::attach(backing, Arc::new(FakeCryptoProvider::new(u)), options)
                                .await
                        })
                        .await
                    };
                    if let Ok(engine) = attach {
                        for u in 0..cfg.device_units {
                            if let Ok(actual) = read_unit(&p, &engine, u, usize_unit).await {
                                let allowed = model.allowed_after_crash(u);
                                let maybe_ok = maybe.get(&u).is_some_and(|m| m.contains(&actual));
                                assert!(
                                    allowed.contains(&actual) || maybe_ok,
                                    "ROLLBACK-SERVED: a restored older backing root attached and \
                                     unit {u} shows an older image than the acknowledged state\n{}",
                                    history()
                                );
                            }
                        }
                        drop(engine);
                    }
                    p.kill();
                    drop(b);
                }
            }
            std::fs::remove_dir_all(world.root.path()).unwrap();
            std::fs::rename(&aside_root, world.root.path()).unwrap();
        }
        // The pinned state may hold units of a stopped session's request.
        for (u, set) in &maybe {
            for image in set {
                if *image != model.read(*u) {
                    model.write(*u, image);
                }
            }
        }
        rb = match world.open(&stats) {
            Ok(b) => Some(Arc::new(b)),
            Err(t) => panic!("ATTACH-REFUSED (backing): {t}\n{}", history()),
        };
    }
    drop(rb);
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    let status = std::process::Command::new("cp")
        .arg("-a")
        .arg("--sparse=always")
        .arg(format!("{}/.", from.display()))
        .arg(to)
        .status()
        .unwrap();
    assert!(status.success(), "cp failed");
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn sweep(name: &str) {
    let budget = Duration::from_secs(env_or("AUDIT_BUDGET_SECS", 30));
    let start = env_or("AUDIT8_SEED_START", env_or("AUDIT_SEED_START", 0));
    let count = env_or("AUDIT8_SEED_COUNT", env_or("AUDIT_SEED_COUNT", 40));
    let cycles = env_or("AUDIT_CYCLES", 6) as usize;
    let stats = Arc::new(Stats::default());
    let started = Instant::now();
    let mut failures = Vec::new();
    let mut run = 0;
    for seed in start..start + count {
        if started.elapsed() > budget {
            break;
        }
        run += 1;
        let stats = stats.clone();
        let owned = name.to_string();
        if let Err(join) =
            tokio::spawn(async move { run_seed(&owned, seed, cycles, stats).await }).await
        {
            let text = match join.try_into_panic() {
                Ok(p) => p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default(),
                Err(e) => e.to_string(),
            };
            println!(
                "AUDIT-FAIL cfg={name} seed={seed} class={}",
                text.split(':').next().unwrap_or("?")
            );
            failures.push((seed, text));
        }
    }
    println!(
        "AUDIT-SWEEP cfg={name} seeds={start}..{} run={run} cycles={cycles} failures={} elapsed={:.0}s | {}",
        start + run,
        failures.len(),
        started.elapsed().as_secs_f64(),
        stats.render()
    );
    if let Some((seed, text)) = failures.first() {
        panic!("{} failure(s); first seed {seed}:\n{text}", failures.len());
    }
}

#[tokio::test]
async fn audit2_rollback_local() {
    sweep("local").await;
}

#[tokio::test]
async fn audit2_rollback_local_faults() {
    sweep("local-faults").await;
}

#[tokio::test]
async fn audit2_rollback_remote() {
    sweep("remote").await;
}

#[tokio::test]
async fn audit2_rollback_remote_faults() {
    sweep("remote-faults").await;
}
