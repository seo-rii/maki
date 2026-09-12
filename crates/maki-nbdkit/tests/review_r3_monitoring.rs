//! MAKI-039: monitoring remains available while storage calls are stuck.

use std::io;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_control::server::ControlBackend;
use maki_core::engine::{Engine, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_nbdkit::control::EngineControlBackend;
use maki_test_support::{clock::ManualClock, CrashableBacking, FakeCryptoProvider};
use serde_json::Value;

#[derive(Default)]
struct Gate {
    state: Mutex<(bool, bool, bool)>, // armed, entered, released
    changed: Condvar,
}

impl Gate {
    fn arm(self: &Arc<Self>) -> Release {
        *self.state.lock().unwrap() = (true, false, false);
        Release(self.clone())
    }

    fn pause(&self) {
        let mut state = self.state.lock().unwrap();
        if state.0 {
            state.1 = true;
            self.changed.notify_all();
            while !state.2 {
                state = self.changed.wait(state).unwrap();
            }
        }
    }

    fn wait_until_entered(&self) {
        let (state, _) = self
            .changed
            .wait_timeout_while(self.state.lock().unwrap(), Duration::from_secs(5), |s| !s.1)
            .unwrap();
        assert!(state.1, "storage operation did not enter fixture gate");
    }
}

struct Release(Arc<Gate>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().2 = true;
        self.0.changed.notify_all();
    }
}

struct PausableBacking {
    inner: CrashableBacking,
    sync: Arc<Gate>,
    free: Arc<Gate>,
}

impl Backing for PausableBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        Ok(Arc::new(PausableFile {
            inner: self.inner.open(path, create)?,
            sync: self.sync.clone(),
        }))
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.inner.exists(path)
    }
    fn remove(&self, path: &str) -> io::Result<()> {
        self.inner.remove(path)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.inner.rename(from, to)
    }
    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        self.inner.list(dir)
    }
    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        self.inner.sync_dir(dir)
    }
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(path)
    }
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.free.pause();
        Ok(Some(1 << 40))
    }
}

struct PausableFile {
    inner: Arc<dyn BackingFile>,
    sync: Arc<Gate>,
}

impl BackingFile for PausableFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        self.sync.pause();
        self.inner.sync_data()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

struct Fixture {
    _runtime: tokio::runtime::Runtime,
    backing: Arc<PausableBacking>,
    clock: Arc<ManualClock>,
    engine: Engine,
    control: Arc<EngineControlBackend>,
}

impl Fixture {
    fn new() -> Self {
        let backing = Arc::new(PausableBacking {
            inner: CrashableBacking::new(),
            sync: Arc::default(),
            free: Arc::default(),
        });
        init::create_volume(
            backing.as_ref(),
            Superblock {
                generation: 0,
                volume_uuid: uuid::Uuid::new_v4(),
                provider_type: "fake".into(),
                crypto_compatibility_id: "test-profile-v1".into(),
                key_identity: "k".into(),
                geometry: Geometry::compute(512, 4096, 512, 4104, 2 << 20, 256 << 10).unwrap(),
                format_version: 1,
                created_unix: 0,
            },
        )
        .unwrap();
        let rt = runtime();
        let clock = Arc::new(ManualClock::new());
        let engine = rt
            .block_on(Engine::attach(
                backing.clone(),
                Arc::new(FakeCryptoProvider::new(4096)),
                EngineOptions {
                    clock: Some(clock.clone()),
                    ..EngineOptions::default()
                },
            ))
            .unwrap();
        let control = Arc::new(EngineControlBackend::new(engine.clone(), "monitoring"));
        Self {
            _runtime: rt,
            backing,
            clock,
            engine,
            control,
        }
    }

    fn monitor(&self) -> (mpsc::Receiver<(Value, Value)>, std::thread::JoinHandle<()>) {
        let control = self.control.clone();
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result =
                runtime().block_on(async { (control.status().await, control.metrics().await) });
            tx.send(result).unwrap();
        });
        (rx, worker)
    }
}

#[test]
fn status_and_metrics_report_cached_sequences_while_drain_sync_is_stuck() {
    let fixture = Fixture::new();
    runtime()
        .block_on(fixture.engine.write(0, &[0x51; 4096], true))
        .unwrap();
    let release = fixture.backing.sync.arm();
    let control = fixture.control.clone();
    let draining = std::thread::spawn(move || runtime().block_on(control.drain()));
    fixture.backing.sync.wait_until_entered();
    fixture.clock.advance(Duration::from_secs(2));
    let (rx, monitor) = fixture.monitor();
    let during = rx.recv_timeout(Duration::from_millis(250));
    // Release and join even when the implementation blocks; no leaked workers.
    drop(release);
    draining.join().unwrap().unwrap();
    monitor.join().unwrap();
    let (status, metrics) = during.expect("monitoring waited for blocked drain storage I/O");
    assert_eq!(status["io_state"], "draining", "{status}");
    assert_eq!(
        status["state"], "busy",
        "must not claim a stuck volume is ready: {status}"
    );
    assert_eq!(status["last_observed_state"], "ready");
    assert_eq!(status["observability"]["volume_snapshot"], "cached");
    assert!(
        status["observability"]["volume_snapshot_age_ms"]
            .as_u64()
            .unwrap()
            >= 2000
    );
    assert_eq!(
        status["durable_sequence"], 1,
        "cached data must come from a completed write"
    );
    assert_eq!(metrics["maki_journal_durable_sequence"], 1);
    assert_eq!(metrics["maki_volume_busy"], 1);
    assert!(
        metrics["maki_volume_state"].is_null(),
        "busy must not be a ready gauge"
    );
    let after = runtime().block_on(fixture.control.status());
    assert_eq!(after["state"], "ready");
    assert_eq!(after["io_state"], "drained");
    assert_eq!(after["observability"]["volume_snapshot"], "current");
    assert_eq!(after["checkpoint_sequence"], 1);
}

#[test]
fn monitoring_does_not_wait_for_the_free_space_cache_or_query_storage() {
    let fixture = Fixture::new();
    runtime()
        .block_on(fixture.engine.write(0, &[0x61; 4096], true))
        .unwrap();
    fixture.clock.advance(Duration::from_secs(2));
    let release = fixture.backing.free.arm();
    let engine = fixture.engine.clone();
    let probing = std::thread::spawn(move || runtime().block_on(engine.stats()));
    fixture.backing.free.wait_until_entered();
    let (rx, monitor) = fixture.monitor();
    let during = rx.recv_timeout(Duration::from_millis(250));
    drop(release);
    probing.join().unwrap();
    monitor.join().unwrap();
    let (status, metrics) =
        during.expect("monitoring waited for a blocked free-space query/cache lock");
    assert_eq!(status["state"], "ready");
    assert_eq!(status["observability"]["volume_snapshot"], "current");
    assert_eq!(status["observability"]["backing_space"], "cached");
    assert!(
        status["observability"]["backing_space_age_ms"]
            .as_u64()
            .unwrap()
            >= 2000
    );
    assert_eq!(status["backing_free_bytes"], 1_u64 << 40);
    assert_eq!(metrics["maki_backing_free_bytes"], 1_u64 << 40);
    assert_eq!(metrics["maki_volume_busy"], 0);
}

#[test]
fn monitoring_reports_unavailable_free_space_without_inventing_a_measurement() {
    let fixture = Fixture::new();
    let status = runtime().block_on(fixture.control.status());
    assert!(
        status["backing_free_bytes"].is_null(),
        "status must not perform a storage query: {status}"
    );
    assert_eq!(status["observability"]["backing_space"], "unavailable");
    assert!(status["observability"]["backing_space_age_ms"].is_null());
}
