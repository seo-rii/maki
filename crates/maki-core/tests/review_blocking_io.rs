//! Slow synchronous storage must not monopolize a Tokio worker. Cancellation
//! must retain admission and write ordering until the detached I/O completes.
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use maki_backing::{Backing, BackingFile, MemBacking, VolumeLock};
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::fake_provider::FakeCryptoProvider;

const READ: usize = 1;
const WRITE: usize = 2;
const SYNC: usize = 3;
const SPACE: usize = 4;
const OPEN: usize = 5;

#[derive(Default)]
struct Gate {
    operation: AtomicUsize,
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: Condvar,
    stalled: AtomicBool,
}

impl Gate {
    fn block(&self, operation: usize) {
        if self
            .operation
            .compare_exchange(operation, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        self.entered.notify_one();
        let released = self.released.lock().unwrap();
        let (_released, timeout) = self
            .wake
            .wait_timeout_while(released, Duration::from_secs(2), |r| !*r)
            .unwrap();
        self.stalled.store(timeout.timed_out(), Ordering::SeqCst);
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

#[derive(Default)]
struct SlowBacking {
    inner: MemBacking,
    gate: Arc<Gate>,
}

struct SlowFile {
    inner: Arc<dyn BackingFile>,
    gate: Arc<Gate>,
}

impl BackingFile for SlowFile {
    fn read_at(&self, offset: u64, data: &mut [u8]) -> io::Result<()> {
        self.gate.block(READ);
        self.inner.read_at(offset, data)
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.gate.block(WRITE);
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        self.gate.block(SYNC);
        self.inner.sync_data()
    }
}

impl Backing for SlowBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        self.gate.block(OPEN);
        Ok(Arc::new(SlowFile {
            inner: self.inner.open(path, create)?,
            gate: self.gate.clone(),
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
    fn list(&self, path: &str) -> io::Result<Vec<String>> {
        self.inner.list(path)
    }
    fn sync_dir(&self, path: &str) -> io::Result<()> {
        self.inner.sync_dir(path)
    }
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(path)
    }
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.gate.block(SPACE);
        Ok(Some(1 << 30))
    }
}

fn options() -> EngineOptions {
    EngineOptions {
        checkpoint: CheckpointPolicy {
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: Duration::from_secs(3600),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn low_space_options() -> EngineOptions {
    let mut options = options();
    options.checkpoint.low_space_checkpoint_bytes = 2 << 30;
    options.checkpoint.journal_high_watermark_bytes = 1;
    options
}

fn backing() -> Arc<SlowBacking> {
    let backing = Arc::new(SlowBacking::default());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xb10c),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    backing
}

async fn fixture() -> (Arc<SlowBacking>, Engine) {
    let backing = backing();
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(1024)),
        options(),
    )
    .await
    .unwrap();
    engine.write(0, &[0x31; 1024], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    (backing, engine)
}

async fn responsive(
    gate: &Arc<Gate>,
    operation: usize,
    work: impl std::future::Future<Output = ()>,
) {
    gate.operation.store(operation, Ordering::SeqCst);
    tokio::join!(work, async {
        gate.entered.notified().await;
        gate.release();
    });
    assert!(
        !gate.stalled.load(Ordering::SeqCst),
        "synchronous storage blocked the async observer"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn slow_read_keeps_runtime_responsive() {
    let (backing, engine) = fixture().await;
    responsive(&backing.gate, READ, async {
        assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0x31; 1024]);
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn slow_write_keeps_runtime_responsive() {
    let (backing, engine) = fixture().await;
    responsive(&backing.gate, WRITE, async {
        engine.write(0, &[0x32; 1024], true).await.unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn slow_flush_keeps_runtime_responsive() {
    let (backing, engine) = fixture().await;
    engine.write(0, &[0x32; 1024], false).await.unwrap();
    responsive(&backing.gate, SYNC, async {
        engine.flush().await.unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn slow_checkpoint_keeps_runtime_responsive() {
    let (backing, engine) = fixture().await;
    engine.write(0, &[0x32; 1024], true).await.unwrap();
    responsive(&backing.gate, WRITE, async {
        engine.checkpoint().await.unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn slow_space_query_keeps_runtime_responsive() {
    let (backing, engine) = fixture().await;
    responsive(&backing.gate, SPACE, async {
        engine.stats().await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn slow_recovery_keeps_runtime_responsive() {
    let backing = backing();
    responsive(&backing.gate, OPEN, async {
        Engine::attach(
            backing.clone(),
            Arc::new(FakeCryptoProvider::new(1024)),
            options(),
        )
        .await
        .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_write_retains_admission_and_orders_later_write() {
    let (backing, engine) = fixture().await;
    backing.gate.operation.store(WRITE, Ordering::SeqCst);
    let first_engine = engine.clone();
    let first = tokio::spawn(async move { first_engine.write(0, &[0x42; 1024], true).await });
    backing.gate.entered.notified().await;
    first.abort();
    let _ = first.await;
    let active = engine.monitoring_snapshot().stats.active_callbacks;
    let second_engine = engine.clone();
    let second = tokio::spawn(async move { second_engine.write(0, &[0x43; 1024], true).await });
    tokio::task::yield_now().await;
    let overtook = second.is_finished();
    backing.gate.release();
    second.await.unwrap().unwrap();
    assert_eq!(
        active, 1,
        "cancelled caller released in-flight I/O admission"
    );
    assert!(!overtook, "a later write overtook the detached write");
    assert!(!backing.gate.stalled.load(Ordering::SeqCst));
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0x43; 1024]);
    assert_eq!(engine.monitoring_snapshot().stats.active_callbacks, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn stopping_checkpoint_worker_waits_for_dispatched_space_query() {
    let backing = backing();
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(1024)),
        low_space_options(),
    )
    .await
    .unwrap();

    backing.gate.operation.store(SPACE, Ordering::SeqCst);
    engine.write(0, &[0x51; 1024], false).await.unwrap();
    backing.gate.entered.notified().await;

    let stopping_engine = engine.clone();
    let stopping = tokio::spawn(async move {
        stopping_engine.stop_checkpoint_worker().await;
    });
    let peer_engine = engine.clone();
    let peer = tokio::spawn(async move {
        peer_engine.stop_checkpoint_worker().await;
    });
    tokio::task::yield_now().await;
    assert!(
        !stopping.is_finished(),
        "worker stop returned while dispatched storage was still running"
    );
    assert!(
        !peer.is_finished(),
        "concurrent worker stop returned before the worker exited"
    );

    backing.gate.release();
    stopping.await.unwrap();
    peer.await.unwrap();
    engine.stop_checkpoint_worker().await;
    assert!(!backing.gate.stalled.load(Ordering::SeqCst));
    assert_eq!(
        engine.stats().await.checkpoints_total,
        0,
        "a stopped worker dispatched checkpoint work after its space query"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_worker_stop_does_not_detach_the_worker() {
    let backing = backing();
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(1024)),
        low_space_options(),
    )
    .await
    .unwrap();

    backing.gate.operation.store(SPACE, Ordering::SeqCst);
    engine.write(0, &[0x61; 1024], false).await.unwrap();
    backing.gate.entered.notified().await;

    let first_engine = engine.clone();
    let first = tokio::spawn(async move {
        first_engine.stop_checkpoint_worker().await;
    });
    tokio::task::yield_now().await;
    assert!(!first.is_finished());
    first.abort();
    let _ = first.await;

    let second_engine = engine.clone();
    let second = tokio::spawn(async move {
        second_engine.stop_checkpoint_worker().await;
    });
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "cancelling the first stop waiter detached the running worker"
    );

    backing.gate.release();
    second.await.unwrap();
    assert!(!backing.gate.stalled.load(Ordering::SeqCst));
}
