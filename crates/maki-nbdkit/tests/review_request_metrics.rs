//! Request metrics count callbacks, separately from resource permits and
//! internal batches. ManualClock covers queueing, errors and cancellation.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::Poll;
use std::time::Duration;

use async_trait::async_trait;
use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_control::server::ControlBackend;
use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_nbdkit::control::EngineControlBackend;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};
use serde_json::{json, Value};
use tokio::sync::Notify;

const UNIT: u32 = 1024;

struct GatedProvider {
    inner: FakeCryptoProvider,
    mode: AtomicU8,
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
}

impl Default for GatedProvider {
    fn default() -> Self {
        Self {
            inner: FakeCryptoProvider::new(UNIT).with_max_batch(1, 1 << 20),
            mode: AtomicU8::new(0),
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        }
    }
}

impl GatedProvider {
    async fn barrier(&self) -> Result<(), CryptoError> {
        match self.mode.load(Ordering::SeqCst) {
            1 => {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                self.release.notified().await;
            }
            2 => {
                return Err(CryptoError::NonRetryableRequest(
                    "test request rejected".into(),
                ))
            }
            _ => {}
        }
        Ok(())
    }

    async fn wait_calls(&self, count: usize) {
        loop {
            let entered = self.entered.notified();
            if self.calls.load(Ordering::SeqCst) >= count {
                return;
            }
            entered.await;
        }
    }
}

#[async_trait]
impl CryptoProvider for GatedProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.barrier().await?;
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.barrier().await?;
        self.inner.decrypt_batch(context, items).await
    }
}

#[derive(Default)]
struct WriteGate {
    armed: AtomicBool,
    entered: Notify,
    released: Mutex<bool>,
    wake: Condvar,
}

#[derive(Default)]
struct MetricBacking {
    inner: CrashableBacking,
    gate: Arc<WriteGate>,
}

struct MetricFile {
    inner: Arc<dyn BackingFile>,
    gate: Arc<WriteGate>,
}

impl BackingFile for MetricFile {
    fn read_at(&self, offset: u64, data: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, data)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if self.gate.armed.swap(false, Ordering::SeqCst) {
            self.gate.entered.notify_one();
            let released = self.gate.released.lock().unwrap();
            let (_released, timeout) = self
                .gate
                .wake
                .wait_timeout_while(released, Duration::from_secs(10), |released| !*released)
                .unwrap();
            if timeout.timed_out() {
                return Err(io::Error::other("test storage gate was not released"));
            }
        }
        self.inner.write_at(offset, data)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }
}

impl Backing for MetricBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        Ok(Arc::new(MetricFile {
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
}

async fn fixture(
    max_callbacks: u32,
    max_request: u64,
) -> (
    Arc<MetricBacking>,
    Arc<GatedProvider>,
    Arc<ManualClock>,
    Engine,
    EngineControlBackend,
) {
    let backing = Arc::new(MetricBacking::default());
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x4E7A1C5),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "fixture".into(),
            geometry: Geometry::compute(
                512,
                UNIT,
                512,
                UNIT + 8,
                32 * UNIT as u64,
                16 * UNIT as u64,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let provider = Arc::new(GatedProvider::default());
    let clock = Arc::new(ManualClock::new());
    let engine = Engine::attach(
        backing.clone(),
        provider.clone(),
        EngineOptions {
            clock: Some(clock.clone()),
            limits: EngineLimits {
                max_active_callbacks: max_callbacks,
                max_request_bytes: max_request,
                max_plaintext_bytes: 32 * UNIT as u64,
                ..Default::default()
            },
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    engine.stop_checkpoint_worker().await;
    let control = EngineControlBackend::new(engine.clone(), "metrics");
    (backing, provider, clock, engine, control)
}

async fn once<F: Future + ?Sized>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    futures_util::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

fn assert_latency(metrics: &Value, prefix: &str, count: u64, sum: f64) {
    assert_eq!(metrics[format!("{prefix}_count")], json!(count), "{prefix}");
    assert_eq!(metrics[format!("{prefix}_sum")], json!(sum), "{prefix}");
}

#[tokio::test(flavor = "current_thread")]
async fn one_request_with_two_provider_batches_uses_two_slots() {
    let (_, provider, clock, engine, control) = fixture(2, 2 * UNIT as u64).await;
    provider.mode.store(1, Ordering::SeqCst);
    let submitted = engine.clone();
    let write =
        tokio::spawn(async move { submitted.write(0, &[1; 2 * UNIT as usize], true).await });
    provider.wait_calls(2).await;
    let active = control.metrics().await;
    clock.advance(Duration::from_secs(5));
    provider.release.notify_waiters();
    write.await.unwrap().unwrap();
    let metrics = control.metrics().await;
    assert_eq!(active["maki_active_requests"], json!(1));
    assert_eq!(active["maki_admission_slots"], json!(2));
    assert_eq!(active["maki_active_callbacks"], json!(2));
    assert_eq!(metrics["maki_active_requests"], json!(0));
    assert_eq!(metrics["maki_requests_success_total"], json!(1));
    assert_latency(&metrics, "maki_request_seconds", 1, 5.0);
    assert_latency(&metrics, "maki_write_request_seconds", 1, 5.0);
    assert_latency(&metrics, "maki_fua_request_seconds", 1, 5.0);
    assert_latency(&metrics, "maki_fua_seconds", 1, 0.0);
}

#[tokio::test(flavor = "current_thread")]
async fn waiting_and_cancelled_requests_keep_separate_counts_and_latencies() {
    let (_, provider, clock, engine, control) = fixture(1, UNIT as u64).await;
    provider.mode.store(1, Ordering::SeqCst);
    let submitted = engine.clone();
    let first = tokio::spawn(async move { submitted.write(0, &[1; UNIT as usize], false).await });
    provider.wait_calls(1).await;
    clock.advance(Duration::from_secs(2));
    let mut queued = Box::pin(engine.read_secret(UNIT as u64, UNIT as usize));
    assert!(once(queued.as_mut()).await.is_pending());
    let active = control.metrics().await;
    clock.advance(Duration::from_secs(3));
    drop(queued);
    let cancelled = control.metrics().await;
    provider.release.notify_waiters();
    first.await.unwrap().unwrap();
    let metrics = control.metrics().await;
    assert_eq!(active["maki_active_requests"], json!(2));
    assert_eq!(active["maki_admission_slots"], json!(1));
    assert_eq!(cancelled["maki_active_requests"], json!(1));
    assert_eq!(metrics["maki_requests_cancelled_total"], json!(1));
    assert_eq!(metrics["maki_requests_success_total"], json!(1));
    assert_latency(&metrics, "maki_read_request_seconds", 1, 3.0);
    assert_latency(&metrics, "maki_write_request_seconds", 1, 5.0);
    assert_latency(&metrics, "maki_request_seconds", 2, 8.0);
}

#[tokio::test(flavor = "current_thread")]
async fn provider_and_range_errors_are_counted_as_failed_requests() {
    let (_, provider, _, engine, control) = fixture(2, 2 * UNIT as u64).await;
    provider.mode.store(2, Ordering::SeqCst);
    assert!(engine.write(0, &[1; UNIT as usize], false).await.is_err());
    assert!(engine.read_secret(1, UNIT as usize).await.is_err());
    let metrics = control.metrics().await;
    assert_eq!(metrics["maki_requests_error_total"], json!(2));
    assert_eq!(metrics["maki_requests_cancelled_total"], json!(0));
    assert_eq!(metrics["maki_admission_slots"], json!(0));
    assert_latency(&metrics, "maki_request_seconds", 2, 0.0);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_flush_records_sync_and_full_request_latency() {
    let (backing, _, clock, engine, control) = fixture(2, 2 * UNIT as u64).await;
    engine.write(0, &[1; UNIT as usize], false).await.unwrap();
    let advancing = clock.clone();
    backing
        .inner
        .set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { path } if path.starts_with("journal/seg-") => {
                advancing.advance(Duration::from_secs(4));
                Some(io::Error::other("injected journal writeback failure"))
            }
            _ => None,
        })));
    assert!(engine.flush().await.is_err());
    backing.inner.set_fault_hook(None);
    let failed = control.metrics().await;
    engine.flush().await.unwrap();
    let metrics = control.metrics().await;
    assert_eq!(failed["maki_requests_error_total"], json!(1));
    assert_latency(&failed, "maki_flush_seconds", 0, 0.0);
    assert_latency(&failed, "maki_flush_request_seconds", 1, 4.0);
    assert_latency(&failed, "maki_journal_sync_seconds", 1, 4.0);
    assert_latency(&metrics, "maki_flush_request_seconds", 2, 4.0);
    assert_latency(&metrics, "maki_journal_sync_seconds", 2, 4.0);
    assert_eq!(metrics["maki_requests_success_total"], json!(2));
    assert_eq!(metrics["maki_requests_cancelled_total"], json!(0));
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_storage_caller_has_zero_requests_and_one_retained_slot() {
    let (backing, _, clock, engine, control) = fixture(2, 2 * UNIT as u64).await;
    backing.gate.armed.store(true, Ordering::SeqCst);
    let submitted = engine.clone();
    let write = tokio::spawn(async move { submitted.write(0, &[1; UNIT as usize], true).await });
    backing.gate.entered.notified().await;
    clock.advance(Duration::from_secs(7));
    write.abort();
    let _ = write.await;
    let cancelled = control.metrics().await;
    *backing.gate.released.lock().unwrap() = true;
    backing.gate.wake.notify_all();
    engine.flush().await.unwrap();
    // FLUSH waits for the storage lock, while the cancelled write's owned
    // orchestration drops its admission guard after that lock is released.
    // Observe that separate completion instead of assuming both have the
    // same scheduler wakeup order. The timeout only catches leaked permits.
    let metrics = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let metrics = control.metrics().await;
            if metrics["maki_admission_slots"] == json!(0) {
                break metrics;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled storage orchestration did not release its admission guard");
    assert_eq!(cancelled["maki_active_requests"], json!(0));
    assert_eq!(cancelled["maki_admission_slots"], json!(1));
    assert_eq!(cancelled["maki_active_callbacks"], json!(1));
    assert_eq!(cancelled["maki_requests_cancelled_total"], json!(1));
    assert_latency(&cancelled, "maki_write_request_seconds", 1, 7.0);
    assert_latency(&cancelled, "maki_fua_request_seconds", 1, 7.0);
    assert_eq!(metrics["maki_admission_slots"], json!(0));
}

#[tokio::test(flavor = "current_thread")]
async fn trim_chunks_and_internal_barrier_count_as_one_trim_request() {
    let (_, _, _, engine, control) = fixture(2, UNIT as u64).await;
    engine.trim(0, 8 * UNIT as usize, true).await.unwrap();
    // There is no complete crypto unit in this range. FUA still requires an
    // internal barrier, which must not become a second external request.
    engine.trim(512, 512, true).await.unwrap();
    let metrics = control.metrics().await;
    assert_eq!(metrics["maki_requests_success_total"], json!(2));
    assert_latency(&metrics, "maki_trim_request_seconds", 2, 0.0);
    assert_latency(&metrics, "maki_flush_request_seconds", 0, 0.0);
    assert_latency(&metrics, "maki_request_seconds", 2, 0.0);
}

#[tokio::test(flavor = "current_thread")]
async fn convenience_read_with_two_batches_counts_one_callback() {
    let (_, provider, clock, engine, control) = fixture(2, 2 * UNIT as u64).await;
    engine
        .write(0, &[0x42; 2 * UNIT as usize], false)
        .await
        .unwrap();
    provider.mode.store(1, Ordering::SeqCst);
    let submitted = engine.clone();
    let read = tokio::spawn(async move { submitted.read(0, 2 * UNIT as usize).await });
    provider.wait_calls(2).await;
    let active = control.metrics().await;
    clock.advance(Duration::from_secs(1));
    provider.release.notify_waiters();
    assert_eq!(read.await.unwrap().unwrap(), vec![0x42; 2 * UNIT as usize]);
    let metrics = control.metrics().await;
    assert_eq!(active["maki_active_requests"], json!(1));
    assert_eq!(active["maki_admission_slots"], json!(2));
    assert_latency(&metrics, "maki_read_request_seconds", 1, 1.0);
    assert_latency(&metrics, "maki_request_seconds", 2, 1.0);
    assert_eq!(metrics["maki_requests_success_total"], json!(2));
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_provider_returns_all_slots_and_counts_one_cancelled_fua() {
    let (_, provider, clock, engine, control) = fixture(2, 2 * UNIT as u64).await;
    provider.mode.store(1, Ordering::SeqCst);
    let submitted = engine.clone();
    let write =
        tokio::spawn(async move { submitted.write(0, &[1; 2 * UNIT as usize], true).await });
    provider.wait_calls(2).await;
    clock.advance(Duration::from_secs(3));
    write.abort();
    let _ = write.await;
    let metrics = control.metrics().await;
    assert_eq!(metrics["maki_active_requests"], json!(0));
    assert_eq!(metrics["maki_admission_slots"], json!(0));
    assert_eq!(metrics["maki_plaintext_bytes"], json!(0));
    assert_eq!(metrics["maki_requests_cancelled_total"], json!(1));
    assert_eq!(metrics["maki_requests_error_total"], json!(0));
    assert_latency(&metrics, "maki_fua_request_seconds", 1, 3.0);
    assert_latency(&metrics, "maki_fua_seconds", 0, 0.0);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_fua_full_latency_includes_provider_wait_and_sync_error() {
    let (backing, provider, clock, engine, control) = fixture(2, 2 * UNIT as u64).await;
    // Create the segment before arming the fault, so its header sync does
    // not intercept the final FUA barrier under test.
    engine.write(0, &[1; UNIT as usize], false).await.unwrap();
    provider.mode.store(1, Ordering::SeqCst);
    let submitted = engine.clone();
    let write = tokio::spawn(async move {
        submitted
            .write(UNIT as u64, &[2; UNIT as usize], true)
            .await
    });
    provider.wait_calls(1).await;
    clock.advance(Duration::from_secs(2));
    let advancing = clock.clone();
    backing
        .inner
        .set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { path } if path.starts_with("journal/seg-") => {
                advancing.advance(Duration::from_secs(4));
                Some(io::Error::other("injected final FUA sync failure"))
            }
            _ => None,
        })));
    provider.release.notify_waiters();
    assert!(write.await.unwrap().is_err());
    backing.inner.set_fault_hook(None);
    let metrics = control.metrics().await;
    assert_eq!(metrics["maki_requests_error_total"], json!(1));
    assert_eq!(metrics["maki_requests_cancelled_total"], json!(0));
    assert_latency(&metrics, "maki_fua_request_seconds", 1, 6.0);
    assert_latency(&metrics, "maki_fua_seconds", 0, 0.0);
    assert_latency(&metrics, "maki_journal_sync_seconds", 1, 4.0);
    assert_latency(&metrics, "maki_write_request_seconds", 2, 6.0);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_flush_full_latency_includes_wait_for_volume_lock() {
    let (backing, _, clock, engine, control) = fixture(2, 2 * UNIT as u64).await;
    engine.write(0, &[1; UNIT as usize], false).await.unwrap();
    backing.gate.armed.store(true, Ordering::SeqCst);
    let submitted = engine.clone();
    let write = tokio::spawn(async move { submitted.write(0, &[2; UNIT as usize], false).await });
    backing.gate.entered.notified().await;
    clock.advance(Duration::from_secs(2));
    let mut flush = Box::pin(engine.flush());
    assert!(once(flush.as_mut()).await.is_pending());
    let active = control.metrics().await;
    clock.advance(Duration::from_secs(3));
    let advancing = clock.clone();
    backing
        .inner
        .set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { path } if path.starts_with("journal/seg-") => {
                advancing.advance(Duration::from_secs(4));
                Some(io::Error::other("injected FLUSH sync failure"))
            }
            _ => None,
        })));
    *backing.gate.released.lock().unwrap() = true;
    backing.gate.wake.notify_all();
    write.await.unwrap().unwrap();
    assert!(flush.await.is_err());
    backing.inner.set_fault_hook(None);
    let metrics = control.metrics().await;
    assert_eq!(active["maki_active_requests"], json!(2));
    assert_latency(&metrics, "maki_flush_request_seconds", 1, 7.0);
    assert_latency(&metrics, "maki_flush_seconds", 0, 0.0);
    assert_latency(&metrics, "maki_journal_sync_seconds", 1, 4.0);
}
