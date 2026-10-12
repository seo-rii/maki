//! BUG-050: one stalled request must not serialize independent split retries.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::ManualClock;
use tokio::sync::Notify;

const UNIT: usize = 64;

// Observe the lifetime of exactly one scheduler-owned input allocation. No
// memory contents are inspected, and its address is consumed before dealloc.
struct LifetimeObserver;
static WATCHED_BUFFER: AtomicUsize = AtomicUsize::new(0);
static WATCHED_DROPPED: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for LifetimeObserver {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHED_BUFFER
            .compare_exchange(ptr as usize, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            WATCHED_DROPPED.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: LifetimeObserver = LifetimeObserver;

#[derive(Default)]
struct Calls {
    active: AtomicUsize,
    peak: AtomicUsize,
    units: Mutex<Vec<Vec<u64>>>,
}

struct ActiveCall(Arc<Calls>);

impl ActiveCall {
    fn enter(calls: Arc<Calls>) -> Self {
        let active = calls.active.fetch_add(1, Ordering::SeqCst) + 1;
        calls.peak.fetch_max(active, Ordering::SeqCst);
        Self(calls)
    }
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Provider {
    calls: Arc<Calls>,
    retry_safe: bool,
    blocked: u16,
    watch_b: bool,
    reject_all: bool,
    started: [Notify; 10],
    release: [Notify; 10],
}

impl Provider {
    fn new(retry_safe: bool, blocked: u16, watch_b: bool, reject_all: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: Arc::new(Calls::default()),
            retry_safe,
            blocked,
            watch_b,
            reject_all,
            started: std::array::from_fn(|_| Notify::new()),
            release: std::array::from_fn(|_| Notify::new()),
        })
    }

    async fn begin(&self, units: Vec<u64>) -> Result<ActiveCall, CryptoError> {
        let call = ActiveCall::enter(self.calls.clone());
        self.calls.units.lock().unwrap().push(units.clone());
        let tag = units[0] / 10;
        if self.reject_all || units.iter().any(|unit| unit / 10 != tag) {
            return Err(CryptoError::NonRetryableRequest(
                "one request rejected".into(),
            ));
        }
        self.started[tag as usize].notify_one();
        if self.blocked & (1 << tag) != 0 {
            self.release[tag as usize].notified().await;
        }
        Ok(call)
    }

    fn saw(&self, units: &[u64]) -> bool {
        self.calls
            .units
            .lock()
            .unwrap()
            .iter()
            .any(|call| call == units)
    }
}

#[async_trait]
impl CryptoProvider for Provider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "split-retry-fixture".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: self.retry_safe,
            batch: BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 8 * UNIT as u64,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        })
    }

    async fn encrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        if self.watch_b
            && items.iter().any(|item| item.unit_index == 10)
            && items.iter().any(|item| item.unit_index == 20)
        {
            let b = items.iter().find(|item| item.unit_index == 20).unwrap();
            WATCHED_DROPPED.store(false, Ordering::SeqCst);
            WATCHED_BUFFER.store(b.data.expose().as_ptr() as usize, Ordering::SeqCst);
        }
        let _active = self
            .begin(items.iter().map(|item| item.unit_index).collect())
            .await?;
        Ok(items
            .iter()
            .map(|item| CiphertextUnit {
                unit_index: item.unit_index,
                data: item.data.expose().to_vec(),
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let _active = self
            .begin(items.iter().map(|item| item.unit_index).collect())
            .await?;
        Ok(items
            .iter()
            .map(|item| PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_slice(&item.data),
            })
            .collect())
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(50),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn config(width: u32, group_len: usize) -> SchedulerConfig {
    SchedulerConfig {
        target_items: group_len * 2,
        target_bytes: 8 * UNIT as u64,
        max_items: 8,
        max_bytes: 8 * UNIT as u64,
        max_wait: Duration::from_millis(5),
        max_pending_items: 8,
        max_pending_plaintext_bytes: 8 * UNIT as u64,
        max_pending_ciphertext_bytes: 8 * UNIT as u64,
        max_inflight_batches: width,
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

type Request = tokio::task::JoinHandle<Result<Vec<u64>, CryptoError>>;

fn request(
    scheduler: &Arc<BatchScheduler>,
    direction: Direction,
    tag: u64,
    count: usize,
) -> Request {
    let scheduler = scheduler.clone();
    tokio::spawn(async move {
        let units = (0..count).map(|i| tag * 10 + i as u64);
        match direction {
            Direction::Encrypt => scheduler
                .encrypt_batch(
                    &context(),
                    &units
                        .map(|unit_index| PlaintextUnit {
                            unit_index,
                            data: SecretBuffer::from_slice(&[unit_index as u8; UNIT]),
                        })
                        .collect::<Vec<_>>(),
                )
                .await
                .map(|items| items.into_iter().map(|item| item.unit_index).collect()),
            Direction::Decrypt => scheduler
                .decrypt_batch(
                    &context(),
                    &units
                        .map(|unit_index| CiphertextUnit {
                            unit_index,
                            data: vec![unit_index as u8; UNIT],
                        })
                        .collect::<Vec<_>>(),
                )
                .await
                .map(|items| items.into_iter().map(|item| item.unit_index).collect()),
        }
    })
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

async fn pair(
    scheduler: &Arc<BatchScheduler>,
    direction: Direction,
    count: usize,
) -> (Request, Request) {
    let a = request(scheduler, direction, 1, count);
    settle().await;
    assert_eq!(scheduler.stats().pending_items(), count as u64);
    let b = request(scheduler, direction, 2, count);
    settle().await;
    (a, b)
}

async fn finished(request: Request) -> Result<Vec<u64>, CryptoError> {
    assert!(
        request.is_finished(),
        "request did not progress after deterministic wakeups"
    );
    request.await.unwrap()
}

fn empty(scheduler: &BatchScheduler, provider: &Provider) {
    assert_eq!(provider.calls.active.load(Ordering::SeqCst), 0);
    assert_eq!(scheduler.stats().inflight_batches(), 0);
    assert_eq!(scheduler.stats().pending_items(), 0);
    assert_eq!(scheduler.stats().pending_bytes(), 0);
}

async fn fresh(scheduler: &Arc<BatchScheduler>, clock: &ManualClock, direction: Direction) {
    let fresh = request(scheduler, direction, 9, 1);
    settle().await;
    clock.advance(Duration::from_millis(5));
    settle().await;
    assert_eq!(finished(fresh).await.unwrap(), vec![90]);
}

async fn independent(direction: Direction) {
    let provider = Provider::new(true, 1 << 1, false, false);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(2, 2),
        clock.clone(),
    ));
    let (a, b) = pair(&scheduler, direction, 2).await;
    assert!(
        provider.saw(&[10, 11]),
        "first retry never acquired its retained slot"
    );
    let b_finished_before_a = b.is_finished();
    let active_while_a_waits = scheduler.stats().inflight_batches();
    provider.release[1].notify_one();
    settle().await;
    assert_eq!(finished(a).await.unwrap(), vec![10, 11]);
    assert_eq!(finished(b).await.unwrap(), vec![20, 21]);
    fresh(&scheduler, &clock, direction).await;
    empty(&scheduler, &provider);
    assert!(provider.calls.peak.load(Ordering::SeqCst) <= 2);
    assert_eq!(active_while_a_waits, 1);
    assert!(
        b_finished_before_a,
        "healthy B waited behind stalled A's split retry"
    );
}

#[tokio::test]
async fn encrypt_retry_groups_progress_independently_and_keep_item_order() {
    independent(Direction::Encrypt).await;
}

#[tokio::test]
async fn decrypt_retry_groups_progress_independently_and_keep_item_order() {
    independent(Direction::Decrypt).await;
}

#[tokio::test]
async fn one_slot_reuses_the_original_permit_without_reacquiring_it() {
    let provider = Provider::new(true, 1 << 1, false, false);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(1, 1),
        clock.clone(),
    ));
    let (a, b) = pair(&scheduler, Direction::Encrypt, 1).await;
    assert!(provider.saw(&[10]));
    assert!(!b.is_finished());
    assert_eq!(scheduler.stats().inflight_batches(), 1);
    provider.release[1].notify_one();
    settle().await;
    assert_eq!(finished(a).await.unwrap(), vec![10]);
    assert_eq!(finished(b).await.unwrap(), vec![20]);
    fresh(&scheduler, &clock, Direction::Encrypt).await;
    empty(&scheduler, &provider);
    assert_eq!(provider.calls.peak.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelling_the_running_retry_releases_one_slot_for_the_next_group() {
    let provider = Provider::new(true, 1 << 1, false, false);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(1, 1),
        clock.clone(),
    ));
    let (a, b) = pair(&scheduler, Direction::Decrypt, 1).await;
    assert!(provider.saw(&[10]));
    a.abort();
    assert!(a.await.unwrap_err().is_cancelled());
    settle().await;
    assert_eq!(finished(b).await.unwrap(), vec![20]);
    fresh(&scheduler, &clock, Direction::Decrypt).await;
    empty(&scheduler, &provider);
    assert_eq!(provider.calls.peak.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelling_all_active_retries_returns_slots_and_call_metrics() {
    let provider = Provider::new(true, (1 << 1) | (1 << 2), false, false);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(2, 1),
        clock.clone(),
    ));
    let (a, b) = pair(&scheduler, Direction::Encrypt, 1).await;
    let both_started = provider.saw(&[10]) && provider.saw(&[20]);
    a.abort();
    b.abort();
    assert!(a.await.unwrap_err().is_cancelled());
    assert!(b.await.unwrap_err().is_cancelled());
    settle().await;
    empty(&scheduler, &provider);
    fresh(&scheduler, &clock, Direction::Encrypt).await;
    empty(&scheduler, &provider);
    assert!(both_started, "second independent retry never started");
}

#[tokio::test]
async fn cancelling_an_unstarted_retry_drops_its_payload_before_the_running_retry_finishes() {
    let provider = Provider::new(true, 1 << 1, true, false);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(1, 1),
        clock.clone(),
    ));
    let (a, b) = pair(&scheduler, Direction::Encrypt, 1).await;
    assert!(provider.saw(&[10]));
    b.abort();
    assert!(b.await.unwrap_err().is_cancelled());
    settle().await;
    let dropped_before_a = WATCHED_DROPPED.load(Ordering::SeqCst);
    assert!(!provider.saw(&[20]), "abandoned retry reached the provider");
    assert_eq!(scheduler.stats().pending_bytes(), 0);
    assert_eq!(scheduler.stats().inflight_batches(), 1);
    provider.release[1].notify_one();
    settle().await;
    assert_eq!(finished(a).await.unwrap(), vec![10]);
    fresh(&scheduler, &clock, Direction::Encrypt).await;
    empty(&scheduler, &provider);
    assert!(WATCHED_DROPPED.load(Ordering::SeqCst));
    assert!(
        dropped_before_a,
        "cancelled pending retry retained its payload behind A"
    );
}

#[tokio::test]
async fn split_retries_share_the_lane_limit_with_ordinary_batches() {
    let provider = Provider::new(true, (1 << 1) | (1 << 3), false, false);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(2, 1),
        clock.clone(),
    ));
    let (a, b) = pair(&scheduler, Direction::Encrypt, 1).await;
    let c = request(&scheduler, Direction::Encrypt, 3, 1);
    settle().await;
    clock.advance(Duration::from_millis(5));
    settle().await;
    assert!(provider.saw(&[30]));
    assert_eq!(scheduler.stats().inflight_batches(), 2);
    let d = request(&scheduler, Direction::Encrypt, 4, 1);
    settle().await;
    clock.advance(Duration::from_millis(5));
    settle().await;
    assert!(!provider.saw(&[40]));
    assert_eq!(scheduler.stats().pending_items(), 1);
    assert_eq!(scheduler.stats().pending_bytes(), UNIT as u64);
    c.abort();
    assert!(c.await.unwrap_err().is_cancelled());
    settle().await;
    assert_eq!(finished(d).await.unwrap(), vec![40]);
    provider.release[1].notify_one();
    settle().await;
    assert_eq!(finished(a).await.unwrap(), vec![10]);
    assert_eq!(finished(b).await.unwrap(), vec![20]);
    empty(&scheduler, &provider);
    assert!(provider.calls.peak.load(Ordering::SeqCst) <= 2);
}

#[tokio::test]
async fn a_retry_waiting_for_capacity_wakes_when_an_ordinary_batch_finishes() {
    let provider = Provider::new(true, (1 << 1) | (1 << 3), false, false);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(2, 1),
        clock.clone(),
    ));
    // A single whole request occupies one slot before the rejected A+B
    // batch occupies the other. No spare permit exists at split time.
    let c = request(&scheduler, Direction::Encrypt, 3, 2);
    settle().await;
    assert!(provider.saw(&[30, 31]));
    let (a, b) = pair(&scheduler, Direction::Encrypt, 1).await;
    assert!(provider.saw(&[10]));
    assert!(!provider.saw(&[20]));
    assert_eq!(scheduler.stats().inflight_batches(), 2);

    provider.release[3].notify_one();
    settle().await;
    assert_eq!(finished(c).await.unwrap(), vec![30, 31]);
    let b_finished_before_a = b.is_finished();
    assert_eq!(scheduler.stats().inflight_batches(), 1);
    provider.release[1].notify_one();
    settle().await;
    assert_eq!(finished(a).await.unwrap(), vec![10]);
    assert_eq!(finished(b).await.unwrap(), vec![20]);
    fresh(&scheduler, &clock, Direction::Encrypt).await;
    empty(&scheduler, &provider);
    assert!(provider.calls.peak.load(Ordering::SeqCst) <= 2);
    assert!(
        b_finished_before_a,
        "B did not wake when an ordinary batch returned spare capacity"
    );
}

#[tokio::test]
async fn a_non_retry_safe_provider_receives_only_the_original_batch() {
    let provider = Provider::new(false, 0, false, false);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), config(2, 1), clock));
    let (a, b) = pair(&scheduler, Direction::Encrypt, 1).await;
    assert!(matches!(
        finished(a).await,
        Err(CryptoError::NonRetryableRequest(_))
    ));
    assert!(matches!(
        finished(b).await,
        Err(CryptoError::NonRetryableRequest(_))
    ));
    assert_eq!(*provider.calls.units.lock().unwrap(), vec![vec![10, 20]]);
    empty(&scheduler, &provider);
}

#[tokio::test]
async fn a_single_rejected_request_is_not_resent() {
    let provider = Provider::new(true, 0, false, true);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(2, 1),
        clock.clone(),
    ));
    let a = request(&scheduler, Direction::Encrypt, 1, 2);
    settle().await;
    assert!(matches!(
        finished(a).await,
        Err(CryptoError::NonRetryableRequest(_))
    ));
    assert_eq!(*provider.calls.units.lock().unwrap(), vec![vec![10, 11]]);
    empty(&scheduler, &provider);
}
