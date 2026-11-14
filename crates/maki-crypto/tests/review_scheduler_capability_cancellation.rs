//! BUG-083: the retry-safety capability check owns the rejected batch's
//! inputs and lane slot. Cancel it when every caller cancels or expires,
//! while preserving a live sibling's opportunity to retry.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

const UNIT: usize = 64;
const DEADLINE: Duration = Duration::from_millis(100);
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(83),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn plaintext(index: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::from_slice(&[index as u8; UNIT]),
    }
}

struct SlowCapabilities {
    inner: FakeCryptoProvider,
    calls: AtomicUsize,
    cancelled_checks: AtomicUsize,
    check_started: Notify,
    check_cancelled: Notify,
    check_gate: Semaphore,
    deadline: Option<Duration>,
}

struct CheckGuard<'a> {
    provider: &'a SlowCapabilities,
    completed: bool,
}

impl Drop for CheckGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.provider
                .cancelled_checks
                .fetch_add(1, Ordering::SeqCst);
            self.provider.check_cancelled.notify_one();
        }
    }
}

#[async_trait]
impl CryptoProvider for SlowCapabilities {
    fn max_operation_time(&self) -> Option<Duration> {
        self.deadline
    }

    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let capabilities = self.inner.capabilities().await?;
        // Decryption's initial capability discovery succeeds; only the
        // re-check after the coalesced batch's rejection is suspended.
        if self.calls.load(Ordering::SeqCst) != 0 {
            let mut guard = CheckGuard {
                provider: self,
                completed: false,
            };
            self.check_started.notify_one();
            self.check_gate.acquire().await.unwrap().forget();
            guard.completed = true;
        }
        Ok(capabilities)
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            assert_eq!(items.len(), 2, "fixture requires a coalesced batch");
            return Err(CryptoError::NonRetryableRequest("batch refused".into()));
        }
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            assert_eq!(items.len(), 2, "fixture requires a coalesced batch");
            return Err(CryptoError::NonRetryableRequest("batch refused".into()));
        }
        self.inner.decrypt_batch(context, items).await
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

type Request = JoinHandle<Result<u64, CryptoError>>;

fn request(scheduler: &Arc<BatchScheduler>, index: u64, direction: Direction) -> Request {
    let scheduler = scheduler.clone();
    tokio::spawn(async move {
        match direction {
            Direction::Encrypt => {
                let output = scheduler
                    .encrypt_batch(&context(), &[plaintext(index)])
                    .await?;
                assert_eq!(output.len(), 1);
                Ok(output[0].unit_index)
            }
            Direction::Decrypt => {
                let ciphertext = FakeCryptoProvider::new(UNIT as u32)
                    .encrypt_batch(&context(), &[plaintext(index)])
                    .await
                    .unwrap();
                let output = scheduler.decrypt_batch(&context(), &ciphertext).await?;
                assert_eq!(output.len(), 1);
                assert_eq!(output[0].data.expose(), &[index as u8; UNIT]);
                Ok(output[0].unit_index)
            }
        }
    })
}

struct Fixture {
    provider: Arc<SlowCapabilities>,
    scheduler: Arc<BatchScheduler>,
    clock: Arc<ManualClock>,
}

impl Fixture {
    fn new(deadline: Option<Duration>) -> Self {
        let provider = Arc::new(SlowCapabilities {
            inner: FakeCryptoProvider::new(UNIT as u32),
            calls: AtomicUsize::new(0),
            cancelled_checks: AtomicUsize::new(0),
            check_started: Notify::new(),
            check_cancelled: Notify::new(),
            check_gate: Semaphore::new(0),
            deadline,
        });
        let clock = Arc::new(ManualClock::new());
        let scheduler = Arc::new(BatchScheduler::with_unit_size(
            provider.clone(),
            SchedulerConfig {
                target_items: 2,
                max_items: 8,
                max_inflight_batches: 1,
                max_wait: Duration::from_secs(60),
                ..SchedulerConfig::default()
            },
            clock.clone(),
            UNIT as u32,
        ));
        Self {
            provider,
            scheduler,
            clock,
        }
    }

    async fn rejected_batch(&self, direction: Direction) -> (Request, Request) {
        let first = request(&self.scheduler, 1, direction);
        let second = request(&self.scheduler, 2, direction);
        tokio::time::timeout(TEST_TIMEOUT, self.provider.check_started.notified())
            .await
            .expect("rejected batch never reached its capability re-check");
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), 1);
        (first, second)
    }

    async fn assert_check_cancelled(&self) {
        tokio::time::timeout(TEST_TIMEOUT, self.provider.check_cancelled.notified())
            .await
            .expect("abandoned capability re-check retained the rejected inputs");
        assert_eq!(self.provider.cancelled_checks.load(Ordering::SeqCst), 1);
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), 1);
    }

    async fn assert_lane_available(&self, direction: Direction) {
        let first = request(&self.scheduler, 3, direction);
        let second = request(&self.scheduler, 4, direction);
        let (first, second) = tokio::time::timeout(TEST_TIMEOUT, async {
            (
                first.await.unwrap().unwrap(),
                second.await.unwrap().unwrap(),
            )
        })
        .await
        .expect("capability re-check retained the only lane slot");
        assert_eq!((first, second), (3, 4));
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn cancelling_every_caller_drops_the_capability_check_and_releases_the_lane() {
    for direction in [Direction::Encrypt, Direction::Decrypt] {
        let fixture = Fixture::new(None);
        let (first, second) = fixture.rejected_batch(direction).await;
        first.abort();
        second.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(second.await.unwrap_err().is_cancelled());
        fixture.assert_check_cancelled().await;
        fixture.assert_lane_available(direction).await;
    }
}

#[tokio::test]
async fn caller_deadlines_also_drop_the_capability_check_and_release_the_lane() {
    for direction in [Direction::Encrypt, Direction::Decrypt] {
        let fixture = Fixture::new(Some(DEADLINE));
        let (first, second) = fixture.rejected_batch(direction).await;
        fixture.clock.advance(DEADLINE);
        for caller in [first, second] {
            let result = tokio::time::timeout(TEST_TIMEOUT, caller)
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(result, Err(CryptoError::Retryable(_))),
                "{result:?}"
            );
        }
        fixture.assert_check_cancelled().await;
        fixture.assert_lane_available(direction).await;
    }
}

#[tokio::test]
async fn a_live_sibling_keeps_the_check_and_gets_its_own_successful_retry() {
    for direction in [Direction::Encrypt, Direction::Decrypt] {
        let fixture = Fixture::new(None);
        let (first, second) = fixture.rejected_batch(direction).await;
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert_eq!(fixture.provider.cancelled_checks.load(Ordering::SeqCst), 0);
        assert!(!second.is_finished());
        fixture.provider.check_gate.add_permits(1);
        let output = tokio::time::timeout(TEST_TIMEOUT, second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(output, 2);
        assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.provider.cancelled_checks.load(Ordering::SeqCst), 0);
    }
}
