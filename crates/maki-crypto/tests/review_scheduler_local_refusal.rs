//! A request that the provider stack refuses before sending anything must
//! fail alone. `EndpointSet` and `RandomPrefixProvider` check every unit of
//! a call before the first RPC and refuse the *whole* call for one bad unit:
//! an empty or oversized ciphertext, or plaintext of a size the provider
//! contract does not accept. When the scheduler had coalesced such a request
//! with healthy ones, that refusal reached every caller of the batch, and a
//! provider that is not retry-safe never re-sends a rejected batch request
//! by request (R5-004). A slot holding a CRC-valid empty ciphertext thus
//! turned every read coalesced with it into EIO, although nothing was sent.
//! The scheduler refuses such a request at admission, so it never joins a
//! batch. It admits by the contract the stack reports, so that contract
//! must not list a size the stack refuses: an endpoint set bound to one
//! plaintext size reports that size only, whatever else its endpoints have
//! in common. A rejection the provider returns after the batch may have
//! been sent still reaches every request in it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    RandomPrefixProvider, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;
use tokio::task::JoinHandle;

const UNIT: u32 = 256;
const PREFIX: u32 = 16;
const MAX_WAIT: Duration = Duration::from_secs(5);

/// The provider stacks the daemon puts under the scheduler.
#[derive(Clone, Copy, Debug)]
enum Stack {
    Endpoints,
    /// The endpoint also declares a plaintext size above its batch byte
    /// limit, which the dispatcher refuses before sending.
    EndpointsWithUnbatchableSize,
    /// The endpoint also declares half the unit as a plaintext size. The
    /// set is bound to the unit and refuses every other size.
    EndpointsWithSmallerSize,
    RandomPrefix,
}

/// A unit the stack refuses before sending any RPC.
#[derive(Clone, Copy, Debug)]
enum Refused {
    EmptyCiphertext,
    OversizedCiphertext,
    /// Half the unit: a size the stack does not serve, whether or not its
    /// endpoint declares it.
    OtherPlaintextSize,
    PlaintextAboveBatchLimit,
}

/// Declares one more plaintext size than it serves and, with `max_bytes`,
/// that batch byte limit.
struct Declares {
    inner: Arc<FakeCryptoProvider>,
    size: u32,
    max_bytes: Option<u64>,
}

#[async_trait]
impl CryptoProvider for Declares {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut caps = self.inner.capabilities().await?;
        caps.supported_plaintext_sizes.push(self.size);
        if let Some(max_bytes) = self.max_bytes {
            caps.batch.max_bytes = max_bytes;
        }
        Ok(caps)
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.inner.decrypt_batch(context, items).await
    }
}

/// Serves the unit and half the unit, each with its own cipher.
struct TwoSizes {
    unit: FakeCryptoProvider,
    half: FakeCryptoProvider,
    calls: AtomicUsize,
}

#[async_trait]
impl CryptoProvider for TwoSizes {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut caps = self.unit.capabilities().await?;
        caps.supported_plaintext_sizes.push(UNIT / 2);
        Ok(caps)
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut out = Vec::new();
        for item in items {
            let cipher = if item.data.len() == (UNIT / 2) as usize {
                &self.half
            } else {
                &self.unit
            };
            out.extend(
                cipher
                    .encrypt_batch(context, std::slice::from_ref(item))
                    .await?,
            );
        }
        Ok(out)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let half = self.half.capabilities().await?.max_ciphertext_size as usize;
        let mut out = Vec::new();
        for item in items {
            let cipher = if item.data.len() == half {
                &self.half
            } else {
                &self.unit
            };
            out.extend(
                cipher
                    .decrypt_batch(context, std::slice::from_ref(item))
                    .await?,
            );
        }
        Ok(out)
    }
}

fn dispatch() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig::default(),
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 8,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: None,
        retry_safe: false,
        validation_interval: Duration::from_secs(1),
    }
}

fn config() -> SchedulerConfig {
    SchedulerConfig {
        // Two single-unit requests reach the target together: without the
        // admission check they always share one provider call.
        target_items: 2,
        target_bytes: 1 << 20,
        max_items: 16,
        max_bytes: 1 << 20,
        max_wait: MAX_WAIT,
        max_pending_items: 64,
        max_pending_plaintext_bytes: 1 << 20,
        max_pending_ciphertext_bytes: 1 << 20,
        max_inflight_batches: 4,
    }
}

struct Fixture {
    endpoint: Arc<FakeCryptoProvider>,
    stack: Arc<dyn CryptoProvider>,
    scheduler: Arc<BatchScheduler>,
    clock: Arc<ManualClock>,
    context: CryptoContext,
}

impl Fixture {
    async fn new(stack: Stack) -> Self {
        let clock = Arc::new(ManualClock::new());
        let wire = match stack {
            Stack::RandomPrefix => UNIT + PREFIX,
            _ => UNIT,
        };
        let endpoint = Arc::new(FakeCryptoProvider::new(wire));
        let served: Arc<dyn CryptoProvider> = match stack {
            Stack::EndpointsWithUnbatchableSize => Arc::new(Declares {
                inner: endpoint.clone(),
                size: 2 * UNIT,
                max_bytes: Some(u64::from(UNIT)),
            }),
            Stack::EndpointsWithSmallerSize => Arc::new(Declares {
                inner: endpoint.clone(),
                size: UNIT / 2,
                max_bytes: None,
            }),
            _ => endpoint.clone(),
        };
        let set: Arc<dyn CryptoProvider> = Arc::new(
            EndpointSet::new(vec![("only".into(), served)], dispatch(), clock.clone())
                .with_plaintext_size(wire),
        );
        let (stack, profile): (Arc<dyn CryptoProvider>, &str) = match stack {
            Stack::RandomPrefix => (
                Arc::new(
                    RandomPrefixProvider::new(set, UNIT, PREFIX, "prefixed-profile-v1".into())
                        .await
                        .unwrap(),
                ),
                "prefixed-profile-v1",
            ),
            _ => (set, "test-profile-v1"),
        };
        let caps = stack.capabilities().await.unwrap();
        assert!(!caps.retry_safe, "the fixture must not be retry-safe");
        let scheduler = Arc::new(BatchScheduler::with_unit_size(
            stack.clone(),
            config(),
            clock.clone(),
            UNIT,
        ));
        Self {
            endpoint,
            stack,
            scheduler,
            clock,
            context: CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(0x10ca1),
                format_version: 3,
                crypto_compatibility_id: profile.into(),
            },
        }
    }

    fn rpcs(&self) -> usize {
        self.endpoint.encrypt_calls() + self.endpoint.decrypt_calls()
    }

    async fn ciphertext(&self, unit_index: u64) -> Vec<CiphertextUnit> {
        self.stack
            .encrypt_batch(&self.context, &[plaintext(unit_index, UNIT)])
            .await
            .unwrap()
    }

    fn spawn(&self, request: Request) -> JoinHandle<Result<Vec<u8>, CryptoError>> {
        let scheduler = self.scheduler.clone();
        let context = self.context.clone();
        tokio::spawn(async move {
            match request {
                Request::Decrypt(items) => scheduler
                    .decrypt_batch(&context, &items)
                    .await
                    .map(|out| out[0].data.expose().to_vec()),
                Request::Encrypt(items) => scheduler
                    .encrypt_batch(&context, &items)
                    .await
                    .map(|out| out[0].data.clone()),
            }
        })
    }
}

enum Request {
    Decrypt(Vec<CiphertextUnit>),
    Encrypt(Vec<PlaintextUnit>),
}

fn plaintext(unit_index: u64, len: u32) -> PlaintextUnit {
    PlaintextUnit {
        unit_index,
        data: SecretBuffer::from_slice(&vec![unit_index as u8; len as usize]),
    }
}

/// Let both requests reach the lane before any time passes, then move the
/// clock until a group waiting for a partner is dispatched alone.
async fn settle(clock: &ManualClock) {
    for _ in 0..8 {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        clock.advance(MAX_WAIT);
    }
}

#[tokio::test]
async fn a_unit_the_stack_refuses_before_sending_fails_alone() {
    let mut failures = Vec::new();
    for stack in [
        Stack::Endpoints,
        Stack::EndpointsWithUnbatchableSize,
        Stack::EndpointsWithSmallerSize,
        Stack::RandomPrefix,
    ] {
        for case in [
            Refused::EmptyCiphertext,
            Refused::OversizedCiphertext,
            Refused::OtherPlaintextSize,
            Refused::PlaintextAboveBatchLimit,
        ] {
            let f = Fixture::new(stack).await;
            let max_ciphertext = f.stack.capabilities().await.unwrap().max_ciphertext_size;
            let (healthy, refused) = match case {
                Refused::EmptyCiphertext | Refused::OversizedCiphertext => {
                    let len = match case {
                        Refused::EmptyCiphertext => 0,
                        _ => max_ciphertext as usize + 1,
                    };
                    (
                        Request::Decrypt(f.ciphertext(1).await),
                        Request::Decrypt(vec![CiphertextUnit {
                            unit_index: 2,
                            data: vec![0x5a; len],
                        }]),
                    )
                }
                Refused::OtherPlaintextSize | Refused::PlaintextAboveBatchLimit => {
                    let len = match case {
                        Refused::OtherPlaintextSize => UNIT / 2,
                        _ => 2 * UNIT,
                    };
                    (
                        Request::Encrypt(vec![plaintext(1, UNIT)]),
                        Request::Encrypt(vec![plaintext(2, len)]),
                    )
                }
            };
            let decrypt = matches!(healthy, Request::Decrypt(_));
            let rpcs = f.rpcs();
            let a = f.spawn(healthy);
            let b = f.spawn(refused);
            settle(&f.clock).await;
            let (a, b) = (a.await.unwrap(), b.await.unwrap());
            let rpcs = f.rpcs() - rpcs;

            assert!(
                matches!(b, Err(CryptoError::NonRetryableRequest(_))),
                "{stack:?} {case:?}: the refused unit itself must fail: {b:?}"
            );
            match &a {
                Ok(out) if decrypt => assert_eq!(out, &vec![1u8; UNIT as usize]),
                Ok(out) => assert!(!out.is_empty()),
                Err(error) => failures.push(format!(
                    "{stack:?} {case:?}: {error} ({rpcs} provider call(s), {} coalesced)",
                    f.scheduler.stats().coalesced_batches_total()
                )),
            }
            if a.is_ok() {
                assert_eq!(rpcs, 1, "{stack:?} {case:?}: only the healthy unit is sent");
                assert_eq!(
                    f.scheduler.stats().coalesced_batches_total(),
                    0,
                    "{stack:?} {case:?}: the refused request joined a batch"
                );
            }
            assert_eq!(f.scheduler.stats().pending_items(), 0);
            assert_eq!(f.scheduler.stats().pending_bytes(), 0);
        }
    }
    assert!(
        failures.is_empty(),
        "a healthy request failed only because it was coalesced with a unit the \
         provider stack refuses before sending anything:\n{}",
        failures.join("\n")
    );
}

/// A set that is not bound to one plaintext size serves every size its
/// endpoints have in common and reports them all: the scheduler admits a
/// unit of each, and may send them in one call.
#[tokio::test]
async fn a_set_not_bound_to_one_size_serves_every_common_size() {
    let clock = Arc::new(ManualClock::new());
    let endpoint = Arc::new(TwoSizes {
        unit: FakeCryptoProvider::new(UNIT),
        half: FakeCryptoProvider::new(UNIT / 2),
        calls: AtomicUsize::new(0),
    });
    let set: Arc<dyn CryptoProvider> = Arc::new(EndpointSet::new(
        vec![("only".into(), endpoint.clone())],
        dispatch(),
        clock.clone(),
    ));
    assert_eq!(
        set.capabilities().await.unwrap().supported_plaintext_sizes,
        [UNIT / 2, UNIT]
    );
    let scheduler = Arc::new(BatchScheduler::new(set, config(), clock.clone()));
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x10ca1),
        format_version: 3,
        crypto_compatibility_id: "test-profile-v1".into(),
    };
    let requests: Vec<_> = [(1, UNIT), (2, UNIT / 2)]
        .into_iter()
        .map(|(unit_index, len)| {
            let scheduler = scheduler.clone();
            let context = context.clone();
            tokio::spawn(async move {
                let item = plaintext(unit_index, len);
                let sealed = scheduler
                    .encrypt_batch(&context, std::slice::from_ref(&item))
                    .await?;
                let opened = scheduler.decrypt_batch(&context, &sealed).await?;
                Ok::<_, CryptoError>(opened[0].data == item.data)
            })
        })
        .collect();
    settle(&clock).await;
    for request in requests {
        assert!(request.await.unwrap().unwrap(), "round trip mismatch");
    }
    assert_eq!(
        endpoint.calls.load(Ordering::SeqCst),
        2,
        "one encrypt and one decrypt call carry both sizes"
    );
    assert_eq!(scheduler.stats().coalesced_batches_total(), 2);
}

/// The admission check does not widen per-request isolation: a provider
/// that is not retry-safe is still sent a rejected batch once, and its
/// verdict reaches every request in it (R5-004).
#[tokio::test]
async fn a_rejection_after_sending_still_reaches_every_coalesced_request() {
    let f = Fixture::new(Stack::Endpoints).await;
    let healthy = f.ciphertext(1).await;
    let mut tampered = f.ciphertext(2).await;
    tampered[0].data[12] ^= 0x01;
    let rpcs = f.rpcs();
    let a = f.spawn(Request::Decrypt(healthy));
    let b = f.spawn(Request::Decrypt(tampered));
    settle(&f.clock).await;
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    assert!(matches!(a, Err(CryptoError::Integrity(_))), "{a:?}");
    assert!(matches!(b, Err(CryptoError::Integrity(_))), "{b:?}");
    assert_eq!(
        f.rpcs() - rpcs,
        1,
        "the batch was re-sent request by request"
    );
    assert_eq!(f.scheduler.stats().coalesced_batches_total(), 1);
}
