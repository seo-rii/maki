//! The attach self-test's compatibility-id probe (SPEC §18 "Context on the
//! wire") must reach the provider that binds the id. With random plaintext
//! prefixes the wrapper translates the volume's derived id into the base id
//! the provider receives. It used to refuse the probe's foreign id itself,
//! before any RPC, and the self-test counted that refusal as proof: a provider
//! that ignores the compatibility id was certified as context-bound exactly
//! when the prefix was enabled. The verdict, and the foreign id the provider
//! is asked to decrypt under, must be the same with and without the wrapper,
//! on the stack the daemon serves through as well.

use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, ErrorClass, PlaintextUnit, RandomPrefixProvider, SecretBuffer, SystemClock,
};
use maki_test_support::fake_provider::FakeCryptoProvider;

const LOGICAL: u32 = 64;
const PREFIX: u32 = 16;
const WIRE: u32 = LOGICAL + PREFIX;
const TAG: usize = 8;
const BASE: &str = "vendor-profile-v1";

fn derived() -> String {
    format!("maki-random-prefix-v1:{PREFIX}:{BASE}")
}

fn context(compatibility_id: &str) -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x4A0D_17C0_FFEE),
        format_version: 3,
        crypto_compatibility_id: compatibility_id.into(),
    }
}

/// An authenticated stream cipher, as a remote provider might run it. The
/// volume UUID, the format version and the unit index always select the
/// key; the compatibility id does only when `binds_profile`, although the
/// provider declares context binding either way. It records the
/// compatibility id of every request it receives.
struct Remote {
    plain: u32,
    binds_profile: bool,
    /// Answer a decrypt under a foreign profile with a one-byte plaintext.
    short_foreign_reply: bool,
    requests: Mutex<Vec<(&'static str, String)>>,
}

impl Remote {
    fn new(plain: u32, binds_profile: bool) -> Arc<Self> {
        Arc::new(Self {
            plain,
            binds_profile,
            short_foreign_reply: false,
            requests: Mutex::new(Vec::new()),
        })
    }

    fn key(&self, context: &CryptoContext, unit: u64) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (context.volume_uuid, context.format_version, unit).hash(&mut hasher);
        if self.binds_profile {
            context.crypto_compatibility_id.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// The compatibility ids of the decrypt requests that did not carry the
    /// provider's own profile.
    fn foreign_decrypts(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(op, profile)| *op == "decrypt" && profile != BASE)
            .map(|(_, profile)| profile.clone())
            .collect()
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

fn keystream(key: u64, len: usize) -> impl Iterator<Item = u8> {
    let mut x = key | 1;
    (0..len).map(move |_| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x >> 24) as u8
    })
}

fn tag(key: u64, body: &[u8]) -> [u8; TAG] {
    body.iter()
        .fold(key ^ 0xcbf2_9ce4_8422_2325, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
        })
        .to_le_bytes()
}

#[async_trait]
impl CryptoProvider for Remote {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "remote".into(),
            crypto_compatibility_id: BASE.into(),
            supported_plaintext_sizes: vec![self.plain],
            max_ciphertext_size: self.plain + TAG as u32,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 16,
                max_bytes: 16 * u64::from(self.plain),
            },
            integrity: Capability::Contractual,
            context_binding: Capability::Contractual,
            replay_protection: Capability::Absent,
        })
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.requests
            .lock()
            .unwrap()
            .push(("encrypt", context.crypto_compatibility_id.clone()));
        Ok(items
            .iter()
            .map(|item| {
                let key = self.key(context, item.unit_index);
                let body: Vec<u8> = item
                    .data
                    .expose()
                    .iter()
                    .zip(keystream(key, item.data.len()))
                    .map(|(p, k)| p ^ k)
                    .collect();
                let mut data = tag(key, &body).to_vec();
                data.extend_from_slice(&body);
                CiphertextUnit {
                    unit_index: item.unit_index,
                    data,
                }
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.requests
            .lock()
            .unwrap()
            .push(("decrypt", context.crypto_compatibility_id.clone()));
        if self.short_foreign_reply && context.crypto_compatibility_id != BASE {
            return Ok(items
                .iter()
                .map(|item| PlaintextUnit {
                    unit_index: item.unit_index,
                    data: SecretBuffer::zeroed(1),
                })
                .collect());
        }
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let key = self.key(context, item.unit_index);
            if item.data.len() < TAG || item.data[..TAG] != tag(key, &item.data[TAG..]) {
                return Err(CryptoError::Integrity("tag mismatch".into()));
            }
            let body = &item.data[TAG..];
            let plain: Vec<u8> = body
                .iter()
                .zip(keystream(key, body.len()))
                .map(|(c, k)| c ^ k)
                .collect();
            out.push(PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_vec(plain),
            });
        }
        Ok(out)
    }
}

/// A layer from another crate that passes every call through unchanged.
struct PassThrough(Arc<dyn CryptoProvider>);

#[async_trait]
impl CryptoProvider for PassThrough {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.0.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.0.encrypt_batch(context, items).await
    }
    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.0.decrypt_batch(context, items).await
    }
}

#[derive(Clone, Copy, Debug)]
enum Stack {
    /// The provider itself, as a volume without random prefixes uses it.
    Bare,
    /// The wrapper directly in front of the provider, as the daemon checks
    /// each remote endpoint at attach and in background validation.
    Prefixed,
    /// The daemon's serving stack for a remote provider: batch scheduler,
    /// random-prefix wrapper, endpoint dispatcher.
    Served,
    /// The wrapper behind the result checks the engine pins it with.
    Checked,
}

const STACKS: [Stack; 4] = [Stack::Bare, Stack::Prefixed, Stack::Served, Stack::Checked];

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
        global_max_inflight_batches: 4,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 4,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: None,
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}

/// `provider`'s plaintext size must be the stack's provider unit: `LOGICAL`
/// for `Bare`, `WIRE` otherwise. Returns the stack and the volume's
/// compatibility id.
async fn stack(
    stack: Stack,
    provider: Arc<dyn CryptoProvider>,
) -> (Arc<dyn CryptoProvider>, String) {
    match stack {
        Stack::Bare => (provider, BASE.into()),
        Stack::Prefixed => (
            Arc::new(
                RandomPrefixProvider::new(provider, LOGICAL, PREFIX, derived())
                    .await
                    .unwrap(),
            ),
            derived(),
        ),
        Stack::Served => {
            let set = EndpointSet::new(
                vec![("only".into(), provider)],
                dispatch(),
                Arc::new(SystemClock::new()),
            )
            .with_plaintext_size(WIRE);
            let prefixed = RandomPrefixProvider::new(Arc::new(set), LOGICAL, PREFIX, derived())
                .await
                .unwrap();
            let scheduler = BatchScheduler::with_unit_size(
                Arc::new(prefixed),
                SchedulerConfig::default(),
                Arc::new(SystemClock::new()),
                LOGICAL,
            );
            (Arc::new(scheduler), derived())
        }
        Stack::Checked => {
            let prefixed = RandomPrefixProvider::new(provider, LOGICAL, PREFIX, derived())
                .await
                .unwrap();
            (
                Arc::new(CheckedProvider::pinned(Arc::new(prefixed), LOGICAL)),
                derived(),
            )
        }
    }
}

fn provider_unit(stack: Stack) -> u32 {
    match stack {
        Stack::Bare => LOGICAL,
        _ => WIRE,
    }
}

/// Self-test `Remote` through `stack`; returns the verdict and the foreign
/// compatibility ids the provider was asked to decrypt under.
async fn self_test(
    binds_profile: bool,
    which: Stack,
) -> (Result<(), CryptoError>, Vec<String>, usize) {
    let remote = Remote::new(provider_unit(which), binds_profile);
    let (provider, profile) = stack(which, remote.clone()).await;
    let result = provider_self_test(
        provider.as_ref(),
        &context(&profile),
        LOGICAL as usize,
        &profile,
    )
    .await;
    (result, remote.foreign_decrypts(), remote.request_count())
}

#[tokio::test]
async fn a_provider_ignoring_the_compatibility_id_fails_with_and_without_the_prefix() {
    let (_, bare_probes, bare_requests) = self_test(false, Stack::Bare).await;
    assert_eq!(
        bare_probes.len(),
        1,
        "one compatibility-id probe: {bare_probes:?}"
    );
    for which in STACKS {
        let (result, probes, requests) = self_test(false, which).await;
        let error = result.expect_err(&format!(
            "{which:?}: a provider that ignores the compatibility id was certified \
             as context-bound (foreign-profile decrypts it received: {probes:?})"
        ));
        assert!(
            error.to_string().contains("compatibility id")
                && error.to_string().contains("original plaintext"),
            "{which:?}: unexpected refusal: {error}"
        );
        assert_eq!(
            probes, bare_probes,
            "{which:?}: the provider must receive the probe it receives without a prefix"
        );
        assert_eq!(
            requests, bare_requests,
            "{which:?}: same self-test on the wire"
        );
    }
}

#[tokio::test]
async fn a_provider_binding_the_compatibility_id_passes_with_and_without_the_prefix() {
    let (_, bare_probes, bare_requests) = self_test(true, Stack::Bare).await;
    assert_eq!(
        bare_probes.len(),
        1,
        "one compatibility-id probe: {bare_probes:?}"
    );
    for which in STACKS {
        let (result, probes, requests) = self_test(true, which).await;
        result.unwrap_or_else(|error| panic!("{which:?}: a bound provider was refused: {error}"));
        assert_eq!(
            probes, bare_probes,
            "{which:?}: the provider must receive the probe it receives without a prefix"
        );
        assert_eq!(
            requests, bare_requests,
            "{which:?}: same self-test on the wire"
        );
    }
}

/// A provider's own explicit refusal of a foreign compatibility id (the
/// local providers and the fake refuse any other id) still proves the
/// binding behind the wrapper, and is now the provider's answer, not the
/// wrapper's.
#[tokio::test]
async fn a_providers_explicit_refusal_is_forwarded_through_the_prefix() {
    let mut calls = Vec::new();
    for which in STACKS {
        let fake = Arc::new(FakeCryptoProvider::new(provider_unit(which)).with_compat_id(BASE));
        let (provider, profile) = stack(which, fake.clone()).await;
        provider_self_test(
            provider.as_ref(),
            &context(&profile),
            LOGICAL as usize,
            &profile,
        )
        .await
        .unwrap_or_else(|error| panic!("{which:?}: {error}"));
        calls.push(fake.decrypt_calls());
    }
    assert!(
        calls.iter().all(|count| *count == calls[0]),
        "every stack must send the provider the same decrypts (bare, prefixed, served, checked): \
         {calls:?}"
    );
}

/// The probe's reply passes the same response checks as any decrypt before
/// the wrapper removes the prefix: a malformed reply is a contract violation,
/// never a context-binding pass and never a short buffer the wrapper slices.
#[tokio::test]
async fn a_malformed_probe_reply_is_refused_before_the_prefix_is_removed() {
    for which in STACKS {
        let remote = Arc::new(Remote {
            short_foreign_reply: true,
            ..Arc::into_inner(Remote::new(provider_unit(which), true)).unwrap()
        });
        let (provider, profile) = stack(which, remote.clone()).await;
        let result = provider_self_test(
            provider.as_ref(),
            &context(&profile),
            LOGICAL as usize,
            &profile,
        )
        .await;
        assert!(
            matches!(&result, Err(error) if error.class() == ErrorClass::ProviderFatal),
            "{which:?}: a malformed probe reply was accepted: {result:?}"
        );
        assert_eq!(remote.foreign_decrypts().len(), 1, "{which:?}");
    }
}

/// The wrapper does not bind the compatibility id; it translates it. Its own
/// refusal of a foreign id, for real traffic, must not read as the field
/// evidence a provider gives, so a layer that does not forward the
/// self-test's probe makes the self-test fail closed instead of certifying
/// a binding nobody exercised.
#[tokio::test]
async fn the_wrappers_own_refusal_never_proves_context_binding() {
    let remote = Remote::new(WIRE, true);
    let wrapper = RandomPrefixProvider::new(remote.clone(), LOGICAL, PREFIX, derived())
        .await
        .unwrap();
    let unit = [PlaintextUnit {
        unit_index: 5,
        data: SecretBuffer::zeroed(LOGICAL as usize),
    }];
    let ciphertext = wrapper
        .encrypt_batch(&context(&derived()), &unit)
        .await
        .unwrap();
    let before = remote.request_count();
    let foreign = context(&format!("{}.other", derived()));
    for refused in [
        wrapper.decrypt_batch(&foreign, &ciphertext).await.err(),
        wrapper.encrypt_batch(&foreign, &unit).await.err(),
    ] {
        let refused = refused.expect("a foreign compatibility id must be refused");
        assert!(
            !matches!(refused, CryptoError::UnsupportedContext(_)),
            "the wrapper's refusal reads as provider field evidence: {refused}"
        );
        assert_eq!(refused.class(), ErrorClass::ProviderFatal);
    }
    assert_eq!(remote.request_count(), before, "refused before any request");

    for binds_profile in [false, true] {
        let remote = Remote::new(WIRE, binds_profile);
        let (prefixed, profile) = stack(Stack::Prefixed, remote.clone()).await;
        let outer = PassThrough(prefixed);
        let result =
            provider_self_test(&outer, &context(&profile), LOGICAL as usize, &profile).await;
        assert!(
            matches!(&result, Err(error) if error.class() == ErrorClass::ProviderFatal),
            "binds_profile = {binds_profile}: an unexercised binding was certified: {result:?}"
        );
        assert!(remote.foreign_decrypts().is_empty());
    }
}
