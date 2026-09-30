//! R5-004: when a coalesced batch fails with a request-specific error, the
//! scheduler re-sends each request alone so an unrelated request gets its
//! own verdict. That re-send must
//! - never reach a provider that is not retry-safe (M-010: such a provider
//!   is never sent the same request twice), and
//! - stay cancellable and counted in flight, like the batch it replaces:
//!   a re-send whose caller has left is abandoned and releases its lane
//!   slot (BUG-012).

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

const UNIT: usize = 64;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(12),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&[i as u8; UNIT]),
    }
}

fn cfg(max_inflight_batches: u32) -> SchedulerConfig {
    SchedulerConfig {
        target_items: 2,
        target_bytes: 1 << 20,
        max_items: 16,
        max_bytes: 1 << 20,
        max_wait: Duration::from_millis(5),
        max_pending_items: 64,
        max_pending_plaintext_bytes: 1 << 20,
        max_pending_ciphertext_bytes: 1 << 20,
        max_inflight_batches,
    }
}

async fn settle() {
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
}

/// What the provider does on its n-th encrypt call.
#[derive(Clone, Copy)]
enum Behaviour {
    Reject,
    Hang,
    Encrypt,
}

struct Scripted {
    inner: FakeCryptoProvider,
    retry_safe: bool,
    script: Vec<Behaviour>,
    calls: AtomicUsize,
    items: AtomicUsize,
}

impl Scripted {
    fn new(retry_safe: bool, script: Vec<Behaviour>) -> Arc<Self> {
        Arc::new(Self {
            inner: FakeCryptoProvider::new(UNIT as u32),
            retry_safe,
            script,
            calls: AtomicUsize::new(0),
            items: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl CryptoProvider for Scripted {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut caps = self.inner.capabilities().await?;
        caps.retry_safe = self.retry_safe;
        Ok(caps)
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.items.fetch_add(items.len(), Ordering::SeqCst);
        match self.script.get(call).copied().unwrap_or(Behaviour::Encrypt) {
            Behaviour::Reject => Err(CryptoError::NonRetryableRequest("HTTP 400".into())),
            Behaviour::Hang => std::future::pending().await,
            Behaviour::Encrypt => self.inner.encrypt_batch(context, items).await,
        }
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.inner.decrypt_batch(context, items).await
    }
}

#[tokio::test]
async fn a_provider_that_is_not_retry_safe_never_receives_a_resend() {
    let provider = Scripted::new(false, vec![Behaviour::Reject]);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), cfg(4), clock));
    let a = {
        let s = scheduler.clone();
        tokio::spawn(async move { s.encrypt_batch(&ctx(), &[pt(1)]).await })
    };
    let b = {
        let s = scheduler.clone();
        tokio::spawn(async move { s.encrypt_batch(&ctx(), &[pt(2)]).await })
    };
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    assert!(
        matches!(a, Err(CryptoError::NonRetryableRequest(_))),
        "{a:?}"
    );
    assert!(
        matches!(b, Err(CryptoError::NonRetryableRequest(_))),
        "{b:?}"
    );
    assert_eq!(
        scheduler.stats().coalesced_batches_total(),
        1,
        "both requests went out in one coalesced call"
    );
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        1,
        "a non-retry-safe provider received the same plaintext units again"
    );
    assert_eq!(provider.items.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_retry_safe_provider_still_gets_per_request_verdicts() {
    let provider = Scripted::new(true, vec![Behaviour::Reject, Behaviour::Reject]);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), cfg(4), clock));
    let a = {
        let s = scheduler.clone();
        tokio::spawn(async move { s.encrypt_batch(&ctx(), &[pt(1)]).await })
    };
    let b = {
        let s = scheduler.clone();
        tokio::spawn(async move { s.encrypt_batch(&ctx(), &[pt(2)]).await })
    };
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    assert!(
        matches!(a, Err(CryptoError::NonRetryableRequest(_))),
        "{a:?}"
    );
    assert_eq!(b.unwrap()[0].unit_index, 2);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn an_abandoned_resend_releases_its_lane_slot() {
    // One lane slot: the batch is rejected, the first re-send hangs.
    let provider = Scripted::new(true, vec![Behaviour::Reject, Behaviour::Hang]);
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), cfg(1), clock.clone()));
    let a = {
        let s = scheduler.clone();
        tokio::spawn(async move { s.encrypt_batch(&ctx(), &[pt(1)]).await })
    };
    let b = {
        let s = scheduler.clone();
        tokio::spawn(async move { s.encrypt_batch(&ctx(), &[pt(2)]).await })
    };
    settle().await;
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        2,
        "batch, then a re-send"
    );
    assert_eq!(
        scheduler.stats().inflight_batches(),
        1,
        "the hanging re-send is a provider call in flight"
    );
    a.abort();
    b.abort();
    settle().await;
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        2,
        "the second re-send's caller left: it must not be sent"
    );
    assert_eq!(scheduler.stats().inflight_batches(), 0);

    // The slot is free again: a fresh request completes.
    let fresh = {
        let s = scheduler.clone();
        tokio::spawn(async move { s.encrypt_batch(&ctx(), &[pt(3)]).await })
    };
    settle().await;
    clock.advance(Duration::from_millis(5));
    let fresh = tokio::time::timeout(Duration::from_secs(5), fresh)
        .await
        .expect("a fresh request waited behind an abandoned re-send")
        .unwrap()
        .unwrap();
    assert_eq!(fresh[0].unit_index, 3);
}
