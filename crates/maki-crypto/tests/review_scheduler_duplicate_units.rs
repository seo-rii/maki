//! BUG-102: the batch scheduler coalesced concurrent requests for the *same*
//! unit into one provider call. Results are matched to requests by position
//! and checked only by `unit_index`, and the AEAD context does not bind the
//! write sequence, so two ciphertexts of one unit are interchangeable to
//! every check. A provider that keys a batch by unit index (a map from unit
//! to result, replying in request order) then hands both callers the same
//! plaintext: a stale read is cached under the newer version, and a partial
//! write merges into the stale plaintext and loses an acknowledged write.
//! A provider call never carries one unit twice.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;

use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x0102),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(unit: u64, fill: u8) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: unit,
        data: SecretBuffer::from_slice(&[fill; UNIT]),
    }
}

/// Records every call's unit indices; decrypt answers through a map keyed
/// by unit index, as a server that indexes its batch by unit would.
struct UnitKeyed {
    inner: FakeCryptoProvider,
    calls: Mutex<Vec<Vec<u64>>>,
}

#[async_trait]
impl CryptoProvider for UnitKeyed {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.calls
            .lock()
            .push(items.iter().map(|i| i.unit_index).collect());
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.calls
            .lock()
            .push(items.iter().map(|i| i.unit_index).collect());
        let plain = self.inner.decrypt_batch(context, items).await?;
        let by_unit: HashMap<u64, Vec<u8>> = plain
            .iter()
            .map(|p| (p.unit_index, p.data.expose().to_vec()))
            .collect();
        Ok(items
            .iter()
            .map(|i| PlaintextUnit {
                unit_index: i.unit_index,
                data: SecretBuffer::from_slice(&by_unit[&i.unit_index]),
            })
            .collect())
    }
}

fn config() -> SchedulerConfig {
    SchedulerConfig {
        // Two single-unit requests reach the target together: without the
        // distinct-unit rule they always share one call.
        target_items: 2,
        target_bytes: 1 << 20,
        max_items: 16,
        max_bytes: 1 << 20,
        max_wait: Duration::from_millis(5),
        max_pending_items: 64,
        max_pending_plaintext_bytes: 1 << 20,
        max_pending_ciphertext_bytes: 1 << 20,
        max_inflight_batches: 4,
    }
}

async fn settle(clock: &ManualClock) {
    for _ in 0..8 {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        clock.advance(Duration::from_millis(5));
    }
}

fn assert_distinct(calls: &[Vec<u64>]) {
    for call in calls {
        let unique: HashSet<_> = call.iter().collect();
        assert_eq!(
            unique.len(),
            call.len(),
            "one provider call carried a unit twice: {call:?}"
        );
    }
}

#[tokio::test]
async fn two_versions_of_one_unit_never_share_a_decrypt_call() {
    let provider = Arc::new(UnitKeyed {
        inner: FakeCryptoProvider::new(UNIT as u32),
        calls: Mutex::new(Vec::new()),
    });
    let old = provider
        .inner
        .encrypt_batch(&ctx(), &[pt(7, 0x05)])
        .await
        .unwrap();
    let new = provider
        .inner
        .encrypt_batch(&ctx(), &[pt(7, 0x06)])
        .await
        .unwrap();
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(),
        clock.clone(),
    ));

    let reader = {
        let scheduler = scheduler.clone();
        tokio::spawn(async move { scheduler.decrypt_batch(&ctx(), &old).await })
    };
    let writer = {
        let scheduler = scheduler.clone();
        tokio::spawn(async move { scheduler.decrypt_batch(&ctx(), &new).await })
    };
    settle(&clock).await;
    let stale = reader.await.unwrap().unwrap();
    let current = writer.await.unwrap().unwrap();

    assert_distinct(&provider.calls.lock());
    assert_eq!(stale[0].data.expose(), &[0x05; UNIT][..]);
    assert_eq!(
        current[0].data.expose(),
        &[0x06; UNIT][..],
        "the newer version decrypted to the older plaintext"
    );
}

#[tokio::test]
async fn two_writes_of_one_unit_never_share_an_encrypt_call() {
    let provider = Arc::new(UnitKeyed {
        inner: FakeCryptoProvider::new(UNIT as u32),
        calls: Mutex::new(Vec::new()),
    });
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(),
        clock.clone(),
    ));
    let tasks: Vec<_> = [(3, 0xA1), (3, 0xA2), (4, 0xB1)]
        .into_iter()
        .map(|(unit, fill)| {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.encrypt_batch(&ctx(), &[pt(unit, fill)]).await })
        })
        .collect();
    settle(&clock).await;
    for (task, fill) in tasks.into_iter().zip([0xA1u8, 0xA2, 0xB1]) {
        let ct = task.await.unwrap().unwrap();
        let back = provider.inner.decrypt_batch(&ctx(), &ct).await.unwrap();
        assert_eq!(back[0].data.expose(), &[fill; UNIT][..]);
    }
    assert_distinct(&provider.calls.lock());
}
