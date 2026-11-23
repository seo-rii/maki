//! A CRC-valid slot header may record an empty ciphertext: a v2 volume
//! keeps one from `Volume::write_ct(unit, &[], ..)` across checkpoint and
//! recovery (AUD-062), and damaged or crafted media can hold one too. Its
//! read fails, since no provider decrypts nothing. The dispatcher refuses
//! such a unit for the whole call before sending anything, so when the
//! batch scheduler coalesced that read with a healthy one on a provider
//! that is not retry-safe, the healthy read failed with it, although no
//! request had been sent. Only the read of the empty slot may fail.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_backing::{Backing, MemBacking};
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::{Volume, VolumeOptions};
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{fake_provider::FakeCryptoProvider, ManualClock};

const UNIT: u32 = 4096;
const MAX_WAIT: Duration = Duration::from_secs(5);
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xe3f7),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, 16 * UNIT as u64, 8 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
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

#[tokio::test]
async fn a_healthy_read_coalesced_with_an_empty_slot_still_succeeds() {
    let fake = Arc::new(FakeCryptoProvider::new(UNIT));
    let sb = superblock();
    let context = CryptoContext {
        volume_uuid: sb.volume_uuid,
        format_version: sb.format_version,
        crypto_compatibility_id: sb.crypto_compatibility_id.clone(),
    };
    let healthy = fake
        .encrypt_batch(
            &context,
            &[PlaintextUnit {
                unit_index: 0,
                data: SecretBuffer::from_slice(&[0x31; UNIT as usize]),
            }],
        )
        .await
        .unwrap();

    // Unit 1's slot header is CRC-valid and records an empty ciphertext.
    // Unit 0 holds the first ciphertext, which attach decrypts to verify the
    // key of a volume without a key canary.
    let backing = Arc::new(MemBacking::new());
    init::create_volume(backing.as_ref(), sb).unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(0, &healthy[0].data, true).unwrap();
    volume.write_ct(1, &[], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    let set = Arc::new(
        EndpointSet::new(
            vec![("only".into(), fake.clone() as Arc<dyn CryptoProvider>)],
            dispatch(),
            Arc::new(ManualClock::new()),
        )
        .with_plaintext_size(UNIT),
    );
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::with_unit_size(
        set,
        SchedulerConfig {
            // Two single-unit reads reach the target together.
            target_items: 2,
            max_wait: MAX_WAIT,
            ..SchedulerConfig::default()
        },
        clock.clone(),
        UNIT,
    ));

    // Attach makes single-unit calls (key canary, context probes): keep the
    // scheduler's clock moving until it is done, then freeze it.
    let attaching = Arc::new(AtomicBool::new(true));
    let ticker = {
        let attaching = attaching.clone();
        let clock = clock.clone();
        tokio::spawn(async move {
            while attaching.load(Ordering::SeqCst) {
                clock.advance(MAX_WAIT);
                tokio::task::yield_now().await;
            }
        })
    };
    let engine = Engine::attach(
        backing as Arc<dyn Backing>,
        scheduler.clone(),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            clock: Some(Arc::new(ManualClock::new())),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    attaching.store(false, Ordering::SeqCst);
    ticker.await.unwrap();

    let coalesced = scheduler.stats().coalesced_batches_total();
    let read = |offset: u64| {
        let engine = engine.clone();
        tokio::spawn(async move { engine.read(offset, UNIT as usize).await })
    };
    let good = read(0);
    let empty = read(u64::from(UNIT));
    // With the clock frozen, the empty slot's read can finish before the
    // healthy one only if it never waited for a batch partner.
    let empty = tokio::time::timeout(TEST_TIMEOUT, empty)
        .await
        .expect("the empty slot's read never finished")
        .unwrap();
    assert!(empty.is_err(), "an empty ciphertext must not read as data");
    let good = tokio::time::timeout(TEST_TIMEOUT, async {
        while !good.is_finished() {
            clock.advance(MAX_WAIT);
            tokio::task::yield_now().await;
        }
        good.await.unwrap()
    })
    .await
    .expect("the healthy read never finished");
    assert_eq!(
        good.expect("a healthy read failed because it shared a batch with an empty slot"),
        vec![0x31; UNIT as usize]
    );
    assert_eq!(scheduler.stats().coalesced_batches_total(), coalesced);
    engine.stop_checkpoint_worker().await;
}
