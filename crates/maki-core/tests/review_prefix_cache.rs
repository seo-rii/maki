use std::sync::Arc;
use std::time::Duration;

use maki_backing::MemBacking;
use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_crypto::RandomPrefixProvider;
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::FakeCryptoProvider;
use uuid::Uuid;

const UNIT: u32 = 4096;
const PREFIX: u32 = 16;

async fn check_working_set(units: u64, budget: u64, retained: u64) {
    let wire = UNIT + PREFIX;
    let provider = Arc::new(
        RandomPrefixProvider::new(
            Arc::new(FakeCryptoProvider::new(wire)),
            UNIT,
            PREFIX,
            "prefix-cache".into(),
        )
        .await
        .unwrap(),
    );
    let backing = Arc::new(MemBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xCACE),
            provider_type: "fake".into(),
            crypto_compatibility_id: "prefix-cache".into(),
            key_identity: "fixture".into(),
            format_version: 1,
            created_unix: 0,
            geometry: Geometry::compute(512, UNIT, 512, wire + 8, 16 << 12, 16 << 12).unwrap(),
        },
    )
    .unwrap();
    let engine = Engine::attach(
        backing,
        provider,
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 1 << 20,
            },
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                ..Default::default()
            },
            cache: Some(EngineCacheConfig {
                max_bytes: budget,
                ttl: Duration::from_secs(3600),
                verify_on_hit: false,
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    for unit in 0..units {
        engine
            .write(
                unit * u64::from(UNIT),
                &vec![unit as u8 + 1; UNIT as usize],
                true,
            )
            .await
            .unwrap();
    }
    engine.checkpoint().await.unwrap();
    let before = engine.stats().await;
    for _ in 0..6 {
        for unit in 0..units {
            let data = engine
                .read(unit * u64::from(UNIT), UNIT as usize)
                .await
                .unwrap();
            assert!(data.iter().all(|&byte| byte == unit as u8 + 1));
        }
    }
    let after = engine.stats().await;
    assert_eq!(after.cache_misses - before.cache_misses, units);
    assert_eq!(after.cache_hits - before.cache_hits, 5 * units);
    assert_eq!(after.cache_entries as u64, units);
    assert_eq!(after.cache_bytes, retained);
    engine.stop_checkpoint_worker().await;
}

#[tokio::test]
async fn logical_unit_budgets_hold_a_full_prefixed_working_set() {
    for units in [1, 4, 8] {
        let budget = units * u64::from(UNIT);
        check_working_set(units, budget, budget).await;
    }
}

#[tokio::test]
async fn cache_with_room_retains_the_decrypted_allocations() {
    let retained = 4 * u64::from(UNIT + PREFIX);
    check_working_set(4, retained, retained).await;
    check_working_set(4, 64 << 20, retained).await;
}
