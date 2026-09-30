//! R5-011 / R5-012: discard must work when it is needed most.
//!
//! R5-011: tombstones were admitted against the emergency reserve *plus*
//! the checkpoint headroom, exactly like writes, so every discard failed
//! with ENOSPC once free space fell below both, although a tombstone
//! carries no payload, its checkpoint writes no slot data, and it is the
//! only way the workload can give space back.
//!
//! R5-012: the "already zero" filter and `discard_ct` read and CRC-checked
//! the whole slot payload, so discarding a damaged unit failed with EIO
//! (a full overwrite of the same unit succeeded), and every discarded unit
//! was read twice under the exclusive volume lock.

use std::sync::Arc;
use std::time::Duration;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

fn geometry() -> Geometry {
    Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap()
}

fn quiet() -> CheckpointPolicy {
    CheckpointPolicy {
        journal_high_watermark_bytes: u64::MAX,
        emergency_reserve_bytes: 0,
        low_space_checkpoint_bytes: 0,
        interval: Duration::from_secs(3600),
        ..Default::default()
    }
}

async fn fixture(policy: CheckpointPolicy) -> (Arc<CrashableBacking>, Engine) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xd15c),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: geometry(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(1024)),
        EngineOptions {
            checkpoint: policy,
            limits: EngineLimits {
                max_request_bytes: 4096,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (backing, engine)
}

#[tokio::test]
async fn a_trim_is_admitted_inside_the_checkpoint_headroom() {
    let mut policy = quiet();
    policy.emergency_reserve_bytes = 1 << 20;
    policy.low_space_checkpoint_bytes = 1 << 20;
    let (backing, engine) = fixture(policy).await;
    backing.set_free_bytes(Some(10 << 20));
    engine.write(0, &[7; 4096], true).await.unwrap();
    engine.write(4096, &[7; 4096], true).await.unwrap();
    engine.checkpoint().await.unwrap();

    // Above the emergency reserve, inside the checkpoint headroom.
    backing.set_free_bytes(Some((2 << 20) - 1));
    assert!(
        engine.write(0, &[8; 1024], false).await.is_err(),
        "a write still needs the checkpoint headroom"
    );
    engine
        .trim(0, 4096, true)
        .await
        .expect("a discard, which frees space, was refused");
    assert_eq!(engine.read(0, 4096).await.unwrap(), vec![0; 4096]);

    // The emergency reserve itself still holds.
    backing.set_free_bytes(Some((1 << 20) - 1));
    engine.write(4096, &[9; 1024], false).await.unwrap_err();
    assert!(engine.trim(4096, 1024, false).await.is_err());
}

async fn damage(backing: &CrashableBacking, unit: u64, offset_in_slot: u64) {
    let file = backing.open(&layout::shard_data(0), false).unwrap();
    file.write_at(geometry().slot_offset(unit) + offset_in_slot, &[0xAA; 8])
        .unwrap();
    file.sync_data().unwrap();
}

#[tokio::test]
async fn a_unit_with_a_damaged_payload_can_be_discarded() {
    let (backing, engine) = fixture(quiet()).await;
    engine.write(0, &[7; 2048], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    damage(&backing, 0, 64 + 10).await;
    assert!(engine.read(0, 1024).await.is_err(), "the damage is visible");

    engine
        .trim(0, 1024, true)
        .await
        .expect("discarding a damaged unit must retire it, not fail with EIO");
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0; 1024]);
    engine.checkpoint().await.unwrap();
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0; 1024]);
    assert_eq!(
        engine.read(1024, 1024).await.unwrap(),
        vec![7; 1024],
        "the neighbour is untouched"
    );
}

#[tokio::test]
async fn a_unit_with_a_damaged_header_can_be_discarded() {
    let (backing, engine) = fixture(quiet()).await;
    engine.write(0, &[7; 1024], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    damage(&backing, 0, 8).await;
    assert!(engine.read(0, 1024).await.is_err(), "the damage is visible");

    engine.trim(0, 1024, true).await.unwrap();
    engine.checkpoint().await.unwrap();
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0; 1024]);
}
