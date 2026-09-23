//! Opt-in discard integrates request bounds, unit ordering, cache visibility
//! and the same FLUSH/FUA durability contract as ordinary writes.
use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};
use rand::SeedableRng;

async fn attach(backing: &Arc<CrashableBacking>) -> Engine {
    Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(1024)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: u64::MAX,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

async fn fixture(discard: bool) -> (Arc<CrashableBacking>, Engine) {
    let backing = Arc::new(CrashableBacking::new());
    let sb = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xd15c),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), sb).unwrap();
    } else {
        init::create_volume(backing.as_ref(), sb).unwrap();
    }
    let engine = attach(&backing).await;
    (backing, engine)
}

#[tokio::test]
async fn legacy_volume_rejects_trim_without_changing_data() {
    let (_backing, engine) = fixture(false).await;
    assert!(!engine.can_trim());
    engine.write(0, &[0x31; 1024], true).await.unwrap();
    assert!(engine.trim(0, 1024, true).await.is_err());
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0x31; 1024]);
    assert_eq!(engine.stats().await.appended_sequence, 1);
}

#[tokio::test]
async fn trim_preserves_partial_unit_edges_and_survives_fua_crash() {
    let (backing, engine) = fixture(true).await;
    assert!(engine.can_trim());
    let mut expected = Vec::new();
    for value in [0x11, 0x22, 0x33, 0x44] {
        expected.extend_from_slice(&[value; 1024]);
    }
    engine.write(0, &expected, true).await.unwrap();
    engine.checkpoint().await.unwrap();
    // Populate any configured read cache before discarding the middle units.
    assert_eq!(engine.read(0, 4096).await.unwrap(), expected);
    engine.trim(512, 3072, true).await.unwrap();
    expected[1024..3072].fill(0);
    assert_eq!(engine.read(0, 4096).await.unwrap(), expected);
    drop(engine);
    backing.crash(&mut rand::rngs::StdRng::seed_from_u64(9));
    let recovered = attach(&backing).await;
    assert_eq!(recovered.read(0, 4096).await.unwrap(), expected);
    recovered.write(1024, &[0x55; 1024], true).await.unwrap();
    recovered.checkpoint().await.unwrap();
    expected[1024..2048].fill(0x55);
    drop(recovered);
    backing.crash(&mut rand::rngs::StdRng::seed_from_u64(10));
    assert_eq!(
        attach(&backing).await.read(0, 4096).await.unwrap(),
        expected
    );
}

#[tokio::test]
async fn trimming_unwritten_units_and_partial_edges_does_not_append() {
    let (_backing, engine) = fixture(true).await;
    engine.trim(0, 16 * 1024, true).await.unwrap();
    assert_eq!(engine.stats().await.appended_sequence, 0);
    engine.write(0, &[0x67; 1024], true).await.unwrap();
    engine.trim(512, 512, false).await.unwrap();
    assert_eq!(engine.stats().await.appended_sequence, 1);
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0x67; 1024]);
    for (offset, len) in [(1, 1024), (0, 0), (0, 513), (16 * 1024, 512)] {
        assert!(engine.trim(offset, len, true).await.is_err());
    }
    assert_eq!(engine.stats().await.appended_sequence, 1);
}

#[tokio::test]
async fn concurrent_trim_and_write_have_whole_unit_ordering() {
    let (backing, engine) = fixture(true).await;
    engine.write(0, &[0x31; 1024], true).await.unwrap();
    let (trim, write) = tokio::join!(
        engine.trim(0, 1024, true),
        engine.write(0, &[0x77; 1024], true)
    );
    trim.unwrap();
    write.unwrap();
    let expected = engine.read(0, 1024).await.unwrap();
    assert!(expected == vec![0; 1024] || expected == vec![0x77; 1024]);
    engine.checkpoint().await.unwrap();
    drop(engine);
    backing.crash(&mut rand::rngs::StdRng::seed_from_u64(11));
    assert_eq!(
        attach(&backing).await.read(0, 1024).await.unwrap(),
        expected
    );
}
