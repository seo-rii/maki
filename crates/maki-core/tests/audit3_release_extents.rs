//! Round-3 audit (scope `release-arith`): request-extent checks must refuse
//! wrapping offsets/lengths identically in debug (overflow-checks on) and
//! release (overflow-checks off, the shipped profile). Run in both:
//!
//!   cargo test -p maki-core --locked --test audit3_release_extents
//!   cargo test -p maki-core --release --locked --test audit3_release_extents
//!
//! A refusal that relied on a debug overflow panic would show up here as an
//! accepted request (release) instead of `CoreError::Invalid`.
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::CoreError;
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

const SIZE: u64 = 16 * 1024;

async fn fixture() -> (Arc<CrashableBacking>, Engine) {
    let backing = Arc::new(CrashableBacking::new());
    let sb = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xa3e7),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, SIZE, 8 * 1024).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    init::create_volume_with_discard(backing.as_ref(), sb).unwrap();
    let engine = Engine::attach(
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
    .unwrap();
    (backing, engine)
}

/// (offset, len) pairs whose `offset + len` wraps u64, or that start at /
/// beyond the export end. Every one is block aligned so only the range
/// check can refuse it.
fn hostile_extents() -> Vec<(u64, usize)> {
    let top = u64::MAX - 511; // aligned to 512
    vec![
        (top, 512),
        (top, 1024),
        (u64::MAX - 1023, 2048),
        (SIZE, 512),
        (SIZE - 512, 1024),
        (1 << 63, 512),
        (512, (usize::MAX / 512) * 512),
        (top, (usize::MAX / 512) * 512),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrapping_extents_are_refused_in_every_profile() {
    let (_backing, engine) = fixture().await;
    engine.write(0, &[0x5a; 1024], true).await.unwrap();
    let before = engine.stats().await.appended_sequence;
    for (offset, len) in hostile_extents() {
        let read = engine.read(offset, len).await;
        assert!(
            matches!(read, Err(CoreError::Invalid(_))),
            "read({offset}, {len}) = {:?}",
            read.as_ref().map(|v| v.len())
        );
        let zero = engine.write_zeroes(offset, len, false).await;
        assert!(
            matches!(zero, Err(CoreError::Invalid(_))),
            "write_zeroes({offset}, {len}) = {zero:?}"
        );
        let trim = engine.trim(offset, len, false).await;
        assert!(
            matches!(trim, Err(CoreError::Invalid(_))),
            "trim({offset}, {len}) = {trim:?}"
        );
        if len <= 4096 {
            let data = vec![0xa5; len];
            let write = engine.write(offset, &data, false).await;
            assert!(
                matches!(write, Err(CoreError::Invalid(_))),
                "write({offset}, {len}) = {write:?}"
            );
        }
    }
    // Nothing was journaled and existing data is untouched.
    assert_eq!(engine.stats().await.appended_sequence, before);
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0x5a; 1024]);
    assert_eq!(engine.read(SIZE - 1024, 1024).await.unwrap(), vec![0; 1024]);
}

/// `Engine::admission_cost` is public and unchecked. Every internal caller
/// validates the extent first, so this is not reachable from NBD; the probe
/// only records that the *function itself* behaves differently per profile
/// (debug: overflow panic; release: a wrapped, far too small cost).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_cost_profile_divergence_is_unreachable_but_real() {
    let (_backing, engine) = fixture().await;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        engine.admission_cost(u64::MAX - 511, 1024)
    }));
    match outcome {
        Err(_) => {
            assert!(cfg!(debug_assertions), "only debug traps the overflow");
            eprintln!("admission_cost(u64::MAX-511, 1024): debug overflow panic");
        }
        Ok(cost) => {
            assert!(!cfg!(debug_assertions), "release wraps silently");
            eprintln!("admission_cost(u64::MAX-511, 1024) = {cost} in release");
        }
    }
}
