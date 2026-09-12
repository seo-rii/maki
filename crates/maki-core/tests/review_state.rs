//! Fourth audit pass: the engine's reported state and its SPEC §40
//! counters.
//!
//! - A journal whose sync failed, and has not been rewritten and synced
//!   since, is a degraded volume (SPEC §26 wants persistence failures
//!   visible), whatever the checkpoint state says; a later successful
//!   barrier clears it, a successful checkpoint does not.
//! - `maki_active_callbacks`, `maki_plaintext_bytes`, `maki_flush_seconds`
//!   and `maki_fua_seconds` come from the engine.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 4096;
const DEVICE_SIZE: u64 = 64 * UNIT as u64;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x5747),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, DEVICE_SIZE, 16 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn engine(backing: &Arc<CrashableBacking>) -> Engine {
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

fn is_segment(path: &str) -> bool {
    path.starts_with(&format!("{}/", layout::JOURNAL_DIR))
        && layout::parse_journal_segment(path.rsplit('/').next().unwrap_or("")).is_some()
}

/// Fail the next `n` `sync_data` calls on journal segments.
fn fail_segment_syncs(backing: &CrashableBacking, n: usize) {
    let remaining = Arc::new(AtomicUsize::new(n));
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if is_segment(path) => {
            let left = remaining.load(Ordering::SeqCst);
            if left > 0 {
                remaining.store(left - 1, Ordering::SeqCst);
                Some(io::Error::other("injected writeback error"))
            } else {
                None
            }
        }
        _ => None,
    })));
}

#[tokio::test]
async fn a_failed_journal_sync_degrades_the_volume_until_a_barrier_succeeds() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = engine(&backing).await;
    engine.write(0, &[1u8; UNIT as usize], false).await.unwrap();
    assert_eq!(engine.state(), EngineState::Ready);

    fail_segment_syncs(&backing, 1);
    assert!(engine.flush().await.is_err());
    let state = engine.state();
    assert!(
        matches!(&state, EngineState::Degraded { reason } if reason.contains("journal sync")),
        "{state:?}"
    );
    let stats = engine.stats().await;
    assert!(matches!(stats.state, EngineState::Degraded { .. }));
    assert!(stats.journal_writeback_uncertain);
    assert_eq!(stats.journal_sync_failures_total, 1);
    assert_eq!(
        stats.flush_latency.count, 0,
        "a failed barrier is not a latency sample"
    );

    // A checkpoint consumes only durable records and can succeed while the
    // journal still cannot be synced: it must not report the volume ready.
    engine.checkpoint().await.unwrap();
    assert!(matches!(engine.state(), EngineState::Degraded { .. }));

    // The barrier that rewrites and syncs clears it.
    engine.flush().await.unwrap();
    assert_eq!(engine.state(), EngineState::Ready);
    let stats = engine.stats().await;
    assert!(!stats.journal_writeback_uncertain);
    assert_eq!(stats.journal_sync_failures_total, 1);
    assert_eq!(stats.flush_latency.count, 1);

    // A FUA write that fails its sync degrades it again.
    fail_segment_syncs(&backing, 1);
    assert!(engine
        .write(UNIT as u64, &[2u8; UNIT as usize], true)
        .await
        .is_err());
    assert!(matches!(engine.state(), EngineState::Degraded { .. }));
    engine
        .write(2 * UNIT as u64, &[3u8; UNIT as usize], true)
        .await
        .unwrap();
    assert_eq!(engine.state(), EngineState::Ready);
}

#[tokio::test]
async fn admission_usage_and_barrier_latencies_are_reported() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = engine(&backing).await;
    for i in 0..3u64 {
        engine
            .write(i * UNIT as u64, &[i as u8; UNIT as usize], true)
            .await
            .unwrap();
    }
    engine.flush().await.unwrap();
    engine.flush().await.unwrap();
    let stats = engine.stats().await;
    assert_eq!(stats.fua_latency.count, 3);
    assert_eq!(stats.flush_latency.count, 2);
    assert!(stats.fua_latency.seconds_max >= 0.0);
    assert!(stats.flush_latency.seconds_sum >= 0.0);
    assert_eq!(stats.active_callbacks, 0, "nothing in flight when idle");
    assert_eq!(stats.plaintext_bytes_in_flight, 0);
}
