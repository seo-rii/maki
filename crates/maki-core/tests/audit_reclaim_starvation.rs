//! Audit (core write path): the configuration validator sizes
//! `backing.journal_max_bytes` (and `limits.max_overlay_bytes`) so that ONE
//! maximal request always fits after an inline reclaim. Admission, however,
//! is not reserved across the reclaim: other admitted writers append into the
//! space the reclaim just freed, and after `MAX_RECLAIM_ROUNDS` (4) the
//! waiting write fails with ENOSPC ("... cannot be reclaimed") although the
//! journal/overlay is reclaimable and nothing failed. With a validated
//! configuration and only a handful of concurrent writers (far below
//! `max_active_callbacks`), ordinary writes fail with ENOSPC; on a kernel NBD
//! device that is a write I/O error to the filesystem.
//!
//! Knobs: `AUDIT_JOURNAL_MULT` / `AUDIT_OVERLAY_MULT` scale the bound over the
//! validated minimum, `AUDIT_WRITERS` sets the writer count (default 6).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::{geometry::Geometry, init, journal, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

const UNIT: u64 = 1024;
const MAX_CT: u64 = UNIT + 8;
const MAX_IO: u64 = 8 * 1024;
const UNITS_PER_WRITER: u64 = 8;
const SEGMENT: u64 = 4096; // the smallest segment size validation accepts

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn units_per_request() -> u64 {
    MAX_IO.div_ceil(UNIT) + 1
}

/// Returns (ENOSPC failures, writes).
async fn run(journal_max: u64, overlay_max: u64, writers: u64) -> (u64, u64) {
    let mut failures = 0u64;
    let mut writes = 0u64;
    for round in 0..10u64 {
        let backing = Arc::new(CrashableBacking::new());
        init::create_volume(
            backing.as_ref(),
            Superblock {
                generation: 0,
                volume_uuid: uuid::Uuid::from_u128(0xa0d1_5a7f + round as u128),
                provider_type: "fake".into(),
                crypto_compatibility_id: "test-profile-v1".into(),
                key_identity: "k".into(),
                geometry: Geometry::compute(
                    512,
                    UNIT as u32,
                    512,
                    MAX_CT as u32,
                    writers * UNITS_PER_WRITER * UNIT,
                    8 * 1024,
                )
                .unwrap(),
                format_version: 1,
                created_unix: 0,
            },
        )
        .unwrap();
        let engine = Engine::attach(
            backing,
            Arc::new(FakeCryptoProvider::new(UNIT as u32)),
            EngineOptions {
                volume: VolumeOptions {
                    journal_segment_size: SEGMENT,
                },
                limits: EngineLimits {
                    max_active_callbacks: 64,
                    max_plaintext_bytes: 1 << 20,
                    max_request_bytes: MAX_IO,
                    max_overlay_bytes: overlay_max,
                    max_overlay_entries: 0,
                },
                checkpoint: CheckpointPolicy {
                    journal_high_watermark_bytes: journal_max / 2,
                    journal_max_bytes: journal_max,
                    max_pending_bytes: 4096,
                    emergency_reserve_bytes: 0,
                    low_space_checkpoint_bytes: 0,
                    interval: Duration::from_secs(3600),
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let enospc = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();
        for w in 0..writers {
            let engine = engine.clone();
            let enospc = enospc.clone();
            tasks.push(tokio::spawn(async move {
                let data = vec![w as u8 + 1; MAX_IO as usize];
                for _ in 0..100 {
                    match engine
                        .write(w * UNITS_PER_WRITER * UNIT, &data, false)
                        .await
                    {
                        Ok(()) => {}
                        Err(e) if e.to_string().contains("cannot be reclaimed") => {
                            enospc.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(e) => panic!("unexpected error: {e}"),
                    }
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        writes += writers * 100;
        failures += enospc.load(Ordering::SeqCst);
        engine.stop_checkpoint_worker().await;
    }
    (failures, writes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_starve_an_inline_journal_reclaim_into_enospc() {
    let record = journal::max_record_len(MAX_CT as u32);
    let multiplier = env("AUDIT_JOURNAL_MULT", 1);
    // Exactly the minimum `validate_journal_bounds` accepts for this geometry.
    let journal_max =
        journal::minimum_journal_limit(SEGMENT, record, units_per_request()).unwrap() * multiplier;
    let writers = env("AUDIT_WRITERS", 6);
    eprintln!("journal_max_bytes = {journal_max} ({multiplier} x the validated minimum)");
    let (failures, writes) = run(journal_max, 0, writers).await;
    eprintln!("{failures} of {writes} maximal writes failed with ENOSPC");
    assert_eq!(
        failures, 0,
        "{failures} of {writes} writes from {writers} concurrent writers got ENOSPC with a \
         validated journal limit and a reclaimable journal"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_starve_an_inline_overlay_reclaim_into_enospc() {
    let multiplier = env("AUDIT_OVERLAY_MULT", 1);
    // Exactly the minimum `limits.max_overlay_bytes` validation accepts:
    // twice (maximum_io / unit + 1) units of max ciphertext.
    let overlay_max = 2 * units_per_request() * MAX_CT * multiplier;
    let writers = env("AUDIT_WRITERS", 6);
    eprintln!("max_overlay_bytes = {overlay_max} ({multiplier} x the validated minimum)");
    let (failures, writes) = run(1 << 30, overlay_max, writers).await;
    eprintln!("{failures} of {writes} maximal writes failed with ENOSPC");
    assert_eq!(
        failures, 0,
        "{failures} of {writes} writes from {writers} concurrent writers got ENOSPC with a \
         validated overlay limit and a reclaimable overlay"
    );
}
