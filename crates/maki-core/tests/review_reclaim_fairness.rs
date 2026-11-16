//! Inline reclaim must keep what it frees for the write that ran it.
//!
//! Configuration validation sizes `backing.journal_max_bytes` and
//! `limits.max_overlay_bytes` so that one maximal request (`nbd.maximum_io`
//! plus one unit of misalignment) always fits after an inline checkpoint. A
//! write over either bound syncs, releases the volume lock, checkpoints and
//! retries admission. Other admitted writers used to take the volume lock
//! first and append into the space that reclaim had just freed, so after a
//! bounded number of rounds the write failed with ENOSPC ("... cannot be
//! reclaimed") although nothing failed and the journal or overlay was
//! reclaimable throughout. On a kernel NBD device that is a write I/O error
//! for the filesystem.
//!
//! Each test runs several concurrent writers of maximal, misaligned requests
//! against bounds at their validated minimum, with no injected faults: no
//! write may fail, the bounds must hold, and every writer's last data must
//! read back.

use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::{geometry::Geometry, init, journal, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

const UNIT: u64 = 1024;
const MAX_CT: u64 = UNIT + 8;
const BLOCK: u64 = 512;
/// `nbd.maximum_io`; a request at a half-unit offset touches nine units.
const MAX_IO: u64 = 8 * UNIT;
const UNITS_PER_WRITER: u64 = 10;
/// The smallest segment size configuration validation accepts.
const SEGMENT: u64 = 4096;
const WRITERS: u64 = 8;
const WRITES_PER_WRITER: u64 = 60;
const VOLUMES: u64 = 3;

/// Crypto units one maximal request can touch, as validation computes it.
fn units_per_request() -> u64 {
    MAX_IO.div_ceil(UNIT) + 1
}

/// The smallest `journal_max_bytes` validation accepts for this geometry.
fn minimum_journal_bytes() -> u64 {
    journal::minimum_journal_limit(
        SEGMENT,
        journal::max_record_len(MAX_CT as u32),
        units_per_request(),
    )
    .unwrap()
}

/// The smallest nonzero `max_overlay_bytes` validation accepts.
fn minimum_overlay_bytes() -> u64 {
    2 * units_per_request() * MAX_CT
}

async fn engine(volume: u64, journal_max: u64, overlay_max: u64) -> Engine {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xFA1E_0000 + volume as u128),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                BLOCK as u32,
                UNIT as u32,
                512,
                MAX_CT as u32,
                WRITERS * UNITS_PER_WRITER * UNIT,
                8 * UNIT,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    Engine::attach(
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
                // Only the write path and the watermark checkpoint.
                interval: Duration::from_secs(3600),
            },
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

fn stamp(writer: u64, write: u64) -> u8 {
    (writer * WRITES_PER_WRITER + write) as u8 | 1
}

/// Run every writer to completion on fresh volumes; return the failures.
async fn concurrent_maximal_writes(journal_max: u64, overlay_max: u64) -> Vec<String> {
    let mut failures = Vec::new();
    for volume in 0..VOLUMES {
        let engine = engine(volume, journal_max, overlay_max).await;
        let mut writers = Vec::new();
        for writer in 0..WRITERS {
            let engine = engine.clone();
            writers.push(tokio::spawn(async move {
                let offset = writer * UNITS_PER_WRITER * UNIT + BLOCK;
                let mut failures = Vec::new();
                for write in 0..WRITES_PER_WRITER {
                    let data = vec![stamp(writer, write); MAX_IO as usize];
                    if let Err(error) = engine.write(offset, &data, false).await {
                        failures.push(format!(
                            "volume {volume} writer {writer} write {write}: {error}"
                        ));
                    }
                }
                failures
            }));
        }
        for writer in writers {
            failures.extend(writer.await.unwrap());
        }
        let stats = engine.stats().await;
        assert!(
            stats.journal_total_bytes <= journal_max,
            "journal {} over its limit {journal_max}",
            stats.journal_total_bytes
        );
        if overlay_max > 0 {
            assert!(
                stats.overlay_bytes <= overlay_max,
                "overlay {} over its limit {overlay_max}",
                stats.overlay_bytes
            );
        }
        if failures.is_empty() {
            for writer in 0..WRITERS {
                let offset = writer * UNITS_PER_WRITER * UNIT + BLOCK;
                assert_eq!(
                    engine.read(offset, MAX_IO as usize).await.unwrap(),
                    vec![stamp(writer, WRITES_PER_WRITER - 1); MAX_IO as usize],
                    "volume {volume} writer {writer} lost its last write"
                );
            }
        }
        engine.stop_checkpoint_worker().await;
    }
    failures
}

fn report(failures: &[String], bound: &str) {
    assert!(
        failures.is_empty(),
        "{} of {} maximal writes from {WRITERS} concurrent writers failed with {bound} at its \
         validated minimum and nothing injected; first: {}",
        failures.len(),
        VOLUMES * WRITERS * WRITES_PER_WRITER,
        failures[0]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_never_take_space_an_inline_journal_reclaim_freed() {
    let failures = concurrent_maximal_writes(minimum_journal_bytes(), 0).await;
    report(&failures, "the journal limit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_never_take_space_an_inline_overlay_reclaim_freed() {
    let failures = concurrent_maximal_writes(1 << 30, minimum_overlay_bytes()).await;
    report(&failures, "the overlay limit");
}
