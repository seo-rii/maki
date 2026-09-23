//! R4-006: a plaintext-cache hit must skip the ciphertext payload read, not
//! only the decryption.
//!
//! The read path used to call `read_ct` (slot header, full ciphertext,
//! CRC) *before* consulting the cache, so a hit only saved the provider
//! call. Now the current version is established first — overlay sequence,
//! or the 64-byte slot header — and a hit for `(unit, sequence)` serves the
//! cached plaintext without reading the payload. Versioning stays exact:
//! a newer write changes the sequence and misses. What a hit no longer does
//! is re-verify the on-disk payload CRC of an already validated version
//! until the entry is evicted, which is documented.
#![allow(clippy::await_holding_lock)]

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_core::CoreError;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{failpoints, CrashableBacking};

const UNIT: u32 = 1024;
const UNITS: u64 = 64;
const CT: u64 = UNIT as u64 + 8;

fn geometry() -> Geometry {
    Geometry::compute(512, UNIT, 512, UNIT + 8, UNITS * UNIT as u64, 16 * UNIT as u64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xCAC4),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn engine(
    backing: &Arc<CrashableBacking>,
    provider: Arc<FakeCryptoProvider>,
    cache: bool,
) -> Engine {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        provider,
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 8192,
            },
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: u64::MAX,
                journal_max_bytes: 64 << 20,
                max_pending_bytes: 64 << 20,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
            },
            cache: cache.then(|| EngineCacheConfig {
                max_bytes: 64 * UNIT as u64,
                ttl: Duration::from_secs(3600),
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

fn off(unit: u64) -> u64 {
    unit * UNIT as u64
}

fn data(stamp: u8) -> Vec<u8> {
    vec![stamp; UNIT as usize]
}

fn damage(backing: &CrashableBacking, unit: u64, header: bool) {
    let g = geometry();
    let (shard, idx) = g.shard_of_unit(unit);
    let file = backing.open(&layout::shard_data(shard), false).unwrap();
    // Header: unit_index field is bytes 0..8 of the 64-byte header (a
    // different unit); payload: a few bytes past the header.
    let offset = g.slot_offset(idx) + if header { 0 } else { 64 + 17 };
    file.write_at(offset, &[0xEE; 8]).unwrap();
    file.sync_data().unwrap();
}

#[tokio::test]
async fn a_cache_hit_reads_only_the_slot_header_from_the_backing() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine(&backing, provider.clone(), true).await;
    engine.write(off(3), &data(0x33), true).await.unwrap();
    engine.checkpoint().await.unwrap(); // unit 3 lives in a slot now

    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x33));
    let decrypts = provider.decrypt_calls();
    let before = backing.read_bytes();
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x33));
    let read = backing.read_bytes() - before;
    assert_eq!(
        provider.decrypt_calls(),
        decrypts,
        "the second read must be served from the cache"
    );
    assert!(
        read <= 64,
        "a cache hit must read at most the 64-byte slot header, read {read} bytes \
         (ciphertext is {CT} bytes)"
    );
    assert!(read > 0, "the current version must still be established from the header");
}

#[tokio::test]
async fn an_overlay_hit_reads_nothing_from_the_backing() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine(&backing, provider.clone(), true).await;
    engine.write(off(5), &data(0x55), false).await.unwrap(); // stays in the overlay
    assert_eq!(engine.read(off(5), UNIT as usize).await.unwrap(), data(0x55));
    let before = backing.read_bytes();
    let decrypts = provider.decrypt_calls();
    assert_eq!(engine.read(off(5), UNIT as usize).await.unwrap(), data(0x55));
    assert_eq!(backing.read_bytes(), before);
    assert_eq!(provider.decrypt_calls(), decrypts);
}

#[tokio::test]
async fn a_newer_version_misses_the_cache_and_is_decrypted_again() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine(&backing, provider.clone(), true).await;
    engine.write(off(3), &data(0x33), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x33));
    let decrypts = provider.decrypt_calls();

    // Overwrite through both paths: overlay first, then checkpointed slot.
    engine.write(off(3), &data(0x34), true).await.unwrap();
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x34));
    assert_eq!(provider.decrypt_calls(), decrypts + 1);
    engine.checkpoint().await.unwrap();
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x34));
    engine.write(off(3), &data(0x35), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x35));
    assert_eq!(provider.decrypt_calls(), decrypts + 2);
}

#[tokio::test]
async fn unwritten_units_and_zero_reads_do_not_touch_the_cache_version_path_incorrectly() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine(&backing, provider.clone(), true).await;
    engine.write(off(3), &data(0x33), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    // A range spanning a written and an unwritten unit.
    let out = engine.read(off(3), 2 * UNIT as usize).await.unwrap();
    assert_eq!(&out[..UNIT as usize], &data(0x33)[..]);
    assert!(out[UNIT as usize..].iter().all(|b| *b == 0));
    let out = engine.read(off(3), 2 * UNIT as usize).await.unwrap();
    assert_eq!(&out[..UNIT as usize], &data(0x33)[..]);
    assert!(out[UNIT as usize..].iter().all(|b| *b == 0));
}

#[tokio::test]
async fn a_damaged_slot_header_is_eio_even_with_a_cached_plaintext() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine(&backing, provider.clone(), true).await;
    engine.write(off(3), &data(0x33), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x33));
    damage(&backing, 3, true);
    let result = engine.read(off(3), UNIT as usize).await;
    assert!(
        matches!(result, Err(CoreError::Corrupt(_))),
        "a header that no longer identifies the unit must not be papered over by the cache: {result:?}"
    );
}

/// The documented trade-off: a hit for the current version does not re-read
/// the payload, so payload-only damage under a valid header is served from
/// the cache until the entry is evicted; the offline deep check still finds
/// it, and eviction restores EIO.
#[tokio::test]
async fn payload_damage_under_a_valid_header_is_served_from_cache_until_eviction() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine(&backing, provider.clone(), true).await;
    engine.write(off(3), &data(0x33), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x33));
    damage(&backing, 3, false);
    assert_eq!(
        engine.read(off(3), UNIT as usize).await.unwrap(),
        data(0x33),
        "the cached, previously verified plaintext of the same version is served"
    );
    assert!(engine.resize_cache(0), "cache is enabled");
    let result = engine.read(off(3), UNIT as usize).await;
    assert!(
        matches!(result, Err(CoreError::Corrupt(_))),
        "after eviction the payload is re-read and its CRC failure is EIO: {result:?}"
    );
}

#[tokio::test]
async fn without_a_cache_every_read_still_reads_and_verifies_the_payload() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine(&backing, provider.clone(), false).await;
    engine.write(off(3), &data(0x33), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x33));
    let before = backing.read_bytes();
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), data(0x33));
    assert!(backing.read_bytes() - before >= 64 + CT);
    damage(&backing, 3, false);
    assert!(matches!(
        engine.read(off(3), UNIT as usize).await,
        Err(CoreError::Corrupt(_))
    ));
}
