//! Phase 10 — engine-level cache behavior, growth, and metrics (SPEC §52).

use std::io;
use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{Engine, EngineCacheConfig, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::failpoints;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 1024;
// Small shards so growth creates many.
const SHARD: u64 = 8 * UNIT as u64;
const DEVICE_SIZE: u64 = 256 * UNIT as u64;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xCA),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, DEVICE_SIZE, SHARD).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn engine_with_cache(
    backing: &Arc<CrashableBacking>,
    provider: Arc<FakeCryptoProvider>,
    cache: Option<EngineCacheConfig>,
) -> Engine {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        provider,
        EngineOptions {
            volume: VolumeOptions::default(),
            cache,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

fn read_cache() -> Option<EngineCacheConfig> {
    Some(EngineCacheConfig {
        max_bytes: 1 << 20,
        ttl: std::time::Duration::from_secs(30),
    })
}

// ---------- versioned cache behavior ----------

#[tokio::test]
async fn cached_reads_skip_the_provider() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider.clone(), read_cache()).await;

    engine.write(0, &vec![0x42; UNIT as usize], false).await.unwrap();
    let calls_after_write = provider.decrypt_calls();
    let first = engine.read(0, UNIT as usize).await.unwrap();
    let calls_after_first = provider.decrypt_calls();
    assert!(calls_after_first > calls_after_write, "first read decrypts");
    let second = engine.read(0, UNIT as usize).await.unwrap();
    assert_eq!(first, second);
    assert_eq!(
        provider.decrypt_calls(),
        calls_after_first,
        "second read must be served from cache"
    );
    let stats = engine.stats().await;
    assert!(stats.cache_hits >= 1, "cache hit recorded");
}

// ---------- stale-read prevention ----------

#[tokio::test]
async fn overwrite_invalidates_cached_plaintext() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider.clone(), read_cache()).await;

    engine.write(0, &vec![0xA1; UNIT as usize], false).await.unwrap();
    assert_eq!(engine.read(0, UNIT as usize).await.unwrap(), vec![0xA1; UNIT as usize]);
    // Overwrite: any cached plaintext for the old version must be dead.
    engine.write(0, &vec![0xB2; UNIT as usize], false).await.unwrap();
    assert_eq!(
        engine.read(0, UNIT as usize).await.unwrap(),
        vec![0xB2; UNIT as usize],
        "stale read = 0"
    );
    // Partial overwrite (RMW) too.
    engine.write(0, &vec![0xC3; 512], false).await.unwrap();
    let got = engine.read(0, UNIT as usize).await.unwrap();
    assert_eq!(&got[..512], &vec![0xC3; 512][..]);
    assert_eq!(&got[512..], &vec![0xB2; 512][..]);
}

/// Racing reads and writes on one unit never yield stale or torn plaintext.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_read_write_with_cache_never_stale() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider, read_cache()).await;
    let off = 3 * UNIT as u64;
    engine.write(off, &vec![0; UNIT as usize], false).await.unwrap();

    let writer = {
        let engine = engine.clone();
        tokio::spawn(async move {
            for i in 1..=40u8 {
                engine.write(off, &vec![i; UNIT as usize], false).await.unwrap();
            }
        })
    };
    let reader = {
        let engine = engine.clone();
        tokio::spawn(async move {
            let mut max_seen = 0u8;
            for _ in 0..200 {
                let got = engine.read(off, UNIT as usize).await.unwrap();
                let first = got[0];
                assert!(got.iter().all(|b| *b == first), "torn read");
                assert!(first >= max_seen, "went backwards: stale cached read");
                max_seen = first;
            }
        })
    };
    writer.await.unwrap();
    reader.await.unwrap();
}

// ---------- cache disabled ----------

#[tokio::test]
async fn cache_off_decrypts_every_read() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider.clone(), None).await;
    engine.write(0, &vec![0x10; UNIT as usize], false).await.unwrap();
    let base = provider.decrypt_calls();
    engine.read(0, UNIT as usize).await.unwrap();
    engine.read(0, UNIT as usize).await.unwrap();
    assert_eq!(provider.decrypt_calls(), base + 2, "no caching in off mode");
    assert_eq!(engine.stats().await.cache_hits, 0);
}

// ---------- runtime resize ----------

#[tokio::test]
async fn cache_resize_at_runtime() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider.clone(), read_cache()).await;
    for i in 0..4u64 {
        engine
            .write(i * UNIT as u64, &vec![i as u8; UNIT as usize], false)
            .await
            .unwrap();
        engine.read(i * UNIT as u64, UNIT as usize).await.unwrap();
    }
    assert!(engine.stats().await.cache_bytes > 0);
    engine.resize_cache(0); // hot resize to zero = disable
    assert_eq!(engine.stats().await.cache_bytes, 0);
    let base = provider.decrypt_calls();
    engine.read(0, UNIT as usize).await.unwrap();
    assert_eq!(provider.decrypt_calls(), base + 1, "no cache after resize to 0");
    engine.resize_cache(1 << 20);
    engine.read(0, UNIT as usize).await.unwrap(); // repopulates
    let base = provider.decrypt_calls();
    engine.read(0, UNIT as usize).await.unwrap();
    assert_eq!(provider.decrypt_calls(), base, "cache active again");
}

// ---------- online growth (SPEC §38, §52) ----------

/// Growth during workload: the virtual device is fixed-size; "growth" is
/// writes reaching previously untouched regions, creating shards on demand
/// while other I/O continues.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn growth_during_workload_creates_shards_consistently() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider, None).await;

    // Steady workload in shard 0 while a "grower" walks into fresh shards.
    let steady = {
        let engine = engine.clone();
        tokio::spawn(async move {
            for i in 0..60u8 {
                engine.write(0, &vec![i; UNIT as usize], false).await.unwrap();
            }
        })
    };
    let grower = {
        let engine = engine.clone();
        tokio::spawn(async move {
            for unit in (8..248u64).step_by(8) {
                engine
                    .write(unit * UNIT as u64, &vec![0x77; UNIT as usize], false)
                    .await
                    .unwrap();
            }
        })
    };
    steady.await.unwrap();
    grower.await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap();

    for unit in (8..248u64).step_by(8) {
        assert_eq!(
            engine.read(unit * UNIT as u64, UNIT as usize).await.unwrap(),
            vec![0x77; UNIT as usize],
            "unit {unit} lost during growth"
        );
    }
}

/// Crash during growth: a failure mid shard-creation (data file created but
/// catalog not yet committed) must recover to a consistent volume with no
/// data loss for durable writes.
#[tokio::test]
async fn crash_during_shard_creation_recovers() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider, None).await;

    // Durable write in shard 0, checkpointed.
    engine.write(0, &vec![0x01; UNIT as usize], true).await.unwrap();
    engine.checkpoint().await.unwrap();

    // Write into a fresh shard, FUA (durable in journal), then make the
    // checkpoint fail at the catalog-commit boundary and crash.
    let far = 100 * UNIT as u64; // shard 12
    engine.write(far, &vec![0x02; UNIT as usize], true).await.unwrap();
    let fp = failpoints::set(
        "store.catalog_store",
        failpoints::FailpointAction::IoError(io::ErrorKind::Other, "crash during growth".to_string()),
    );
    assert!(engine.checkpoint().await.is_err(), "checkpoint must fail");
    drop(fp);
    drop(engine);
    backing.crash_all_lost();

    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider, None).await;
    assert_eq!(engine.read(0, UNIT as usize).await.unwrap(), vec![0x01; UNIT as usize]);
    assert_eq!(
        engine.read(far, UNIT as usize).await.unwrap(),
        vec![0x02; UNIT as usize],
        "FUA write must survive interrupted growth (journal is authoritative)"
    );
    // And the retried checkpoint completes.
    engine.checkpoint().await.unwrap();
    drop(engine);
    backing.crash_all_lost();
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider, None).await;
    assert_eq!(engine.read(far, UNIT as usize).await.unwrap(), vec![0x02; UNIT as usize]);
}

// ---------- metrics ----------

#[tokio::test]
async fn stats_expose_required_metrics_inputs() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with_cache(&backing, provider, read_cache()).await;
    engine.write(0, &vec![1; UNIT as usize], false).await.unwrap();
    engine.read(0, UNIT as usize).await.unwrap();
    engine.read(0, UNIT as usize).await.unwrap();
    engine.flush().await.unwrap();
    let stats = engine.stats().await;
    assert!(stats.appended_sequence >= 1);
    assert_eq!(stats.durable_sequence, stats.appended_sequence);
    assert!(stats.overlay_units >= 1);
    assert!(stats.cache_hits >= 1);
    assert!(stats.cache_misses >= 1);
    let ck = engine.checkpoint().await.unwrap();
    assert_eq!(engine.stats().await.checkpoint_sequence, ck);
}
