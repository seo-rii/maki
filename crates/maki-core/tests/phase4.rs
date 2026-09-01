//! Phase 4 — Block Core (SPEC §28, §46).
//!
//! The engine (plaintext, byte-addressed) is exercised against reference
//! models: a plain byte array for live differential testing, and the
//! Phase-0 durability oracle for crash cases.

use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{AttachError, Engine, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const BLOCK: u32 = 512;
const UNIT: u32 = 2048;
const DEVICE_SIZE: u64 = 1024 * UNIT as u64; // 1 MiB, 1024 units

fn geometry() -> Geometry {
    Geometry::compute(BLOCK, UNIT, 512, UNIT + 8, DEVICE_SIZE, 64 * UNIT as u64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x44),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn provider() -> Arc<FakeCryptoProvider> {
    Arc::new(FakeCryptoProvider::new(UNIT))
}

async fn new_engine(backing: &Arc<CrashableBacking>) -> Engine {
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    attach(backing).await.unwrap()
}

async fn attach(backing: &Arc<CrashableBacking>) -> Result<Engine, AttachError> {
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        provider(),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 1 << 20,
            },
            ..Default::default()
        },
    )
    .await
}

// ---------- zero read ----------

#[tokio::test]
async fn zero_read_everywhere_on_fresh_volume() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    assert_eq!(engine.size(), DEVICE_SIZE);
    for (off, len) in [(0u64, 512usize), (512, 1024), (DEVICE_SIZE - 4096, 4096)] {
        let data = engine.read(off, len).await.unwrap();
        assert!(data.iter().all(|b| *b == 0), "fresh read must be zeros");
        assert_eq!(data.len(), len);
    }
}

// ---------- read/write ----------

#[tokio::test]
async fn write_then_read_roundtrip() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    let data = vec![0xAB; UNIT as usize];
    engine.write(2048, &data, false).await.unwrap();
    assert_eq!(engine.read(2048, UNIT as usize).await.unwrap(), data);
    // neighbors untouched
    assert!(engine
        .read(2048 - 512, 512)
        .await
        .unwrap()
        .iter()
        .all(|b| *b == 0));
}

#[tokio::test]
async fn alignment_and_bounds_are_enforced() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    assert!(engine.read(1, 512).await.is_err(), "unaligned offset");
    assert!(engine.read(0, 100).await.is_err(), "unaligned length");
    assert!(engine.read(DEVICE_SIZE, 512).await.is_err(), "past end");
    assert!(engine
        .write(DEVICE_SIZE - 512, &[0u8; 1024], false)
        .await
        .is_err());
    assert!(engine.read(0, 0).await.is_err(), "zero length");
}

// ---------- multi-unit request ----------

#[tokio::test]
async fn multi_unit_write_and_read_cross_boundaries() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    // 3 full units + trailing half unit, starting mid-unit.
    let start = UNIT as u64 / 2; // 512, mid-unit but block-aligned
    let len = 3 * UNIT as usize + 512;
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    engine.write(start, &data, false).await.unwrap();
    assert_eq!(engine.read(start, len).await.unwrap(), data);
    // The bytes before `start` in unit 0 are still zeros (RMW preserved).
    assert!(engine.read(0, 512).await.unwrap().iter().all(|b| *b == 0));
}

// ---------- partial-unit RMW ----------

#[tokio::test]
async fn partial_unit_rmw_preserves_surrounding_bytes() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    let base: Vec<u8> = (0..UNIT as usize).map(|i| i as u8).collect();
    engine.write(0, &base, false).await.unwrap();
    // Overwrite a block-aligned 512-byte span inside unit 0.
    engine.write(512, &[0xEE; 512], false).await.unwrap();

    let mut expect = base.clone();
    expect[512..1024].fill(0xEE);
    assert_eq!(engine.read(0, UNIT as usize).await.unwrap(), expect);
}

#[tokio::test]
async fn rmw_on_unwritten_unit_merges_with_zeros() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    engine.write(512, &[0x77; 512], false).await.unwrap(); // inside unit 0
    let got = engine.read(0, UNIT as usize).await.unwrap();
    assert!(got[..512].iter().all(|b| *b == 0));
    assert!(got[512..1024].iter().all(|b| *b == 0x77));
    assert!(got[1024..].iter().all(|b| *b == 0));
}

// ---------- concurrent writes (SPEC §28) ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_to_distinct_units_all_land() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    let mut tasks = Vec::new();
    for i in 0..32u64 {
        let engine = engine.clone();
        tasks.push(tokio::spawn(async move {
            let data = vec![i as u8 + 1; UNIT as usize];
            engine.write(i * UNIT as u64, &data, false).await.unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    for i in 0..32u64 {
        let got = engine.read(i * UNIT as u64, UNIT as usize).await.unwrap();
        assert_eq!(got, vec![i as u8 + 1; UNIT as usize]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_unit_writes_serialize_without_tearing() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    for _round in 0..10 {
        let mut tasks = Vec::new();
        for w in 1..=4u8 {
            let engine = engine.clone();
            tasks.push(tokio::spawn(async move {
                // Each writer does a partial RMW of a different quarter AND a
                // full-unit write, racing on unit 7.
                let off = 7 * UNIT as u64;
                engine
                    .write(off + (w as u64 - 1) * 512, &[w; 512], false)
                    .await
                    .unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        // All four quarter-writes must have landed (serialized RMW never
        // loses a concurrent update).
        let got = engine.read(7 * UNIT as u64, UNIT as usize).await.unwrap();
        for w in 1..=4u8 {
            let s = (w as usize - 1) * 512;
            assert_eq!(
                &got[s..s + 512],
                &vec![w; 512][..],
                "lost update from writer {w}"
            );
        }
    }
}

// ---------- concurrent read/write ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_during_writes_see_old_or_new_never_mixed() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    let unit9 = 9 * UNIT as u64;
    engine
        .write(unit9, &vec![0x00; UNIT as usize], false)
        .await
        .unwrap();

    let writer = {
        let engine = engine.clone();
        tokio::spawn(async move {
            for i in 1..=50u8 {
                engine
                    .write(unit9, &vec![i; UNIT as usize], false)
                    .await
                    .unwrap();
            }
        })
    };
    let reader = {
        let engine = engine.clone();
        tokio::spawn(async move {
            for _ in 0..200 {
                let got = engine.read(unit9, UNIT as usize).await.unwrap();
                let first = got[0];
                assert!(
                    got.iter().all(|b| *b == first),
                    "torn read: mixed unit content"
                );
            }
        })
    };
    writer.await.unwrap();
    reader.await.unwrap();
}

// ---------- FUA / FLUSH ----------

#[tokio::test]
async fn fua_write_survives_crash() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    engine
        .write(4096, &vec![0x5A; UNIT as usize], true)
        .await
        .unwrap();
    drop(engine);
    backing.crash_all_lost();
    let engine = attach(&backing).await.unwrap();
    assert_eq!(
        engine.read(4096, UNIT as usize).await.unwrap(),
        vec![0x5A; UNIT as usize]
    );
}

#[tokio::test]
async fn flush_makes_prior_writes_durable() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    engine
        .write(0, &vec![0x11; UNIT as usize], false)
        .await
        .unwrap();
    engine.flush().await.unwrap();
    engine
        .write(UNIT as u64, &vec![0x22; UNIT as usize], false)
        .await
        .unwrap(); // post-flush, volatile
    drop(engine);
    backing.crash_all_lost();
    let engine = attach(&backing).await.unwrap();
    assert_eq!(
        engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x11; UNIT as usize]
    );
    assert!(engine
        .read(UNIT as u64, UNIT as usize)
        .await
        .unwrap()
        .iter()
        .all(|b| *b == 0));
}

// ---------- attach guards ----------

#[tokio::test]
async fn attach_refuses_crypto_profile_mismatch() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let wrong = Arc::new(FakeCryptoProvider::new(UNIT).with_compat_id("other-profile"));
    let err = Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        wrong,
        EngineOptions::default(),
    )
    .await;
    assert!(matches!(err, Err(AttachError::Crypto(_))), "{err:?}");
}

#[tokio::test]
async fn attach_refuses_wrong_unit_size_provider() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let wrong = Arc::new(FakeCryptoProvider::new(4096));
    assert!(Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        wrong,
        EngineOptions::default(),
    )
    .await
    .is_err());
}

// ---------- corrupted ciphertext is EIO, never plaintext ----------

#[tokio::test]
async fn corrupted_ciphertext_with_valid_slot_crc_is_eio() {
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    engine
        .write(0, &vec![0x99; UNIT as usize], true)
        .await
        .unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);

    // Tamper with the ciphertext on disk and FIX the slot CRC so only the
    // provider's integrity check can catch it.
    let g = geometry();
    let f = backing.open(&layout::shard_data(0), false).unwrap();
    let mut header = vec![0u8; 64];
    f.read_at(0, &mut header).unwrap();
    let h = maki_format::slot::SlotHeader::decode(&header).unwrap();
    let mut ct = vec![0u8; h.ciphertext_len as usize];
    f.read_at(64, &mut ct).unwrap();
    ct[100] ^= 0x01;
    let fixed = maki_format::slot::SlotHeader {
        ciphertext_crc: crc32fast::hash(&ct),
        ..h
    };
    f.write_at(0, &fixed.encode()).unwrap();
    f.write_at(64, &ct).unwrap();
    f.sync_data().unwrap();
    let _ = g;

    let engine = attach(&backing).await.unwrap();
    assert!(
        engine.read(0, UNIT as usize).await.is_err(),
        "corrupted ciphertext must be EIO, never decrypted garbage"
    );
}

// ---------- differential model test (cache disabled) ----------

async fn differential_run(seed: u64, ops: usize) {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(31).wrapping_add(1));
    let backing = Arc::new(CrashableBacking::new());
    let engine = new_engine(&backing).await;
    let mut model = vec![0u8; DEVICE_SIZE as usize];
    let max_blocks = (DEVICE_SIZE / BLOCK as u64) as usize;

    for op in 0..ops {
        match rng.random_range(0..100u32) {
            0..=54 => {
                let blocks = rng.random_range(1..=8usize);
                let start = rng.random_range(0..=max_blocks - blocks);
                let off = start as u64 * BLOCK as u64;
                let len = blocks * BLOCK as usize;
                let fill: u8 = rng.random();
                let data: Vec<u8> = (0..len).map(|i| fill.wrapping_add(i as u8)).collect();
                let fua = rng.random_bool(0.2);
                engine.write(off, &data, fua).await.unwrap();
                model[off as usize..off as usize + len].copy_from_slice(&data);
            }
            55..=89 => {
                let blocks = rng.random_range(1..=8usize);
                let start = rng.random_range(0..=max_blocks - blocks);
                let off = start as u64 * BLOCK as u64;
                let len = blocks * BLOCK as usize;
                let got = engine.read(off, len).await.unwrap();
                assert_eq!(
                    got,
                    &model[off as usize..off as usize + len],
                    "seed {seed} op {op}: read mismatch at {off}+{len}"
                );
            }
            90..=94 => engine.flush().await.unwrap(),
            _ => {
                engine.checkpoint().await.unwrap();
            }
        }
    }
    // Full sweep at the end.
    let got = engine.read(0, DEVICE_SIZE as usize).await.unwrap();
    assert_eq!(got, model, "seed {seed}: final sweep mismatch");
}

/// Smoke: ~10,000 randomized ops across seeds.
#[tokio::test]
async fn phase4_differential_smoke() {
    for seed in 0..10u64 {
        differential_run(seed, 1000).await;
    }
}

/// Full phase gate: 100,000+ randomized I/O operations, model mismatch = 0.
#[tokio::test]
#[ignore = "phase gate: 100,000+ randomized ops"]
async fn phase4_gate_full() {
    for seed in 0..50u64 {
        differential_run(seed, 2000).await;
    }
    differential_run(999, 10_000).await;
}
