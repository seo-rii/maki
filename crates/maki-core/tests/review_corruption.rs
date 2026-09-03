//! Recovery under random single-file corruption (SPEC §12, §27).
//!
//! A deterministic workload (writes, FUA, flushes, checkpoints, a final
//! flush so *everything acknowledged is durable*) is run on a fresh volume;
//! then one on-disk file is damaged at random (bit flips, truncation, a
//! zeroed range) and the volume is deep-checked and re-attached.
//!
//! Required outcomes, by what was damaged:
//! * journal segment or checkpoint state: attach fails closed, or succeeds
//!   with every unit exactly as acknowledged (a mutation that hit slack);
//! * data shard: attach succeeds; a unit reads back exactly or fails with
//!   an error — never a different stamp and never zeros;
//! * anything else (one side of an A/B record, the durable mark, the
//!   superblock copies, the canary): attach succeeds and every unit reads
//!   back exactly.
//!
//! Nothing may panic, including the deep checker.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::store::SlotStore;
use maki_core::volume::VolumeOptions;
use maki_crypto::CryptoProvider;
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::{CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const BLOCK: u32 = 512;
const UNIT: u32 = 1024;
const UNITS: u64 = 192;
const DEVICE_SIZE: u64 = UNITS * UNIT as u64;
const SEGMENT: u64 = 12 << 10;
const ITERATIONS: u64 = 80;

fn geometry() -> Geometry {
    Geometry::compute(BLOCK, UNIT, 512, UNIT + 8, DEVICE_SIZE, 16 * UNIT as u64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xC0DE),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn provider() -> Arc<dyn CryptoProvider> {
    Arc::new(FakeCryptoProvider::new(UNIT))
}

fn options() -> EngineOptions {
    EngineOptions {
        volume: VolumeOptions {
            journal_segment_size: SEGMENT,
        },
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: 64 << 20,
            journal_max_bytes: 128 << 20,
            max_pending_bytes: 64 << 20,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: Duration::from_secs(3600),
        },
        ..Default::default()
    }
}

fn stamp_bytes(stamp: u16) -> Vec<u8> {
    stamp
        .to_be_bytes()
        .iter()
        .copied()
        .cycle()
        .take(UNIT as usize)
        .collect()
}

fn decode_stamp(unit: u64, buf: &[u8]) -> u16 {
    let first = u16::from_be_bytes([buf[0], buf[1]]);
    for pair in buf.chunks(2) {
        assert_eq!(
            u16::from_be_bytes([pair[0], pair[1]]),
            first,
            "unit {unit}: torn read"
        );
    }
    first
}

/// Deterministic workload; returns the acknowledged (and, after the final
/// flush, durable) stamp of every written unit.
async fn workload(backing: &Arc<CrashableBacking>) -> BTreeMap<u64, u16> {
    let engine = Engine::attach(backing.clone() as Arc<dyn Backing>, provider(), options())
        .await
        .expect("attach fresh");
    let mut rng = StdRng::seed_from_u64(0x0C0DE);
    let mut acked = BTreeMap::new();
    for round in 1..=260u16 {
        let unit = rng.random_range(0..UNITS);
        let fua = rng.random_bool(0.3);
        engine
            .write(unit * UNIT as u64, &stamp_bytes(round), fua)
            .await
            .unwrap();
        acked.insert(unit, round);
        if round % 40 == 0 {
            engine.flush().await.unwrap();
        }
        if round % 65 == 0 {
            engine.checkpoint().await.unwrap();
        }
    }
    // Leave a checkpointed body plus a journal tail; everything durable.
    engine.flush().await.unwrap();
    drop(engine);
    tokio::time::sleep(Duration::from_millis(20)).await;
    acked
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Journal,
    CheckpointState,
    DataShard,
    Other,
}

fn candidates(backing: &dyn Backing) -> Vec<(String, Target)> {
    let mut out = vec![
        (layout::SUPERBLOCK_A.to_string(), Target::Other),
        (layout::SUPERBLOCK_B.to_string(), Target::Other),
        (layout::SHARD_CATALOG_A.to_string(), Target::Other),
        (layout::SHARD_CATALOG_B.to_string(), Target::Other),
        (layout::KEY_CANARY_A.to_string(), Target::Other),
        (layout::KEY_CANARY_B.to_string(), Target::Other),
        (layout::JOURNAL_DURABLE_MARK.to_string(), Target::Other),
        (CHECKPOINT_STATE_A.to_string(), Target::CheckpointState),
        (CHECKPOINT_STATE_B.to_string(), Target::CheckpointState),
    ];
    for name in backing.list(layout::JOURNAL_DIR).unwrap() {
        if layout::parse_journal_segment(&name).is_some() {
            out.push((format!("{}/{name}", layout::JOURNAL_DIR), Target::Journal));
        }
    }
    for name in backing.list(layout::DATA_DIR).unwrap() {
        let path = format!("{}/{name}", layout::DATA_DIR);
        let target = if name.contains("alloc") {
            Target::Other
        } else {
            Target::DataShard
        };
        out.push((path, target));
    }
    out.retain(|(p, _)| backing.exists(p).unwrap_or(false));
    out
}

fn corrupt(backing: &dyn Backing, path: &str, rng: &mut StdRng) -> String {
    let file = backing.open(path, false).unwrap();
    let len = file.len().unwrap();
    if len == 0 {
        file.write_at(0, &[rng.random::<u8>() | 1]).unwrap();
        return "append one byte to empty file".into();
    }
    match rng.random_range(0..3u32) {
        0 => {
            let n = rng.random_range(1..=8usize).min(len as usize);
            let mut offsets = BTreeSet::new();
            while offsets.len() < n {
                offsets.insert(rng.random_range(0..len));
            }
            for o in &offsets {
                let mut b = [0u8; 1];
                file.read_at(*o, &mut b).unwrap();
                b[0] ^= 1 << rng.random_range(0..8);
                file.write_at(*o, &b).unwrap();
            }
            format!("flip {n} bit(s) at {offsets:?}")
        }
        1 => {
            let keep = rng.random_range(0..len);
            file.set_len(keep).unwrap();
            format!("truncate {len} -> {keep}")
        }
        _ => {
            let start = rng.random_range(0..len);
            let n = (len - start).min(64);
            file.write_at(start, &vec![0u8; n as usize]).unwrap();
            format!("zero {n} bytes at {start}")
        }
    }
}

/// Truncate the newest valid copy of an A/B record so the store falls back
/// to the older one.
fn drop_newest_side<T: maki_format::ab::AbRecord>(backing: &dyn Backing, a: &str, b: &str) {
    let (ga, gb) = AbStore::new(a.to_string(), b.to_string())
        .side_generations::<T>(backing)
        .unwrap();
    let victim = match (ga, gb) {
        (Some(x), Some(y)) if x >= y => a,
        (Some(_), Some(_)) => b,
        (Some(_), None) => a,
        (None, Some(_)) => b,
        (None, None) => panic!("no valid side of {a}/{b}"),
    };
    backing.open(victim, false).unwrap().set_len(3).unwrap();
}

async fn read_stamp(engine: &Engine, unit: u64) -> u16 {
    let buf = engine
        .read(unit * UNIT as u64, UNIT as usize)
        .await
        .unwrap();
    decode_stamp(unit, &buf)
}

/// Review follow-up (found by the corruption fuzz): when the newest copy of
/// a shard's allocation map is unreadable, the older copy does not list the
/// slots the last checkpoint filled. Those units must still read back from
/// their slot headers, never as zeros, and the next checkpoint must repair
/// the map.
#[tokio::test]
async fn allocation_map_fallback_never_reads_checkpointed_data_as_zeros() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let expected = workload(&backing).await;

    for name in backing.list(layout::DATA_DIR).unwrap() {
        if name.ends_with(".alloc.a") {
            let stem = name.trim_end_matches(".alloc.a");
            let a = format!("{}/{stem}.alloc.a", layout::DATA_DIR);
            let b = format!("{}/{stem}.alloc.b", layout::DATA_DIR);
            drop_newest_side::<AllocationMap>(backing.as_ref(), &a, &b);
        }
    }

    let engine = Engine::attach(backing.clone() as Arc<dyn Backing>, provider(), options())
        .await
        .expect("one valid allocation copy per shard remains");
    for unit in 0..UNITS {
        let want = expected.get(&unit).copied().unwrap_or(0);
        assert_eq!(read_stamp(&engine, unit).await, want, "unit {unit}");
    }
    // The deep checker reports (not errors on) the stale copies, and a
    // checkpoint rewrites them.
    engine.checkpoint().await.unwrap();
    drop(engine);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let store = SlotStore::open(backing.clone() as Arc<dyn Backing>, geometry()).unwrap();
    assert!(
        store.repaired_allocations().is_empty(),
        "checkpoint did not persist the repaired allocation maps"
    );
}

/// The deep checker names the stale copies before any checkpoint repairs
/// them, and a checkpoint with nothing new to apply still persists the
/// repair.
#[tokio::test]
async fn deep_check_reports_allocation_repair_and_idle_checkpoint_persists_it() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let expected = workload(&backing).await;
    // Everything durable is checkpointed: the next checkpoint has no new
    // records to apply.
    let engine = Engine::attach(backing.clone() as Arc<dyn Backing>, provider(), options())
        .await
        .unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);
    tokio::time::sleep(Duration::from_millis(20)).await;
    for name in backing.list(layout::DATA_DIR).unwrap() {
        if name.ends_with(".alloc.a") {
            let stem = name.trim_end_matches(".alloc.a");
            let a = format!("{}/{stem}.alloc.a", layout::DATA_DIR);
            let b = format!("{}/{stem}.alloc.b", layout::DATA_DIR);
            drop_newest_side::<AllocationMap>(backing.as_ref(), &a, &b);
        }
    }
    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("repaired from slot headers")),
        "{:?}",
        report.warnings
    );
    let engine = Engine::attach(backing.clone() as Arc<dyn Backing>, provider(), options())
        .await
        .unwrap();
    for unit in 0..UNITS {
        let want = expected.get(&unit).copied().unwrap_or(0);
        assert_eq!(read_stamp(&engine, unit).await, want, "unit {unit}");
    }
    engine.checkpoint().await.unwrap(); // nothing new, repair only
    drop(engine);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let store = SlotStore::open(backing.clone() as Arc<dyn Backing>, geometry()).unwrap();
    assert!(
        store.repaired_allocations().is_empty(),
        "idle checkpoint did not persist"
    );
}

/// Both copies of a cataloged shard's allocation map gone: SPEC §27 keeps
/// this fail-closed (attach refused, deep check reports an error) rather
/// than guessing; it is offline-repair territory.
#[tokio::test]
async fn missing_allocation_maps_refuse_attach() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let _ = workload(&backing).await;
    let mut removed = 0;
    for name in backing.list(layout::DATA_DIR).unwrap() {
        if name.starts_with("shard-00000000.alloc.") {
            backing
                .remove(&format!("{}/{name}", layout::DATA_DIR))
                .unwrap();
            removed += 1;
        }
    }
    assert!(removed > 0, "shard 0 has no allocation copies to remove");
    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    assert!(
        report.errors.iter().any(|e| e.contains("allocation map")),
        "{:?}",
        report.errors
    );
    let Err(err) = Engine::attach(backing.clone() as Arc<dyn Backing>, provider(), options()).await
    else {
        panic!("attach must refuse");
    };
    assert!(err.to_string().contains("allocation map"), "{err}");
}

/// The shard catalog has the same A/B fallback: its older copy does not
/// list a shard created by the last checkpoint. The shard's data file is
/// adopted from the directory instead of its units reading as zeros.
#[tokio::test]
async fn catalog_fallback_never_hides_a_shard() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let engine = Engine::attach(backing.clone() as Arc<dyn Backing>, provider(), options())
        .await
        .unwrap();
    let per_shard = geometry().units_per_shard();
    let first = 0u64;
    let last = UNITS - 1;
    assert!(last / per_shard > first / per_shard, "need two shards");
    engine
        .write(first * UNIT as u64, &stamp_bytes(0x0101), true)
        .await
        .unwrap();
    engine.checkpoint().await.unwrap(); // catalog generation 1: shard of `first`
    engine
        .write(last * UNIT as u64, &stamp_bytes(0x0202), true)
        .await
        .unwrap();
    engine.checkpoint().await.unwrap(); // generation 2 adds the last shard
    drop(engine);
    tokio::time::sleep(Duration::from_millis(20)).await;

    drop_newest_side::<ShardCatalog>(
        backing.as_ref(),
        layout::SHARD_CATALOG_A,
        layout::SHARD_CATALOG_B,
    );
    let engine = Engine::attach(backing.clone() as Arc<dyn Backing>, provider(), options())
        .await
        .unwrap();
    assert_eq!(read_stamp(&engine, first).await, 0x0101);
    assert_eq!(
        read_stamp(&engine, last).await,
        0x0202,
        "shard hidden by catalog fallback"
    );
    engine.checkpoint().await.unwrap();
    drop(engine);
    tokio::time::sleep(Duration::from_millis(20)).await;
    // The newest valid catalog copy now lists both shards (no adoption
    // needed any more).
    let catalog = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .load::<ShardCatalog>(backing.as_ref())
        .unwrap()
        .expect("a valid catalog copy");
    assert!(
        catalog.contains(first / per_shard) && catalog.contains(last / per_shard),
        "catalog not re-persisted with the adopted shard"
    );
    let engine = Engine::attach(backing.clone() as Arc<dyn Backing>, provider(), options())
        .await
        .unwrap();
    assert_eq!(read_stamp(&engine, last).await, 0x0202);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_under_random_single_file_corruption() {
    for iteration in 0..ITERATIONS {
        let mut rng = StdRng::seed_from_u64(0xBAD + iteration);
        let backing = Arc::new(CrashableBacking::new());
        init::create_volume(backing.as_ref(), superblock()).unwrap();
        let expected = workload(&backing).await;

        let candidates = candidates(backing.as_ref());
        let (path, target) = candidates[rng.random_range(0..candidates.len())].clone();
        let what = corrupt(backing.as_ref(), &path, &mut rng);
        let case = format!("iteration {iteration}: {path} ({target:?}): {what}");

        // The deep checker must never panic on damaged input.
        let _ = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT);

        let attached =
            Engine::attach(backing.clone() as Arc<dyn Backing>, provider(), options()).await;
        let engine = match attached {
            Ok(engine) => engine,
            Err(e) => {
                assert!(
                    matches!(target, Target::Journal | Target::CheckpointState),
                    "{case}: attach refused although only a redundant or \
                     non-authoritative file was damaged: {e}"
                );
                continue;
            }
        };

        for unit in 0..UNITS {
            let want = expected.get(&unit).copied().unwrap_or(0);
            match engine.read(unit * UNIT as u64, UNIT as usize).await {
                Ok(buf) => {
                    let got = decode_stamp(unit, &buf);
                    assert!(
                        got == want,
                        "{case}: unit {unit} reads {got:#06x}, acknowledged {want:#06x}"
                    );
                }
                Err(e) => {
                    assert_eq!(
                        target,
                        Target::DataShard,
                        "{case}: unit {unit} unreadable ({e}) although its shard is intact"
                    );
                }
            }
        }
    }
}
