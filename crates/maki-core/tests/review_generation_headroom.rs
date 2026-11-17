//! A/B metadata generations that leave recovery no room to store.
//!
//! Every A/B store advances a record's generation by one, and the store
//! refuses to wrap (MAKI-027). Recovery and attach store the checkpoint
//! state, both durable-proof copies, every discard map and the key canary on
//! each attach, and replay stores allocation maps and the catalog as often
//! as the journal requires, so a CRC-valid generation near `u64::MAX` made
//! attach refuse (or a later checkpoint fail) while the read-only deep check
//! passed the volume. No writer produces a generation anywhere near that:
//! recovery now refuses one in the top quarter of the generation space
//! before any write, and the deep check reports the same.

use std::sync::{Arc, Mutex};

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::engine::{Engine, EngineOptions};
use maki_format::checkpoint::{CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::durable_proof::{DURABLE_PROOF_A, DURABLE_PROOF_B};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;
use uuid::Uuid;

const UNIT: u32 = 512;
/// The highest generation recovery accepts: `2^62` stores below `u64::MAX`.
const LIMIT: u64 = u64::MAX - (1 << 62);

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x9e4e_4a71),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, 16 * UNIT as u64, 8 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> EngineOptions {
    let mut options = EngineOptions::default();
    options.checkpoint.emergency_reserve_bytes = 0;
    options.checkpoint.low_space_checkpoint_bytes = 0;
    options
}

async fn attach(backing: &Arc<CrashableBacking>) -> Result<Engine, String> {
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        options(),
    )
    .await
    .map_err(|error| error.to_string())
}

/// A v3 volume with a bound canary, a checkpointed unit and a journal record
/// above the checkpoint (so the next attach replays it into the shard).
async fn volume() -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    let engine = attach(&backing).await.unwrap();
    engine.write(0, &[7u8; UNIT as usize], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine
        .write(UNIT as u64, &[8u8; UNIT as usize], true)
        .await
        .unwrap();
    engine.stop_checkpoint_worker().await;
    drop(engine);
    backing
}

/// The generation of one copy (every A/B record encodes
/// `magic[8] version[4] generation[8] ... crc32`).
fn generation_of(backing: &CrashableBacking, path: &str) -> u64 {
    let file = backing.open(path, false).unwrap();
    let mut bytes = [0u8; 8];
    file.read_at(12, &mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}

/// Rewrite the newer copy of a pair with `generation` and a valid CRC, so
/// the pair's selected content is unchanged.
fn set_generation(backing: &CrashableBacking, (a, b): &(String, String), generation: u64) {
    let path = if generation_of(backing, a) >= generation_of(backing, b) {
        a
    } else {
        b
    };
    let file = backing.open(path, false).unwrap();
    let mut bytes = vec![0u8; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes[12..20].copy_from_slice(&generation.to_le_bytes());
    let end = bytes.len() - 4;
    let crc = crc32fast::hash(&bytes[..end]);
    bytes[end..].copy_from_slice(&crc.to_le_bytes());
    file.write_at(0, &bytes).unwrap();
    file.sync_data().unwrap();
}

fn pairs() -> Vec<(&'static str, (String, String))> {
    let pair = |a: &str, b: &str| (a.to_string(), b.to_string());
    vec![
        (
            "superblock",
            pair(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B),
        ),
        (
            "shard catalog",
            pair(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B),
        ),
        (
            "allocation map",
            (layout::shard_alloc_a(0), layout::shard_alloc_b(0)),
        ),
        (
            "discard map",
            (layout::shard_discard_a(0), layout::shard_discard_b(0)),
        ),
        (
            "checkpoint state",
            pair(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B),
        ),
        ("durable proof", pair(DURABLE_PROOF_A, DURABLE_PROOF_B)),
        (
            "key canary",
            pair(layout::KEY_CANARY_A, layout::KEY_CANARY_B),
        ),
    ]
}

fn observe_mutations(backing: &CrashableBacking) -> Arc<Mutex<Vec<String>>> {
    let mutations = Arc::new(Mutex::new(Vec::new()));
    let observed = mutations.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if !matches!(op, FaultOp::Open { create: false, .. }) {
            observed.lock().unwrap().push(format!("{op:?}"));
        }
        None
    })));
    mutations
}

#[tokio::test]
async fn generations_without_store_headroom_are_refused_by_check_and_attach() {
    let mut failures = Vec::new();
    for (what, pair) in pairs() {
        for generation in [LIMIT + 1, u64::MAX - 1, u64::MAX] {
            let what = format!("{what} generation {generation}");
            let backing = volume().await;
            set_generation(&backing, &pair, generation);

            let mutations = observe_mutations(&backing);
            let report = deep_check(backing.clone() as Arc<dyn Backing>, 256 << 20).unwrap();
            let attached = attach(&backing).await;
            backing.set_fault_hook(None);

            let check_refused = report
                .errors
                .iter()
                .any(|error| error.contains("generation"));
            let mutations = mutations.lock().unwrap();
            match attached {
                Ok(_) => failures.push(format!(
                    "{what}: attach accepted (check errors {:?})",
                    report.errors
                )),
                Err(error) if !check_refused => failures.push(format!(
                    "{what}: the deep check passed (errors {:?}) but attach refused: {error}",
                    report.errors
                )),
                Err(_) if !mutations.is_empty() => failures.push(format!(
                    "{what}: storage changed before the refusal: {mutations:?}"
                )),
                Err(_) => {}
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Generations up to the bound are checked clean and attach, and one at a
/// common boundary value such as `i64::MAX` keeps attaching: the bound
/// leaves `2^62` stores below it as well as above it.
#[tokio::test]
async fn generations_up_to_the_bound_are_accepted_by_check_and_attach() {
    for (what, pair) in pairs() {
        for generation in [i64::MAX as u64, LIMIT] {
            let what = format!("{what} generation {generation}");
            let backing = volume().await;
            set_generation(&backing, &pair, generation);
            let attaches = if generation == LIMIT { 1 } else { 2 };
            for _ in 0..attaches {
                let report = deep_check(backing.clone() as Arc<dyn Backing>, 256 << 20).unwrap();
                assert!(report.ok(), "{what}: {:?}", report.errors);
                let engine = attach(&backing)
                    .await
                    .unwrap_or_else(|error| panic!("{what}: {error}"));
                engine.stop_checkpoint_worker().await;
                drop(engine);
            }
        }
    }
}
