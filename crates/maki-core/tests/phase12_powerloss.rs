//! Phase 12 — power-loss qualification, simulation tier (SPEC §54).
//!
//! The SPEC's test hierarchy is WSL (development) → QEMU/KVM (hard VM power
//! cut) → bare metal (final qualification). This file is the development
//! tier: the *exact* SPEC §54 scenarios executed against the full engine
//! over `CrashableBacking`, whose crash model (independent survival of every
//! unsynced write, torn tails, orphaned dirents) is a superset of what a
//! power cut can do to a POSIX filesystem. The QEMU/bare-metal runbook is
//! in docs/phase-12.md.

use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{Engine, EngineOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const DEVICE_UNITS: u64 = 64;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x12),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            UNIT,
            UNIT,
            512,
            UNIT + 8,
            DEVICE_UNITS * UNIT as u64,
            16 * UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn attach(backing: &Arc<CrashableBacking>) -> Engine {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions::default(),
    )
    .await
    .unwrap()
}

fn off(unit: u64) -> u64 {
    unit * UNIT as u64
}

fn old_img(unit: u64) -> Vec<u8> {
    vec![0x10 + unit as u8; UNIT as usize]
}

fn new_img(unit: u64) -> Vec<u8> {
    vec![0xA0 + unit as u8; UNIT as usize]
}

/// SPEC §54 critical test:
/// ```text
/// WRITE A · WRITE B · FLUSH success · WRITE C · power cut
/// ⇒ A = new, B = new, C = old or new
/// ```
async fn critical_sequence(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(97).wrapping_add(11));
    let backing = Arc::new(CrashableBacking::new());
    let engine = attach(&backing).await;

    // Establish "old" content durably for A, B, C.
    for unit in [0u64, 1, 2] {
        engine.write(off(unit), &old_img(unit), false).await.unwrap();
    }
    engine.flush().await.unwrap();

    // The critical sequence.
    engine.write(off(0), &new_img(0), false).await.unwrap(); // WRITE A
    engine.write(off(1), &new_img(1), false).await.unwrap(); // WRITE B
    engine.flush().await.unwrap(); // FLUSH success
    engine.write(off(2), &new_img(2), false).await.unwrap(); // WRITE C
    drop(engine); // power cut
    backing.crash(&mut rng);

    let engine = attach(&backing).await;
    let a = engine.read(off(0), UNIT as usize).await.unwrap();
    let b = engine.read(off(1), UNIT as usize).await.unwrap();
    let c = engine.read(off(2), UNIT as usize).await.unwrap();
    assert_eq!(a, new_img(0), "seed {seed}: A must be new (FLUSH violation)");
    assert_eq!(b, new_img(1), "seed {seed}: B must be new (FLUSH violation)");
    assert!(
        c == old_img(2) || c == new_img(2),
        "seed {seed}: C must be old or new, never torn or foreign"
    );
}

/// SPEC §54 FUA test:
/// ```text
/// WRITE A + FUA success · power cut ⇒ A = new
/// ```
async fn fua_sequence(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(193).wrapping_add(7));
    let backing = Arc::new(CrashableBacking::new());
    let engine = attach(&backing).await;
    engine.write(off(5), &old_img(5), false).await.unwrap();
    engine.flush().await.unwrap();

    engine.write(off(5), &new_img(5), true).await.unwrap(); // WRITE A + FUA
    drop(engine); // power cut
    backing.crash(&mut rng);

    let engine = attach(&backing).await;
    let a = engine.read(off(5), UNIT as usize).await.unwrap();
    assert_eq!(a, new_img(5), "seed {seed}: FUA violation");
}

#[tokio::test]
async fn spec54_critical_sequence_smoke() {
    for seed in 0..100u64 {
        critical_sequence(seed).await;
    }
}

#[tokio::test]
async fn spec54_fua_sequence_smoke() {
    for seed in 0..100u64 {
        fua_sequence(seed).await;
    }
}

/// Both outcomes for C must actually occur across seeds (the crash model
/// is genuinely nondeterministic, not accidentally always-durable).
#[tokio::test]
async fn spec54_c_exhibits_both_outcomes() {
    let mut saw_old = false;
    let mut saw_new = false;
    for seed in 0..300u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let backing = Arc::new(CrashableBacking::new());
        let engine = attach(&backing).await;
        engine.write(off(2), &old_img(2), false).await.unwrap();
        engine.flush().await.unwrap();
        engine.write(off(2), &new_img(2), false).await.unwrap();
        drop(engine);
        backing.crash(&mut rng);
        let engine = attach(&backing).await;
        let c = engine.read(off(2), UNIT as usize).await.unwrap();
        if c == old_img(2) {
            saw_old = true;
        } else if c == new_img(2) {
            saw_new = true;
        } else {
            panic!("seed {seed}: impossible content for C");
        }
        if saw_old && saw_new {
            return;
        }
    }
    panic!("crash model never produced both outcomes (old={saw_old}, new={saw_new})");
}

/// Release-gate tier of the same scenarios (SPEC §56: QEMU hard power loss
/// 300+; this is the simulation-tier equivalent at 500 each).
#[tokio::test]
#[ignore = "phase gate: 500+ power-loss cycles per scenario"]
async fn phase12_gate_full() {
    for seed in 0..500u64 {
        critical_sequence(seed).await;
        fua_sequence(seed).await;
    }
}
