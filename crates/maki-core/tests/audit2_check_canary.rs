//! Audit round 2 (sweeps-r2): the deep check passes a volume whose next
//! attach is certain to refuse.
//!
//! Found by `audit2_sweep_engine.rs` (cfg random-any, mode death-damage, seed
//! 3020: media damage truncated `canary.a` and flipped bits in `canary.b` of
//! a used v3 volume whose units were all trimmed). `deep_check` reported the
//! canary as "absent" (a warning, so `check passed`), while every attach
//! refused with "volume has data but no key canary: volume has history but no
//! readable ciphertext to probe" — whatever the provider. `check.rs` promises
//! that "anything that would refuse attach ... is reported here", and
//! docs/operations.md lists canary metadata that failed validation as an
//! `unrecoverable` ERROR verdict.

use std::sync::Arc;

use maki_backing::{Backing, MemBacking};
use maki_core::engine::{Engine, EngineOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use uuid::Uuid;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xA0D2_CA4A),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 520, 16 * 512, 8 * 512).unwrap(),
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

fn flip_byte(backing: &dyn Backing, path: &str, at: u64) {
    let file = backing.open(path, false).unwrap();
    let mut b = [0u8; 1];
    file.read_at(at, &mut b).unwrap();
    b[0] ^= 0x10;
    file.write_at(at, &b).unwrap();
    file.sync_data().unwrap();
}

#[tokio::test]
async fn deep_check_passes_a_used_volume_whose_attach_must_refuse() {
    let backing: Arc<dyn Backing> = Arc::new(MemBacking::new());
    init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();

    // A used volume that no longer holds any ciphertext: write, then trim.
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(512)),
        options(),
    )
    .await
    .unwrap();
    engine.write(0, &[7u8; 512], true).await.unwrap();
    engine.trim(0, 512, true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine.stop_checkpoint_worker().await;
    drop(engine);

    // Media damage to both canary copies (one bit-ish flip each).
    flip_byte(backing.as_ref(), "canary.a", 40);
    flip_byte(backing.as_ref(), "canary.b", 40);

    let report = maki_core::check::deep_check(backing.clone(), 256 << 20).unwrap();
    let attach = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(512)),
        options(),
    )
    .await;
    let refused = attach.as_ref().err().map(|e| e.to_string());
    println!(
        "deep check errors {:?} warnings {:?}; attach: {:?}",
        report.errors, report.warnings, refused
    );
    // The contract: a clean deep check (no ERROR, `check passed`) means the
    // runtime attaches. Here the runtime refuses for every provider.
    assert!(
        !report.errors.is_empty() || attach.is_ok(),
        "deep check passed (errors {:?}, warnings {:?}) but attach refused: {}",
        report.errors,
        report.warnings,
        refused.unwrap_or_default()
    );
}
