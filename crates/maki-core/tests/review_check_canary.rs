//! The deep check's key-canary verdict must match what attach does.
//!
//! `AbStore::load` returns no canary both when no copy exists and when every
//! copy fails validation, and attach treats the two alike: a pristine volume
//! binds a new canary, while a volume with history must first decrypt
//! existing ciphertext with an integrity-capable provider. With no
//! ciphertext left to probe (every unit trimmed), every attach refuses,
//! whatever the provider. The deep check reported such a volume's damaged
//! canary as "absent", a warning, and printed `check passed`.

use std::sync::Arc;

use maki_backing::{Backing, MemBacking};
use maki_core::check::deep_check;
use maki_core::engine::{Engine, EngineOptions};
use maki_format::checker::CheckReport;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::fake_provider::FakeCryptoProvider;
use uuid::Uuid;

const UNIT: u32 = 512;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xCA4A_57A7),
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

fn provider() -> Arc<FakeCryptoProvider> {
    Arc::new(FakeCryptoProvider::new(UNIT))
}

async fn attach(backing: &Arc<dyn Backing>) -> Result<Engine, String> {
    Engine::attach(backing.clone(), provider(), options())
        .await
        .map_err(|error| error.to_string())
}

async fn detach(engine: Engine) {
    engine.stop_checkpoint_worker().await;
    drop(engine);
}

#[derive(Clone, Copy, Debug)]
enum Canary {
    /// One byte of each copy flipped: both copies exist, neither validates.
    Damaged,
    /// Both copies removed.
    Removed,
}

fn break_canary(backing: &dyn Backing, how: Canary) {
    for path in [layout::KEY_CANARY_A, layout::KEY_CANARY_B] {
        match how {
            Canary::Damaged => {
                let file = backing.open(path, false).unwrap();
                let mut byte = [0u8; 1];
                file.read_at(40, &mut byte).unwrap();
                byte[0] ^= 0x10;
                file.write_at(40, &byte).unwrap();
                file.sync_data().unwrap();
            }
            Canary::Removed => backing.remove(path).unwrap(),
        }
    }
}

fn canary_lines(report: &CheckReport) -> (Vec<&String>, Vec<&String>) {
    let canary = |line: &&String| line.contains("key canary");
    (
        report.errors.iter().filter(canary).collect(),
        report.warnings.iter().filter(canary).collect(),
    )
}

/// A used v3 volume whose only unit was trimmed: no ciphertext remains.
async fn used_volume_without_ciphertext(checkpoint_trim: bool) -> Arc<dyn Backing> {
    let backing: Arc<dyn Backing> = Arc::new(MemBacking::new());
    init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    let engine = attach(&backing).await.unwrap();
    engine.write(0, &[7u8; UNIT as usize], true).await.unwrap();
    if !checkpoint_trim {
        engine.checkpoint().await.unwrap();
    }
    engine.trim(0, UNIT as usize, true).await.unwrap();
    if checkpoint_trim {
        engine.checkpoint().await.unwrap();
    }
    detach(engine).await;
    backing
}

#[tokio::test]
async fn canary_loss_on_a_used_volume_without_ciphertext_fails_the_deep_check() {
    for how in [Canary::Damaged, Canary::Removed] {
        // The trim is either checkpointed or still a journal tombstone that
        // recovery applies before attach looks for ciphertext to probe.
        for checkpoint_trim in [true, false] {
            let what = format!("{how:?}, trim checkpointed: {checkpoint_trim}");
            let backing = used_volume_without_ciphertext(checkpoint_trim).await;
            break_canary(backing.as_ref(), how);

            let report = deep_check(backing.clone(), 256 << 20).unwrap();
            if !checkpoint_trim {
                assert!(
                    report
                        .info
                        .iter()
                        .any(|line| line.contains("1 record(s) newer than the checkpoint")),
                    "{what}: the trim is not a journal tombstone: {:?}",
                    report.info
                );
            }
            let attached = attach(&backing).await;
            let error = attached
                .err()
                .unwrap_or_else(|| panic!("{what}: attach accepted the volume"));
            assert!(error.contains("no readable ciphertext"), "{what}: {error}");
            let (errors, warnings) = canary_lines(&report);
            assert!(
                !report.ok() && !errors.is_empty(),
                "{what}: deep check passed (errors {:?}, warnings {warnings:?}) although every \
                 attach refuses: {error}",
                report.errors
            );
            if matches!(how, Canary::Damaged) {
                assert!(
                    errors.iter().any(|line| line.contains("no copy validates")),
                    "{what}: {errors:?}"
                );
            }
        }
    }
}

/// A volume that still holds ciphertext can bind a new canary with an
/// integrity-capable provider, so the check must not fail it; it warns.
#[tokio::test]
async fn canary_loss_on_a_volume_with_ciphertext_is_a_warning() {
    for how in [Canary::Damaged, Canary::Removed] {
        let backing: Arc<dyn Backing> = Arc::new(MemBacking::new());
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
        let engine = attach(&backing).await.unwrap();
        engine.write(0, &[7u8; UNIT as usize], true).await.unwrap();
        engine.checkpoint().await.unwrap();
        detach(engine).await;
        break_canary(backing.as_ref(), how);

        let report = deep_check(backing.clone(), 256 << 20).unwrap();
        let (errors, warnings) = canary_lines(&report);
        assert!(errors.is_empty(), "{how:?}: {errors:?}");
        assert!(report.ok(), "{how:?}: {:?}", report.errors);
        assert!(
            warnings
                .iter()
                .any(|line| line.contains("integrity-capable provider")),
            "{how:?}: {warnings:?}"
        );
        if matches!(how, Canary::Damaged) {
            assert!(
                warnings
                    .iter()
                    .any(|line| line.contains("no copy validates")),
                "{how:?}: {warnings:?}"
            );
        }
        let engine = attach(&backing).await.unwrap();
        detach(engine).await;
    }
}

/// A pristine volume binds a new canary at the next attach.
#[tokio::test]
async fn canary_loss_on_a_pristine_volume_is_a_warning() {
    for how in [Canary::Damaged, Canary::Removed] {
        let backing: Arc<dyn Backing> = Arc::new(MemBacking::new());
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
        detach(attach(&backing).await.unwrap()).await;
        break_canary(backing.as_ref(), how);

        let report = deep_check(backing.clone(), 256 << 20).unwrap();
        let (errors, warnings) = canary_lines(&report);
        assert!(errors.is_empty(), "{how:?}: {errors:?}");
        assert!(report.ok(), "{how:?}: {:?}", report.errors);
        assert!(!warnings.is_empty(), "{how:?}: {:?}", report.warnings);
        detach(attach(&backing).await.unwrap()).await;
    }
}
