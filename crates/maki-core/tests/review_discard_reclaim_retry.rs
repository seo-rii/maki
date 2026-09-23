//! Replay preserves reservations, then ordinary checkpoints must finish
//! interrupted physical reclamation without requiring another journal record.
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

fn fixture(large: bool) -> (Arc<CrashableBacking>, Volume, Geometry) {
    let backing = Arc::new(CrashableBacking::new());
    let size = if large { 16 << 20 } else { 8 << 10 };
    let geometry = Geometry::compute(512, 1024, 512, 1032, size * 2, size).unwrap();
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xdec1a17),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: geometry.clone(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    (backing, volume, geometry)
}

fn raw_slot(backing: &CrashableBacking, geometry: &Geometry, unit: u64) -> Vec<u8> {
    let (shard, in_shard) = geometry.shard_of_unit(unit);
    let mut bytes = vec![0; geometry.slot_size as usize];
    backing
        .open(&layout::shard_data(shard), false)
        .unwrap()
        .read_at(geometry.slot_offset(in_shard), &mut bytes)
        .unwrap();
    bytes
}

fn recovered_discard() -> (Arc<CrashableBacking>, Volume, Geometry) {
    let (backing, mut volume, geometry) = fixture(false);
    volume.write_ct(1, &[0x41; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(1, true).unwrap();
    drop(volume);
    let recovered = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    assert!(recovered.read_ct(1).unwrap().is_none());
    assert!(raw_slot(&backing, &geometry, 1).iter().any(|b| *b != 0));
    (backing, recovered, geometry)
}

#[test]
fn idle_checkpoint_reclaims_a_discard_consumed_by_recovery() {
    let (backing, mut volume, geometry) = recovered_discard();
    let sequence = volume.checkpoint_sequence();
    assert_eq!(sequence, volume.journal_appended_sequence());
    assert_eq!(volume.checkpoint().unwrap(), sequence);
    assert!(raw_slot(&backing, &geometry, 1).iter().all(|b| *b == 0));
    assert!(volume.read_ct(1).unwrap().is_none());
}

#[test]
fn failed_reclamation_retains_its_cursor_for_retry() {
    let (backing, mut volume, geometry) = recovered_discard();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        matches!(op, FaultOp::WriteAt { path, .. } if path.ends_with(".dat"))
            .then(|| io::Error::other("physical release temporarily failed"))
    })));
    assert!(volume.checkpoint().is_err());
    assert!(volume.read_ct(1).unwrap().is_none());
    backing.set_fault_hook(None);
    volume.checkpoint().unwrap();
    assert!(raw_slot(&backing, &geometry, 1).iter().all(|b| *b == 0));
}

#[test]
fn recovered_discard_does_not_release_a_newer_write_reservation() {
    let (backing, mut volume, geometry) = recovered_discard();
    volume.write_ct(1, &[0x42; 1032], false).unwrap();
    // A newer tombstone can hide a still-needed intermediate write slot.
    volume.discard_ct(1, false).unwrap();
    let before = raw_slot(&backing, &geometry, 1);
    volume.checkpoint().unwrap();
    assert_eq!(raw_slot(&backing, &geometry, 1), before);
    volume.flush().unwrap();
    volume.checkpoint().unwrap();
    assert!(raw_slot(&backing, &geometry, 1).iter().all(|b| *b == 0));
}

#[test]
fn reclamation_scans_a_bounded_number_of_slots_per_checkpoint() {
    let (backing, mut volume, geometry) = fixture(true);
    // Both units belong to one shard, on opposite sides of the scan budget.
    for unit in [1, 4097] {
        volume.write_ct(unit, &[0x51; 1032], true).unwrap();
    }
    volume.checkpoint().unwrap();
    for unit in [1, 4097] {
        volume.discard_ct(unit, true).unwrap();
    }
    drop(volume);
    let mut recovered = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    recovered.checkpoint().unwrap();
    assert!(raw_slot(&backing, &geometry, 1).iter().all(|b| *b == 0));
    assert!(raw_slot(&backing, &geometry, 4097).iter().any(|b| *b != 0));
    recovered.checkpoint().unwrap();
    assert!(raw_slot(&backing, &geometry, 4097).iter().all(|b| *b == 0));
}

#[tokio::test]
async fn idle_background_worker_reclaims_after_attach_without_new_writes() {
    let (backing, volume, geometry) = fixture(false);
    drop(volume);
    let provider = Arc::new(FakeCryptoProvider::new(1024));
    let options = || EngineOptions {
        checkpoint: CheckpointPolicy {
            interval: Duration::from_millis(10),
            journal_high_watermark_bytes: u64::MAX,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let engine = Engine::attach(backing.clone(), provider.clone(), options())
        .await
        .unwrap();
    engine.stop_checkpoint_worker().await;
    engine.write(1024, &[0x61; 1024], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine.trim(1024, 1024, true).await.unwrap();
    drop(engine);

    let punches = Arc::new(AtomicUsize::new(0));
    let observed = punches.clone();
    let released = Arc::new(tokio::sync::Notify::new());
    let notified = released.clone();
    let slot_size = geometry.slot_size as usize;
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(op, FaultOp::WriteAt { path, len, .. }
            if path.ends_with(".dat") && *len == slot_size)
        {
            observed.fetch_add(1, Ordering::SeqCst);
            notified.notify_one();
        }
        None
    })));
    let recovered = Engine::attach(backing.clone(), provider, options())
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), released.notified()).await;
    recovered.stop_checkpoint_worker().await;
    assert!(
        result.is_ok(),
        "idle worker never attempted physical reclamation"
    );
    assert_eq!(punches.load(Ordering::SeqCst), 1);
    assert!(raw_slot(&backing, &geometry, 1).iter().all(|b| *b == 0));
    assert_eq!(recovered.read(1024, 1024).await.unwrap(), vec![0; 1024]);
}
