//! Failed first-write reservations remain reclaimable through ordinary v3 TRIM.
#![cfg(target_os = "linux")]

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use maki_backing::{Backing, FileBacking};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::failpoints::{self, FailpointAction};

fn fixture() -> (tempfile::TempDir, Arc<FileBacking>, Volume) {
    let directory = tempfile::tempdir().unwrap();
    let backing = Arc::new(FileBacking::new(directory.path()).unwrap());
    let probe = backing.open("audit-punch-probe", true).unwrap();
    probe.allocate_range(0, 16384).unwrap();
    probe.punch_hole(0, 16384).unwrap();
    drop(probe);
    backing.remove("audit-punch-probe").unwrap();
    let geometry = Geometry::compute(512, 4096, 512, 4104, 1 << 20, 1 << 20).unwrap();
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xa0d17019),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry,
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    (directory, backing, volume)
}

#[test]
fn successful_write_reservations_are_reclaimed_by_trim_control() {
    let _lock = failpoints::test_lock();
    let (directory, _backing, mut volume) = fixture();
    for unit in 0..128 {
        volume.write_ct(unit, &[0x71; 4104], false).unwrap();
    }
    volume.flush().unwrap();
    volume.checkpoint().unwrap();
    let path = directory.path().join(layout::shard_data(0));
    let before = std::fs::metadata(&path).unwrap().blocks();
    for unit in 0..128 {
        volume.discard_ct(unit, false).unwrap();
    }
    volume.flush().unwrap();
    volume.checkpoint().unwrap();
    let after = std::fs::metadata(&path).unwrap().blocks();
    eprintln!("successful writes: allocated blocks {before} -> {after}");
    assert!(after < before / 4);
}

#[test]
fn rejected_first_write_reservations_remain_reclaimable_after_trim_and_restart() {
    let _lock = failpoints::test_lock();
    let (directory, backing, mut volume) = fixture();
    let failure = failpoints::set(
        "journal.append.write",
        FailpointAction::IoError(
            std::io::ErrorKind::StorageFull,
            "audit append refusal".into(),
        ),
    );
    for unit in 0..128 {
        assert!(volume.write_ct(unit, &[0x71; 4104], false).is_err());
        assert!(volume.read_ct(unit).unwrap().is_none());
    }
    drop(failure);
    assert_eq!(volume.journal_appended_sequence(), 0);
    assert_eq!(volume.overlay_len(), 0);
    let allocation =
        maki_format::ab::AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0))
            .load::<maki_format::allocation::AllocationMap>(backing.as_ref())
            .unwrap()
            .unwrap();
    assert_eq!(allocation.set_count(), 0);
    let path = directory.path().join(layout::shard_data(0));
    let before = std::fs::metadata(&path).unwrap().blocks();
    assert!(
        before >= 128 * 8,
        "reservations should consume physical blocks"
    );
    for unit in 0..128 {
        volume.discard_ct(unit, false).unwrap();
    }
    assert_eq!(volume.journal_appended_sequence(), 0);
    volume.flush().unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    let mut recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    for _ in 0..8 {
        recovered.checkpoint().unwrap();
    }
    let after = std::fs::metadata(&path).unwrap().blocks();
    eprintln!("rejected writes: allocated blocks {before} -> {after}");
    assert!(
        after < before / 4,
        "TRIM/checkpoint/restart retained {after} of {before} allocated blocks for writes never accepted"
    );
}

#[test]
fn trim_after_restart_reclaims_failed_reservations_without_an_in_memory_tracker() {
    let _lock = failpoints::test_lock();
    let (directory, backing, mut volume) = fixture();
    let failure = failpoints::set(
        "journal.append.write",
        FailpointAction::IoError(std::io::ErrorKind::StorageFull, "append refusal".into()),
    );
    for unit in 0..128 {
        assert!(volume.write_ct(unit, &[0x71; 4104], false).is_err());
    }
    drop(failure);
    drop(volume);
    let mut volume = Volume::recover(backing, VolumeOptions::default()).unwrap();
    let path = directory.path().join(layout::shard_data(0));
    let before = std::fs::metadata(&path).unwrap().blocks();
    assert!(before >= 128 * 8);
    for unit in 0..128 {
        volume.discard_ct(unit, false).unwrap();
    }
    volume.checkpoint().unwrap();
    let after = std::fs::metadata(&path).unwrap().blocks();
    assert!(
        after < before / 4,
        "failed reservation survives post-restart TRIM: {before} -> {after}"
    );
}

#[test]
fn discard_marker_barrier_failure_keeps_the_reservation_until_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let _lock = failpoints::test_lock();
    for (point, fail_at) in [
        ("discard.store", 0),
        ("discard.store", 1),
        ("discard.dirsync", 0),
    ] {
        let (directory, _backing, mut volume) = fixture();
        let failure = failpoints::set(
            "journal.append.write",
            FailpointAction::IoError(std::io::ErrorKind::StorageFull, "append refusal".into()),
        );
        for unit in 0..128 {
            assert!(volume.write_ct(unit, &[0x71; 4104], false).is_err());
        }
        drop(failure);
        let path = directory.path().join(layout::shard_data(0));
        let before = std::fs::metadata(&path).unwrap().blocks();
        for unit in 0..128 {
            volume.discard_ct(unit, false).unwrap();
        }
        let calls = AtomicUsize::new(0);
        let failure = failpoints::set(
            point,
            FailpointAction::Callback(Arc::new(move || {
                (calls.fetch_add(1, Ordering::SeqCst) == fail_at)
                    .then(|| std::io::Error::other("discard barrier refusal"))
            })),
        );
        assert!(volume.checkpoint().is_err(), "{point} call {fail_at}");
        assert_eq!(std::fs::metadata(&path).unwrap().blocks(), before);
        drop(failure);
        volume.checkpoint().unwrap();
        assert!(std::fs::metadata(&path).unwrap().blocks() < before / 4);
    }
}

#[test]
fn a_failed_punch_retries_the_durable_zero_trim_after_restart() {
    let _lock = failpoints::test_lock();
    let (directory, backing, mut volume) = fixture();
    let failure = failpoints::set(
        "journal.append.write",
        FailpointAction::IoError(std::io::ErrorKind::StorageFull, "append refusal".into()),
    );
    for unit in 0..128 {
        assert!(volume.write_ct(unit, &[0x71; 4104], false).is_err());
    }
    drop(failure);
    let path = directory.path().join(layout::shard_data(0));
    let before = std::fs::metadata(&path).unwrap().blocks();
    for unit in 0..128 {
        volume.discard_ct(unit, false).unwrap();
    }
    let failure = failpoints::set(
        "discard.punch",
        FailpointAction::IoError(std::io::ErrorKind::Other, "punch refusal".into()),
    );
    volume.checkpoint().unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().blocks(), before);
    drop(failure);
    drop(volume);
    let mut recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    recovered.checkpoint().unwrap();
    assert!(std::fs::metadata(&path).unwrap().blocks() < before / 4);
}

#[test]
fn a_later_write_uses_the_reserved_slot_before_reclamation() {
    let _lock = failpoints::test_lock();
    let (_directory, backing, mut volume) = fixture();
    let failure = failpoints::set(
        "journal.append.write",
        FailpointAction::IoError(std::io::ErrorKind::StorageFull, "append refusal".into()),
    );
    assert!(volume.write_ct(0, &[0x71; 4104], false).is_err());
    drop(failure);
    volume.discard_ct(0, false).unwrap();
    volume.write_ct(0, &[0x72; 4104], true).unwrap();
    volume.checkpoint().unwrap();
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![0x72; 4104]);
    drop(volume);
    let volume = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![0x72; 4104]);
}

#[test]
fn engine_zero_trim_keeps_failed_reservations_in_the_reclamation_set() {
    use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
    use maki_test_support::FakeCryptoProvider;
    let _lock = failpoints::test_lock();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (directory, _backing, volume) = fixture();
        let engine = Engine::attach_recovered(
            volume,
            Arc::new(FakeCryptoProvider::new(4096)),
            EngineOptions {
                checkpoint: CheckpointPolicy {
                    emergency_reserve_bytes: 0,
                    low_space_checkpoint_bytes: 0,
                    journal_high_watermark_bytes: u64::MAX,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        engine.stop_checkpoint_worker().await;
        let failure = failpoints::set(
            "journal.append.write",
            FailpointAction::IoError(std::io::ErrorKind::StorageFull, "append refusal".into()),
        );
        for unit in 0..128 {
            assert!(engine
                .write(unit * 4096, &[0x71; 4096], false)
                .await
                .is_err());
        }
        drop(failure);
        let path = directory.path().join(layout::shard_data(0));
        let before = std::fs::metadata(&path).unwrap().blocks();
        assert!(before >= 128 * 8);
        engine.trim(0, 128 * 4096, true).await.unwrap();
        engine.checkpoint().await.unwrap();
        assert_eq!(engine.stats().await.appended_sequence, 0);
        let after = std::fs::metadata(&path).unwrap().blocks();
        assert!(
            after < before / 4,
            "engine filtered reclamation: {before} -> {after}"
        );
    });
}
