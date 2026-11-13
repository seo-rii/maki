//! Progress observations must follow completed recovery work and disappear
//! from normal volume I/O. They do not move the persistent replay horizon.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

fn fixture() -> (Arc<CrashableBacking>, Volume) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x9A096E55),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "fixture".into(),
            geometry: Geometry::compute(512, 512, 512, 512, 512 * 64, 512 * 64).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    (backing, volume)
}

#[test]
fn recovery_observations_cover_replay_but_are_not_retained_for_live_io() {
    let (backing, mut volume) = fixture();
    for unit in 0..16 {
        volume.write_ct(unit, &[unit as u8; 512], false).unwrap();
    }
    volume.flush().unwrap();
    drop(volume);

    let completed = AtomicUsize::new(0);
    let mut volume =
        Volume::recover_with_progress(backing.clone(), VolumeOptions::default(), &|| {
            completed.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    assert_eq!(volume.checkpoint_sequence(), 16);
    assert!(
        completed.load(Ordering::SeqCst) > 16,
        "scan and replay must expose ongoing work"
    );
    let observed = completed.load(Ordering::SeqCst);
    volume.write_ct(0, &[99; 512], true).unwrap();
    volume.checkpoint().unwrap();
    assert_eq!(completed.load(Ordering::SeqCst), observed);
    drop(volume);
    backing.crash_all_lost();
    let volume = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![99; 512]);
    for unit in 1..16 {
        assert_eq!(
            volume.read_ct(unit).unwrap().unwrap().1,
            vec![unit as u8; 512]
        );
    }
}

#[test]
fn allocation_map_repair_reports_each_completed_slot_probe() {
    let (backing, mut volume) = fixture();
    volume.write_ct(0, &[37; 512], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    backing.remove(&layout::shard_alloc_b(0)).unwrap();
    backing.sync_dir(layout::DATA_DIR).unwrap();
    let completed = AtomicUsize::new(0);
    let volume = Volume::recover_with_progress(backing, VolumeOptions::default(), &|| {
        completed.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    // A single metadata phase notification cannot keep a slow header scan
    // alive: this fixture has at least63 unallocated positions to inspect.
    assert!(completed.load(Ordering::SeqCst) >= 63);
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![37; 512]);
}

#[test]
fn a_blocked_failed_replay_barrier_does_not_report_progress() {
    let (backing, mut volume) = fixture();
    for unit in 0..16 {
        volume.write_ct(unit, &[unit as u8; 512], false).unwrap();
    }
    volume.flush().unwrap();
    drop(volume);
    let completed = Arc::new(AtomicUsize::new(0));
    let observed = completed.clone();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    backing.set_fault_hook(Some(Arc::new(move |operation| {
        if matches!(operation, FaultOp::SyncData { path } if path.ends_with(".dat")) {
            entered_tx.send(observed.load(Ordering::SeqCst)).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            return Some(io::Error::other("injected blocked recovery barrier"));
        }
        None
    })));
    let worker_backing = backing.clone();
    let worker_count = completed.clone();
    let worker = std::thread::spawn(move || {
        Volume::recover_with_progress(worker_backing, VolumeOptions::default(), &|| {
            worker_count.fetch_add(1, Ordering::SeqCst);
        })
    });
    let at_barrier = entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let while_blocked = completed.load(Ordering::SeqCst);
    release_tx.send(()).unwrap();
    assert!(worker.join().unwrap().is_err());
    assert_eq!(while_blocked, at_barrier);
    assert_eq!(completed.load(Ordering::SeqCst), at_barrier);

    backing.set_fault_hook(None);
    backing.crash_all_lost();
    let volume = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert_eq!(volume.checkpoint_sequence(), 16);
    for unit in 0..16 {
        assert_eq!(
            volume.read_ct(unit).unwrap().unwrap().1,
            vec![unit as u8; 512]
        );
    }
}
