//! BUG-020: failed sync must not lose a previously truncated journal length.
//! These tests persist a failed append prefix before retrying a shorter record.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{crash_backing::FaultOp, failpoints, CrashableBacking};
use uuid::Uuid;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}
fn new_volume(backing: &Arc<CrashableBacking>, discard: bool) -> Volume {
    let superblock = Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x202610120001),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 1024, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock).unwrap();
    }
    Volume::recover(backing.clone(), options()).unwrap()
}

fn fill(volume: &mut Volume) {
    for unit in 0..3 {
        volume
            .write_ct(unit, &vec![(unit + 1) as u8; 940], true)
            .unwrap();
    }
}

fn partial_append(backing: &Arc<CrashableBacking>, volume: &mut Volume) -> String {
    let path = volume.journal_active_segment_path().unwrap();
    let once = Arc::new(AtomicBool::new(true));
    let target = path.clone();
    backing.set_partial_write_hook(Some(Arc::new(move |op| match op {
        FaultOp::WriteAt { path, .. } if *path == target && once.swap(false, Ordering::SeqCst) => {
            Some((
                700,
                io::Error::new(io::ErrorKind::StorageFull, "partial ENOSPC"),
            ))
        }
        _ => None,
    })));
    assert!(volume.write_ct(3, &vec![9; 1000], false).is_err());
    backing.set_partial_write_hook(None);
    // Background writeback may persist a failed syscall's partial prefix.
    backing.open(&path, false).unwrap().sync_data().unwrap();
    assert!(backing.open(&path, false).unwrap().len().unwrap() > 3060);
    path
}

fn fail_sync_once(backing: &Arc<CrashableBacking>, path: &str) {
    let target = path.to_owned();
    let once = Arc::new(AtomicBool::new(true));
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if *path == target && once.swap(false, Ordering::SeqCst) => {
            Some(io::Error::other(
                "writeback EIO clears all dirty operations",
            ))
        }
        _ => None,
    })));
}

fn assert_data(volume: &Volume) {
    for unit in 0..3 {
        assert_eq!(
            volume.read_ct(unit).unwrap().unwrap().1,
            vec![(unit + 1) as u8; 940]
        );
    }
    assert!(volume.read_ct(3).unwrap().is_none());
    assert_eq!(volume.read_ct(5).unwrap().unwrap().1, vec![3; 1024]);
}

#[test]
fn flush_retry_after_shorter_append_must_republish_exact_length() {
    let _guard = failpoints::test_lock();
    for discard in [false, true] {
        let backing = Arc::new(CrashableBacking::new().with_tearing(512));
        let mut volume = new_volume(&backing, discard);
        fill(&mut volume);
        let path = partial_append(&backing, &mut volume);
        assert_eq!(volume.write_ct(4, &[2; 64], false).unwrap(), 4);
        assert_eq!(backing.open(&path, false).unwrap().len().unwrap(), 3060);
        fail_sync_once(&backing, &path);
        assert!(volume.flush().is_err());
        backing.set_fault_hook(None);
        volume.flush().unwrap();
        volume.write_ct(5, &vec![3; 1024], true).unwrap();
        assert_eq!(volume.journal_segment_count(), 2);
        drop(volume);
        backing.crash_all_lost();
        println!(
            "post_crash_old_segment_len={}",
            backing.open(&path, false).unwrap().len().unwrap()
        );
        let result = Volume::recover(backing.clone(), options());
        if let Err(ref e) = result {
            println!("recovery_error={e:?}");
        }
        let volume = result
            .expect("successful FLUSH retry and subsequent FUA must preserve a recoverable volume");
        assert_data(&volume);
        assert_eq!(volume.read_ct(4).unwrap().unwrap().1, vec![2; 64]);
    }
}

#[test]
fn failed_recovery_truncate_then_restart_must_republish_exact_length() {
    let _guard = failpoints::test_lock();
    for discard in [false, true] {
        let backing = Arc::new(CrashableBacking::new().with_tearing(512));
        let mut volume = new_volume(&backing, discard);
        fill(&mut volume);
        // Keep an already checkpoint-covered active segment: ordinary checkpoint
        // reclaims only sealed segments. A successful bounded recovery therefore
        // has no uncovered replay and does not delete this segment.
        assert_eq!(volume.checkpoint().unwrap(), 3);
        assert_eq!(volume.journal_segment_count(), 1);
        let path = partial_append(&backing, &mut volume);
        drop(volume);
        fail_sync_once(&backing, &path);
        let first = Volume::recover(backing.clone(), options());
        assert!(first.is_err());
        drop(first);
        backing.set_fault_hook(None);
        assert_eq!(backing.open(&path, false).unwrap().len().unwrap(), 2964);
        let mut volume = Volume::recover(backing.clone(), options())
            .expect("restart after failed truncation sync should stabilize accepted image");
        assert_eq!(volume.checkpoint_sequence(), 3);
        assert_eq!(volume.journal_segment_count(), 1);
        volume.write_ct(5, &vec![3; 1024], true).unwrap();
        assert_eq!(volume.journal_segment_count(), 2);
        drop(volume);
        backing.crash_all_lost();
        println!(
            "post_crash_old_segment_len={}",
            backing.open(&path, false).unwrap().len().unwrap()
        );
        let result = Volume::recover(backing.clone(), options());
        if let Err(ref e) = result {
            println!("recovery_error={e:?}");
        }
        let volume = result.expect(
            "successful recovery restart and subsequent FUA must preserve a recoverable volume",
        );
        assert_data(&volume);
    }
}

#[test]
fn cleanup_only_flush_retries_length_even_without_new_accepted_records() {
    let _guard = failpoints::test_lock();
    for discard in [false, true] {
        let backing = Arc::new(CrashableBacking::new().with_tearing(512));
        let mut volume = new_volume(&backing, discard);
        fill(&mut volume);
        let path = partial_append(&backing, &mut volume);
        fail_sync_once(&backing, &path);
        assert!(volume.flush().is_err());
        backing.set_fault_hook(None);
        volume.flush().unwrap();
        assert_eq!(volume.journal_durable_sequence(), 3);
        volume.write_ct(5, &[3; 1024], true).unwrap();
        drop(volume);
        backing.crash_all_lost();
        let volume = Volume::recover(backing, options())
            .expect("tail removal after failed sync is durable without a new accepted record");
        assert_data(&volume);
    }
}

#[test]
fn failed_length_reassertion_refuses_flush_and_keeps_retry_armed() {
    let _guard = failpoints::test_lock();
    for discard in [false, true] {
        let backing = Arc::new(CrashableBacking::new().with_tearing(512));
        let mut volume = new_volume(&backing, discard);
        fill(&mut volume);
        let path = partial_append(&backing, &mut volume);
        volume.write_ct(4, &[2; 64], false).unwrap();
        fail_sync_once(&backing, &path);
        assert!(volume.flush().is_err());

        let target = path.clone();
        let truncate_failed = Arc::new(AtomicBool::new(false));
        let failed_in_hook = truncate_failed.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SetLen { path, .. } if *path == target => {
                failed_in_hook.store(true, Ordering::SeqCst);
                Some(io::Error::other("exact length could not be reasserted"))
            }
            _ => None,
        })));
        assert!(volume.flush().is_err(), "a failed length retry cannot ACK");
        assert!(truncate_failed.load(Ordering::SeqCst));
        backing.set_fault_hook(None);
        volume.flush().unwrap();
        assert_eq!(volume.journal_durable_sequence(), 4);
        volume.write_ct(5, &[3; 1024], true).unwrap();
        drop(volume);
        backing.crash_all_lost();
        let volume = Volume::recover(backing, options()).unwrap();
        assert_data(&volume);
        assert_eq!(volume.read_ct(4).unwrap().unwrap().1, vec![2; 64]);
    }
}
