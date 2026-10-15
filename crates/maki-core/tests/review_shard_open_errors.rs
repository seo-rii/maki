//! BUG-124: every cataloged shard keeps its data file open from attach on,
//! so a volume with about a thousand shards meets the default soft limit of
//! 1024 descriptors. Opening a shard data file can therefore fail for a
//! resource reason; that is an I/O error to report as such, never the
//! "data file missing" corruption that sends operators after damage that
//! does not exist. A data file that really is missing stays corruption.

use std::io;
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::recovery::RecoveryError;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

const EMFILE: i32 = 24;

fn cataloged_volume() -> (Arc<CrashableBacking>, VolumeOptions) {
    let backing = Arc::new(CrashableBacking::new());
    let superblock = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::new_v4(),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * 1024, 512 * 64).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    init::create_volume(backing.as_ref(), superblock).unwrap();
    let options = VolumeOptions {
        journal_segment_size: 4096,
    };
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    volume.write_ct(0, &[7; 540], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    (backing, options)
}

#[test]
fn descriptor_exhaustion_opening_a_shard_is_not_reported_as_corruption() {
    let (backing, options) = cataloged_volume();
    let shard = layout::shard_data(0);
    backing.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| match op {
        FaultOp::Open {
            path,
            create: false,
        } if *path == shard => Some(io::Error::from_raw_os_error(EMFILE)),
        _ => None,
    })));
    match Volume::recover(backing.clone(), options.clone()) {
        Err(RecoveryError::Io(error)) => assert_eq!(error.raw_os_error(), Some(EMFILE)),
        Err(other) => panic!("descriptor exhaustion was reported as {other:?}"),
        Ok(_) => panic!("the injected open failure was ignored"),
    }

    // The condition is transient: with descriptors available the same
    // backing attaches and serves the checkpointed unit.
    backing.set_fault_hook(None);
    let volume = Volume::recover(backing, options).unwrap();
    let (_, ciphertext) = volume.read_ct(0).unwrap().expect("unit 0 was written");
    assert_eq!(ciphertext, vec![7; 540]);
}

#[test]
fn a_missing_shard_data_file_is_still_corruption() {
    let (backing, options) = cataloged_volume();
    backing.remove(&layout::shard_data(0)).unwrap();
    backing.sync_dir(layout::DATA_DIR).unwrap();
    match Volume::recover(backing, options) {
        Err(RecoveryError::Corrupt(message)) => assert!(
            message.contains("data file missing"),
            "unexpected corruption message: {message}"
        ),
        Err(other) => panic!("a missing data file was reported as {other:?}"),
        Ok(_) => panic!("a cataloged shard without its data file attached"),
    }
}
