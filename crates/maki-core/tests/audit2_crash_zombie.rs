//! Audit (round 2, durability-pr-review): #167 made every file and lock
//! handle opened before a simulated power loss dead afterwards, because "no
//! power loss can produce" a state the dead process changed afterwards. The
//! namespace operations of the shared `CrashableBacking` (open/create,
//! remove, rename, sync_dir) carry no epoch, so a component of the dead
//! process that is still alive in the test (a `Volume` or `Engine` not yet
//! dropped, a checkpoint worker mid-pass, a detached publish task) still
//! creates files through *new* handles and makes them durable after the
//! power loss. Here a pre-crash `Volume` acknowledges a FUA write after the
//! power loss (it rolls into a new segment opened through the backing), and
//! the next recovery serves that write.

use std::sync::Arc;

use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::CrashableBacking;

const CT: usize = 520;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

#[test]
fn a_volume_of_the_dead_process_still_writes_durably_after_a_power_loss() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xA2DE_AD00),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, CT as u32, 512 * 64, 512 * 64).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();

    let mut dead = Volume::recover(backing.clone(), options()).unwrap();
    // Fill the active segment with synced records, so the next append rolls
    // (sealing a segment with nothing unsynced touches no old handle).
    for unit in 0..7 {
        dead.write_ct(unit, &[0x11; CT], true).unwrap();
    }

    backing.crash_all_lost(); // the process holding `dead` is gone

    let zombie = dead.write_ct(1, &[0xEE; CT], true);
    eprintln!("write by the dead process after the power loss: {zombie:?}");
    drop(dead);

    let recovered = Volume::recover(backing.clone(), options()).unwrap();
    let unit1 = recovered.read_ct(1).unwrap().map(|(_, ct)| ct[0]);
    assert!(
        zombie.is_err() && unit1 == Some(0x11),
        "a process killed by the power loss acknowledged a FUA write afterwards ({zombie:?}) \
         and recovery serves it: unit 1 starts with {unit1:x?} (0xee = the dead process's write)"
    );
}
