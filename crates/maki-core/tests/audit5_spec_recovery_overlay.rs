//! Round-5 audit (docs-spec): what attach-time recovery does with the
//! journal records above the checkpoint.
//!
//! `docs/architecture.md` ("Recovery and checkpointing") says recovery
//! "scans journal segments, and rebuilds the in-memory overlay from records
//! newer than the checkpoint", and that "Volume attach retains only the
//! latest record per unit". SPEC §27 says instead that a second scan replays
//! the accepted records "through a bounded ciphertext batch into checkpoint
//! slots", advances the checkpoint and prunes the covered segments before
//! READY. These tests record which of the two the code does.

use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::{failpoints, CrashableBacking};
use uuid::Uuid;

const SEGMENT: u64 = 4096;
const UNITS: u64 = 128;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: SEGMENT,
    }
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xa0d1_7005),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * UNITS, 512 * 48).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn ct(unit: u64, version: u64) -> Vec<u8> {
    let mut v = vec![(unit as u8).wrapping_mul(31).wrapping_add(version as u8); 540];
    v[..8].copy_from_slice(&unit.to_le_bytes());
    v[8..16].copy_from_slice(&version.to_le_bytes());
    v
}

/// After a restart (and after a power loss) with durable, never
/// checkpointed records in the journal, the recovered volume has an EMPTY
/// overlay: recovery applied every record to its slot, advanced the
/// checkpoint to the durable sequence and deleted every journal segment.
#[test]
fn attach_recovery_checkpoints_the_journal_and_leaves_the_overlay_empty() {
    let _guard = failpoints::test_lock();
    for power_loss in [false, true] {
        let backing = Arc::new(CrashableBacking::new().with_tearing(512));
        init::create_volume(backing.as_ref(), superblock()).unwrap();

        let mut volume = Volume::recover(backing.process() as Arc<dyn Backing>, options()).unwrap();
        // Twenty units, two versions each: several 4 KiB segments.
        for version in 1..=2u64 {
            for unit in 0..20u64 {
                volume.write_ct(unit, &ct(unit, version), false).unwrap();
            }
        }
        volume.flush().unwrap();
        let durable = volume.journal_durable_sequence();
        assert_eq!(durable, 40);
        assert_eq!(volume.checkpoint_sequence(), 0, "nothing checkpointed yet");
        assert!(volume.overlay_len() > 0);
        assert!(volume.journal_segment_count() > 1);
        drop(volume);
        if power_loss {
            backing.crash_all_lost();
        }

        let volume = Volume::recover(backing.process() as Arc<dyn Backing>, options()).unwrap();
        eprintln!(
            "power_loss={power_loss}: overlay_len={} overlay_bytes={} checkpoint={} durable={} \
             segments={}",
            volume.overlay_len(),
            volume.overlay_bytes(),
            volume.checkpoint_sequence(),
            volume.journal_durable_sequence(),
            volume.journal_segment_count(),
        );
        // SPEC §27's description holds; docs/architecture.md's does not.
        assert_eq!(
            volume.overlay_len(),
            0,
            "recovery did not rebuild the overlay from the journal"
        );
        assert_eq!(volume.overlay_bytes(), 0);
        assert_eq!(volume.checkpoint_sequence(), durable);
        assert_eq!(volume.journal_segment_count(), 0);
        for unit in 0..20u64 {
            let (sequence, data) = volume.read_ct(unit).unwrap().unwrap();
            assert_eq!(data, ct(unit, 2));
            assert_eq!(sequence, 20 + unit + 1);
        }
    }
}
