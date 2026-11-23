//! Audit round 4 (storage-review): #194 checks covered journal records
//! against slot metadata in windows of `MAX_CHECKPOINT_UNITS` (65,536)
//! units; journals naming more distinct covered units take the rescan path
//! (`verify_checkpoint_slots` rereads every verified prefix per window). The
//! in-crate unit tests only exercise windows with a limit of 2. This probes
//! the real multi-window path end to end: a valid but stale slot header in
//! the first and in the second window must both refuse recovery, and a
//! healthy volume must attach.

use std::sync::Arc;

use maki_backing::{Backing, MemBacking};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::slot::SlotHeader;
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};

const UNITS: u64 = 70_000;

fn options() -> VolumeOptions {
    VolumeOptions {
        // Keep every record in one never-sealed segment, so the covered
        // records survive the checkpoint.
        journal_segment_size: 64 << 20,
    }
}

fn build() -> (Arc<MemBacking>, Geometry) {
    let backing = Arc::new(MemBacking::new());
    let geometry = Geometry::compute(512, 512, 512, 520, UNITS * 512, 4096 * 512).unwrap();
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xa4_e71d),
            provider_type: "fake".into(),
            crypto_compatibility_id: "windows".into(),
            key_identity: "k".into(),
            geometry: geometry.clone(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(backing.clone(), options()).unwrap();
    for unit in 0..UNITS {
        volume
            .write_ct(unit, &(unit as u32).to_le_bytes(), false)
            .unwrap();
    }
    volume.flush().unwrap();
    assert_eq!(volume.checkpoint().unwrap(), UNITS);
    assert!(volume.journal_segment_count() > 0, "covered records must survive");
    drop(volume);
    (backing, geometry)
}

/// Rewrite one slot header with a valid, but older, write sequence.
fn make_stale(backing: &MemBacking, geometry: &Geometry, unit: u64) {
    let (shard, in_shard) = geometry.shard_of_unit(unit);
    let file = backing.open(&layout::shard_data(shard), false).unwrap();
    let offset = geometry.slot_offset(in_shard);
    let mut bytes = [0u8; 64];
    file.read_at(offset, &mut bytes).unwrap();
    let mut header = SlotHeader::decode(&bytes).unwrap();
    assert_eq!(header.write_sequence, unit + 1);
    assert!(header.write_sequence > 1);
    header.write_sequence -= 1;
    file.write_at(offset, &header.encode()).unwrap();
}

#[test]
fn multi_window_covered_slot_verification() {
    let (backing, geometry) = build();
    // Control: a healthy volume attaches (and nothing is replayed).
    let volume = Volume::recover(backing.clone(), options()).expect("healthy volume attaches");
    assert_eq!(volume.checkpoint_sequence(), UNITS);
    drop(volume);

    // First window.
    make_stale(&backing, &geometry, 7);
    let first = Volume::recover(backing.clone(), options());
    eprintln!("stale slot in window 1: {:?}", first.as_ref().err());
    assert!(first.is_err(), "stale slot metadata in the first window was accepted");
    drop(first);

    // Second window only.
    let (backing, geometry) = build();
    make_stale(&backing, &geometry, UNITS - 3);
    let second = Volume::recover(backing.clone(), options());
    eprintln!("stale slot in window 2: {:?}", second.as_ref().err());
    assert!(second.is_err(), "stale slot metadata in the second window was accepted");
    let report = maki_core::check::deep_check(backing.clone(), 64 << 20).unwrap();
    eprintln!("deep check errors: {:?}", report.errors);
    assert!(!report.errors.is_empty(), "deep check missed the second-window stale slot");
}
