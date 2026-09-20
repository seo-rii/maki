use maki_backing::{Backing, MemBacking};
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::checker::check_volume;
use maki_format::durable_proof::{DURABLE_PROOF_A, DURABLE_PROOF_B};
use maki_format::geometry::Geometry;
use maki_format::superblock::{
    load_volume_superblock, Superblock, VolumeSuperblock, SUPERBLOCK_SIZE, SUPERBLOCK_VERSION_V2,
    SUPERBLOCK_VERSION_V3,
};
use maki_format::{init, layout, FormatError};
use uuid::Uuid;

fn sb() -> Superblock {
    Superblock {
        generation: 9,
        volume_uuid: Uuid::from_u128(0x1234),
        provider_type: "remote-http".into(),
        crypto_compatibility_id: "profile-v1".into(),
        key_identity: "key-1".into(),
        geometry: Geometry::compute(4096, 4096, 512, 4384, 64 << 20, 16 << 20).unwrap(),
        format_version: 1,
        created_unix: 1,
    }
}

fn rewrite_version(bytes: &mut [u8], version: u32) {
    bytes[8..12].copy_from_slice(&version.to_le_bytes());
    let crc = crc32fast::hash(&bytes[..SUPERBLOCK_SIZE - 4]);
    bytes[SUPERBLOCK_SIZE - 4..].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn default_creation_remains_v2_and_discard_creation_is_v3() {
    let old = MemBacking::new();
    let original = sb();
    init::create_volume(&old, original.clone()).unwrap();
    let loaded = load_volume_superblock(&old).unwrap();
    assert_eq!(loaded.metadata_version, SUPERBLOCK_VERSION_V2);
    assert_eq!(loaded.superblock.format_version, original.format_version);

    let new = MemBacking::new();
    init::create_volume_with_discard(&new, original.clone()).unwrap();
    let loaded = load_volume_superblock(&new).unwrap();
    assert_eq!(loaded.metadata_version, SUPERBLOCK_VERSION_V3);
    assert_eq!(loaded.superblock.format_version, original.format_version);
    assert!(new.exists(layout::SUPERBLOCK_A).unwrap());
    assert!(new.exists(layout::SUPERBLOCK_B).unwrap());
}

#[test]
fn v3_envelope_roundtrips_but_unknown_v4_and_mixed_versions_fail_closed() {
    let record = VolumeSuperblock {
        superblock: sb(),
        metadata_version: SUPERBLOCK_VERSION_V3,
    };
    assert_eq!(VolumeSuperblock::decode(&record.encode()).unwrap(), record);

    let backing = MemBacking::new();
    init::create_volume_with_discard(&backing, sb()).unwrap();
    let file = backing.open(layout::SUPERBLOCK_B, false).unwrap();
    let mut bytes = vec![0; SUPERBLOCK_SIZE];
    file.read_at(0, &mut bytes).unwrap();
    rewrite_version(&mut bytes, 4);
    file.write_at(0, &bytes).unwrap();
    assert!(matches!(
        load_volume_superblock(&backing),
        Err(FormatError::Unsupported(_))
    ));

    rewrite_version(&mut bytes, SUPERBLOCK_VERSION_V2);
    file.write_at(0, &bytes).unwrap();
    assert!(matches!(
        load_volume_superblock(&backing),
        Err(FormatError::Invalid(_))
    ));
}

#[test]
fn v3_requires_durable_proof() {
    let backing = MemBacking::new();
    init::create_volume_with_discard(&backing, sb()).unwrap();
    backing.remove(DURABLE_PROOF_A).unwrap();
    backing.remove(DURABLE_PROOF_B).unwrap();
    let report = check_volume(&backing).unwrap();
    assert!(!report.ok());
    assert!(report
        .errors
        .iter()
        .any(|e| e.contains("required durable proof")));
}

fn catalog_shard(backing: &MemBacking, discard_units: u64, both: bool) {
    let mut catalog = ShardCatalog::new();
    catalog.insert(0);
    let cat = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
    cat.store(backing, &mut catalog).unwrap();
    let mut alloc = AllocationMap::new(sb().geometry.units_per_shard());
    let alloc_store = AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0));
    alloc_store.store(backing, &mut alloc).unwrap();
    backing.open(&layout::shard_data(0), true).unwrap();
    let mut discard = AllocationMap::new(discard_units);
    let discard_store = AbStore::new(layout::shard_discard_a(0), layout::shard_discard_b(0));
    discard_store.store(backing, &mut discard).unwrap();
    if both {
        discard_store.store(backing, &mut discard).unwrap();
    }
}

#[test]
fn checker_validates_v3_discard_maps_and_reports_single_copy_fallback() {
    let missing = MemBacking::new();
    init::create_volume_with_discard(&missing, sb()).unwrap();
    let mut catalog = ShardCatalog::new();
    catalog.insert(0);
    AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .store(&missing, &mut catalog)
        .unwrap();
    let mut alloc = AllocationMap::new(sb().geometry.units_per_shard());
    AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0))
        .store(&missing, &mut alloc)
        .unwrap();
    missing.open(&layout::shard_data(0), true).unwrap();
    assert!(!check_volume(&missing).unwrap().ok());

    let wrong = MemBacking::new();
    init::create_volume_with_discard(&wrong, sb()).unwrap();
    catalog_shard(&wrong, 1, true);
    assert!(!check_volume(&wrong).unwrap().ok());

    let fallback = MemBacking::new();
    init::create_volume_with_discard(&fallback, sb()).unwrap();
    catalog_shard(&fallback, sb().geometry.units_per_shard(), false);
    let report = check_volume(&fallback).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    assert!(report
        .warnings
        .iter()
        .any(|w| w.contains("discard map") && w.contains("one valid copy")));

    let valid = MemBacking::new();
    init::create_volume_with_discard(&valid, sb()).unwrap();
    catalog_shard(&valid, sb().geometry.units_per_shard(), true);
    assert!(check_volume(&valid).unwrap().ok());
    assert_ne!(layout::shard_discard_a(0), layout::shard_alloc_a(0));
}
