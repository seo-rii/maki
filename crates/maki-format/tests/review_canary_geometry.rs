//! The key canary is encrypted at a reserved unit index, and attach refuses
//! a volume whose units reach it (the canary would share a unit with data).
//! Geometry creation, configuration validation and therefore `volume
//! create` accepted such a geometry: with 512- or 1024-byte units an export
//! below the signed NBD size limit can reach the index (512-byte units from
//! just over 2 EiB), so a volume was created that no attach would ever open.

use maki_format::canary::CANARY_UNIT_INDEX;
use maki_format::config::parse_config;
use maki_format::geometry::{Geometry, SLOT_HEADER_SIZE};
use maki_format::superblock::Superblock;

const SHARD: u64 = 1 << 40;

fn compute(unit: u32, units: u64) -> Result<Geometry, maki_format::FormatError> {
    Geometry::compute(512, unit, 512, unit, units * u64::from(unit), SHARD)
}

#[test]
fn geometry_creation_refuses_units_that_reach_the_canary_index() {
    for unit in [512u32, 1024] {
        let units = CANARY_UNIT_INDEX + 1;
        assert!(units * u64::from(unit) <= i64::MAX as u64, "reachable");
        let error = compute(unit, units).expect_err("unit index CANARY_UNIT_INDEX is addressable");
        assert!(error.to_string().contains("canary"), "{error}");
    }
    // The highest addressable unit is CANARY_UNIT_INDEX - 1: still valid.
    let geometry = compute(512, CANARY_UNIT_INDEX).unwrap();
    assert_eq!(geometry.num_units(), CANARY_UNIT_INDEX);
}

#[test]
fn configuration_validation_refuses_a_volume_attach_would_refuse() {
    let size = (CANARY_UNIT_INDEX + 1) * 512;
    let raw = format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = {size}
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "1TiB"
[crypto]
provider = "local-aes-xts"
crypto_compatibility_id = "v1"
key = {{ source = "credential", name = "k" }}
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[nbd]
minimum_io = 512
preferred_io = 512
[backing]
root = "/x"
"#
    );
    let config = parse_config(&raw).unwrap();
    assert!(config.geometry().is_err(), "create computes this geometry");
    let error = config.validate().expect_err("validated");
    assert!(error.to_string().contains("canary"), "{error}");
    // Control: one unit less validates.
    let smaller = raw.replace(&size.to_string(), &(size - 512).to_string());
    parse_config(&smaller).unwrap().validate().unwrap();
}

/// Such a volume could only come from an older binary and never attached;
/// its superblock is now refused when loaded, as for the other geometry
/// limits, instead of at the later attach check.
#[test]
fn a_stored_geometry_that_reaches_the_canary_index_is_refused_on_load() {
    let max_ciphertext_size = 512;
    let slot_size = (u64::from(SLOT_HEADER_SIZE) + max_ciphertext_size).next_multiple_of(512);
    let superblock = Superblock {
        generation: 1,
        volume_uuid: uuid::Uuid::from_u128(0xCA1A),
        provider_type: "local-aes-xts".into(),
        crypto_compatibility_id: "v1".into(),
        key_identity: "k".into(),
        geometry: Geometry {
            device_block_size: 512,
            crypto_unit_size: 512,
            slot_alignment: 512,
            max_ciphertext_size: max_ciphertext_size as u32,
            slot_header_size: SLOT_HEADER_SIZE,
            slot_size,
            max_virtual_size: (CANARY_UNIT_INDEX + 1) * 512,
            shard_logical_size: SHARD,
        },
        format_version: 1,
        created_unix: 1_756_684_800,
    };
    assert!(Superblock::decode(&superblock.encode()).is_err());
    // Control: the same superblock one unit smaller loads.
    let mut smaller = superblock.clone();
    smaller.geometry.max_virtual_size = CANARY_UNIT_INDEX * 512;
    assert_eq!(Superblock::decode(&smaller.encode()).unwrap(), smaller);
}
