//! BUG-084: validate the full-unit charge of every permitted NBD request,
//! including requests smaller than a crypto unit and finite export bounds.

use maki_format::config::{parse_config, VolumeConfig};

fn config(unit: u32, minimum: u32, maximum: u64, size: u64) -> VolumeConfig {
    let mut cfg = parse_config(
        r#"
config_schema_version = 1
[volume]
name = "admission"
max_virtual_size = "64KiB"
device_block_size = 512
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = { source = "env", name = "test-key" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/test"
"#,
    )
    .unwrap();
    cfg.volume.crypto_unit_size = unit;
    cfg.volume.max_virtual_size.0 = size;
    cfg.volume.shard_logical_size.0 = size;
    cfg.crypto.capabilities.supported_plaintext_sizes = vec![unit];
    cfg.crypto.capabilities.max_ciphertext_size = unit + 28;
    cfg.nbd.minimum_io = minimum;
    cfg.nbd.preferred_io = Some(minimum);
    cfg.nbd.maximum_io.0 = maximum;
    cfg
}

fn exact_budget(mut cfg: VolumeConfig, budget: u64) {
    cfg.limits.max_plaintext_bytes.0 = budget;
    cfg.validate()
        .unwrap_or_else(|error| panic!("exact budget {budget}: {error}"));
    cfg.limits.max_plaintext_bytes.0 = budget - 1;
    let error = cfg
        .validate()
        .expect_err("one byte short cannot admit every request")
        .to_string();
    assert!(error.contains("limits.max_plaintext_bytes"), "{error}");
    assert!(error.contains(&format!("at least {budget}")), "{error}");
}

#[test]
fn a_sub_unit_request_can_need_two_whole_units() {
    let mut cfg = config(4096, 512, 1024, 65536);
    cfg.limits.max_plaintext_bytes.0 = 5120;
    let error = cfg
        .validate()
        .expect_err("offset 3584 + 1024 touches two 4096-byte units")
        .to_string();
    assert!(error.contains("limits.max_plaintext_bytes"), "{error}");
    assert!(error.contains("8192"), "{error}");
    exact_budget(cfg, 8192);
}

#[test]
fn alignment_and_export_bounds_exclude_unreachable_extra_units() {
    // Unit-aligned requests cannot touch an extra unit at either end.
    exact_budget(config(4096, 4096, 4096, 8192), 4096);
    // One minimum-size block cannot straddle a unit made of whole blocks.
    exact_budget(config(4096, 512, 512, 8192), 4096);
    // A maximum larger than the export does not enlarge its actual requests.
    exact_budget(config(4096, 512, 8192, 4096), 4096);
    // The larger minimum is valid; every request is still a whole unit count.
    exact_budget(config(4096, 8192, 8192, 16384), 8192);
}

#[test]
fn non_power_of_two_units_respect_minimum_alignment_and_finite_offsets() {
    exact_budget(config(1536, 512, 1024, 6144), 3072);
    // With only offset 0 or 2048 available, no 4096-byte request covers all
    // four units of this export. An unbounded phase calculation overcharges.
    exact_budget(config(1536, 2048, 4096, 6144), 4608);
}

fn exhaustive_unit_charge(unit: u64, minimum: u64, maximum: u64, size: u64) -> u64 {
    let mut greatest = 0;
    for offset in (0..size).step_by(minimum as usize) {
        for len in (minimum..=maximum.min(size - offset)).step_by(minimum as usize) {
            // Count actual overlapping unit intervals, independently of the
            // validation's longest-request and repeating-phase calculation.
            let units = (0..size)
                .step_by(unit as usize)
                .filter(|start| *start < offset + len && *start + unit > offset)
                .count() as u64;
            greatest = greatest.max(units * unit);
        }
    }
    greatest
}

#[test]
fn budget_matches_all_requests_in_small_geometries() {
    for unit in [512_u32, 1024, 1536, 2048, 2560, 3072, 4096] {
        for minimum in [512_u32, 1024, 2048, 4096] {
            // Find the smallest export divisible by both, without repeating
            // the implementation's gcd/phase calculation in this oracle.
            let base = (u64::from(unit)..)
                .step_by(unit as usize)
                .find(|size| size.is_multiple_of(u64::from(minimum)))
                .unwrap();
            for size in [base, base * 2, base * 3] {
                for maximum in [minimum, minimum * 2, minimum * 4] {
                    let budget = exhaustive_unit_charge(
                        u64::from(unit),
                        u64::from(minimum),
                        u64::from(maximum),
                        size,
                    );
                    exact_budget(config(unit, minimum, u64::from(maximum), size), budget);
                }
            }
        }
    }
}

#[test]
fn the_largest_power_of_two_wire_request_does_not_wrap_the_charge() {
    let mut cfg = config(4096, 512, 1 << 31, 1 << 32);
    cfg.limits.max_plaintext_bytes.0 = u64::from(u32::MAX >> 1);
    cfg.limits.max_ciphertext_bytes.0 = cfg.limits.max_plaintext_bytes.0;
    cfg.backing.journal_max_bytes.0 = 64 << 30;
    let error = cfg.validate().unwrap_err().to_string();
    assert!(error.contains("limits.max_plaintext_bytes"), "{error}");
    assert!(error.contains("2147487744"), "{error}");
}
