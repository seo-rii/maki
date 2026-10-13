//! BUG-074: configuration progress bounds must include every roll header,
//! including the retained active segment and records larger than a segment.

use maki_format::config::{parse_config, VolumeConfig};
use maki_format::journal::{
    checked_append_footprint, max_record_len, minimum_journal_limit, SEGMENT_HEADER_SIZE,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

const REQUEST: u64 = 1 << 20;
const SEGMENT: u64 = 4096;

fn config(unit: u32, limit: u64) -> VolumeConfig {
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "journal-progress"
max_virtual_size = "4MiB"
device_block_size = 512
crypto_unit_size = {unit}
shard_logical_size = "2MiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [{unit}]
max_ciphertext_size = {}
[[crypto.http.endpoint]]
name = "unused"
url = "http://127.0.0.1:1"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.decrypt]
path = "/decrypt"
[backing]
root = "/unused"
journal_segment_size = "{SEGMENT}B"
journal_max_bytes = "{limit}B"
journal_emergency_reserve_bytes = "0B"
checkpoint_reserve_bytes = "0B"
[nbd]
minimum_io = 512
preferred_io = 512
maximum_io = "{REQUEST}B"
"#,
        unit + 8
    ))
    .unwrap()
}

fn minimum(unit: u32) -> u64 {
    let record = max_record_len(unit + 8);
    let count = REQUEST.div_ceil(u64::from(unit)) + 1;
    let header = SEGMENT_HEADER_SIZE as u64;
    let records_per_segment = ((SEGMENT - header) / record).max(1);
    let append = count * record + count.div_ceil(records_per_segment) * header;
    let retained = SEGMENT.max(header + record);
    (2 * SEGMENT + count * record).max(retained + append)
}

#[test]
fn former_record_only_minimum_is_rejected_for_repeated_roll_headers() {
    let old_minimum = 2 * SEGMENT + (REQUEST / 512 + 1) * max_record_len(520);
    assert_eq!(old_minimum, 1_139_240);
    let error = config(512, old_minimum)
        .validate()
        .expect_err("a maximum request cannot fit even an empty journal at this limit")
        .to_string();
    assert!(error.contains(&minimum(512).to_string()), "{error}");
    assert!(error.contains("segment headers"), "{error}");
}

#[test]
fn progress_minimum_includes_an_oversized_retained_record() {
    let unit = 8192;
    let old_minimum = 2 * SEGMENT + (REQUEST / u64::from(unit) + 1) * max_record_len(unit + 8);
    assert!(minimum(unit) > old_minimum);
    config(unit, old_minimum)
        .validate()
        .expect_err("a reclaim retains the active segment, including its oversized record");
}

#[test]
fn header_inclusive_minimum_is_accepted_and_one_byte_less_is_rejected() {
    for unit in [512, 1024, 4096, 8192, 65536] {
        let limit = minimum(unit);
        config(unit, limit).validate().unwrap();
        config(unit, limit - 1)
            .validate()
            .expect_err("the progress boundary must not accept one byte less");
    }
}

fn reference_append(
    segment: u64,
    mut active: Option<(u64, u64)>,
    records: impl IntoIterator<Item = u64>,
) -> u64 {
    let header = SEGMENT_HEADER_SIZE as u64;
    let mut bytes = 0;
    for record in records {
        let roll = active.is_none_or(|(offset, count)| count > 0 && offset + record > segment);
        if roll {
            bytes += header + record;
            active = Some((header + record, 1));
        } else {
            let (offset, count) = active.unwrap();
            bytes += record;
            active = Some((offset + record, count + 1));
        }
    }
    bytes
}

#[test]
fn grouped_projection_matches_recordwise_rolls_at_empty_exact_and_oversized_boundaries() {
    let header = SEGMENT_HEADER_SIZE as u64;
    for segment in [4096, 8192, 65536] {
        for record in [32, 552, segment - header, segment - header + 1, 2 * segment] {
            for active in [
                None,
                Some((header, 0)),
                Some((segment, 1)),
                Some((header + record, 1)),
            ] {
                for count in [0, 1, 2, 7, 8, 129] {
                    assert_eq!(
                        checked_append_footprint(segment, active, [(record, count)]),
                        Some(reference_append(
                            segment,
                            active,
                            std::iter::repeat_n(record, count as usize)
                        )),
                        "segment={segment}, record={record}, active={active:?}, count={count}"
                    );
                }
            }
        }
    }
}

#[test]
fn random_variable_lengths_never_exceed_the_maximum_record_progress_bound() {
    let mut random = StdRng::seed_from_u64(0x74);
    for _ in 0..2000 {
        let segment = random.random_range(4096..=65536);
        let largest_record = random.random_range(32..=131072);
        let count = random.random_range(1..=257);
        let retained = segment.max(SEGMENT_HEADER_SIZE as u64 + largest_record);
        let records: Vec<u64> = (0..count)
            .map(|_| random.random_range(32..=largest_record))
            .collect();
        let active = Some((retained, 1));
        let reference = reference_append(segment, active, records.iter().copied());
        assert_eq!(
            checked_append_footprint(segment, active, records.iter().map(|&record| (record, 1))),
            Some(reference)
        );
        assert!(
            retained + reference <= minimum_journal_limit(segment, largest_record, count).unwrap()
        );
    }
}

#[test]
fn projection_handles_large_record_counts_without_iteration_and_rejects_overflow() {
    let count = 1_000_000_000_000;
    assert_eq!(
        checked_append_footprint(SEGMENT, None, [(552, count)]),
        Some(552 * count + 48 * count.div_ceil(7))
    );
    assert_eq!(
        checked_append_footprint(SEGMENT, None, [(552, u64::MAX)]),
        None
    );
    assert_eq!(
        checked_append_footprint(SEGMENT, None, [(u64::MAX, 1)]),
        None
    );
    assert_eq!(
        checked_append_footprint(SEGMENT, Some((48, u64::MAX)), [(32, 1)]),
        None
    );
    assert_eq!(checked_append_footprint(SEGMENT, None, [(0, 1)]), None);
    assert_eq!(minimum_journal_limit(u64::MAX, 552, 1), None);
    assert_eq!(minimum_journal_limit(SEGMENT, 552, u64::MAX), None);
}
