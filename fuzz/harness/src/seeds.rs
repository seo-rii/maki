//! The committed seed corpus: what `fuzz/seeds/<target>/` holds.
//!
//! The valid inputs are the code's own encodings (a Maki encoder's output,
//! or, where Maki has no encoder because the bytes come from another
//! program, the bytes that program sends). Around them are a few inputs cut
//! short or changed. A seed's name says what its target must do with it:
//! `valid-*` is accepted, `refused-*` is refused, and a `noise-*` input
//! (a valid one with bytes changed at random) only must not crash.
//!
//! The generator is deterministic. `MAKI_FUZZ_WRITE_SEEDS=1 cargo test -p
//! maki-fuzz-harness --test review_fuzz_corpus` writes its output to
//! `fuzz/seeds`; without the variable that test checks that the committed
//! files hold it.

use maki_format::ab::AbRecord;
use maki_format::allocation::AllocationMap;
use maki_format::canary::{canary_plaintext, KeyCanary, CANARY_UNIT_INDEX};
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::durable_proof::DurableProof;
use maki_format::geometry::Geometry;
use maki_format::journal::{encode_record, DurableMark, JournalRecord, SegmentHeader};
use maki_format::slot::SlotHeader;
use maki_format::superblock::{Superblock, VolumeSuperblock, SUPERBLOCK_VERSION_V3};
use uuid::Uuid;

/// One seed: its target, its file name and its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    pub target: &'static str,
    pub name: String,
    pub bytes: Vec<u8>,
}

/// What a target must do with a seed, by the seed's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    Accepted,
    Refused,
    Either,
}

impl Expect {
    /// The expectation a seed's file name states; `None` for a name that
    /// states none.
    pub fn of(name: &str) -> Option<Self> {
        if name.starts_with("valid-") {
            Some(Self::Accepted)
        } else if name.starts_with("refused-") {
            Some(Self::Refused)
        } else if name.starts_with("noise-") {
            Some(Self::Either)
        } else {
            None
        }
    }
}

/// Every seed, in a fixed order.
pub fn all() -> Vec<Seed> {
    let mut seeds = Vec::new();
    let mut add = |target: &'static str, found: Vec<(String, Vec<u8>)>| {
        seeds.extend(found.into_iter().map(|(name, bytes)| Seed {
            target,
            name,
            bytes,
        }));
    };
    add("format_decoders", format_decoders());
    add("format_records", format_records());
    add("journal_scan", journal_scan());
    add("config_parse", config_parse());
    add("endpoint_url", endpoint_url());
    add("probe_parsers", probe_parsers());
    // The helper's code is Linux's. The kernel's netlink answers are in its
    // byte order; the committed ones are little-endian.
    #[cfg(target_os = "linux")]
    add("nbd_handshake", crate::nbd::handshake_seeds());
    #[cfg(all(target_os = "linux", target_endian = "little"))]
    add("nbd_netlink", crate::nbd::netlink_seeds());
    add("backing_records", maki_backing::fuzzing::seeds());
    seeds
}

/// xorshift64*: reproducible noise.
pub(crate) struct Noise(u64);

impl Noise {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }

    /// `bytes` with one to four bytes changed, past the first `keep`.
    pub(crate) fn changed(&mut self, bytes: &[u8], keep: usize) -> Vec<u8> {
        let mut changed = bytes.to_vec();
        if changed.len() > keep {
            for _ in 0..1 + self.below(4) {
                let at = keep + self.below(changed.len() - keep);
                changed[at] ^= 1 + (self.next() % 255) as u8;
            }
        }
        changed
    }
}

/// `prefix` followed by `body`.
pub(crate) fn framed(prefix: &[u8], body: &[u8]) -> Vec<u8> {
    [prefix, body].concat()
}

const VOLUME: Uuid = Uuid::from_u128(0x4d41_4b49_0000_4000_8000_0000_0000_f00d);

fn superblock() -> Superblock {
    Superblock {
        generation: 3,
        volume_uuid: VOLUME,
        provider_type: "remote-http".into(),
        crypto_compatibility_id: "vendor-v1".into(),
        key_identity: "key".into(),
        geometry: Geometry::compute(4096, 4096, 512, 4384, 1 << 30, 64 << 20)
            .expect("the sample geometry"),
        format_version: 1,
        created_unix: 1_700_000_000,
    }
}

/// Each record `format_decoders` and `format_records` select, by its
/// selector byte: its name and its encoding.
fn records() -> Vec<(u8, &'static str, Vec<u8>)> {
    let mut map = AllocationMap::new(4096);
    map.set(1, true);
    map.set(4000, true);
    let mut catalog = ShardCatalog::new();
    catalog.insert(0);
    catalog.insert(5);
    let mut checkpoint = CheckpointState::default();
    checkpoint.checkpoint_sequence = 77;
    let proof = DurableProof {
        generation: 4,
        volume_uuid: VOLUME,
        durable_sequence: 120,
        segment_index: 2,
        durable_size: 8240,
    };
    vec![
        (0, "superblock", superblock().encode()),
        (
            1,
            "segment-header",
            SegmentHeader {
                segment_index: 7,
                volume_uuid: VOLUME,
                base_sequence: 99,
            }
            .encode(),
        ),
        (
            2,
            "durable-mark",
            DurableMark {
                segment_index: 7,
                durable_size: 12345,
            }
            .encode()
            .to_vec(),
        ),
        (
            3,
            "key-canary",
            KeyCanary {
                generation: 1,
                volume_uuid: VOLUME,
                unit_index: CANARY_UNIT_INDEX,
                ciphertext: canary_plaintext(&VOLUME, 128),
            }
            .encode(),
        ),
        (
            4,
            "slot-header",
            SlotHeader {
                unit_index: 42,
                write_sequence: 1000,
                ciphertext_len: 4384,
                flags: 0,
                ciphertext_crc: 0xDEAD_BEEF,
            }
            .encode()
            .to_vec(),
        ),
        (5, "allocation-map", AbRecord::encode(&map)),
        (6, "shard-catalog", AbRecord::encode(&catalog)),
        (7, "checkpoint-state", AbRecord::encode(&checkpoint)),
        (8, "durable-proof", AbRecord::encode(&proof)),
        (
            9,
            "volume-superblock",
            VolumeSuperblock {
                superblock: superblock(),
                metadata_version: SUPERBLOCK_VERSION_V3,
            }
            .encode(),
        ),
    ]
}

/// Raw images: a flipped byte is caught by the record's CRC-32.
fn format_decoders() -> Vec<(String, Vec<u8>)> {
    let mut noise = Noise::new(0xdec0_de00);
    let mut seeds = Vec::new();
    for (selector, name, image) in records() {
        let mut flipped = image.clone();
        let at = noise.below(flipped.len());
        flipped[at] ^= 0x10;
        seeds.push((format!("valid-{name}"), framed(&[selector], &image)));
        seeds.push((
            format!("refused-{name}-bit-flip"),
            framed(&[selector], &flipped),
        ));
        seeds.push((
            format!("refused-{name}-truncated"),
            framed(&[selector], &image[..image.len() / 2]),
        ));
    }
    seeds
}

/// The same images; this target repairs the CRC-32, so a changed byte may
/// be accepted.
fn format_records() -> Vec<(String, Vec<u8>)> {
    let mut noise = Noise::new(0x5eed_0f0f);
    let mut seeds = Vec::new();
    for (selector, name, image) in records() {
        seeds.push((format!("valid-{name}"), framed(&[selector], &image)));
        seeds.push((
            format!("noise-{name}"),
            framed(&[selector], &noise.changed(&image, 0)),
        ));
        seeds.push((
            format!("refused-{name}-truncated"),
            framed(&[selector], &image[..image.len() / 2]),
        ));
    }
    seeds
}

/// A segment body of records `first..first + count`.
fn journal_records(first: u64, count: u64) -> (Vec<u8>, Vec<usize>) {
    let mut body = Vec::new();
    let mut ends = Vec::new();
    for sequence in first..first + count {
        body.extend(
            encode_record(&JournalRecord {
                sequence,
                unit_index: sequence * 3,
                payload: (0..40 + sequence as usize).map(|i| i as u8).collect(),
            })
            .expect("a sample journal record"),
        );
        ends.push(body.len());
    }
    (body, ends)
}

/// The scanner's input: the base sequence, the knob that sets the durable
/// prefix (an odd knob makes `knob * 7 % (len + 1)` bytes durable), then
/// the segment body.
fn scan_input(first: u64, knob: u8, body: &[u8]) -> Vec<u8> {
    let mut input = first.to_le_bytes().to_vec();
    input.push(knob);
    input.extend_from_slice(body);
    input
}

/// An odd knob whose durable prefix covers byte `at` of a `len`-byte body.
fn durable_over(at: usize, len: usize) -> u8 {
    (1..=255u8)
        .step_by(2)
        .find(|knob| usize::from(*knob) * 7 % (len + 1) > at)
        .expect("a knob whose durable prefix covers the byte")
}

fn journal_scan() -> Vec<(String, Vec<u8>)> {
    let (body, ends) = journal_records(10, 3);
    let mut zero_tail = body.clone();
    zero_tail.extend_from_slice(&[0; 64]);
    let mut damaged = body.clone();
    damaged[ends[0] + 40] ^= 0x01;
    let (gap, _) = journal_records(13, 1);
    let mut noise = Noise::new(0x0005_ca75);
    vec![
        ("valid-three-records".into(), scan_input(10, 0, &body)),
        (
            "valid-three-records-durable".into(),
            scan_input(10, durable_over(body.len() - 1, body.len()), &body),
        ),
        ("valid-zero-tail".into(), scan_input(10, 0, &zero_tail)),
        (
            "refused-torn-tail".into(),
            scan_input(10, 0, &body[..ends[2] - 5]),
        ),
        (
            "refused-damage-in-durable-prefix".into(),
            scan_input(10, durable_over(ends[0] + 40, damaged.len()), &damaged),
        ),
        (
            "refused-sequence-gap".into(),
            scan_input(10, 0, &[&body[..ends[1]], gap.as_slice()].concat()),
        ),
        (
            "noise-three-records".into(),
            scan_input(10, 3, &noise.changed(&body, 0)),
        ),
    ]
}

/// A local-provider volume: the smallest configuration that validates. The
/// key is a credential reference; a configuration never holds a literal
/// (SPEC §9).
const LOCAL_CONFIG: &str = r#"config_schema_version = 1

[volume]
name = "seed"
max_virtual_size = "1GiB"
device_block_size = 4096
crypto_unit_size = 4096
shard_logical_size = "64MiB"

[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = { source = "credential", name = "crypto-token" }

[crypto.capabilities]
mode = "declared"
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384

[backing]
root = "/var/lib/maki/seed"
"#;

fn config_parse() -> Vec<(String, Vec<u8>)> {
    let literal_key = LOCAL_CONFIG.replace(
        r#"key = { source = "credential", name = "crypto-token" }"#,
        r#"key = "not-a-real-key""#,
    );
    let mut noise = Noise::new(0x00c0_f1a5);
    vec![
        ("valid-local-provider".into(), LOCAL_CONFIG.into()),
        (
            "refused-unknown-field".into(),
            LOCAL_CONFIG
                .replace("[backing]\n", "[backing]\nnot_a_setting = 1\n")
                .into(),
        ),
        ("refused-literal-key".into(), literal_key.into()),
        (
            "refused-block-size".into(),
            LOCAL_CONFIG
                .replace("device_block_size = 4096", "device_block_size = 3000")
                .into(),
        ),
        (
            "refused-not-toml".into(),
            LOCAL_CONFIG.replace(" = ", " ").into(),
        ),
        (
            "noise-local-provider".into(),
            noise.changed(LOCAL_CONFIG.as_bytes(), 0),
        ),
    ]
}

fn endpoint_url() -> Vec<(String, Vec<u8>)> {
    [
        ("valid-https", "https://crypto.internal:8443/v1"),
        ("valid-ipv6", "https://[::1]:8443/v1"),
        ("valid-loopback", "http://127.0.0.1:7000"),
        ("refused-no-scheme", "crypto.internal:8443"),
        ("refused-userinfo", "https://user:secret@crypto.internal"),
        ("refused-port", "https://crypto.internal:99999"),
        ("refused-unclosed-ipv6", "https://[::1:8443"),
    ]
    .into_iter()
    .map(|(name, url)| (name.to_string(), url.as_bytes().to_vec()))
    .collect()
}

/// A mount table as `/proc/self/mountinfo` shows it, with the mount the
/// target looks for, and sysfs device names.
const MOUNTINFO: &str = "\
22 1 252:1 / / rw,relatime shared:1 - xfs /dev/vda1 rw,attr2,inode64
36 22 253:3 / /mnt/target rw,nosuid,nodev,noatime shared:40 - xfs /dev/mapper/maki--vg-data rw,attr2,inode64,logbufs=8
37 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,size=4096k,mode=755
";

fn probe_parsers() -> Vec<(String, Vec<u8>)> {
    let mut noise = Noise::new(0x9b0b_e000);
    let without = MOUNTINFO
        .lines()
        .filter(|line| !line.contains("/mnt/target"))
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    vec![
        ("valid-mountinfo".into(), MOUNTINFO.into()),
        (
            "valid-mountinfo-escaped-and-not-utf8".into(),
            [
                MOUNTINFO.as_bytes(),
                &b"38 22 0:6 / /mnt/space\\040name rw - tmpfs \xff\xfe rw\n"[..],
            ]
            .concat(),
        ),
        ("refused-mountinfo-without-target".into(), without.into()),
        (
            "refused-device-names".into(),
            "nbd0,nbd1\nnbd1,dm-0\ndm-0,nbd0\n/dev/nbd12\n/dev/nbd01\nnbd4294967296\n".into(),
        ),
        (
            "noise-mountinfo".into(),
            noise.changed(MOUNTINFO.as_bytes(), 0),
        ),
    ]
}
