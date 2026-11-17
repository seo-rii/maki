//! audit2 (decoder-fuzz): CRC-VALID, structure-aware mutation of every
//! maki-format codec, plus random bytes, under a per-thread counting
//! allocator.
//!
//! Round 1 fuzzed these decoders only with random or bit-flipped bytes,
//! which the CRC rejects before any field is looked at. Here every mutated
//! image gets a correct trailing CRC (recomputed exactly as `Writer::
//! finish_with_crc` does), so the field validation behind the CRC is what is
//! exercised. Properties checked for every decoded image:
//!   * no panic (debug build: overflow checks on);
//!   * bounded allocation (peak live bytes during decode <= 4 x input + 64 KiB);
//!   * an accepted record satisfies the record's own invariants;
//!   * an accepted record re-encodes to exactly the accepted bytes
//!     (a mismatch is counted as "non-canonical acceptance" and printed;
//!     the dedicated tests at the bottom pin the ones found).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_format::allocation::AllocationMap;
use maki_format::canary::KeyCanary;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::durable_proof::DurableProof;
use maki_format::geometry::Geometry;
use maki_format::journal::{
    encode_record, scan_segment_bounded, DurableMark, JournalRecord, ScanOutcome, SegmentHeader,
    MAX_PAYLOAD,
};
use maki_format::slot::SlotHeader;
use maki_format::superblock::{
    Superblock, VolumeSuperblock, SUPERBLOCK_VERSION, SUPERBLOCK_VERSION_V2,
    SUPERBLOCK_VERSION_V3,
};

// ---------------------------------------------------------------- allocator

struct Counting;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn note_alloc(size: usize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + size as isize;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now)
            }
        });
    });
}

fn note_free(size: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get() - size as isize));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_free(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_free(layout.size());
        note_alloc(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Run `f`, returning its result and the peak number of bytes it had live
/// at once on this thread above the starting level.
fn measured<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let start = LIVE.with(|l| l.get());
    PEAK.with(|p| p.set(start));
    let out = f();
    let peak = PEAK.with(|p| p.get());
    (out, (peak - start).max(0) as usize)
}

fn bound(input: usize) -> usize {
    4 * input + 64 * 1024
}

// ---------------------------------------------------------------- helpers

/// Recompute the trailing crc32 exactly as `Writer::finish_with_crc`.
fn recrc(buf: &mut [u8]) {
    let n = buf.len();
    let crc = crc32fast::hash(&buf[..n - 4]);
    buf[n - 4..].copy_from_slice(&crc.to_le_bytes());
}

fn interesting_u64(rng: &mut StdRng, current: u64) -> u64 {
    match rng.random_range(0..14u32) {
        0 => 0,
        1 => 1,
        2 => u64::MAX,
        3 => u64::MAX - 1,
        4 => i64::MAX as u64,
        5 => i64::MAX as u64 + 1,
        6 => u32::MAX as u64,
        7 => u32::MAX as u64 + 1,
        8 => current.wrapping_add(1),
        9 => current.wrapping_sub(1),
        10 => 1 << rng.random_range(0..64),
        11 => rng.random_range(0..4096),
        12 => current ^ (1 << rng.random_range(0..64)),
        _ => rng.random(),
    }
}

fn interesting_u32(rng: &mut StdRng, current: u32) -> u32 {
    match rng.random_range(0..12u32) {
        0 => 0,
        1 => 1,
        2 => u32::MAX,
        3 => u32::MAX - 1,
        4 => i32::MAX as u32,
        5 => current.wrapping_add(1),
        6 => current.wrapping_sub(1),
        7 => 1 << rng.random_range(0..32),
        8 => rng.random_range(0..65536),
        9 => current ^ (1 << rng.random_range(0..32)),
        _ => rng.random(),
    }
}

#[derive(Clone, Copy)]
enum Field {
    U32(usize),
    U64(usize),
    Bytes(usize, usize),
}

/// Mutate one field (value-aware) of a CRC-covered image, then fix its CRC.
fn mutate_fields(rng: &mut StdRng, image: &mut [u8], fields: &[Field]) {
    let rounds = rng.random_range(1..=3);
    for _ in 0..rounds {
        match fields[rng.random_range(0..fields.len())] {
            Field::U32(at) => {
                let cur = u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
                let v = interesting_u32(rng, cur);
                image[at..at + 4].copy_from_slice(&v.to_le_bytes());
            }
            Field::U64(at) => {
                let cur = u64::from_le_bytes(image[at..at + 8].try_into().unwrap());
                let v = interesting_u64(rng, cur);
                image[at..at + 8].copy_from_slice(&v.to_le_bytes());
            }
            Field::Bytes(at, len) => match rng.random_range(0..3u32) {
                0 => image[at..at + len].fill(0),
                1 => image[at + rng.random_range(0..len)] = rng.random(),
                _ => rng.fill(&mut image[at..at + len]),
            },
        }
    }
    recrc(image);
}

/// Resize the CRC-covered payload (insert/remove bytes just before the CRC,
/// or truncate mid-record), then fix the CRC.
fn resize_payload(rng: &mut StdRng, image: &[u8]) -> Vec<u8> {
    let mut payload = image[..image.len() - 4].to_vec();
    match rng.random_range(0..3u32) {
        0 => {
            let extra = rng.random_range(1..32);
            for _ in 0..extra {
                payload.push(rng.random());
            }
        }
        1 if !payload.is_empty() => {
            let keep = rng.random_range(0..payload.len());
            payload.truncate(keep);
        }
        _ => {
            let at = rng.random_range(0..=payload.len());
            payload.insert(at, rng.random());
        }
    }
    payload.extend_from_slice(&[0; 4]);
    recrc(&mut payload);
    payload
}

#[derive(Default, Debug)]
struct Stats {
    tried: u64,
    accepted: u64,
    noncanonical: u64,
    noncanonical_example: Option<String>,
    invariant_violations: Vec<String>,
    panics: Vec<String>,
    over_alloc: Vec<String>,
}

impl Stats {
    fn report(&self, name: &str, seed: u64) {
        eprintln!(
            "[audit2 codec] {name}: seed {seed:#x} tried {} accepted {} non-canonical {} \
             invariant-violations {} panics {} over-alloc {}{}",
            self.tried,
            self.accepted,
            self.noncanonical,
            self.invariant_violations.len(),
            self.panics.len(),
            self.over_alloc.len(),
            self.noncanonical_example
                .as_ref()
                .map(|e| format!(" (e.g. {e})"))
                .unwrap_or_default()
        );
    }
}

/// Decode `image` with `decode`; on success check `invariant` and exact
/// re-encoding.
fn exercise<T>(
    stats: &mut Stats,
    image: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, maki_format::FormatError>,
    encode: impl Fn(&T) -> Vec<u8>,
    invariant: impl Fn(&T) -> Result<(), String>,
    canonical_len: impl Fn(&[u8]) -> usize,
) {
    stats.tried += 1;
    let result = catch_unwind(AssertUnwindSafe(|| measured(|| decode(image))));
    let (decoded, peak) = match result {
        Ok(v) => v,
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            if stats.panics.len() < 4 {
                stats.panics.push(format!("{msg}: {:02x?}", &image[..image.len().min(96)]));
            }
            return;
        }
    };
    if peak > bound(image.len()) && stats.over_alloc.len() < 4 {
        stats
            .over_alloc
            .push(format!("peak {peak} for input {}", image.len()));
    }
    let Ok(record) = decoded else { return };
    stats.accepted += 1;
    if let Err(violation) = invariant(&record) {
        if stats.invariant_violations.len() < 4 {
            stats.invariant_violations.push(violation);
        }
    }
    let reencoded = encode(&record);
    let considered = &image[..canonical_len(image).min(image.len())];
    if reencoded != considered {
        stats.noncanonical += 1;
        if stats.noncanonical_example.is_none() {
            let at = reencoded
                .iter()
                .zip(considered)
                .position(|(a, b)| a != b)
                .unwrap_or(reencoded.len().min(considered.len()));
            stats.noncanonical_example = Some(format!(
                "first difference at byte {at}, re-encoded {} bytes vs accepted {} bytes",
                reencoded.len(),
                considered.len()
            ));
        }
    }
}

fn random_bytes(rng: &mut StdRng, max: usize) -> Vec<u8> {
    let n = rng.random_range(0..max);
    (0..n).map(|_| rng.random()).collect()
}

const ITER: usize = 20_000;

fn assert_clean(name: &str, stats: &Stats) {
    assert!(stats.panics.is_empty(), "{name} panicked: {:?}", stats.panics);
    assert!(
        stats.over_alloc.is_empty(),
        "{name} over-allocated: {:?}",
        stats.over_alloc
    );
    assert!(
        stats.invariant_violations.is_empty(),
        "{name} accepted records violating invariants: {:?}",
        stats.invariant_violations
    );
}

// ---------------------------------------------------------------- allocation map

fn valid_map(rng: &mut StdRng, units: u64) -> Vec<u8> {
    let mut map = AllocationMap::new(units);
    for _ in 0..rng.random_range(0..8) {
        if units > 0 {
            map.set(rng.random_range(0..units), true);
        }
    }
    map.encode()
}

/// Bits set in the trailing padding of the bitmap (bits >= units).
fn padding_bits(image: &[u8]) -> u32 {
    let units = u64::from_le_bytes(image[20..28].try_into().unwrap());
    let bytes = &image[28..image.len() - 4];
    if units % 8 == 0 || bytes.is_empty() {
        return 0;
    }
    let last = bytes[bytes.len() - 1];
    (last >> (units % 8)).count_ones()
}

#[test]
fn allocation_map_crc_valid_mutations() {
    let seed = 0xA11C_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut stats = Stats::default();
    let mut padding_accepted = 0u64;
    for i in 0..ITER {
        let units = match rng.random_range(0..4u32) {
            0 => rng.random_range(0..64),
            1 => rng.random_range(0..5000),
            2 => 1000,
            _ => 1001,
        };
        let mut image = valid_map(&mut rng, units);
        let image = match i % 4 {
            0 => {
                let fields = [Field::U32(8), Field::U64(12), Field::U64(20)];
                mutate_fields(&mut rng, &mut image, &fields);
                image
            }
            1 => resize_payload(&mut rng, &image),
            2 => {
                // Consistent length but padding bits set (units % 8 != 0).
                let n = image.len();
                if n > 32 {
                    image[n - 5] |= 0x80;
                    recrc(&mut image);
                }
                image
            }
            _ => {
                // units changed and bitmap resized to match.
                let new_units = interesting_u64(&mut rng, units) % (1 << 20);
                let mut v = image[..28].to_vec();
                v[20..28].copy_from_slice(&new_units.to_le_bytes());
                let nb = new_units.div_ceil(8) as usize;
                v.extend((0..nb).map(|_| rng.random::<u8>()));
                v.extend_from_slice(&[0; 4]);
                recrc(&mut v);
                v
            }
        };
        if image.len() > 32 && padding_bits(&image) > 0 && AllocationMap::decode(&image).is_ok() {
            padding_accepted += 1;
        }
        exercise(
            &mut stats,
            &image,
            AllocationMap::decode,
            AllocationMap::encode,
            |m| {
                if m.units() > 1 << 32 {
                    return Err(format!("units {} above MAX_UNITS", m.units()));
                }
                if m.set_count() > m.units() {
                    return Err(format!(
                        "set_count {} exceeds units {} (padding bits counted)",
                        m.set_count(),
                        m.units()
                    ));
                }
                Ok(())
            },
            |img| img.len(),
        );
    }
    for _ in 0..ITER {
        let image = random_bytes(&mut rng, 512);
        exercise(
            &mut stats,
            &image,
            AllocationMap::decode,
            AllocationMap::encode,
            |_| Ok(()),
            |img| img.len(),
        );
    }
    stats.report("allocation map", seed);
    eprintln!("[audit2 codec] allocation map: CRC-valid images with padding bits accepted: {padding_accepted}");
    assert!(stats.panics.is_empty(), "{:?}", stats.panics);
    assert!(stats.over_alloc.is_empty(), "{:?}", stats.over_alloc);
    // Padding-bit acceptance is pinned separately
    // (allocation_map_accepts_padding_bits_that_inflate_set_count).
}

// ---------------------------------------------------------------- catalog

fn valid_catalog(rng: &mut StdRng) -> Vec<u8> {
    let mut c = ShardCatalog::new();
    for _ in 0..rng.random_range(0..10) {
        c.insert(rng.random_range(0..64));
    }
    c.encode()
}

#[test]
fn shard_catalog_crc_valid_mutations() {
    let seed = 0xCA7A_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut stats = Stats::default();
    for i in 0..ITER {
        let mut image = valid_catalog(&mut rng);
        let image = match i % 3 {
            0 => {
                let count = u32::from_le_bytes(image[20..24].try_into().unwrap()) as usize;
                let mut fields = vec![Field::U32(8), Field::U64(12), Field::U32(20)];
                for e in 0..count {
                    fields.push(Field::U64(24 + 8 * e));
                }
                mutate_fields(&mut rng, &mut image, &fields);
                image
            }
            1 => resize_payload(&mut rng, &image),
            _ => {
                // count raised to a huge value with few entries following.
                image[20..24].copy_from_slice(&rng.random_range(1u32 << 20..=1 << 24).to_le_bytes());
                recrc(&mut image);
                image
            }
        };
        exercise(
            &mut stats,
            &image,
            ShardCatalog::decode,
            ShardCatalog::encode,
            |c| {
                let v: Vec<u64> = c.shard_indices().collect();
                if v.windows(2).any(|w| w[0] >= w[1]) {
                    return Err("not ascending".into());
                }
                Ok(())
            },
            |img| img.len(),
        );
    }
    for _ in 0..ITER {
        let image = random_bytes(&mut rng, 512);
        exercise(
            &mut stats,
            &image,
            ShardCatalog::decode,
            ShardCatalog::encode,
            |_| Ok(()),
            |img| img.len(),
        );
    }
    stats.report("shard catalog", seed);
    assert_clean("shard catalog", &stats);
    assert_eq!(stats.noncanonical, 0, "catalog accepted non-canonical bytes");
}

// ---------------------------------------------------------------- checkpoint

#[test]
fn checkpoint_state_crc_valid_mutations() {
    let seed = 0xC4E0_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut stats = Stats::default();
    for i in 0..ITER {
        let mut state = CheckpointState::default();
        state.checkpoint_sequence = rng.random_range(0..1000);
        let mut image = state.encode();
        let image = if i % 2 == 0 {
            mutate_fields(
                &mut rng,
                &mut image,
                &[Field::U32(8), Field::U64(12), Field::U64(20), Field::Bytes(0, 8)],
            );
            image
        } else {
            resize_payload(&mut rng, &image)
        };
        exercise(
            &mut stats,
            &image,
            CheckpointState::decode,
            CheckpointState::encode,
            |_| Ok(()),
            |img| img.len(),
        );
    }
    stats.report("checkpoint state", seed);
    assert_clean("checkpoint state", &stats);
    assert_eq!(stats.noncanonical, 0);
}

// ---------------------------------------------------------------- slot header

#[test]
fn slot_header_crc_valid_mutations() {
    let seed = 0x5107_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut stats = Stats::default();
    for _ in 0..ITER {
        let mut image = SlotHeader {
            unit_index: rng.random_range(0..1024),
            write_sequence: rng.random_range(1..1000),
            ciphertext_len: 540,
            flags: 0,
            ciphertext_crc: rng.random(),
        }
        .encode()
        .to_vec();
        mutate_fields(
            &mut rng,
            &mut image,
            &[
                Field::U64(8),
                Field::U64(16),
                Field::U32(24),
                Field::U32(28),
                Field::U32(32),
                Field::Bytes(36, 24),
            ],
        );
        exercise(
            &mut stats,
            &image,
            SlotHeader::decode,
            |h| h.encode().to_vec(),
            |_| Ok(()),
            |_| 64,
        );
    }
    stats.report("slot header", seed);
    assert_clean("slot header", &stats);
    // Non-canonical acceptance (flags / reserved bytes) is pinned in
    // slot_header_accepts_nonzero_reserved_and_unknown_flags.
}

// ---------------------------------------------------------------- segment header / mark / proof

#[test]
fn segment_header_mark_and_proof_crc_valid_mutations() {
    let seed = 0x5E6D_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut seg = Stats::default();
    let mut mark = Stats::default();
    let mut proof = Stats::default();
    for i in 0..ITER {
        let mut image = SegmentHeader {
            segment_index: rng.random_range(0..100),
            volume_uuid: Uuid::from_u128(rng.random()),
            base_sequence: rng.random_range(1..10000),
        }
        .encode();
        let image = if i % 3 != 0 {
            mutate_fields(
                &mut rng,
                &mut image,
                &[Field::U32(8), Field::U64(12), Field::Bytes(20, 16), Field::U64(36)],
            );
            image
        } else {
            resize_payload(&mut rng, &image)
        };
        exercise(
            &mut seg,
            &image,
            SegmentHeader::decode,
            SegmentHeader::encode,
            |_| Ok(()),
            |_| 48,
        );

        let mut image = DurableMark {
            segment_index: rng.random_range(0..100),
            durable_size: rng.random_range(48..1 << 20),
        }
        .encode()
        .to_vec();
        let image = if i % 3 != 0 {
            mutate_fields(&mut rng, &mut image, &[Field::U32(8), Field::U64(12), Field::U64(20)]);
            image
        } else {
            resize_payload(&mut rng, &image)
        };
        exercise(
            &mut mark,
            &image,
            DurableMark::decode,
            |m| m.encode().to_vec(),
            |_| Ok(()),
            |_| 32,
        );

        let mut image = DurableProof {
            generation: rng.random_range(0..10),
            volume_uuid: Uuid::from_u128(rng.random()),
            durable_sequence: rng.random_range(1..1000),
            segment_index: rng.random_range(0..10),
            durable_size: rng.random_range(80..1 << 20),
        }
        .encode();
        let image = if i % 3 != 0 {
            mutate_fields(
                &mut rng,
                &mut image,
                &[
                    Field::U32(8),
                    Field::U64(12),
                    Field::Bytes(20, 16),
                    Field::U64(36),
                    Field::U64(44),
                    Field::U64(52),
                ],
            );
            image
        } else {
            resize_payload(&mut rng, &image)
        };
        exercise(
            &mut proof,
            &image,
            DurableProof::decode,
            DurableProof::encode,
            |p| {
                if p.durable_sequence == 0 && (p.segment_index != 0 || p.durable_size != 0) {
                    return Err("empty proof with a location".into());
                }
                if p.durable_sequence != 0
                    && (p.durable_sequence == u64::MAX
                        || p.segment_index == u64::MAX
                        || p.durable_size < 80
                        || p.durable_size > i64::MAX as u64)
                {
                    return Err(format!("proof out of bounds: {p:?}"));
                }
                Ok(())
            },
            |img| img.len(),
        );
    }
    seg.report("segment header", seed);
    mark.report("durable mark", seed);
    proof.report("durable proof", seed);
    assert_clean("segment header", &seg);
    assert_clean("durable mark", &mark);
    assert_clean("durable proof", &proof);
    assert_eq!(seg.noncanonical, 0);
    assert_eq!(mark.noncanonical, 0);
    assert_eq!(proof.noncanonical, 0);
}

// ---------------------------------------------------------------- canary

#[test]
fn key_canary_crc_valid_mutations() {
    let seed = 0xCA9A_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut stats = Stats::default();
    for i in 0..ITER {
        let ct_len = rng.random_range(0..600);
        let mut image = KeyCanary {
            generation: rng.random_range(0..5),
            volume_uuid: Uuid::from_u128(rng.random()),
            unit_index: maki_format::canary::CANARY_UNIT_INDEX,
            ciphertext: (0..ct_len).map(|_| rng.random()).collect(),
        }
        .encode();
        let image = match i % 3 {
            0 => {
                mutate_fields(
                    &mut rng,
                    &mut image,
                    &[
                        Field::U32(8),
                        Field::U64(12),
                        Field::Bytes(20, 16),
                        Field::U64(36),
                        Field::U32(44),
                    ],
                );
                image
            }
            1 => resize_payload(&mut rng, &image),
            _ => {
                // ciphertext length field shrunk: the rest becomes trailing bytes.
                let len = u32::from_le_bytes(image[44..48].try_into().unwrap());
                let shrunk = len.saturating_sub(rng.random_range(1..=16));
                image[44..48].copy_from_slice(&shrunk.to_le_bytes());
                recrc(&mut image);
                image
            }
        };
        exercise(
            &mut stats,
            &image,
            KeyCanary::decode,
            KeyCanary::encode,
            |_| Ok(()),
            |img| img.len(),
        );
    }
    stats.report("key canary", seed);
    assert_clean("key canary", &stats);
    // Trailing-byte acceptance is pinned in
    // key_canary_accepts_crc_valid_trailing_bytes.
}

// ---------------------------------------------------------------- superblock

fn geometry() -> Geometry {
    Geometry::compute(512, 4096, 4096, 4096 + 28, 1 << 30, 1 << 26).unwrap()
}

fn superblock(version: u32) -> Vec<u8> {
    VolumeSuperblock {
        superblock: Superblock {
            generation: 3,
            volume_uuid: Uuid::from_u128(0x5B5B),
            provider_type: "local".into(),
            crypto_compatibility_id: "aes-xts-v1".into(),
            key_identity: "key-1".into(),
            geometry: geometry(),
            format_version: 1,
            created_unix: 1_700_000_000,
        },
        metadata_version: version,
    }
    .encode()
}

/// Geometry methods later code relies on must not overflow for anything
/// the decoder accepts.
fn geometry_invariants(g: &Geometry) -> Result<(), String> {
    let plan = g.capacity_plan().map_err(|e| format!("capacity_plan: {e}"))?;
    let per = g.units_per_shard();
    if per == 0 || per > u32::MAX as u64 {
        return Err(format!("units_per_shard {per}"));
    }
    per.checked_mul(g.slot_size)
        .ok_or("shard physical size overflows")?;
    g.num_shards()
        .checked_mul(per)
        .ok_or("num_shards * units_per_shard overflows")?;
    if g.num_units() >= maki_format::canary::CANARY_UNIT_INDEX {
        return Err("units reach the canary index".into());
    }
    if g.max_virtual_size > i64::MAX as u64 {
        return Err("size beyond i64".into());
    }
    if g.max_ciphertext_size > MAX_PAYLOAD {
        return Err("ciphertext beyond journal payload bound".into());
    }
    let _ = plan;
    Ok(())
}

#[test]
fn superblock_crc_valid_mutations() {
    let seed = 0x5B00_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut stats = Stats::default();
    let fields = [
        Field::U32(8),
        Field::U64(12),
        Field::Bytes(20, 16),
        Field::U32(36),
        Field::U32(40),
        Field::U32(44),
        Field::U32(48),
        Field::U32(52),
        Field::U64(56),
        Field::U64(64),
        Field::U64(72),
        Field::U32(80),
        Field::U64(84),
        Field::U64(92),
        Field::Bytes(100, 2),
        Field::Bytes(102, 32),
        Field::Bytes(200, 3892),
    ];
    for i in 0..ITER {
        let version = [SUPERBLOCK_VERSION, SUPERBLOCK_VERSION_V2, SUPERBLOCK_VERSION_V3][i % 3];
        let mut image = superblock(version);
        mutate_fields(&mut rng, &mut image, &fields);
        if i % 5 == 0 {
            // Recompute slot_size/slot_header_size from the (mutated)
            // geometry inputs so decode reaches Geometry::compute's result.
            let rd32 = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
            let rd64 = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
            if let Ok(g) = Geometry::compute(
                rd32(&image, 36),
                rd32(&image, 40),
                rd32(&image, 44),
                rd32(&image, 48),
                rd64(&image, 64),
                rd64(&image, 72),
            ) {
                image[52..56].copy_from_slice(&g.slot_header_size.to_le_bytes());
                image[56..64].copy_from_slice(&g.slot_size.to_le_bytes());
                recrc(&mut image);
            }
        }
        exercise(
            &mut stats,
            &image,
            VolumeSuperblock::decode,
            VolumeSuperblock::encode,
            |sb| geometry_invariants(&sb.superblock.geometry),
            |_| 4096,
        );
    }
    // Geometry-only sweep: mostly-plausible inputs with one or two extreme values.
    let mut geo_accepted = 0;
    for _ in 0..ITER * 5 {
        let pick = |rng: &mut StdRng, v: &[u64]| v[rng.random_range(0..v.len())];
        let mut dbs = pick(&mut rng, &[512, 1024, 4096, 65536]) as u32;
        let mut cus = dbs * pick(&mut rng, &[1, 2, 4, 8, 16, 128]) as u32;
        let mut align = pick(&mut rng, &[512, 4096, 1 << 20, 1 << 31]) as u32;
        let mut mct = cus.saturating_add(pick(&mut rng, &[0, 16, 28, 64, 4096]) as u32);
        let units = pick(&mut rng, &[1, 7, 1 << 20, 1 << 32, 1 << 40, 0x0010_0000_4D41_4B48]);
        let mut mvs = (cus as u64).saturating_mul(units);
        let per = pick(&mut rng, &[1, 8, 1000, 1 << 16, 1 << 31, (1 << 32) - 1, 1 << 32]);
        let mut sls = (cus as u64).saturating_mul(per);
        match rng.random_range(0..8u32) {
            0 => dbs = interesting_u32(&mut rng, dbs),
            1 => cus = interesting_u32(&mut rng, cus),
            2 => align = interesting_u32(&mut rng, align),
            3 => mct = interesting_u32(&mut rng, mct),
            4 => mvs = interesting_u64(&mut rng, mvs),
            5 => sls = interesting_u64(&mut rng, sls),
            _ => {}
        }
        let (dbs, cus, align, mct, mvs, sls) = (dbs, cus, align, mct, mvs, sls);
        let r = catch_unwind(|| Geometry::compute(dbs, cus, align, mct, mvs, sls));
        match r {
            Err(_) => panic!("Geometry::compute panicked on {dbs} {cus} {align} {mct} {mvs} {sls}"),
            Ok(Ok(g)) => {
                geo_accepted += 1;
                if let Err(e) = geometry_invariants(&g) {
                    panic!("accepted geometry violates {e}: {g:?}");
                }
            }
            Ok(Err(_)) => {}
        }
    }
    eprintln!("[audit2 codec] geometry sweep: {} tried, {geo_accepted} accepted", ITER * 5);
    stats.report("superblock", seed);
    assert_clean("superblock", &stats);
    // Non-canonical acceptance (padding after the strings) is pinned in
    // superblock_accepts_nonzero_padding_after_strings.
}

// ---------------------------------------------------------------- journal records

#[test]
fn journal_scanner_crc_valid_record_mutations() {
    let seed = 0x7041_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut panics = Vec::new();
    let mut over = Vec::new();
    let mut violations = Vec::new();
    let mut outcomes = [0u64; 3];
    for _ in 0..ITER {
        let first = rng.random_range(1..1000u64);
        let n = rng.random_range(1..8);
        let mut buf = Vec::new();
        let mut starts = Vec::new();
        for k in 0..n {
            starts.push(buf.len());
            buf.extend(encode_record(&JournalRecord {
                sequence: first + k,
                unit_index: rng.random_range(0..64),
                payload: (0..rng.random_range(0..200)).map(|_| rng.random()).collect(),
            }));
        }
        // Mutate one record header field CRC-validly; optionally also
        // recompute its payload CRC over the (new) payload length.
        let r = starts[rng.random_range(0..starts.len())];
        let field = rng.random_range(0..3u32);
        match field {
            0 => {
                let cur = u64::from_le_bytes(buf[r + 4..r + 12].try_into().unwrap());
                let v = interesting_u64(&mut rng, cur);
                buf[r + 4..r + 12].copy_from_slice(&v.to_le_bytes());
            }
            1 => {
                let cur = u64::from_le_bytes(buf[r + 12..r + 20].try_into().unwrap());
                let v = interesting_u64(&mut rng, cur);
                buf[r + 12..r + 20].copy_from_slice(&v.to_le_bytes());
            }
            _ => {
                let cur = u32::from_le_bytes(buf[r + 20..r + 24].try_into().unwrap());
                let v = if rng.random_bool(0.5) {
                    interesting_u32(&mut rng, cur)
                } else {
                    cur.saturating_add(rng.random_range(0..64)).saturating_sub(rng.random_range(0..64))
                };
                buf[r + 20..r + 24].copy_from_slice(&v.to_le_bytes());
                let end = (r + 32 + v as usize).min(buf.len());
                let crc = crc32fast::hash(&buf[r + 32..end]);
                buf[r + 24..r + 28].copy_from_slice(&crc.to_le_bytes());
            }
        }
        let crc = crc32fast::hash(&buf[r..r + 28]);
        buf[r + 28..r + 32].copy_from_slice(&crc.to_le_bytes());
        if rng.random_bool(0.2) {
            buf.extend(std::iter::repeat_n(0, rng.random_range(0..100)));
        }
        let durable = match rng.random_range(0..3u32) {
            0 => None,
            1 => Some(buf.len()),
            _ => Some(rng.random_range(0..=buf.len())),
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            measured(|| scan_segment_bounded(&buf, first, durable))
        }));
        let ((records, outcome), peak) = match result {
            Ok(v) => v,
            Err(_) => {
                if panics.len() < 4 {
                    panics.push(format!("first {first} durable {durable:?} buf {:02x?}", &buf[..buf.len().min(64)]));
                }
                continue;
            }
        };
        if peak > bound(buf.len()) && over.len() < 4 {
            over.push(format!("peak {peak} for {}", buf.len()));
        }
        let mut expect = first;
        let mut pos = 0usize;
        for rec in &records {
            if rec.sequence != expect {
                violations.push(format!("sequence {} where {expect}", rec.sequence));
            }
            expect += 1;
            pos += 32 + rec.payload.len();
        }
        if pos > buf.len() {
            violations.push("records exceed buffer".into());
        }
        match &outcome {
            ScanOutcome::Clean => {
                outcomes[0] += 1;
                if buf[pos..].iter().any(|b| *b != 0) {
                    violations.push(format!("Clean with non-zero bytes after {pos}"));
                }
            }
            ScanOutcome::TornTail { at } => {
                outcomes[1] += 1;
                if *at != pos {
                    violations.push(format!("TornTail at {at} but records end at {pos}"));
                }
                if durable.is_some_and(|d| *at < d) {
                    violations.push(format!("TornTail at {at} inside durable prefix {durable:?}"));
                }
            }
            ScanOutcome::Corrupt { at, .. } => {
                outcomes[2] += 1;
                if *at != pos {
                    violations.push(format!("Corrupt at {at} but records end at {pos}"));
                }
            }
        }
    }
    eprintln!(
        "[audit2 codec] journal scanner: seed {seed:#x} {ITER} CRC-valid mutated segments; \
         clean {} torn {} corrupt {}",
        outcomes[0], outcomes[1], outcomes[2]
    );
    assert!(panics.is_empty(), "{panics:?}");
    assert!(over.is_empty(), "{over:?}");
    violations.truncate(8);
    assert!(violations.is_empty(), "{violations:?}");
}

// ---------------------------------------------------------------- pinned non-canonical acceptances

/// The bitmap's padding bits (bit positions >= units in the last byte) are
/// never validated. A CRC-valid map with only padding bits set decodes, and
/// `set_count()` (used by `SlotStore::open` to decide whether an adopted
/// shard "was ever checkpointed into") reports allocations that do not
/// exist.
#[test]
fn allocation_map_accepts_padding_bits_that_inflate_set_count() {
    let mut image = AllocationMap::new(1001).encode();
    let n = image.len();
    // Last bitmap byte holds unit 1000 (bit 0) and seven padding bits.
    image[n - 5] = 0b1111_1110;
    recrc(&mut image);
    let map = AllocationMap::decode(&image).expect("padding bits are accepted");
    let real = (0..map.units()).filter(|u| map.get(*u)).count() as u64;
    assert_eq!(real, 0, "no real unit is allocated");
    assert_eq!(
        map.set_count(),
        0,
        "set_count() counts {} padding bits as allocations",
        map.set_count()
    );
}

/// The 24 reserved bytes and the flags word of a slot header are never
/// checked; a CRC-valid header with garbage there decodes and re-encodes to
/// different bytes.
#[test]
fn slot_header_accepts_nonzero_reserved_and_unknown_flags() {
    let mut image = SlotHeader {
        unit_index: 5,
        write_sequence: 9,
        ciphertext_len: 540,
        flags: 0,
        ciphertext_crc: 0x1234,
    }
    .encode()
    .to_vec();
    image[28..32].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    image[40] = 0x5a;
    recrc(&mut image);
    let header = SlotHeader::decode(&image).expect("accepted");
    assert!(
        header.encode().to_vec() == image,
        "accepted header with flags {:#x} and non-zero reserved bytes re-encodes differently",
        header.flags
    );
}

/// The superblock's padding after the three strings is not checked.
#[test]
fn superblock_accepts_nonzero_padding_after_strings() {
    let mut image = superblock(SUPERBLOCK_VERSION_V2);
    image[3000] = 0x77;
    recrc(&mut image);
    let sb = VolumeSuperblock::decode(&image).expect("accepted");
    assert!(sb.encode() == image, "accepted superblock (padding byte 3000 = 0x77) re-encodes differently");
}

/// A canary's decoder ignores bytes after the ciphertext.
#[test]
fn key_canary_accepts_crc_valid_trailing_bytes() {
    let mut image = KeyCanary {
        generation: 1,
        volume_uuid: Uuid::from_u128(7),
        unit_index: maki_format::canary::CANARY_UNIT_INDEX,
        ciphertext: vec![1, 2, 3],
    }
    .encode();
    let n = image.len();
    image.splice(n - 4..n - 4, [9u8; 5]);
    recrc(&mut image);
    let canary = KeyCanary::decode(&image).expect("accepted");
    assert!(
        canary.encode() == image,
        "accepted canary with 5 trailing bytes re-encodes differently ({} vs {} bytes)",
        canary.encode().len(),
        image.len()
    );
}
