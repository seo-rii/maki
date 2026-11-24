//! audit2 (decoder-fuzz), one level up from the codecs: build a small
//! volume, apply a CRC-VALID, field-aware mutation to ONE metadata file
//! (superblock, catalog, allocation/discard map, checkpoint state, durable
//! proof, durable mark, journal segment header or record, slot header),
//! then run the deep offline check and recovery and read every unit.
//!
//! Properties:
//!   * neither the deep check nor recovery panics (debug sanitizers on);
//!   * they agree: the check never passes a volume recovery refuses, and a
//!     check without errors means every unit reads without EIO;
//!   * recovery never serves an OLDER version of a unit, or zeros for a unit
//!     with written data, unless the mutation itself explains it (a discard
//!     bit, a re-pointed unit index); every such case is printed;
//!   * an accepted volume stays attachable: write, flush, checkpoint, drop,
//!     recover again, and the same units read the same.
//!
//! The Volume layer stores ciphertext without authenticating it, so a
//! CRC-valid change of a journal record's unit index or payload length
//! legitimately yields foreign or garbage ciphertext here (the engine's
//! crypto context binding refuses it); those outcomes are counted, not
//! failed.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::recovery::RecoveryError;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::init;
use maki_test_support::failpoints;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const CT_LEN: usize = 540;
const SEGMENT: u64 = 4096;
const UNITS: u64 = 128;

fn geometry() -> Geometry {
    // 128 units, 48 units per shard: three shards, the last one partial.
    Geometry::compute(512, UNIT, 512, 544, UNITS * UNIT as u64, 48 * UNIT as u64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xA0D1_7202),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: SEGMENT,
    }
}

fn ct(unit: u64, version: u64) -> Vec<u8> {
    let mut v = vec![(unit.wrapping_mul(31).wrapping_add(version)) as u8; CT_LEN];
    v[..8].copy_from_slice(&unit.to_le_bytes());
    v[8..16].copy_from_slice(&version.to_le_bytes());
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Zero,
    Version(u64),
    Foreign(u64, u64),
    Garbage,
    Eio(String),
}

fn classify(unit: u64, read: Result<Option<(u64, Vec<u8>)>, maki_core::error::CoreError>) -> Value {
    match read {
        Err(e) => Value::Eio(e.to_string()),
        Ok(None) => Value::Zero,
        Ok(Some((_, data))) => {
            if data.len() != CT_LEN {
                return Value::Garbage;
            }
            let u = u64::from_le_bytes(data[..8].try_into().unwrap());
            let v = u64::from_le_bytes(data[8..16].try_into().unwrap());
            if data != ct(u, v) {
                Value::Garbage
            } else if u != unit {
                Value::Foreign(u, v)
            } else {
                Value::Version(v)
            }
        }
    }
}

/// What the workload wrote: per unit, the version history; `discarded`
/// when the latest operation on it was a discard.
#[derive(Default, Clone)]
struct Model {
    versions: BTreeMap<u64, Vec<u64>>,
    discarded: BTreeMap<u64, bool>,
}

fn build(rng: &mut StdRng, discard: bool) -> (Arc<CrashableBacking>, Model) {
    let backing = Arc::new(CrashableBacking::new());
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    let mut vol = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
    let mut model = Model::default();
    let mut version = 0u64;
    let phases = rng.random_range(1..=3);
    for phase in 0..phases {
        for _ in 0..rng.random_range(4..24) {
            let unit = rng.random_range(0..UNITS);
            if discard && rng.random_bool(0.12) && model.versions.contains_key(&unit) {
                vol.discard_ct(unit, rng.random_bool(0.3)).unwrap();
                model.discarded.insert(unit, true);
                continue;
            }
            version += 1;
            vol.write_ct(unit, &ct(unit, version), rng.random_bool(0.2)).unwrap();
            model.versions.entry(unit).or_default().push(version);
            model.discarded.insert(unit, false);
        }
        vol.flush().unwrap();
        if phase + 1 < phases || rng.random_bool(0.5) {
            vol.checkpoint().unwrap();
        }
    }
    // A few unflushed writes; a restart (not a power loss) keeps them.
    for _ in 0..rng.random_range(0..4) {
        let unit = rng.random_range(0..UNITS);
        version += 1;
        vol.write_ct(unit, &ct(unit, version), false).unwrap();
        model.versions.entry(unit).or_default().push(version);
        model.discarded.insert(unit, false);
    }
    drop(vol);
    (backing, model)
}

// ------------------------------------------------------------------ mutation

fn interesting_u64(rng: &mut StdRng, current: u64) -> u64 {
    match rng.random_range(0..13u32) {
        0 => 0,
        1 => 1,
        2 => u64::MAX,
        3 => u64::MAX - 1,
        4 => i64::MAX as u64,
        5 => current.wrapping_add(1),
        6 => current.wrapping_sub(1),
        7 => current.wrapping_add(rng.random_range(2..64)),
        8 => current.saturating_sub(rng.random_range(2..64)),
        9 => current.wrapping_add(1 << 32),
        10 => rng.random_range(0..256),
        11 => current ^ (1 << rng.random_range(0..64)),
        _ => rng.random(),
    }
}

fn interesting_u32(rng: &mut StdRng, current: u32) -> u32 {
    match rng.random_range(0..10u32) {
        0 => 0,
        1 => 1,
        2 => u32::MAX,
        3 => current.wrapping_add(1),
        4 => current.wrapping_sub(1),
        5 => current.wrapping_add(rng.random_range(2..64)),
        6 => current.saturating_sub(rng.random_range(2..64)),
        7 => rng.random_range(0..1024),
        _ => rng.random(),
    }
}

fn rd64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn rd32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn set64(rng: &mut StdRng, b: &mut [u8], at: usize) -> String {
    let old = rd64(b, at);
    let v = interesting_u64(rng, old);
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    format!("u64@{at} {old} -> {v}")
}
fn set32(rng: &mut StdRng, b: &mut [u8], at: usize) -> String {
    let old = rd32(b, at);
    let v = interesting_u32(rng, old);
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    format!("u32@{at} {old} -> {v}")
}
fn recrc_range(b: &mut [u8], start: usize, end: usize) {
    // crc32 over [start, end - 4) stored at [end - 4, end).
    let crc = crc32fast::hash(&b[start..end - 4]);
    b[end - 4..end].copy_from_slice(&crc.to_le_bytes());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Superblock,
    Catalog,
    AllocMap,
    DiscardMap,
    Checkpoint,
    Proof,
    Mark,
    Segment,
    SlotData,
}

fn kind_of(path: &str) -> Option<Kind> {
    let name = path.rsplit('/').next().unwrap();
    Some(if name.starts_with("superblock.") {
        Kind::Superblock
    } else if name.starts_with("shard-catalog.") {
        Kind::Catalog
    } else if name.contains(".alloc.") {
        Kind::AllocMap
    } else if name.contains(".discard.") {
        Kind::DiscardMap
    } else if path.starts_with("checkpoint/state.") {
        Kind::Checkpoint
    } else if name.starts_with("durable-proof.") {
        Kind::Proof
    } else if name == "durable-mark" {
        Kind::Mark
    } else if name.starts_with("seg-") {
        Kind::Segment
    } else if name.ends_with(".dat") {
        Kind::SlotData
    } else {
        return None;
    })
}

fn files(backing: &CrashableBacking) -> Vec<String> {
    let mut out = Vec::new();
    for dir in ["", "data", "journal", "checkpoint"] {
        if dir.is_empty() || backing.exists(dir).unwrap_or(false) {
            for name in backing.list(dir).unwrap_or_default() {
                let path = if dir.is_empty() { name } else { format!("{dir}/{name}") };
                if kind_of(&path).is_some() {
                    out.push(path);
                }
            }
        }
    }
    out.sort();
    out
}

fn read_file(backing: &CrashableBacking, path: &str) -> Vec<u8> {
    let f = backing.open(path, false).unwrap();
    let mut v = vec![0; f.len().unwrap() as usize];
    f.read_at(0, &mut v).unwrap();
    v
}

fn write_file(backing: &CrashableBacking, path: &str, bytes: &[u8]) {
    let f = backing.open(path, false).unwrap();
    f.set_len(bytes.len() as u64).unwrap();
    f.write_at(0, bytes).unwrap();
    f.sync_data().unwrap();
}

/// Mutate one field of `bytes` (a file of `kind`) keeping every CRC valid.
/// Returns a description and whether the change re-points a unit index or
/// ciphertext length (outcomes the Volume layer cannot authenticate).
fn mutate(rng: &mut StdRng, kind: Kind, bytes: &mut Vec<u8>, discarded_hint: bool) -> Option<(String, bool)> {
    let n = bytes.len();
    let mut repoints = false;
    let desc = match kind {
        Kind::Superblock => {
            if n != 4096 {
                return None;
            }
            let d = match rng.random_range(0..9u32) {
                0 => {
                    let v = [1u32, 2, 3][rng.random_range(0..3)];
                    let old = rd32(bytes, 8);
                    bytes[8..12].copy_from_slice(&v.to_le_bytes());
                    format!("metadata version {old} -> {v}")
                }
                1 => set64(rng, bytes, 12),
                2 => {
                    bytes[20 + rng.random_range(0..16)] ^= 1;
                    "volume uuid bit".into()
                }
                3 => set64(rng, bytes, 64),
                4 => set64(rng, bytes, 72),
                5 => set32(rng, bytes, 40),
                6 => set32(rng, bytes, 48),
                7 => set64(rng, bytes, 84),
                _ => {
                    bytes[rng.random_range(100..140)] = rng.random();
                    "string bytes".into()
                }
            };
            recrc_range(bytes, 0, 4096);
            d
        }
        Kind::Catalog => {
            let count = rd32(bytes, 20) as usize;
            let d = match rng.random_range(0..5u32) {
                0 => set64(rng, bytes, 12),
                1 => set32(rng, bytes, 20),
                2 if count > 0 => {
                    let e = rng.random_range(0..count);
                    set64(rng, bytes, 24 + 8 * e)
                }
                3 if count > 0 => {
                    // drop the last entry consistently
                    let new = count - 1;
                    bytes.drain(24 + 8 * new..24 + 8 * count);
                    bytes[20..24].copy_from_slice(&(new as u32).to_le_bytes());
                    format!("catalog drops entry {new}")
                }
                _ => {
                    // add an entry consistently
                    let at = 24 + 8 * count;
                    let shard: u64 = rng.random_range(0..5);
                    bytes.splice(at..at, shard.to_le_bytes());
                    bytes[20..24].copy_from_slice(&(count as u32 + 1).to_le_bytes());
                    format!("catalog appends shard {shard}")
                }
            };
            let n = bytes.len();
            recrc_range(bytes, 0, n);
            d
        }
        Kind::AllocMap | Kind::DiscardMap => {
            let units = rd64(bytes, 20);
            let d = match rng.random_range(0..6u32) {
                0 => set64(rng, bytes, 12),
                1 => set64(rng, bytes, 20),
                2 | 3 if units > 0 => {
                    let u = rng.random_range(0..units);
                    let byte = 28 + (u / 8) as usize;
                    bytes[byte] ^= 1 << (u % 8);
                    format!("toggle bit for in-shard unit {u}")
                }
                4 if units % 8 != 0 => {
                    bytes[n - 5] |= 0x80;
                    "padding bit".into()
                }
                _ => {
                    for b in &mut bytes[28..n - 4] {
                        *b = 0xff;
                    }
                    "all bits set".into()
                }
            };
            let n = bytes.len();
            recrc_range(bytes, 0, n);
            d
        }
        Kind::Checkpoint => {
            let d = if rng.random_bool(0.3) { set64(rng, bytes, 12) } else { set64(rng, bytes, 20) };
            recrc_range(bytes, 0, n);
            d
        }
        Kind::Proof => {
            let d = match rng.random_range(0..5u32) {
                0 => set64(rng, bytes, 12),
                1 => {
                    bytes[20 + rng.random_range(0..16)] ^= 1;
                    "proof uuid bit".into()
                }
                2 => set64(rng, bytes, 36),
                3 => set64(rng, bytes, 44),
                _ => set64(rng, bytes, 52),
            };
            recrc_range(bytes, 0, n);
            d
        }
        Kind::Mark => {
            if n < 32 {
                return None;
            }
            let d = if rng.random_bool(0.5) { set64(rng, bytes, 12) } else { set64(rng, bytes, 20) };
            recrc_range(bytes, 0, 32);
            d
        }
        Kind::Segment => {
            if n < 48 {
                return None;
            }
            // Locate records.
            let mut starts = Vec::new();
            let mut pos = 48;
            while pos + 32 <= n && &bytes[pos..pos + 4] == b"MJR1" {
                starts.push(pos);
                pos += 32 + rd32(bytes, pos + 20) as usize;
            }
            if starts.is_empty() || rng.random_bool(0.35) {
                let d = match rng.random_range(0..3u32) {
                    0 => set64(rng, bytes, 12),
                    1 => {
                        bytes[20 + rng.random_range(0..16)] ^= 1;
                        "segment uuid bit".into()
                    }
                    _ => set64(rng, bytes, 36),
                };
                recrc_range(bytes, 0, 48);
                format!("segment header {d}")
            } else {
                let r = starts[rng.random_range(0..starts.len())];
                let d = match rng.random_range(0..3u32) {
                    0 => set64(rng, bytes, r + 4),
                    1 => {
                        repoints = true;
                        set64(rng, bytes, r + 12)
                    }
                    _ => {
                        repoints = true;
                        let d = set32(rng, bytes, r + 20);
                        let len = rd32(bytes, r + 20) as usize;
                        let end = (r + 32 + len).min(n);
                        let crc = crc32fast::hash(&bytes[r + 32..end]);
                        bytes[r + 24..r + 28].copy_from_slice(&crc.to_le_bytes());
                        d
                    }
                };
                recrc_range(bytes, r, r + 32);
                format!("record@{r} {d}")
            }
        }
        Kind::SlotData => {
            // slot size 1024 (64 + 544 aligned to 512)
            let slot = 1024usize;
            let written: Vec<usize> = (0..n / slot)
                .filter(|i| bytes[i * slot..i * slot + 8] == *b"MAKISLT1")
                .collect();
            if written.is_empty() {
                return None;
            }
            let at = written[rng.random_range(0..written.len())] * slot;
            let d = match rng.random_range(0..5u32) {
                0 => {
                    repoints = true;
                    set64(rng, bytes, at + 8)
                }
                1 => set64(rng, bytes, at + 16),
                2 => {
                    repoints = true;
                    let d = set32(rng, bytes, at + 24);
                    let len = rd32(bytes, at + 24) as usize;
                    let end = (at + 64 + len).min(n);
                    let crc = crc32fast::hash(&bytes[at + 64..end]);
                    bytes[at + 32..at + 36].copy_from_slice(&crc.to_le_bytes());
                    d
                }
                3 => set32(rng, bytes, at + 28),
                _ => {
                    bytes[at + 36 + rng.random_range(0..24)] = rng.random();
                    "slot reserved byte".into()
                }
            };
            recrc_range(bytes, at, at + 64);
            format!("slot@{} {d}", at / slot)
        }
    };
    let _ = discarded_hint;
    Some((desc, repoints))
}

// ------------------------------------------------------------------ run

#[derive(Debug, Default)]
struct Tally {
    iterations: u64,
    mutated: BTreeMap<String, u64>,
    both_refuse: u64,
    both_accept: u64,
    check_passes_attach_refuses: Vec<String>,
    check_fails_attach_serves_all: Vec<String>,
    check_clean_reads_eio: Vec<String>,
    stale_or_lost: Vec<String>,
    explained_foreign: u64,
    unstable: Vec<String>,
    panics: Vec<String>,
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn read_all(vol: &Volume) -> Vec<Value> {
    (0..UNITS).map(|u| classify(u, vol.read_ct(u))).collect()
}

fn run_one(rng: &mut StdRng, tally: &mut Tally, seed: u64, iteration: u64) {
    let discard = rng.random_bool(0.5);
    let (backing, model) = build(rng, discard);
    let all = files(&backing);
    let path = all[rng.random_range(0..all.len())].clone();
    let kind = kind_of(&path).unwrap();
    let mut bytes = read_file(&backing, &path);
    let Some((desc, repoints)) = mutate(rng, kind, &mut bytes, discard) else {
        return;
    };
    write_file(&backing, &path, &bytes);
    // Sometimes make both A/B copies carry the mutation (no fallback).
    let mut desc = desc;
    let sibling = if let Some(stem) = path.strip_suffix(".a") {
        Some(format!("{stem}.b"))
    } else {
        path.strip_suffix(".b").map(|stem| format!("{stem}.a"))
    };
    if let Some(sibling) = sibling {
        if backing.exists(&sibling).unwrap_or(false) && rng.random_bool(0.3) {
            write_file(&backing, &sibling, &bytes);
            desc.push_str(" [both copies]");
        }
    }
    tally.iterations += 1;
    *tally.mutated.entry(format!("{kind:?}")).or_insert(0) += 1;
    let what = format!("seed {seed:#x} iter {iteration} v{} {path}: {desc}", if discard { 3 } else { 2 });

    let check = catch_unwind(AssertUnwindSafe(|| {
        deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT)
    }));
    let check = match check {
        Err(p) => {
            tally.panics.push(format!("deep_check panicked ({}) on {what}", panic_text(p)));
            return;
        }
        Ok(Err(e)) => {
            tally.panics.push(format!("deep_check returned Err ({e}) on {what}"));
            return;
        }
        Ok(Ok(r)) => r,
    };
    let structural_errors: Vec<&String> =
        check.errors.iter().filter(|e| !e.starts_with("slot:")).collect();
    let legacy_v1 = check.warnings.iter().any(|w| w.starts_with("legacy v1 volume"));

    let recovered = catch_unwind(AssertUnwindSafe(|| {
        Volume::recover(backing.clone() as Arc<dyn Backing>, options())
    }));
    let vol = match recovered {
        Err(p) => {
            tally.panics.push(format!("recover panicked ({}) on {what}", panic_text(p)));
            return;
        }
        Ok(Err(RecoveryError::AlreadyAttached)) => {
            tally.panics.push(format!("lock left held after deep check on {what}"));
            return;
        }
        Ok(Err(e)) => {
            if check.ok() && !legacy_v1 {
                tally
                    .check_passes_attach_refuses
                    .push(format!("{what}: recovery: {e}"));
            } else {
                tally.both_refuse += 1;
            }
            return;
        }
        Ok(Ok(vol)) => vol,
    };
    let reads = catch_unwind(AssertUnwindSafe(|| read_all(&vol)));
    let values = match reads {
        Err(p) => {
            tally.panics.push(format!("read panicked ({}) on {what}", panic_text(p)));
            return;
        }
        Ok(v) => v,
    };
    let eio: Vec<u64> = (0..UNITS)
        .filter(|u| matches!(values[*u as usize], Value::Eio(_)))
        .collect();
    if check.ok() && !eio.is_empty() {
        tally.check_clean_reads_eio.push(format!(
            "{what}: units {eio:?} EIO ({:?})",
            values[eio[0] as usize]
        ));
    }
    if !structural_errors.is_empty() && eio.is_empty() {
        tally
            .check_fails_attach_serves_all
            .push(format!("{what}: check: {}", structural_errors[0]));
    } else {
        tally.both_accept += 1;
    }
    let mutation_touches_discard = kind == Kind::DiscardMap
        || (kind == Kind::Superblock && desc.starts_with("metadata version"));
    for unit in 0..UNITS {
        let history = model.versions.get(&unit);
        let latest = history.and_then(|h| h.last().copied());
        let discarded = model.discarded.get(&unit).copied().unwrap_or(false);
        let bad = match (&values[unit as usize], latest) {
            (Value::Eio(_), _) => None,
            (Value::Foreign(..) | Value::Garbage, _) if repoints => {
                tally.explained_foreign += 1;
                None
            }
            (Value::Foreign(u, v), _) => Some(format!("unit {unit} serves unit {u}'s version {v}")),
            (Value::Garbage, _) => Some(format!("unit {unit} serves garbage")),
            (Value::Zero, None) => None,
            (Value::Zero, Some(_)) if discarded || mutation_touches_discard => None,
            (Value::Zero, Some(v)) => Some(format!("unit {unit} reads zeros; latest version {v}")),
            (Value::Version(v), Some(l)) if *v == l && !discarded => None,
            (Value::Version(v), Some(_)) if discarded && mutation_touches_discard => {
                let _ = v;
                None
            }
            (Value::Version(v), Some(l)) => Some(format!(
                "unit {unit} serves version {v}; latest {l}{}",
                if discarded { " (discarded)" } else { "" }
            )),
            (Value::Version(v), None) => Some(format!("unit {unit} serves version {v} never written")),
        };
        if let Some(bad) = bad {
            if repoints && kind == Kind::Segment {
                // A re-pointed journal record can legitimately move a newer
                // version away from this unit.
                tally.explained_foreign += 1;
                continue;
            }
            tally.stale_or_lost.push(format!("{what}: {bad} [check ok: {}]", check.ok()));
            break;
        }
    }

    // Stability: an accepted volume keeps working and re-recovers the same.
    let stable = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let mut vol = vol;
        let target = (0..UNITS)
            .find(|u| matches!(values[*u as usize], Value::Zero | Value::Version(_)))
            .unwrap_or(0);
        vol.write_ct(target, &ct(target, 1_000_000), true)
            .map_err(|e| format!("write after recovery: {e}"))?;
        vol.flush().map_err(|e| format!("flush after recovery: {e}"))?;
        vol.checkpoint().map_err(|e| format!("checkpoint after recovery: {e}"))?;
        drop(vol);
        let again = Volume::recover(backing.clone() as Arc<dyn Backing>, options())
            .map_err(|e| format!("second recovery refused: {e}"))?;
        for unit in 0..UNITS {
            let now = classify(unit, again.read_ct(unit));
            let before = &values[unit as usize];
            let expect_new = unit == target;
            let same = if expect_new {
                now == Value::Version(1_000_000)
            } else {
                match (before, &now) {
                    (Value::Eio(_), Value::Eio(_)) => true,
                    (a, b) => a == b,
                }
            };
            if !same {
                return Err(format!("unit {unit}: {before:?} then {now:?}"));
            }
        }
        Ok(())
    }));
    match stable {
        Err(p) => tally
            .panics
            .push(format!("post-recovery use panicked ({}) on {what}", panic_text(p))),
        Ok(Err(e)) => tally.unstable.push(format!("{what}: {e}")),
        Ok(Ok(())) => {}
    }
}

fn sweep(seed: u64, iterations: u64) -> Tally {
    let _guard = failpoints::test_lock();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut tally = Tally::default();
    for i in 0..iterations {
        run_one(&mut rng, &mut tally, seed, i);
    }
    tally
}

fn report(t: &Tally, seed: u64) {
    eprintln!(
        "[audit2 metadata] seed {seed:#x}: {} mutated volumes {:?}; both refuse {}, both accept {}, \
         explained foreign/garbage {}",
        t.iterations, t.mutated, t.both_refuse, t.both_accept, t.explained_foreign
    );
    for (name, list) in [
        ("PANIC", &t.panics),
        ("CHECK-PASSES/ATTACH-REFUSES", &t.check_passes_attach_refuses),
        ("CHECK-CLEAN/READ-EIO", &t.check_clean_reads_eio),
        ("CHECK-FAILS/ATTACH-SERVES-ALL", &t.check_fails_attach_serves_all),
        ("STALE-OR-LOST", &t.stale_or_lost),
        ("UNSTABLE", &t.unstable),
    ] {
        eprintln!("[audit2 metadata]   {name}: {}", list.len());
        let limit = if std::env::var_os("AUDIT2_ALL").is_some() { usize::MAX } else { 12 };
        for item in list.iter().take(limit) {
            eprintln!("[audit2 metadata]     {item}");
        }
    }
}

/// Longer run with another seed (release-gate style; ~5 min in debug).
#[test]
#[ignore]
fn crc_valid_metadata_mutations_long() {
    let seed = 0x00A0_D172_0002;
    let tally = sweep(seed, 12_000);
    report(&tally, seed);
    assert!(tally.panics.is_empty(), "panics: {:#?}", &tally.panics[..tally.panics.len().min(4)]);
    assert!(
        tally.check_passes_attach_refuses.is_empty()
            && tally.check_clean_reads_eio.is_empty()
            && tally.stale_or_lost.is_empty()
            && tally.unstable.is_empty(),
        "see the [audit2 metadata] report above"
    );
}

#[test]
fn crc_valid_metadata_mutations_check_and_recovery_agree() {
    // Round 8: AUDIT8_SEED_START is XORed into the seed, AUDIT8_SEED_COUNT
    // is the number of mutated volumes.
    let get = |k: &str| std::env::var(k).ok().and_then(|s| s.parse::<u64>().ok());
    let seed = 0x00A0_D172_0001 ^ get("AUDIT8_SEED_START").unwrap_or(0);
    let tally = sweep(seed, get("AUDIT8_SEED_COUNT").unwrap_or(2500) as _);
    report(&tally, seed);
    assert!(tally.panics.is_empty(), "panics: {:#?}", &tally.panics[..tally.panics.len().min(4)]);
    assert!(
        tally.check_passes_attach_refuses.is_empty()
            && tally.check_clean_reads_eio.is_empty()
            && tally.stale_or_lost.is_empty()
            && tally.unstable.is_empty(),
        "see the [audit2 metadata] report above"
    );
}
