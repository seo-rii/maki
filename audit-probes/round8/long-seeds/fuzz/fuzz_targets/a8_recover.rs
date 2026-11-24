#![no_main]
//! Round-8 audit target (not in the repository): coverage-guided fuzzing of
//! offline deep check + recovery + attach + reads over a mutated volume.
//!
//! A small real volume (v2 or v3 envelope; checkpointed slots, sealed and
//! active journal segments, trims) is built once per process. Each input is
//! a list of mutations of its files (bit flips, field overwrites, truncation,
//! zeroing, copying one file over another, removal), optionally followed by
//! a checksum repair of the frame that was touched, so validation behind the
//! CRC-32 is reached. Oracles:
//!   - nothing panics, hangs or over-allocates (deep check, recovery, attach,
//!     reads, a write + flush + checkpoint on the attached volume);
//!   - a unit that reads successfully holds zeros or a value that was once
//!     written to *that* unit (never another unit's data, never garbage).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const UNITS: u64 = 16;
const REC: u64 = 32 + UNIT as u64 + 8;
const SEGMENT: u64 = 48 + 3 * REC;
const SLOT: u64 = 1024; // align_up(64 + 520, 512)

struct Base {
    files: BTreeMap<String, Vec<u8>>,
    dirs: Vec<String>,
    /// Every value ever written to each unit (zeros are always allowed).
    history: Vec<BTreeSet<Vec<u8>>>,
}

fn options() -> EngineOptions {
    EngineOptions {
        volume: VolumeOptions {
            journal_segment_size: SEGMENT,
        },
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: u64::MAX,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: std::time::Duration::from_secs(3600),
            ..Default::default()
        },
        ..EngineOptions::default()
    }
}

fn image(unit: u64, stamp: u32) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    let seed = (unit as u32).wrapping_mul(0x9E37_79B1) ^ stamp.wrapping_mul(0x85EB_CA6B);
    for (i, b) in v.iter_mut().enumerate() {
        *b = (seed.wrapping_add(i as u32).wrapping_mul(0x2545_F491) >> 24) as u8;
    }
    v[0] |= 1;
    v
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    })
}

fn snapshot(backing: &CrashableBacking) -> (BTreeMap<String, Vec<u8>>, Vec<String>) {
    let mut files = BTreeMap::new();
    let dirs = vec!["data".to_string(), "journal".to_string(), "checkpoint".to_string()];
    for dir in ["", "data", "journal", "checkpoint"] {
        for name in backing.list(dir).unwrap_or_default() {
            let path = if dir.is_empty() {
                name
            } else {
                format!("{dir}/{name}")
            };
            if let Ok(file) = backing.open(&path, false) {
                let mut bytes = vec![0u8; file.len().unwrap() as usize];
                file.read_at(0, &mut bytes).unwrap();
                files.insert(path, bytes);
            }
        }
    }
    files.remove("volume.lock");
    (files, dirs)
}

fn build(discard: bool, variant: u32) -> Base {
    let backing = Arc::new(CrashableBacking::new());
    let superblock = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xA8F0_0000 + variant as u128),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(UNIT, UNIT, 512, UNIT + 8, UNITS * UNIT as u64, 4 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock).unwrap();
    }
    let mut history = vec![BTreeSet::new(); UNITS as usize];
    runtime().block_on(async {
        let engine = Engine::attach(
            backing.process(),
            Arc::new(FakeCryptoProvider::new(UNIT)),
            options(),
        )
        .await
        .unwrap();
        let mut x = 0x9E37_79B9u32.wrapping_mul(variant + 1);
        let mut next = |n: u32| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x % n
        };
        for stamp in 1..=(40 + 10 * variant) {
            let unit = next(UNITS as u32 - 1) as u64; // unit 15 stays unwritten
            match next(10) {
                0..=5 => {
                    let data = image(unit, stamp);
                    engine.write(unit * UNIT as u64, &data, next(4) == 0).await.unwrap();
                    history[unit as usize].insert(data);
                }
                6 if discard => {
                    engine.trim(unit * UNIT as u64, UNIT as usize, false).await.unwrap();
                }
                7 => engine.flush().await.unwrap(),
                8 if stamp % 3 == 0 => {
                    engine.flush().await.unwrap();
                    engine.checkpoint().await.unwrap();
                }
                _ => {}
            }
        }
        // Variants end clean-flushed, or with an unsynced tail.
        if variant % 2 == 0 {
            engine.flush().await.unwrap();
        }
        engine.stop_checkpoint_worker().await;
        drop(engine);
    });
    let (files, dirs) = snapshot(&backing);
    Base {
        files,
        dirs,
        history,
    }
}

fn bases() -> &'static Vec<Base> {
    static BASES: OnceLock<Vec<Base>> = OnceLock::new();
    BASES.get_or_init(|| vec![build(false, 0), build(true, 1), build(false, 2), build(true, 3)])
}

fn crc_tail(frame: &mut [u8]) {
    if frame.len() >= 4 {
        let n = frame.len() - 4;
        let crc = crc32fast::hash(&frame[..n]);
        frame[n..].copy_from_slice(&crc.to_le_bytes());
    }
}

/// Repair the checksums of `bytes` according to what kind of file it is.
fn repair(path: &str, bytes: &mut Vec<u8>) {
    if path.starts_with("journal/seg-") {
        if bytes.len() >= 48 {
            crc_tail(&mut bytes[..48]);
        }
        // Walk records leniently: lengths from the (possibly mutated) header.
        let mut pos = 48usize;
        while pos + 32 <= bytes.len() {
            if &bytes[pos..pos + 4] != b"MJR1" {
                break;
            }
            let len = u32::from_le_bytes(bytes[pos + 20..pos + 24].try_into().unwrap()) as usize;
            let end = pos + 32 + len;
            if end <= bytes.len() {
                let crc = crc32fast::hash(&bytes[pos + 32..end]);
                bytes[pos + 24..pos + 28].copy_from_slice(&crc.to_le_bytes());
            }
            crc_tail(&mut bytes[pos..pos + 32]);
            if end > bytes.len() {
                break;
            }
            pos = end;
        }
    } else if path == "journal/durable-mark" {
        if bytes.len() >= 32 {
            crc_tail(&mut bytes[..32]);
        }
    } else if path.starts_with("data/") && path.ends_with(".data") {
        let mut pos = 0usize;
        while pos + 64 <= bytes.len() {
            if &bytes[pos..pos + 8] == b"MAKISLT1" {
                let len = u32::from_le_bytes(bytes[pos + 24..pos + 28].try_into().unwrap()) as usize;
                if pos + 64 + len <= bytes.len() {
                    let crc = crc32fast::hash(&bytes[pos + 64..pos + 64 + len]);
                    bytes[pos + 32..pos + 36].copy_from_slice(&crc.to_le_bytes());
                }
                crc_tail(&mut bytes[pos..pos + 64]);
            }
            pos += SLOT as usize;
        }
    } else if path.starts_with("superblock.") {
        if bytes.len() >= 4096 {
            crc_tail(&mut bytes[..4096]);
        }
    } else {
        // A/B records: one frame, CRC over everything before the trailer.
        crc_tail(bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let base = &bases()[(data[0] % 4) as usize];
    let mut files = base.files.clone();
    let names: Vec<String> = files.keys().cloned().collect();
    let mut input = &data[1..];
    let mut mutations = 0;
    while input.len() >= 4 && mutations < 6 {
        let name = names[input[0] as usize % names.len()].clone();
        let op = input[1];
        let pos = u16::from_le_bytes([input[2], input[3]]) as usize;
        input = &input[4..];
        let mut arg = [0u8; 8];
        let take = input.len().min(8);
        arg[..take].copy_from_slice(&input[..take]);
        input = &input[take..];
        mutations += 1;
        let Some(mut bytes) = files.get(&name).cloned() else {
            continue;
        };
        match op & 0x0F {
            0 => {
                if !bytes.is_empty() {
                    let at = pos % bytes.len();
                    bytes[at] ^= 1 << (arg[0] & 7);
                }
            }
            1 => {
                // overwrite up to 8 bytes (a field)
                let n = 1 + (arg[7] as usize & 7);
                if bytes.len() >= n {
                    let at = pos % (bytes.len() - n + 1);
                    bytes[at..at + n].copy_from_slice(&arg[..n]);
                }
            }
            2 => bytes.truncate(pos % (bytes.len() + 1)),
            3 => {
                if !bytes.is_empty() {
                    let at = pos % bytes.len();
                    let n = (1 + arg[0] as usize).min(bytes.len() - at);
                    bytes[at..at + n].fill(0);
                }
            }
            4 => {
                // copy another file over this one (A over B, an older segment)
                let other = &names[arg[0] as usize % names.len()];
                bytes = base.files[other].clone();
            }
            5 => {
                files.remove(&name);
                continue;
            }
            6 => bytes.extend(std::iter::repeat(arg[0]).take(1 + (pos % 96))),
            7 => {
                // small integer tweak of a little-endian u64 field
                if bytes.len() >= 8 {
                    let at = pos % (bytes.len() - 7);
                    let v = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
                    let d = (arg[0] % 5) as u64;
                    let nv = if arg[1] & 1 == 0 { v.wrapping_add(d) } else { v.wrapping_sub(d) };
                    bytes[at..at + 8].copy_from_slice(&nv.to_le_bytes());
                }
            }
            _ => {
                // extreme values in a u64 field
                if bytes.len() >= 8 {
                    let at = pos % (bytes.len() - 7);
                    let v = [u64::MAX, u64::MAX - 1, 1 << 63, (1 << 32) - 1, 0][arg[0] as usize % 5];
                    bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
                }
            }
        }
        if op & 0x80 == 0 {
            repair(&name, &mut bytes);
        }
        files.insert(name, bytes);
    }

    let backing = Arc::new(CrashableBacking::new());
    for dir in &base.dirs {
        backing.create_dir_all(dir).unwrap();
    }
    for (path, bytes) in &files {
        let file = backing.open(path, true).unwrap();
        file.write_at(0, bytes).unwrap();
        file.sync_data().unwrap();
    }
    for dir in ["", "data", "journal", "checkpoint"] {
        backing.sync_dir(dir).unwrap();
    }

    // 1. The offline deep check never panics.
    let _ = maki_core::check::deep_check(backing.process() as Arc<dyn Backing>, SEGMENT);

    // 2. Recovery + attach: accepted or refused, never a panic.
    runtime().block_on(async {
        let engine = match Engine::attach(
            backing.process(),
            Arc::new(FakeCryptoProvider::new(UNIT)),
            options(),
        )
        .await
        {
            Ok(engine) => engine,
            Err(_) => return,
        };
        // 3. Reads: an error, zeros, or a value once written to that unit.
        if engine.size() == UNITS * UNIT as u64 {
            for unit in 0..UNITS {
                if let Ok(actual) = engine.read(unit * UNIT as u64, UNIT as usize).await {
                    let zero = actual.iter().all(|b| *b == 0);
                    assert!(
                        zero || base.history[unit as usize].contains(&actual),
                        "unit {unit} reads data that was never written to it: {:02x?}",
                        &actual[..16]
                    );
                }
            }
            // 4. The accepted volume keeps working (errors allowed, no panic).
            let data = image(3, 0xFFFF);
            let _ = engine.write(3 * UNIT as u64, &data, true).await;
            let _ = engine.flush().await;
            let _ = engine.checkpoint().await;
            let _ = engine.read(3 * UNIT as u64, UNIT as usize).await;
        }
        engine.stop_checkpoint_worker().await;
        drop(engine);
    });
});
