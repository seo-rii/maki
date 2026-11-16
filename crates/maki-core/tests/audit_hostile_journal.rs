//! Audit (recovery-codecs): hostile/odd journal directories. For random
//! segment sets (valid and invalid headers, random bases and indexes, CRC-
//! valid records with plausible and implausible sequences, zero tails, torn
//! records), random advisory marks and random (encodable) durable proofs:
//!
//! * recovery must never panic (debug sanitizers included);
//! * if recovery accepts the volume, a plain restart must accept it again
//!   and expose exactly the same unit contents (recovery is idempotent), and
//!   the writer must be able to append, flush, checkpoint and recover.

use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::durable_proof::{DurableProof, DURABLE_PROOF_A, DURABLE_PROOF_B};
use maki_format::journal::{encode_record, DurableMark, JournalRecord, SegmentHeader};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::{failpoints, CrashableBacking};

const UNITS: u64 = 16;
const UUID: u128 = 0x4057_11E0;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(UUID),
        provider_type: "fake".into(),
        crypto_compatibility_id: "audit".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 544, UNITS * 512, 4 * 512).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

fn write_file(backing: &CrashableBacking, path: &str, bytes: &[u8]) {
    let file = backing.open(path, true).unwrap();
    file.set_len(0).unwrap();
    file.write_at(0, bytes).unwrap();
    file.sync_data().unwrap();
}

fn snapshot(volume: &Volume) -> Vec<Result<Option<Vec<u8>>, String>> {
    (0..UNITS)
        .map(|u| {
            volume
                .read_ct(u)
                .map(|v| v.map(|(_, ct)| ct))
                .map_err(|e| e.to_string())
        })
        .collect()
}

fn build(seed: u64, discard: bool) -> (Arc<CrashableBacking>, String) {
    let mut rng = StdRng::seed_from_u64(seed);
    let backing = Arc::new(CrashableBacking::new());
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    let mut desc = Vec::new();
    // A plausible history most of the time, random perturbations on top.
    let segments = rng.random_range(0..5u64);
    let mut index = rng.random_range(0..3u64);
    let mut sequence = 1u64;
    let mut last_end: Option<(u64, u64, u64)> = None; // (index, seq, size)
    for s in 0..segments {
        let mut base = sequence;
        if rng.random_bool(0.15) {
            base = base.saturating_add_signed(rng.random_range(-3i64..4));
        }
        let header_uuid = if rng.random_bool(0.03) {
            Uuid::from_u128(7)
        } else {
            Uuid::from_u128(UUID)
        };
        let mut bytes = SegmentHeader {
            segment_index: if rng.random_bool(0.03) { index + 1 } else { index },
            volume_uuid: header_uuid,
            base_sequence: base,
        }
        .encode();
        let records = rng.random_range(0..6u64);
        let mut seq = base;
        for _ in 0..records {
            let mut rec_seq = seq;
            if rng.random_bool(0.05) {
                rec_seq = rec_seq.wrapping_add(1);
            }
            let unit = if rng.random_bool(0.03) {
                UNITS + 1
            } else {
                rng.random_range(0..UNITS)
            };
            let len = if discard && rng.random_bool(0.2) {
                0
            } else {
                rng.random_range(1..=544usize)
            };
            let payload: Vec<u8> = (0..len).map(|i| (i as u64 ^ seed ^ seq) as u8).collect();
            bytes.extend(encode_record(&JournalRecord {
                sequence: rec_seq,
                unit_index: unit,
                payload,
            }));
            seq += 1;
            last_end = Some((index, seq - 1, bytes.len() as u64));
        }
        let last = s + 1 == segments;
        match rng.random_range(0..10) {
            0 => bytes.extend(vec![0u8; rng.random_range(1..200)]),
            1 => {
                let cut = rng.random_range(0..bytes.len());
                bytes.truncate(cut);
            }
            2 if last => {
                let n = bytes.len().min(48);
                bytes[..n].fill(0);
            }
            3 => {
                let at = rng.random_range(0..bytes.len());
                bytes[at] ^= 0x40;
            }
            _ => {}
        }
        write_file(&backing, &layout::journal_segment(index), &bytes);
        desc.push(format!(
            "seg {index}: base {base} records {records} len {}",
            bytes.len()
        ));
        sequence = seq;
        index += rng.random_range(1..3);
    }
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();

    if sequence > 1 && rng.random_bool(0.5) {
        let mut state = maki_format::checkpoint::CheckpointState::default();
        state.checkpoint_sequence = rng.random_range(0..sequence);
        let ab = maki_format::ab::AbStore::new(
            maki_format::checkpoint::CHECKPOINT_STATE_A,
            maki_format::checkpoint::CHECKPOINT_STATE_B,
        );
        ab.store(backing.as_ref(), &mut state).unwrap();
        ab.store(backing.as_ref(), &mut state).unwrap();
        desc.push(format!("checkpoint {}", state.checkpoint_sequence));
        // Checkpoint-covered prefixes may have lost segments.
        if rng.random_bool(0.5) {
            let names = backing.list(layout::JOURNAL_DIR).unwrap();
            if let Some(name) = names.iter().find(|n| n.starts_with("seg-")) {
                backing.remove(&format!("{}/{name}", layout::JOURNAL_DIR)).unwrap();
                desc.push(format!("removed {name}"));
            }
        }
        backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    }
    if rng.random_bool(0.5) {
        let mark = DurableMark {
            segment_index: rng.random_range(0..index + 2),
            durable_size: rng.random_range(0..600),
        };
        write_file(&backing, layout::JOURNAL_DURABLE_MARK, &mark.encode());
        desc.push(format!("mark {mark:?}"));
    }
    if let Some((idx, seq, size)) = last_end.filter(|_| rng.random_bool(0.6)) {
        let mut proof = DurableProof {
            generation: 5,
            volume_uuid: Uuid::from_u128(UUID),
            durable_sequence: seq,
            segment_index: idx,
            durable_size: size,
        };
        if rng.random_bool(0.2) {
            proof.durable_sequence = proof.durable_sequence.saturating_sub(1).max(1);
        }
        if rng.random_bool(0.1) {
            proof.durable_size += 1;
        }
        write_file(&backing, DURABLE_PROOF_A, &proof.encode());
        if rng.random_bool(0.7) {
            proof.generation = 6;
            write_file(&backing, DURABLE_PROOF_B, &proof.encode());
        }
        desc.push(format!("proof {proof:?}"));
    }
    (backing, desc.join("; "))
}

fn one(seed: u64, discard: bool) -> Result<bool, String> {
    let (backing, desc) = build(seed, discard);
    let first = match Volume::recover(backing.clone() as Arc<dyn Backing>, options()) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let image = snapshot(&first);
    let seq = first.journal_durable_sequence();
    drop(first);
    let second = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).map_err(|e| {
        format!("seed {seed}: accepted once, refused on restart: {e}\n  {desc}")
    })?;
    if snapshot(&second) != image || second.journal_durable_sequence() != seq {
        return Err(format!(
            "seed {seed}: second recovery shows different state\n  {desc}"
        ));
    }
    drop(second);
    backing.crash_all_lost();
    let mut third = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).map_err(|e| {
        format!("seed {seed}: accepted, then refused after power loss: {e}\n  {desc}")
    })?;
    if snapshot(&third) != image {
        return Err(format!(
            "seed {seed}: power loss after an accepting recovery changed the state\n  {desc}"
        ));
    }
    third
        .write_ct(1, &[9; 544], false)
        .map_err(|e| format!("seed {seed}: write after recovery: {e}\n  {desc}"))?;
    third
        .flush()
        .map_err(|e| format!("seed {seed}: flush after recovery: {e}\n  {desc}"))?;
    third
        .checkpoint()
        .map_err(|e| format!("seed {seed}: checkpoint after recovery: {e}\n  {desc}"))?;
    drop(third);
    backing.crash_all_lost();
    let fourth = Volume::recover(backing.clone() as Arc<dyn Backing>, options())
        .map_err(|e| format!("seed {seed}: final recovery: {e}\n  {desc}"))?;
    if fourth.read_ct(1).map_err(|e| e.to_string())?.map(|v| v.1) != Some(vec![9; 544]) {
        return Err(format!("seed {seed}: flushed write lost\n  {desc}"));
    }
    Ok(true)
}

#[test]
fn hostile_journal_directories_never_panic_and_accepted_ones_are_stable() {
    let _guard = failpoints::test_lock();
    let mut accepted = 0;
    let mut failures = Vec::new();
    for seed in 0..6000u64 {
        let discard = seed % 2 == 1;
        match std::panic::catch_unwind(|| one(seed, discard)) {
            Ok(Ok(true)) => accepted += 1,
            Ok(Ok(false)) => {}
            Ok(Err(e)) => failures.push(e),
            Err(p) => failures.push(format!(
                "seed {seed}: PANIC {}",
                p.downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default()
            )),
        }
    }
    eprintln!("accepted {accepted} of 6000");
    assert!(
        failures.is_empty(),
        "{} failure(s):\n{}",
        failures.len(),
        failures
            .iter()
            .take(6)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
