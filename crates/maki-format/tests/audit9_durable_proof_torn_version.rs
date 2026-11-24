//! Audit round 9 (r8-storage, successor): classify the one failure of the
//! predecessor's release sweep `sweep-ab-release1.log` (cfg r9-ab, mode
//! ab-chain-chaos, seed 1373): "recovery failed: unsupported version:
//! durable proof version 0".
//!
//! `DurableProofStore::read_copy` refuses, as a future format, a side whose
//! length is not 64 bytes, that is at least 12 bytes long, starts with the
//! magic and carries a version other than 1. Since #386 a store first
//! empties an existing side that does not decode (set_len 0, fdatasync), then
//! sets the length to 64 and writes the record. A side of that shape after a
//! crash needs all of: a `write_at` that persisted a prefix shorter than the
//! record and failed (the partial-write hook), a crash that drops the
//! `set_len(64)` and keeps the partial write torn with a hole exactly over
//! bytes 8..12 (the version) while keeping bytes 0..8 (the magic), i.e. a
//! tearing unit of at most 8 bytes. This test counts, per tearing unit, how
//! many sampled power losses after such a store leave a proof that no
//! recovery accepts. Expected: some at units 1, 4 and 8, none at 16 and
//! above (a real sector is 512 bytes or more). Passes either way; it prints.

use maki_backing::Backing;
use maki_format::ab::AbStore;
use maki_format::durable_proof::{DurableProof, DurableProofStore, DURABLE_PROOF_A, DURABLE_PROOF_B};
use maki_format::FormatError;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::Arc;
use uuid::Uuid;

fn outcome(gran: usize, seed: u64, partial: usize) -> Result<(), String> {
    let backing = CrashableBacking::new().with_tearing(gran);
    let uuid = Uuid::from_u128(0xA9_0001);
    let proof = DurableProofStore::initialize(&backing, uuid).unwrap();
    // Side b exists but does not decode (a store cut earlier): the next
    // store targets it and empties it first (#386).
    let file = backing.open(DURABLE_PROOF_B, false).unwrap();
    file.set_len(63).unwrap();
    file.sync_data().unwrap();
    drop(file);
    backing.set_partial_write_hook(Some(Arc::new(move |op| match op {
        FaultOp::WriteAt { path, len, .. } if path.ends_with("durable-proof.b") && *len == 64 => {
            Some((partial, std::io::Error::other("short write")))
        }
        _ => None,
    })));
    let mut next = DurableProof {
        durable_sequence: 0,
        ..proof
    };
    let stored = AbStore::new(DURABLE_PROOF_A, DURABLE_PROOF_B).store(&backing, &mut next);
    assert!(stored.is_err(), "the partial write fails the store");
    backing.set_partial_write_hook(None);
    backing.crash(&mut StdRng::seed_from_u64(seed));
    match DurableProofStore::load(&backing, uuid) {
        Ok(_) => Ok(()),
        Err(FormatError::Unsupported(text)) => {
            let file = backing.open(DURABLE_PROOF_B, false).unwrap();
            let len = file.len().unwrap();
            let mut bytes = vec![0u8; len as usize];
            file.read_at(0, &mut bytes).unwrap();
            Err(format!("{text}; side b {len} bytes: {:02x?}", &bytes[..len.min(16) as usize]))
        }
        Err(e) => Err(format!("other: {e}")),
    }
}

#[test]
fn audit9_torn_short_proof_side_reads_as_a_future_version() {
    let seeds = 4000u64;
    for gran in [1usize, 4, 8, 13, 16, 24, 512] {
        for partial in [12usize, 55] {
            let mut refused = 0;
            let mut first = None;
            for seed in 0..seeds {
                if let Err(text) = outcome(gran, seed, partial) {
                    refused += 1;
                    first.get_or_insert((seed, text));
                }
            }
            println!(
                "tear {gran:>3} B, partial write {partial:>2} of 64 B: {refused} of {seeds} power \
                 losses leave a proof no recovery accepts; first {first:?}"
            );
        }
    }
}
