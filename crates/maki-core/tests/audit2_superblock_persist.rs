//! Audit (round 2, durability-pr-review): `persist_volume_superblock` (#164)
//! under the finest tearing the crash model allows (1- and 8-byte sectors),
//! with creation and recovery both killed at random backing operations and
//! random power losses in between. Once a recovery succeeded and a FUA write
//! was acknowledged, no later interrupted recovery or power loss may leave
//! the volume without a valid superblock, and the acknowledged data must stay
//! readable.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

const CT: usize = 544;
static ACKED: AtomicUsize = AtomicUsize::new(0);

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xA25B_0001),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, CT as u32, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 64 * 1024,
    }
}

fn die_at(backing: &CrashableBacking, cut: usize) {
    let seen = Arc::new(AtomicUsize::new(0));
    backing.set_fault_hook(Some(Arc::new(move |_op: &FaultOp<'_>| {
        (seen.fetch_add(1, Ordering::SeqCst) >= cut).then(|| io::Error::other("process died"))
    })));
}

fn recover(backing: &Arc<CrashableBacking>) -> Result<Volume, String> {
    Volume::recover(backing.clone() as Arc<dyn Backing>, options()).map_err(|e| e.to_string())
}

fn run(seed: u64, gran: usize, discard: bool) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let backing = Arc::new(CrashableBacking::new().with_tearing(gran));
    // Creation killed at a random operation (or not at all), then a power
    // loss or a restart.
    die_at(&backing, rng.random_range(0..120));
    let created = if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock())
    } else {
        init::create_volume(backing.as_ref(), superblock())
    };
    backing.set_fault_hook(None);
    if rng.random_bool(0.5) {
        backing.crash(&mut rng);
    }
    let _ = created;

    // Recovery attempts, each possibly killed at a random operation and
    // followed by a power loss or a restart.
    let mut acknowledged: Option<u8> = None;
    for round in 0..12u8 {
        let interrupted = rng.random_bool(0.6);
        if interrupted {
            die_at(&backing, rng.random_range(0..80));
        }
        let outcome = recover(&backing);
        backing.set_fault_hook(None);
        match outcome {
            Ok(mut volume) => {
                if !interrupted {
                    let stamp = 0x40 | round;
                    volume
                        .write_ct(3, &[stamp; CT], true)
                        .map_err(|e| format!("round {round}: FUA write failed: {e}"))?;
                    acknowledged = Some(stamp);
                }
                drop(volume);
            }
            Err(error) => {
                if acknowledged.is_some() && !interrupted {
                    return Err(format!(
                        "round {round}: uninterrupted recovery of an acknowledged volume failed: \
                         {error}"
                    ));
                }
                if error.contains("no valid superblock") && acknowledged.is_some() {
                    return Err(format!(
                        "round {round}: acknowledged volume lost its superblock: {error}"
                    ));
                }
            }
        }
        if rng.random_bool(0.7) {
            backing.crash(&mut rng);
        }
    }
    // Final clean recovery after the worst-case power loss.
    backing.crash_all_lost();
    match (recover(&backing), acknowledged) {
        (Ok(volume), Some(stamp)) => {
            ACKED.fetch_add(1, Ordering::SeqCst);
            let unit = volume
                .read_ct(3)
                .map_err(|e| format!("read: {e}"))?
                .map(|(_, ct)| ct[0]);
            if unit != Some(stamp) {
                return Err(format!(
                    "acknowledged unit 3 (stamp {stamp:#x}) reads {unit:x?} after power loss"
                ));
            }
            Ok(())
        }
        (Err(error), Some(_)) => Err(format!("final recovery failed: {error}")),
        _ => Ok(()),
    }
}

#[test]
fn persist_never_loses_an_acknowledged_volume_under_fine_tearing() {
    let mut failures = Vec::new();
    for gran in [1usize, 8, 512] {
        for seed in 0..300u64 {
            for discard in [false, true] {
                if let Err(error) = run(seed * 7 + gran as u64, gran, discard) {
                    failures.push(format!("gran {gran} seed {seed} discard {discard}: {error}"));
                }
            }
        }
    }
    eprintln!("runs whose acknowledged write was checked: {}", ACKED.load(Ordering::SeqCst));
    assert!(
        failures.is_empty(),
        "{} failing runs; first: {}",
        failures.len(),
        failures[0]
    );
}
