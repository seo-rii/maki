//! Deterministic mixed write/discard model across checkpoint failures and crashes.

use std::sync::Arc;

use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{failpoints, CrashableBacking};
use rand::{rngs::StdRng, Rng, SeedableRng};

const UNITS: usize = 32;
const CIPHERTEXT: usize = 1032;
const SEEDS: [u64; 8] = [
    0x0000_0000_0000_0001,
    0x0123_4567_89ab_cdef,
    0x1357_9bdf_2468_ace0,
    0x5eed_fade_d15c_a4d0,
    0x8000_0000_0000_0001,
    0xa5a5_5a5a_dead_beef,
    0xfeed_face_cafe_babe,
    0xffff_ffff_ffff_ffc5,
];

fn new_volume(seed: u64) -> (Arc<CrashableBacking>, Volume) {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xd15c_0000_0000_0000 | seed as u128),
            provider_type: "test".into(),
            crypto_compatibility_id: "discard-model-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                512,
                1024,
                512,
                CIPHERTEXT as u32,
                (UNITS * 1024) as u64,
                8 * 1024,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    (backing, volume)
}

fn assert_model(volume: &Volume, model: &[Option<Vec<u8>>], context: &str) {
    for (unit, expected) in model.iter().enumerate() {
        let actual = volume
            .read_ct(unit as u64)
            .unwrap()
            .map(|(_, ciphertext)| ciphertext);
        assert_eq!(actual, *expected, "{context}: unit {unit}");
    }
}

#[test]
fn mixed_discard_model_survives_failed_checkpoints_and_repeated_crashes() {
    let _serial = failpoints::test_lock();
    for seed in SEEDS {
        let (backing, mut volume) = new_volume(seed);
        let mut rng = StdRng::seed_from_u64(seed);
        let mut model = vec![None; UNITS];

        // Give every shard real slots before the mixed epochs so a later
        // discard exercises physical reclamation as well as logical zeroing.
        for (unit, expected) in model.iter_mut().enumerate() {
            let value = (unit as u8).wrapping_mul(17).wrapping_add(1);
            let ciphertext = vec![value; CIPHERTEXT];
            volume.write_ct(unit as u64, &ciphertext, false).unwrap();
            *expected = Some(ciphertext);
        }
        volume.flush().unwrap();
        volume.checkpoint().unwrap();

        for epoch in 0..4usize {
            // Force both directions on different shards every epoch: a
            // durable tombstone and an ordinary write that clears one.
            let allocated: Vec<_> = model
                .iter()
                .enumerate()
                .filter_map(|(unit, value)| value.is_some().then_some(unit))
                .collect();
            let discarded = allocated[rng.random_range(0..allocated.len())];
            volume.discard_ct(discarded as u64, false).unwrap();
            model[discarded] = None;
            let tombstones: Vec<_> = model
                .iter()
                .enumerate()
                .filter_map(|(unit, value)| (unit != discarded && value.is_none()).then_some(unit))
                .collect();
            let rewritten = tombstones
                .get(rng.random_range(0..tombstones.len().max(1)))
                .copied()
                .unwrap_or((discarded + 8) % UNITS);
            let ciphertext = vec![(seed as u8).wrapping_add(epoch as u8 + 0x40); CIPHERTEXT];
            volume
                .write_ct(rewritten as u64, &ciphertext, false)
                .unwrap();
            model[rewritten] = Some(ciphertext);

            for step in 0..14u8 {
                let unit = rng.random_range(0..UNITS);
                if rng.random_range(0..100u8) < 42 {
                    volume.discard_ct(unit as u64, false).unwrap();
                    model[unit] = None;
                } else {
                    let value = (seed as u8)
                        .wrapping_add((epoch as u8).wrapping_mul(31))
                        .wrapping_add(step);
                    let ciphertext = vec![value; CIPHERTEXT];
                    volume.write_ct(unit as u64, &ciphertext, false).unwrap();
                    model[unit] = Some(ciphertext);
                }
            }

            // From here onward every modeled mutation must survive the crash,
            // regardless of how far the following checkpoint progressed.
            volume.flush().unwrap();
            assert_model(
                &volume,
                &model,
                &format!("seed {seed:#x} epoch {epoch} live"),
            );

            let failpoint = match epoch {
                0 => Some("discard.store"),
                1 => Some("discard.dirsync"),
                2 => Some("discard.punch"),
                _ => None,
            };
            if let Some(name) = failpoint {
                let owner = std::thread::current().id();
                let guard = failpoints::set(
                    name,
                    failpoints::FailpointAction::Callback(Arc::new(move || {
                        (std::thread::current().id() == owner)
                            .then(|| std::io::Error::other("modeled checkpoint failure"))
                    })),
                );
                assert!(volume.checkpoint().is_err(), "{name} was not exercised");
                drop(guard);
            } else {
                volume.checkpoint().unwrap();
            }

            drop(volume);
            backing.crash(&mut rng);
            volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
            assert_model(
                &volume,
                &model,
                &format!("seed {seed:#x} epoch {epoch} recovered"),
            );
        }

        // The recovered instance must remain writable and checkpointable.
        let final_unit = rng.random_range(0..UNITS);
        let final_ciphertext = vec![0xe7; CIPHERTEXT];
        volume
            .write_ct(final_unit as u64, &final_ciphertext, true)
            .unwrap();
        model[final_unit] = Some(final_ciphertext);
        volume.checkpoint().unwrap();
        assert_model(&volume, &model, &format!("seed {seed:#x} final retry"));
    }
}
