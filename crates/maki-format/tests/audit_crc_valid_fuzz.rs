//! Audit (config-format): CRC-valid mutation fuzz of the identity records
//! (superblock envelopes, key canary, durable proof). `review_fuzz.rs` only
//! mutates without fixing the CRC, so field validation behind the checksum
//! is barely exercised, and the durable proof (required by every v2/v3
//! recovery) has no fuzz coverage at all. Decoders must never panic.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_format::canary::KeyCanary;
use maki_format::durable_proof::DurableProof;
use maki_format::geometry::Geometry;
use maki_format::superblock::{Superblock, VolumeSuperblock};

fn recrc(mut image: Vec<u8>) -> Vec<u8> {
    let n = image.len();
    if n >= 4 {
        let crc = crc32fast::hash(&image[..n - 4]);
        image[n - 4..].copy_from_slice(&crc.to_le_bytes());
    }
    image
}

fn seeds() -> Vec<Vec<u8>> {
    let sb = Superblock {
        generation: 3,
        volume_uuid: Uuid::from_u128(0x1234),
        provider_type: "local-aes-gcm-siv".into(),
        crypto_compatibility_id: "profile".into(),
        key_identity: "key".into(),
        geometry: Geometry::compute(4096, 4096, 512, 4384, 1 << 30, 64 << 20).unwrap(),
        format_version: 1,
        created_unix: 1,
    };
    let v3 = VolumeSuperblock {
        superblock: sb.clone(),
        metadata_version: 3,
    };
    vec![
        sb.encode(),
        v3.encode(),
        KeyCanary {
            generation: 1,
            volume_uuid: Uuid::from_u128(9),
            unit_index: 77,
            ciphertext: vec![1; 64],
        }
        .encode(),
        DurableProof {
            generation: 1,
            volume_uuid: Uuid::from_u128(9),
            durable_sequence: 5,
            segment_index: 1,
            durable_size: 4096,
        }
        .encode(),
    ]
}

#[test]
fn crc_valid_mutations_never_panic() {
    let mut rng = StdRng::seed_from_u64(0xa0d17);
    let seeds = seeds();
    for i in 0..200_000 {
        let seed = &seeds[i % seeds.len()];
        let mut image = seed.clone();
        for _ in 0..rng.random_range(1..=4) {
            let at = rng.random_range(8..image.len().saturating_sub(4).max(9));
            match rng.random_range(0..3u32) {
                0 => image[at] ^= 1 << rng.random_range(0..8),
                1 => image[at] = rng.random(),
                _ => image[at] = [0, 0xff, 0x7f, 0x80][rng.random_range(0..4)],
            }
        }
        let image = recrc(image);
        let _ = Superblock::decode(&image);
        let _ = VolumeSuperblock::decode(&image);
        let _ = KeyCanary::decode(&image);
        let _ = DurableProof::decode(&image);
    }
}
