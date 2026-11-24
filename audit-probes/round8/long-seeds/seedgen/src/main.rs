//! usage: a8-seedgen <corpora-root>
//! Writes seed inputs for the committed fuzz targets (format_decoders,
//! journal_scan) and for the round-8 CRC-fixing targets.
use std::fs;
use std::path::Path;

use maki_format::ab::AbRecord;
use maki_format::allocation::AllocationMap;
use maki_format::canary::KeyCanary;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::durable_proof::DurableProof;
use maki_format::geometry::Geometry;
use maki_format::journal::{encode_record_parts, DurableMark, SegmentHeader};
use maki_format::slot::SlotHeader;
use maki_format::superblock::{Superblock, VolumeSuperblock};
use uuid::Uuid;

fn put(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(name), bytes).unwrap();
}

fn sel(sel: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![sel];
    v.extend_from_slice(body);
    v
}

fn superblocks() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let geos = [
        (512u32, 512u32, 512u32, 520u32, 48 * 512u64, 8 * 512u64),
        (512, 4096, 4096, 4096 + 16, 1 << 30, 64 << 20),
        (4096, 16384, 512, 16384 + 28, 1 << 40, 1 << 30),
        (65536, 65536, 65536, 65536, 65536, 65536),
    ];
    for (i, g) in geos.iter().enumerate() {
        let geometry = Geometry::compute(g.0, g.1, g.2, g.3, g.4, g.5).unwrap();
        let sb = Superblock {
            generation: i as u64 * 7,
            volume_uuid: Uuid::from_u128(0xA8A8_0000 + i as u128),
            provider_type: ["fake", "local", "http", "grpc"][i].into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".repeat(1 + i * 40),
            geometry,
            format_version: 1,
            created_unix: 1_700_000_000 + i as u64,
        };
        for version in [1u32, 2, 3] {
            let vs = VolumeSuperblock {
                superblock: sb.clone(),
                metadata_version: version,
            };
            out.push((format!("sb-g{i}-v{version}"), vs.encode()));
        }
    }
    out
}

fn main() {
    let root = std::env::args().nth(1).expect("corpora root");
    let root = Path::new(&root);
    let uuid = Uuid::from_u128(0x5EED);

    // --- format_decoders (committed target: selector % 8) and the
    // CRC-fixing variant (selector % 10: 8 = durable proof, 9 = volume
    // superblock envelope).
    for target in ["format_decoders", "a8_decoders_crcfix"] {
        let dir = root.join(target);
        for (name, image) in superblocks() {
            put(&dir, &format!("{name}.s0"), &sel(0, &image));
            if target == "a8_decoders_crcfix" {
                put(&dir, &format!("{name}.s9"), &sel(9, &image));
            }
        }
        for (i, (idx, base)) in [(0u64, 1u64), (7, 1000), (u64::MAX - 1, u64::MAX - 1)]
            .iter()
            .enumerate()
        {
            let h = SegmentHeader {
                segment_index: *idx,
                volume_uuid: uuid,
                base_sequence: *base,
            };
            put(&dir, &format!("seghdr-{i}"), &sel(1, &h.encode()));
        }
        for (i, (idx, size)) in [(0u64, 48u64), (3, 1 << 20), (u64::MAX, u64::MAX)]
            .iter()
            .enumerate()
        {
            let m = DurableMark {
                segment_index: *idx,
                durable_size: *size,
            };
            put(&dir, &format!("mark-{i}"), &sel(2, &m.encode()));
        }
        for (i, len) in [0usize, 1, 520, 4104].iter().enumerate() {
            let c = KeyCanary {
                generation: i as u64,
                volume_uuid: uuid,
                unit_index: maki_format::canary::CANARY_UNIT_INDEX,
                ciphertext: (0..*len).map(|b| (b * 31 + i) as u8).collect(),
            };
            put(&dir, &format!("canary-{i}"), &sel(3, &c.encode()));
        }
        for (i, (unit, seq, len)) in [(0u64, 1u64, 0u32), (47, 9, 520), (1 << 40, u64::MAX, 16 << 20)]
            .iter()
            .enumerate()
        {
            let h = SlotHeader {
                unit_index: *unit,
                write_sequence: *seq,
                ciphertext_len: *len,
                flags: 0,
                ciphertext_crc: 0xDEAD_BEEF,
            };
            put(&dir, &format!("slot-{i}"), &sel(4, &h.encode()));
        }
        for (i, units) in [0u64, 1, 7, 8, 9, 67, 4096].iter().enumerate() {
            let mut m = AllocationMap::new(*units);
            for u in (0..*units).step_by(3) {
                m.set(u, true);
            }
            m.set_generation(i as u64 + 1);
            put(&dir, &format!("alloc-{i}"), &sel(5, &AbRecord::encode(&m)));
        }
        for (i, shards) in [vec![], vec![0u64], vec![0, 1, 2, 5, 9], vec![1 << 23, (1 << 24) - 1]]
            .iter()
            .enumerate()
        {
            let mut c = ShardCatalog::new();
            for s in shards {
                c.insert(*s);
            }
            c.set_generation(i as u64 + 3);
            put(&dir, &format!("catalog-{i}"), &sel(6, &AbRecord::encode(&c)));
        }
        for (i, seq) in [0u64, 1, 1 << 33, u64::MAX].iter().enumerate() {
            let mut s = CheckpointState::default();
            s.checkpoint_sequence = *seq;
            s.set_generation(i as u64);
            put(&dir, &format!("ckpt-{i}"), &sel(7, &AbRecord::encode(&s)));
        }
        if target == "a8_decoders_crcfix" {
            let mut p = DurableProof::initial(uuid);
            put(&dir, "proof-0", &sel(8, &p.encode()));
            p.generation = 9;
            p.durable_sequence = 77;
            p.segment_index = 3;
            p.durable_size = 4096;
            put(&dir, "proof-1", &sel(8, &p.encode()));
        }
    }

    // --- journal_scan: first_sequence (8) + knob (1) + segment body.
    for target in ["journal_scan", "a8_journal_model"] {
        let dir = root.join(target);
        for (i, (first, lens)) in [
            (1u64, vec![0usize]),
            (1, vec![520, 520, 520]),
            (100, vec![1, 0, 4104, 17]),
            (u64::MAX - 2, vec![8, 8, 8]),
            (5, vec![520, 0, 0, 0, 520]),
        ]
        .iter()
        .enumerate()
        {
            let mut body = Vec::new();
            for (n, len) in lens.iter().enumerate() {
                let payload: Vec<u8> = (0..*len).map(|b| (b * 7 + n) as u8).collect();
                body.extend(
                    encode_record_parts(first.wrapping_add(n as u64), n as u64 * 3, &payload)
                        .unwrap(),
                );
            }
            for (k, knob) in [0u8, 1, 0x55, 0xFF].iter().enumerate() {
                let mut v = first.to_le_bytes().to_vec();
                v.push(*knob);
                v.extend_from_slice(&body);
                put(&dir, &format!("seg-{i}-k{k}"), &v);
                // zero tail and torn tail variants
                let mut z = v.clone();
                z.extend_from_slice(&[0u8; 64]);
                put(&dir, &format!("seg-{i}-k{k}-zeros"), &z);
                if v.len() > 20 {
                    put(&dir, &format!("seg-{i}-k{k}-torn"), &v[..v.len() - 5]);
                }
            }
        }
    }
    println!("seeds written under {}", root.display());
}
