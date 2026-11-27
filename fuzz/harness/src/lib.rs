//! The entry functions of Maki's coverage-guided fuzz targets.
//!
//! Each target in `fuzz/fuzz_targets/` is one line that hands libFuzzer's
//! input to the function of the same name here, so the stable toolchain can
//! run the same code: `tests/review_fuzz_corpus.rs` feeds every committed
//! seed (`fuzz/seeds/<target>/`) through its target's function in the
//! default suite. A function panics where the code under test broke a rule
//! (libFuzzer reports that as a crash), and otherwise returns whether the
//! code accepted the input. [`seeds`] writes the committed seeds.
//!
//! A function starts no thread per input
//! (`tests/review_fuzz_entry_threads.rs`): libFuzzer runs millions of
//! inputs in one process, and under AddressSanitizer the process's memory
//! grows with every thread it has started.

#[cfg(target_os = "linux")]
mod nbd;
pub mod seeds;

#[cfg(target_os = "linux")]
pub use nbd::{helper_reports, helper_sysfs, nbd_handshake, nbd_netlink};

use maki_format::ab::AbRecord;
use maki_format::allocation::AllocationMap;
use maki_format::canary::KeyCanary;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::config::{parse_config, parse_endpoint_url};
use maki_format::durable_proof::DurableProof;
use maki_format::journal::{scan_segment_bounded, DurableMark, ScanOutcome, SegmentHeader};
use maki_format::slot::SlotHeader;
use maki_format::superblock::{Superblock, VolumeSuperblock};
use maki_privileged::probe::{
    choose_free_nbd, nbd_device_of, nbd_index, parse_mountinfo, resolve_leaf_devices,
};

/// An entry function: the input, and whether the code accepted it.
pub type Entry = fn(&[u8]) -> bool;

/// One fuzz target: the name of its `[[bin]]` in `fuzz/Cargo.toml` and of
/// its seed directory, and its entry function. The entry is `None` where the
/// code it fuzzes is not built.
#[derive(Clone, Copy, Debug)]
pub struct Target {
    pub name: &'static str,
    pub entry: Option<Entry>,
}

/// Every fuzz target.
pub const TARGETS: &[Target] = &[
    Target {
        name: "format_decoders",
        entry: Some(format_decoders),
    },
    Target {
        name: "format_records",
        entry: Some(format_records),
    },
    Target {
        name: "journal_scan",
        entry: Some(journal_scan),
    },
    Target {
        name: "config_parse",
        entry: Some(config_parse),
    },
    Target {
        name: "endpoint_url",
        entry: Some(endpoint_url),
    },
    Target {
        name: "probe_parsers",
        entry: Some(probe_parsers),
    },
    Target {
        name: "nbd_handshake",
        entry: NBD_HANDSHAKE,
    },
    Target {
        name: "nbd_netlink",
        entry: NBD_NETLINK,
    },
    Target {
        name: "backing_records",
        entry: Some(backing_records),
    },
    Target {
        name: "witness_rpc",
        entry: Some(witness_rpc),
    },
    Target {
        name: "witness_etcd",
        entry: Some(witness_etcd),
    },
    Target {
        name: "http_response",
        entry: Some(http_response),
    },
    Target {
        name: "websocket_response",
        entry: Some(websocket_response),
    },
    Target {
        name: "grpc_response",
        entry: Some(grpc_response),
    },
    Target {
        name: "helper_reports",
        entry: HELPER_REPORTS,
    },
    Target {
        name: "helper_sysfs",
        entry: HELPER_SYSFS,
    },
];

// The root helper's kernel NBD code and its executor are built on Linux
// only.
#[cfg(target_os = "linux")]
const NBD_HANDSHAKE: Option<Entry> = Some(nbd_handshake);
#[cfg(target_os = "linux")]
const NBD_NETLINK: Option<Entry> = Some(nbd_netlink);
#[cfg(target_os = "linux")]
const HELPER_REPORTS: Option<Entry> = Some(helper_reports);
#[cfg(target_os = "linux")]
const HELPER_SYSFS: Option<Entry> = Some(helper_sysfs);
#[cfg(not(target_os = "linux"))]
const NBD_HANDSHAKE: Option<Entry> = None;
#[cfg(not(target_os = "linux"))]
const NBD_NETLINK: Option<Entry> = None;
#[cfg(not(target_os = "linux"))]
const HELPER_REPORTS: Option<Entry> = None;
#[cfg(not(target_os = "linux"))]
const HELPER_SYSFS: Option<Entry> = None;

/// Every on-disk decoder of `maki-format`, on raw bytes. A decoder must
/// reject any corrupt image with an error — never panic, over-allocate, or
/// loop. The first input byte selects the decoder; the rest is the
/// candidate image.
///
/// Every decoder checks a magic, a length and a CRC-32 before it looks at a
/// field, and a fuzzer starting from an empty corpus almost never produces
/// an image that passes them: this target exercises those checks.
/// [`format_records`] repairs the checksum first and exercises what lies
/// behind it. The journal's record frames have their own target,
/// [`journal_scan`].
pub fn format_decoders(data: &[u8]) -> bool {
    let Some((&sel, body)) = data.split_first() else {
        return false;
    };
    match sel % 10 {
        0 => Superblock::decode(body).is_ok(),
        1 => SegmentHeader::decode(body).is_ok(),
        2 => DurableMark::decode(body).is_ok(),
        3 => KeyCanary::decode(body).is_ok(),
        4 => SlotHeader::decode(body).is_ok(),
        5 => <AllocationMap as AbRecord>::decode(body).is_ok(),
        6 => <ShardCatalog as AbRecord>::decode(body).is_ok(),
        7 => <CheckpointState as AbRecord>::decode(body).is_ok(),
        8 => <DurableProof as AbRecord>::decode(body).is_ok(),
        _ => <VolumeSuperblock as AbRecord>::decode(body).is_ok(),
    }
}

/// Make the last four bytes of `frame` the CRC-32 of the bytes before them.
fn repair(frame: &mut [u8]) {
    if frame.len() >= 4 {
        let payload = frame.len() - 4;
        let crc = crc32fast::hash(&frame[..payload]);
        frame[payload..].copy_from_slice(&crc.to_le_bytes());
    }
}

/// A fixed-size frame is checked on a prefix of the input.
fn repair_prefix(body: &mut [u8], size: usize) {
    if body.len() >= size {
        repair(&mut body[..size]);
    }
}

fn round_trip<T: AbRecord + PartialEq + std::fmt::Debug>(body: &[u8]) -> bool {
    let Ok(record) = T::decode(body) else {
        return false;
    };
    let again = record.encode();
    assert!(
        again.len() as u64 <= T::MAX_ENCODED_LEN,
        "an accepted record encodes beyond its type's bound"
    );
    let back = T::decode(&again).expect("an accepted record must decode again");
    assert_eq!(back, record, "an accepted record changed in a round trip");
    true
}

/// What the on-disk decoders of `maki-format` do behind their checksum.
/// Every decoder verifies a CRC-32 before it looks at a field, so a fuzzer
/// that feeds raw bytes ([`format_decoders`]) stays in front of it. This
/// target makes the last four bytes of the frame the decoder will check the
/// CRC-32 of the bytes before them, and then requires of every image a
/// decoder accepts:
///
/// 1. the decoded record encodes again without a panic, within the record
///    type's own length bound;
/// 2. that encoding decodes to the same record. The A/B store rewrites a
///    record from its decoded form, so a record that does not survive the
///    round trip changes on its next store.
///
/// The first input byte selects the record type; the rest is the candidate
/// image.
pub fn format_records(data: &[u8]) -> bool {
    let Some((&sel, body)) = data.split_first() else {
        return false;
    };
    let mut body = body.to_vec();
    match sel % 10 {
        0 => {
            repair_prefix(&mut body, 4096);
            let Ok(superblock) = Superblock::decode(&body) else {
                return false;
            };
            let again = superblock.encode();
            assert_eq!(again.len(), 4096);
            assert_eq!(
                Superblock::decode(&again).expect("decode again"),
                superblock
            );
            true
        }
        1 => {
            repair_prefix(&mut body, 48);
            let Ok(header) = SegmentHeader::decode(&body) else {
                return false;
            };
            assert_eq!(
                SegmentHeader::decode(&header.encode()).expect("decode again"),
                header
            );
            true
        }
        2 => {
            repair_prefix(&mut body, 32);
            let Ok(mark) = DurableMark::decode(&body) else {
                return false;
            };
            assert_eq!(
                DurableMark::decode(&mark.encode()).expect("decode again"),
                mark
            );
            true
        }
        3 => {
            repair(&mut body);
            round_trip::<KeyCanary>(&body)
        }
        4 => {
            repair_prefix(&mut body, 64);
            let Ok(header) = SlotHeader::decode(&body) else {
                return false;
            };
            assert_eq!(
                SlotHeader::decode(&header.encode()).expect("decode again"),
                header
            );
            true
        }
        5 => {
            repair(&mut body);
            let Ok(map) = <AllocationMap as AbRecord>::decode(&body) else {
                return false;
            };
            let again = AbRecord::encode(&map);
            assert_eq!(AllocationMap::encoded_len(map.units()), again.len() as u64);
            let back = <AllocationMap as AbRecord>::decode(&again).expect("decode again");
            assert_eq!(AbRecord::encode(&back), again);
            assert_eq!(back.units(), map.units());
            // No unit at or beyond `units` is ever reported as set.
            assert!(map.set_count() <= map.units());
            assert_eq!(map.set_units(u64::MAX).count() as u64, map.set_count());
            true
        }
        6 => {
            repair(&mut body);
            round_trip::<ShardCatalog>(&body)
        }
        7 => {
            repair(&mut body);
            round_trip::<CheckpointState>(&body)
        }
        8 => {
            repair(&mut body);
            round_trip::<DurableProof>(&body)
        }
        _ => {
            repair_prefix(&mut body, 4096);
            round_trip::<VolumeSuperblock>(&body)
        }
    }
}

/// The journal segment scanner. On any input it must terminate with a
/// classification (Clean / TornTail / Corrupt) and never panic, over-read,
/// or loop. The leading bytes seed the base sequence and the durable-length
/// hint the scanner uses to tell durable corruption from a torn tail. An
/// input is accepted when the segment scans clean.
pub fn journal_scan(data: &[u8]) -> bool {
    if data.len() < 9 {
        return false;
    }
    let first_sequence = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let knob = data[8];
    let buf = &data[9..];
    let durable_len = if knob & 1 == 0 {
        None
    } else {
        // A durable prefix anywhere in [0, buf.len()].
        Some((knob as usize).wrapping_mul(7) % (buf.len() + 1))
    };
    let (_, outcome) = scan_segment_bounded(buf, first_sequence, durable_len);
    outcome == ScanOutcome::Clean
}

/// TOML config parsing, validation, and geometry derivation. Any input must
/// resolve to Ok/Err without panicking; a parsed config must survive
/// `validate()` and `geometry()` without panicking on any
/// accepted-then-inspected value. An input is accepted when it validates.
pub fn config_parse(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let Ok(cfg) = parse_config(text) else {
        return false;
    };
    let valid = cfg.validate().is_ok();
    let _ = cfg.geometry();
    valid
}

/// The endpoint-URL parser (scheme/host/userinfo and the loopback plaintext
/// policy). It must classify any string without panicking.
pub fn endpoint_url(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok_and(|text| parse_endpoint_url(text).is_ok())
}

/// The decoders of maki-backing's own records: the local witness's anchor,
/// the remote enrollment binding, the remote witness's state, the rollback
/// manifest and a manifest slot, and the name of a remote namespace
/// (`maki_backing::fuzzing::records`, which describes the input). An input
/// is accepted when the record decodes.
pub fn backing_records(data: &[u8]) -> bool {
    maki_backing::fuzzing::records(data)
}

/// The privileged helper's pure parsers, which read `/proc/self/mountinfo`
/// and sysfs names. None may panic on malformed input.
/// `resolve_leaf_devices` is walked with a synthetic slaves relation
/// derived from the input to exercise cycles and deep chains. An input is
/// accepted when it holds a mount at `/mnt/target`.
pub fn probe_parsers(data: &[u8]) -> bool {
    // The kernel's mount table is bytes: paths need not be UTF-8.
    let mounted = parse_mountinfo(data, "/mnt/target").is_some();
    let Ok(text) = std::str::from_utf8(data) else {
        return mounted;
    };
    let _ = parse_mountinfo(text, text);
    for line in text.lines() {
        let _ = nbd_device_of(line);
        let _ = nbd_index(line);
    }

    // A synthetic sysfs `slaves` relation: a device's slaves are the
    // comma-separated tokens of its name (minus itself). Cycles and long
    // chains are possible; the walk must still terminate.
    let mut slaves = |name: &str| -> Vec<String> {
        name.split(',')
            .filter(|t| !t.is_empty() && *t != name)
            .map(str::to_string)
            .collect()
    };
    if let Some(start) = text.lines().next() {
        let _ = resolve_leaf_devices(start, &mut slaves);
    }

    // choose_free_nbd over a device list derived from the lines.
    let devices: Vec<(String, bool)> = text
        .lines()
        .map(|l| (l.to_string(), l.len() % 2 == 0))
        .collect();
    let _ = choose_free_nbd(&devices);
    mounted
}

/// The witness's RPC over one connection: a client reading the server's
/// answer, and a server reading a request, handing it to the file
/// authority's handler and writing the answer the client must read back as
/// sent (`maki_witness::fuzzing::rpc`, which describes the input). An input
/// is accepted when the side that reads it accepts a record.
pub fn witness_rpc(data: &[u8]) -> bool {
    maki_witness::fuzzing::rpc(data)
}

/// The witness's etcd store reading etcd's answers to its range and
/// transaction requests (`maki_witness::fuzzing::etcd`, which describes the
/// input). An input is accepted when the store accepts the answer.
pub fn witness_etcd(data: &[u8]) -> bool {
    maki_witness::fuzzing::etcd(data)
}

/// The HTTP provider's reading of a response: the body's bounded
/// accumulation, the JSON mappings of one item and of a batch, a raw body,
/// and the status (`maki_crypto_http::fuzzing::response`, which describes
/// the input). The selective JSON parser must agree with serde_json. An
/// input is accepted when the provider accepts the response.
pub fn http_response(data: &[u8]) -> bool {
    maki_crypto_http::fuzzing::response(data)
}

/// The WebSocket provider's reading of a message and of the response it
/// carries (`maki_crypto_websocket::fuzzing::message`, which describes the
/// input). The frame parser must agree with serde_json. An input is
/// accepted when the provider accepts the response as the request's
/// results.
pub fn websocket_response(data: &[u8]) -> bool {
    maki_crypto_websocket::fuzzing::message(data)
}

/// The gRPC provider's reading of a response's initial headers, of its body
/// as tonic polls it and of its message (`maki_crypto_grpc::fuzzing::response`,
/// which describes the input). An input is accepted when the provider
/// accepts what it read.
pub fn grpc_response(data: &[u8]) -> bool {
    maki_crypto_grpc::fuzzing::response(data)
}
