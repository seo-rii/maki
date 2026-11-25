//! The fuzz harness's way into the decoders of this crate's own records
//! (`fuzz/harness`, target `backing_records`). Built only with the
//! `fuzzing` feature, which only the harness enables: nothing here is part
//! of a backing.
//!
//! Each record is read back from storage that the process does not
//! control alone (a backing root, a witness directory, a remote witness's
//! state directory), and a check run as root reads them too:
//!
//! - the local witness's anchor (`anchor`, [`crate::witness`]);
//! - the remote enrollment binding (`remote.enrollment`);
//! - the remote witness's state (`remote.state`, [`crate::remote_witness`]);
//! - the rollback manifest, which open authenticates against the witness
//!   before it decodes it, and a manifest slot, which a check of an
//!   interrupted creation reads without that authentication;
//! - the name of a remote namespace in a backing root, which GC and the
//!   witness's records both read.
//!
//! The rollback format marker is compared byte for byte and the arena's
//! pages by their digests: neither has a decoder. The durable proof is
//! `maki-format`'s, fuzzed with its records.
//!
//! An input's first byte selects the record (its low four bits, modulo 6);
//! [`REPAIR`] makes a checksummed record's checksum match first, so a run
//! reaches what lies behind it, and [`SECOND_SLOT`] reads a manifest slot
//! as slot 1. The rest is the record's bytes.

use crate::remote_witness::{self, CanonicalState};
use crate::rollback::fuzzing::{self as rollback, enrollment};
use crate::witness::{self, Anchor};
use crate::{Backing, MemBacking};

pub const ANCHOR: u8 = 0;
pub const ENROLLMENT: u8 = 1;
pub const REMOTE_STATE: u8 = 2;
pub const MANIFEST: u8 = 3;
pub const MANIFEST_SLOT: u8 = 4;
pub const NAMESPACE: u8 = 5;
/// Make the record's checksum match before it is decoded.
pub const REPAIR: u8 = 0x80;
/// Read a manifest slot as slot 1 rather than slot 0.
pub const SECOND_SLOT: u8 = 0x40;

/// Decode the record `data` selects, and return whether it was accepted.
/// Panics where an accepted record breaks a rule its readers rely on: it
/// must be its own encoding (each is stored as written and compared as
/// bytes), and its fields must be in range.
pub fn records(data: &[u8]) -> bool {
    let Some((&selector, body)) = data.split_first() else {
        return false;
    };
    let repair = selector & REPAIR != 0;
    match (selector & 0x0f) % 6 {
        ANCHOR => anchor(body, repair),
        ENROLLMENT => binding(body, repair),
        REMOTE_STATE => remote_state(body, repair),
        MANIFEST => manifest(body),
        MANIFEST_SLOT => manifest_slot(body, usize::from(selector & SECOND_SLOT != 0)),
        _ => namespace(body),
    }
}

fn anchor(body: &[u8], repair: bool) -> bool {
    // The witness reads an anchor of exactly its length.
    let Ok(mut image) = <[u8; witness::fuzzing::ENCODED_LEN]>::try_from(body) else {
        return false;
    };
    if repair {
        let checksum = witness::fuzzing::checksum(&image[..witness::fuzzing::BODY_LEN]);
        image[witness::fuzzing::BODY_LEN..].copy_from_slice(&checksum);
    }
    let Ok(anchor) = witness::fuzzing::decode(&image) else {
        return false;
    };
    assert_ne!(anchor.identity, [0; 16], "an anchor of no identity");
    assert!(anchor.generation <= i64::MAX as u64, "{anchor:?}");
    assert_eq!(
        witness::fuzzing::encode(&anchor),
        image,
        "an accepted anchor is not its own encoding"
    );
    true
}

fn binding(body: &[u8], repair: bool) -> bool {
    let mut image = body.to_vec();
    if repair && image.len() == enrollment::LENGTH {
        let checksum = enrollment::checksum(&image[..enrollment::COVERED]);
        image[enrollment::COVERED..].copy_from_slice(&checksum);
    }
    let Ok((identity, capacity)) = enrollment::decode(&image) else {
        return false;
    };
    let again = enrollment::encode(identity, capacity).expect("an accepted binding encodes");
    assert_eq!(
        again.as_slice(),
        image.as_slice(),
        "an accepted binding is not its own encoding"
    );
    true
}

fn remote_state(body: &[u8], repair: bool) -> bool {
    let mut image = body.to_vec();
    if repair {
        remote_witness::fuzzing::seal(&mut image);
    }
    let Ok(state) = CanonicalState::decode(&image) else {
        return false;
    };
    state
        .record()
        .validate()
        .expect("an accepted state's record validates");
    assert_eq!(
        state.encode().expect("an accepted state encodes"),
        image,
        "an accepted state is not its own encoding"
    );
    true
}

fn manifest(body: &[u8]) -> bool {
    let Ok(canonical) = rollback::manifest(body) else {
        return false;
    };
    assert_eq!(
        rollback::manifest(&canonical).ok().as_ref(),
        Some(&canonical),
        "a manifest's canonical encoding does not decode to itself"
    );
    // Open accepts nothing but the canonical bytes.
    canonical == body
}

fn manifest_slot(body: &[u8], index: usize) -> bool {
    let disk = MemBacking::new();
    let slot = disk
        .open(rollback::MANIFESTS[index], true)
        .expect("a slot in memory");
    slot.write_at(0, body).expect("a slot in memory");
    let unpublished =
        rollback::unpublished_slot(&disk, index).expect("a slot in memory reads back");
    if body.iter().all(|byte| *byte == 0) {
        assert!(unpublished, "an all-zero slot is unwritten");
    } else if index == 1 {
        assert!(!unpublished, "a creation writes nothing to slot 1");
    }
    unpublished
}

fn namespace(body: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(body) else {
        return false;
    };
    let fence = rollback::namespace_fence(name);
    assert_eq!(
        fence,
        remote_witness::fuzzing::namespace_fence(name).ok(),
        "GC and the witness's records read {name:?} differently"
    );
    let Some(fence) = fence else {
        return false;
    };
    let mut session = [0; 16];
    for (byte, pair) in session.iter_mut().zip(name.as_bytes()[24..].chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    assert_eq!(
        remote_witness::namespace(fence, session),
        name,
        "a namespace is not the name of its fence and session"
    );
    true
}

/// `selector` followed by `bytes`.
fn input(selector: u8, bytes: &[u8]) -> Vec<u8> {
    [&[selector][..], bytes].concat()
}

/// `bytes` with byte `at` changed.
fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    changed[at] ^= 0x20;
    changed
}

/// The envelope of `state`, a remote state's encoding, around `body`
/// instead, sealed.
fn sealed(state: &[u8], body: &[u8]) -> Vec<u8> {
    let mut image = state[..8].to_vec();
    image.extend_from_slice(&[0; 4]);
    image.extend_from_slice(body);
    image.extend_from_slice(&[0; 32]);
    remote_witness::fuzzing::seal(&mut image);
    image
}

/// The committed seeds of `backing_records`: each record as this crate
/// encodes it, and copies changed where a reader must refuse them. A seed's
/// name says what [`records`] returns for it (`valid-` true, `refused-`
/// false, `noise-` either).
pub fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>| seeds.push((name.to_string(), bytes));

    let anchor = witness::fuzzing::encode(&Anchor {
        identity: [7; 16],
        generation: 12,
        root: [0x5a; 32],
    });
    let body = witness::fuzzing::BODY_LEN;
    add("valid-anchor", input(ANCHOR, &anchor));
    add(
        "refused-anchor-checksum",
        input(ANCHOR, &flipped(&anchor, 33)),
    );
    add(
        "refused-anchor-reserved-bytes",
        input(ANCHOR | REPAIR, &flipped(&anchor, 12)),
    );
    let mut nil = anchor;
    nil[16..32].fill(0);
    add("refused-anchor-nil-identity", input(ANCHOR | REPAIR, &nil));
    let mut far = anchor;
    far[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    add(
        "refused-anchor-generation-out-of-range",
        input(ANCHOR | REPAIR, &far),
    );
    add("refused-anchor-short", input(ANCHOR, &anchor[..body]));
    add(
        "noise-anchor",
        input(ANCHOR | REPAIR, &flipped(&anchor, 40)),
    );

    let binding = enrollment::encode([9; 16], 64 << 20).expect("a sample binding");
    add("valid-enrollment", input(ENROLLMENT, &binding));
    add(
        "refused-enrollment-checksum",
        input(ENROLLMENT, &flipped(&binding, 10)),
    );
    let mut odd = binding;
    odd[24..32].copy_from_slice(&4097u64.to_le_bytes());
    add(
        "refused-enrollment-capacity",
        input(ENROLLMENT | REPAIR, &odd),
    );
    let mut nil = binding;
    nil[8..24].fill(0);
    add(
        "refused-enrollment-nil-identity",
        input(ENROLLMENT | REPAIR, &nil),
    );
    add(
        "refused-enrollment-magic",
        input(ENROLLMENT | REPAIR, &flipped(&binding, 0)),
    );
    add(
        "refused-enrollment-long",
        input(ENROLLMENT | REPAIR, &[&binding[..], &[0]].concat()),
    );

    let states = remote_witness::fuzzing::samples();
    for (name, state) in &states {
        add(
            &format!("valid-remote-state-{name}"),
            input(REMOTE_STATE, state),
        );
    }
    let active = &states
        .iter()
        .find(|(name, _)| *name == "active")
        .expect("an active sample")
        .1;
    let json = std::str::from_utf8(&active[12..active.len() - 32]).expect("a JSON body");
    add(
        "refused-remote-state-checksum",
        input(REMOTE_STATE, &flipped(active, 20)),
    );
    add(
        "refused-remote-state-noncanonical",
        input(REMOTE_STATE, &sealed(active, format!("{json} ").as_bytes())),
    );
    add(
        "refused-remote-state-unknown-field",
        input(
            REMOTE_STATE,
            &sealed(active, json.replacen('{', "{\"extra\":1,", 1).as_bytes()),
        ),
    );
    add(
        "refused-remote-state-inconsistent",
        input(
            REMOTE_STATE,
            &sealed(
                active,
                json.replace("\"phase\":\"active\"", "\"phase\":\"released\"")
                    .replacen("\"fence\":1", "\"fence\":0", 1)
                    .as_bytes(),
            ),
        ),
    );
    add(
        "refused-remote-state-length",
        input(REMOTE_STATE, &active[..active.len() - 1]),
    );
    add("refused-remote-state-empty", input(REMOTE_STATE, &[]));
    add(
        "noise-remote-state-active",
        input(REMOTE_STATE | REPAIR, &flipped(active, 200)),
    );

    let manifests = rollback::samples();
    for (name, manifest) in &manifests {
        add(&format!("valid-manifest-{name}"), input(MANIFEST, manifest));
    }
    let (initial, used) = (&manifests[0].1, &manifests[1].1);
    let used_json = std::str::from_utf8(used).expect("a JSON manifest");
    add(
        "refused-manifest-noncanonical",
        input(MANIFEST, format!(" {used_json}").as_bytes()),
    );
    add(
        "refused-manifest-unknown-field",
        input(
            MANIFEST,
            used_json.replacen('{', "{\"extra\":1,", 1).as_bytes(),
        ),
    );
    add(
        "refused-manifest-aliased-page",
        input(
            MANIFEST,
            used_json.replace("\"slot\":1,", "\"slot\":5,").as_bytes(),
        ),
    );
    add(
        "refused-manifest-capacity",
        input(
            MANIFEST,
            used_json
                .replace("\"capacity\":16384", "\"capacity\":16385")
                .as_bytes(),
        ),
    );
    add(
        "refused-manifest-page-beyond-file",
        input(
            MANIFEST,
            used_json.replace("\"len\":8197", "\"len\":4096").as_bytes(),
        ),
    );
    add("refused-manifest-not-json", input(MANIFEST, &used[..40]));
    add("noise-manifest-used", input(MANIFEST, &flipped(used, 60)));

    // A slot as a creation writes it: the manifest's length, the manifest
    // and the slot's reserved zeros.
    let slot = |manifest: &[u8]| -> Vec<u8> {
        let mut image = (manifest.len() as u64).to_le_bytes().to_vec();
        image.extend_from_slice(manifest);
        image.extend_from_slice(&[0; 64]);
        image
    };
    add("valid-slot-zeros", input(MANIFEST_SLOT, &[0; 256]));
    add(
        "valid-slot-second-zeros",
        input(MANIFEST_SLOT | SECOND_SLOT, &[0; 256]),
    );
    add(
        "valid-slot-initial-manifest",
        input(MANIFEST_SLOT, &slot(initial)),
    );
    add(
        "refused-slot-published-manifest",
        input(MANIFEST_SLOT, &slot(used)),
    );
    add(
        "refused-slot-second-initial-manifest",
        input(MANIFEST_SLOT | SECOND_SLOT, &slot(initial)),
    );
    let mut long = slot(initial);
    let beyond = long.len() as u64;
    long[..8].copy_from_slice(&beyond.to_le_bytes());
    add(
        "refused-slot-length-beyond-file",
        input(MANIFEST_SLOT, &long),
    );
    add(
        "refused-slot-torn-manifest",
        input(MANIFEST_SLOT, &slot(initial)[..8 + initial.len() / 2]),
    );
    add(
        "noise-slot-initial-manifest",
        input(MANIFEST_SLOT, &flipped(&slot(initial), 30)),
    );

    let name = remote_witness::namespace(1, [2; 16]);
    add("valid-namespace", input(NAMESPACE, name.as_bytes()));
    add(
        "valid-namespace-last-fence",
        input(
            NAMESPACE,
            remote_witness::namespace(u64::MAX, [0xab; 16]).as_bytes(),
        ),
    );
    add(
        "refused-namespace-nil-session",
        input(NAMESPACE, remote_witness::namespace(1, [0; 16]).as_bytes()),
    );
    add(
        "refused-namespace-nil-fence",
        input(NAMESPACE, remote_witness::namespace(0, [2; 16]).as_bytes()),
    );
    add(
        "refused-namespace-uppercase",
        input(
            NAMESPACE,
            remote_witness::namespace(1, [0xab; 16])
                .to_uppercase()
                .replace("REMOTE", "remote")
                .as_bytes(),
        ),
    );
    add(
        "refused-namespace-short",
        input(NAMESPACE, &name.as_bytes()[..55]),
    );
    add(
        "refused-namespace-tombstone",
        input(NAMESPACE, format!(".remote-gc-{name}").as_bytes()),
    );
    seeds
}
