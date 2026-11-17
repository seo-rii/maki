//! audit2 (decoder-fuzz): digest-VALID, structure-aware mutation of the
//! local witness anchor and of the remote-witness authority state
//! (`CanonicalState`, the `remote.state` envelope), plus a random walk over
//! the remote-witness state machine.
//!
//! Each mutated image carries a correct SHA-256 (recomputed with the same
//! domain separation as the code), so the field validation behind it is
//! exercised. Properties:
//!   * no panic (debug overflow checks on), including in `apply` on any
//!     state `decode` accepts;
//!   * bounded allocation (per-thread counting allocator);
//!   * accepted records re-encode to exactly the accepted bytes;
//!   * every state `apply` produces decodes back to itself.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use maki_backing::remote_witness::{
    namespace, Action, CanonicalState, Descriptor, Phase, Record, Request, Role,
    SessionAuthorization,
};
use maki_backing::witness::{Anchor, FileWitness};

// ---------------------------------------------------------------- allocator

struct Counting;
thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}
fn note_alloc(size: usize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + size as isize;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now)
            }
        });
    });
}
fn note_free(size: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get() - size as isize));
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_free(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_free(layout.size());
        note_alloc(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

fn measured<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let start = LIVE.with(|l| l.get());
    PEAK.with(|p| p.set(start));
    let out = f();
    let peak = PEAK.with(|p| p.get());
    (out, (peak - start).max(0) as usize)
}

fn panic_text(panic: Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

// ---------------------------------------------------------------- remote state envelope

const STATE_MAGIC: &[u8; 8] = b"MAKIRW02";
const STATE_DOMAIN: &[u8] = b"maki-remote-witness-state-v2\0";
const MAX_BYTES: usize = 64 * 1024;

/// Field-for-field mirror of the private `Stored`: identical serde output.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format: u32,
    record: Record,
    last_request_hash: Option<[u8; 32]>,
    session_authorization_hash: Option<[u8; 32]>,
}

fn wrap_state(body: &[u8]) -> Vec<u8> {
    let mut bytes = STATE_MAGIC.to_vec();
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    let mut hash = Sha256::new();
    hash.update(STATE_DOMAIN);
    hash.update(&bytes);
    let sum: [u8; 32] = hash.finalize().into();
    bytes.extend_from_slice(&sum);
    bytes
}

fn body_of(envelope: &[u8]) -> &[u8] {
    &envelope[12..envelope.len() - 32]
}

const ID: [u8; 16] = [0x11; 16];

fn interesting_u64(rng: &mut StdRng, current: u64) -> u64 {
    match rng.random_range(0..12u32) {
        0 => 0,
        1 => 1,
        2 => u64::MAX,
        3 => u64::MAX - 1,
        4 => i64::MAX as u64,
        5 => i64::MAX as u64 + 1,
        6 => current.wrapping_add(1),
        7 => current.wrapping_sub(1),
        8 => rng.random_range(0..8),
        9 => 1 << rng.random_range(0..64),
        _ => rng.random(),
    }
}

fn bytes16(rng: &mut StdRng, pool: &[[u8; 16]]) -> [u8; 16] {
    match rng.random_range(0..4u32) {
        0 => [0; 16],
        1 => pool[rng.random_range(0..pool.len())],
        _ => {
            let mut b = [0; 16];
            b[0] = rng.random_range(1..6);
            b
        }
    }
}

fn mutate_namespace(rng: &mut StdRng, current: &str) -> String {
    match rng.random_range(0..9u32) {
        0 => namespace(rng.random_range(0..4), [rng.random_range(0..3); 16]),
        1 => namespace(u64::MAX, [0xff; 16]),
        2 => {
            // Same byte length, a multi-byte character inside the hex fields.
            let mut s = current.to_string();
            if s.len() == 56 {
                let at = rng.random_range(7..54);
                if s.is_char_boundary(at) && s.is_char_boundary(at + 2) {
                    s.replace_range(at..at + 2, "é");
                }
            }
            s
        }
        3 => current.to_uppercase(),
        4 => format!("{current}0"),
        5 => current.chars().take(55).collect(),
        6 => "remote-0000000000000001-..//..//..//..//..//..//..//..//".into(),
        7 => String::new(),
        _ => {
            let mut s: Vec<u8> = current.as_bytes().to_vec();
            if !s.is_empty() {
                let at = rng.random_range(0..s.len());
                s[at] = b"0123456789abcdefABCDEF-/x"[rng.random_range(0..25)];
            }
            String::from_utf8_lossy(&s).into_owned()
        }
    }
}

fn mutate_descriptor(rng: &mut StdRng, d: &mut Descriptor) {
    match rng.random_range(0..6u32) {
        0 => d.anchor.identity = bytes16(rng, &[ID]),
        1 => d.anchor.generation = interesting_u64(rng, d.anchor.generation),
        2 => d.anchor.root = [rng.random(); 32],
        3 => d.epoch = interesting_u64(rng, d.epoch),
        _ => d.namespace = mutate_namespace(rng, &d.namespace),
    }
}

fn some_descriptor(rng: &mut StdRng, record: &Record) -> Descriptor {
    record.current.clone().unwrap_or_else(|| Descriptor {
        anchor: Anchor {
            identity: ID,
            generation: rng.random_range(0..3),
            root: [7; 32],
        },
        epoch: 0,
        namespace: namespace(record.fence.max(1), record.session),
    })
}

fn mutate_stored(rng: &mut StdRng, s: &mut Stored) {
    for _ in 0..rng.random_range(1..=3) {
        let r = &mut s.record;
        match rng.random_range(0..14u32) {
            0 => s.format = [0, 1, 2, 3, u32::MAX][rng.random_range(0..5)],
            1 => r.identity = bytes16(rng, &[ID]),
            2 => r.fence = interesting_u64(rng, r.fence),
            3 => r.session = bytes16(rng, &[r.session]),
            4 => r.last_operation = bytes16(rng, &[r.last_operation]),
            5 => {
                r.phase = [Phase::Released, Phase::Claimed, Phase::RestoreClaimed, Phase::Active]
                    [rng.random_range(0..4)]
            }
            6 => r.current = None,
            7 => {
                let mut d = some_descriptor(rng, r);
                mutate_descriptor(rng, &mut d);
                r.current = Some(d);
            }
            8 => {
                if let Some(d) = r.current.as_mut() {
                    mutate_descriptor(rng, d);
                }
            }
            9 => {
                let mut d = some_descriptor(rng, r);
                if rng.random_bool(0.5) {
                    mutate_descriptor(rng, &mut d);
                }
                r.restore_source = Some(d);
            }
            10 => r.restore_source = None,
            11 => s.last_request_hash = if rng.random_bool(0.5) { None } else { Some([rng.random(); 32]) },
            12 => {
                s.session_authorization_hash =
                    if rng.random_bool(0.5) { None } else { Some([rng.random(); 32]) }
            }
            _ => {
                if r.phase == Phase::Active {
                    if let Some(d) = r.current.as_mut() {
                        d.namespace = namespace(r.fence, r.session);
                    }
                }
            }
        }
    }
}

const AUTHS: [[u8; 32]; 3] = [[0; 32], [0xa1; 32], [0xb2; 32]];
const OPS: [[u8; 16]; 4] = [[0; 16], [1; 16], [2; 16], [3; 16]];

fn random_request(rng: &mut StdRng, record: &Record) -> (Role, Request) {
    let role = if rng.random_bool(0.6) { Role::Admin } else { Role::Writer };
    let current = record.current.clone();
    let next_namespace = namespace(record.fence, record.session);
    let mut anchor = current.as_ref().map(|d| d.anchor.clone()).unwrap_or(Anchor {
        identity: ID,
        generation: 0,
        root: [9; 32],
    });
    let action = match rng.random_range(0..9u32) {
        0 => Action::Inspect,
        1 => Action::Claim,
        2 => Action::Takeover,
        3 => Action::RecoverEnrollment,
        4 => {
            let mut source = some_descriptor(rng, record);
            if rng.random_bool(0.3) {
                mutate_descriptor(rng, &mut source);
            }
            Action::ClaimRestore { source }
        }
        5 => {
            let mut descriptor = match (&current, record.phase) {
                (Some(d), Phase::RestoreClaimed) => Descriptor {
                    anchor: Anchor {
                        generation: d.anchor.generation.wrapping_add(1),
                        ..d.anchor.clone()
                    },
                    epoch: d.epoch.wrapping_add(1),
                    namespace: next_namespace,
                },
                (Some(d), _) => Descriptor {
                    namespace: next_namespace,
                    ..d.clone()
                },
                (None, _) => Descriptor {
                    anchor: anchor.clone(),
                    epoch: 0,
                    namespace: next_namespace,
                },
            };
            if rng.random_bool(0.2) {
                mutate_descriptor(rng, &mut descriptor);
            }
            Action::Activate { descriptor }
        }
        6 => {
            anchor.generation = anchor.generation.wrapping_add(1);
            anchor.root = [rng.random(); 32];
            if rng.random_bool(0.2) {
                anchor.generation = interesting_u64(rng, anchor.generation);
            }
            Action::Advance { anchor }
        }
        _ => Action::Release,
    };
    let expected = match rng.random_range(0..6u32) {
        0 => None,
        1 => {
            let mut r = record.clone();
            r.fence = r.fence.wrapping_add(1);
            Some(r)
        }
        _ => Some(record.clone()),
    };
    let authorization = if action == Action::Inspect && rng.random_bool(0.8) {
        None
    } else {
        match rng.random_range(0..5u32) {
            0 => None,
            1 => Some(SessionAuthorization::from_bytes(AUTHS[0])),
            2 => Some(SessionAuthorization::from_bytes(AUTHS[2])),
            _ => Some(SessionAuthorization::from_bytes(AUTHS[1])),
        }
    };
    let operation_id = if rng.random_bool(0.2) {
        record.last_operation
    } else if rng.random_bool(0.1) {
        OPS[rng.random_range(0..OPS.len())]
    } else {
        let mut id = [0u8; 16];
        rng.fill(&mut id);
        id
    };
    (
        role,
        Request {
            operation_id,
            expected,
            action,
            authorization,
        },
    )
}

/// apply never panics; any state it returns encodes and decodes to itself.
fn check_apply(
    state: &CanonicalState,
    role: Role,
    request: &Request,
    failures: &mut Vec<String>,
) -> Option<CanonicalState> {
    match catch_unwind(AssertUnwindSafe(|| state.apply(role, request))) {
        Err(panic) => {
            failures.push(format!(
                "apply panicked ({}) on {:?} with {role:?} {request:?}",
                panic_text(panic),
                state.record()
            ));
            None
        }
        Ok(Err(_)) => None,
        Ok(Ok(next)) => {
            match next.encode() {
                Ok(bytes) => match CanonicalState::decode(&bytes) {
                    Ok(back) if back == next => {}
                    Ok(_) => failures.push("apply result does not round-trip".into()),
                    Err(e) => failures.push(format!(
                        "apply accepted a state its own decoder refuses ({e}): {:?}",
                        next.record()
                    )),
                },
                Err(e) => failures.push(format!(
                    "apply returned a state that cannot be encoded ({e}): {:?}",
                    next.record()
                )),
            }
            Some(next)
        }
    }
}

#[test]
fn remote_state_machine_random_walk_is_closed_and_panic_free() {
    let seed = 0x5EED_0201;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut failures = Vec::new();
    let mut transitions = 0u64;
    let mut phases = std::collections::BTreeMap::new();
    let walks = 3000;
    let steps = 40;
    for _ in 0..walks {
        let mut state = CanonicalState::initial(ID).unwrap();
        for _ in 0..steps {
            let (role, request) = random_request(&mut rng, state.record());
            if let Some(next) = check_apply(&state, role, &request, &mut failures) {
                if next != state {
                    transitions += 1;
                }
                state = next;
                *phases
                    .entry(format!("{:?}", state.record().phase))
                    .or_insert(0u64) += 1;
            }
        }
    }
    eprintln!(
        "[audit2 witness] state-machine walk: seed {seed:#x} {walks} walks x {steps} steps, \
         {transitions} state changes, phases visited {phases:?}"
    );
    failures.truncate(6);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Collect reachable states, then mutate their envelopes digest-validly.
#[test]
fn remote_state_envelope_digest_valid_mutations() {
    let seed = 0x5EED_0202;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut corpus: Vec<Vec<u8>> = vec![CanonicalState::initial(ID).unwrap().encode().unwrap()];
    for _ in 0..400 {
        let mut state = CanonicalState::initial(ID).unwrap();
        for _ in 0..30 {
            let (role, request) = random_request(&mut rng, state.record());
            if let Ok(next) = state.apply(role, &request) {
                state = next;
            }
        }
        corpus.push(state.encode().unwrap());
    }
    let mut failures = Vec::new();
    let (mut tried, mut accepted, mut noncanonical) = (0u64, 0u64, 0u64);
    let mut max_peak = 0usize;
    for i in 0..30_000 {
        let base = &corpus[rng.random_range(0..corpus.len())];
        let candidate: Vec<u8> = match i % 4 {
            // typed mutation, canonical serialization, correct digest
            0 | 1 => {
                let mut stored: Stored = serde_json::from_slice(body_of(base)).unwrap();
                mutate_stored(&mut rng, &mut stored);
                wrap_state(&serde_json::to_vec(&stored).unwrap())
            }
            // byte-level JSON mutation, correct digest
            2 => {
                let mut body = body_of(base).to_vec();
                for _ in 0..rng.random_range(1..4) {
                    let at = rng.random_range(0..body.len());
                    match rng.random_range(0..4u32) {
                        0 => body[at] = b"0123456789"[rng.random_range(0..10)],
                        1 => body[at] = b"{}[],:\"null-e9 "[rng.random_range(0..15)],
                        2 => {
                            body.insert(at, b"0123456789"[rng.random_range(0..10)]);
                        }
                        _ => {
                            body.remove(at);
                        }
                    }
                }
                wrap_state(&body)
            }
            // envelope-level: length field, truncation, random
            _ => {
                let mut b = base.clone();
                match rng.random_range(0..3u32) {
                    0 => {
                        let n = rng.random_range(0..b.len());
                        b.truncate(n);
                    }
                    1 => {
                        let v: u32 = rng.random();
                        b[8..12].copy_from_slice(&v.to_le_bytes());
                    }
                    _ => {
                        b = (0..rng.random_range(0..200)).map(|_| rng.random()).collect();
                    }
                }
                b
            }
        };
        tried += 1;
        let result = catch_unwind(AssertUnwindSafe(|| {
            measured(|| CanonicalState::decode(&candidate))
        }));
        let (decoded, peak) = match result {
            Ok(v) => v,
            Err(panic) => {
                failures.push(format!("decode panicked: {}", panic_text(panic)));
                continue;
            }
        };
        max_peak = max_peak.max(peak);
        if peak > 8 * MAX_BYTES {
            failures.push(format!("decode peak {peak} bytes for {} input", candidate.len()));
        }
        let Ok(state) = decoded else { continue };
        accepted += 1;
        if state.encode().ok().as_deref() != Some(candidate.as_slice()) {
            noncanonical += 1;
        }
        if let Err(e) = state.record().validate() {
            failures.push(format!("decoded record fails validate: {e}"));
        }
        for _ in 0..8 {
            let (role, request) = random_request(&mut rng, state.record());
            check_apply(&state, role, &request, &mut failures);
        }
    }
    eprintln!(
        "[audit2 witness] remote.state envelope: seed {seed:#x} tried {tried} accepted {accepted} \
         non-canonical {noncanonical} max decode peak {max_peak} bytes"
    );
    failures.truncate(6);
    assert!(failures.is_empty(), "{failures:#?}");
    assert_eq!(noncanonical, 0);
}

/// The server's handler parses untrusted `Request` JSON from a peer.
#[test]
fn remote_request_json_mutations_never_panic_and_stay_bounded() {
    let seed = 0x5EED_0203;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut corpus = Vec::new();
    let state = CanonicalState::initial(ID).unwrap();
    for _ in 0..200 {
        let (_, request) = random_request(&mut rng, state.record());
        corpus.push(serde_json::to_vec(&request).unwrap());
    }
    let mut failures = Vec::new();
    let mut parsed = 0;
    for _ in 0..40_000 {
        let mut b = corpus[rng.random_range(0..corpus.len())].clone();
        for _ in 0..rng.random_range(1..5) {
            let at = rng.random_range(0..b.len());
            match rng.random_range(0..5u32) {
                0 => b[at] = b"0123456789"[rng.random_range(0..10)],
                1 => b[at] = b"{}[],:\"nul-e9 \\"[rng.random_range(0..15)],
                2 => b.insert(at, rng.random()),
                3 => {
                    b.remove(at);
                }
                _ => {
                    // deep nesting / long arrays
                    let n = rng.random_range(1..400);
                    let s: Vec<u8> = if rng.random_bool(0.5) {
                        std::iter::repeat_n(b'[', n).collect()
                    } else {
                        (0..n).flat_map(|_| *b"0,").collect()
                    };
                    b.splice(at..at, s);
                }
            }
        }
        b.truncate(MAX_BYTES);
        let r = catch_unwind(AssertUnwindSafe(|| {
            measured(|| serde_json::from_slice::<Request>(&b).map(|_| ()))
        }));
        match r {
            Err(p) => failures.push(format!("Request parse panicked: {}", panic_text(p))),
            Ok((res, peak)) => {
                if res.is_ok() {
                    parsed += 1;
                }
                if peak > 16 * MAX_BYTES {
                    failures.push(format!("Request parse peak {peak}"));
                }
            }
        }
    }
    eprintln!("[audit2 witness] Request JSON: seed {seed:#x} 40000 mutated, {parsed} parsed");
    failures.truncate(6);
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------- local witness anchor

const ANCHOR_DOMAIN: &[u8] = b"maki-file-witness-anchor-v1\0";

fn anchor_image(identity: [u8; 16], generation: u64, root: [u8; 32]) -> [u8; 104] {
    let mut b = [0u8; 104];
    b[..8].copy_from_slice(b"MAKIWIT1");
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[16..32].copy_from_slice(&identity);
    b[32..40].copy_from_slice(&generation.to_le_bytes());
    b[40..72].copy_from_slice(&root);
    resign_anchor(&mut b);
    b
}

fn resign_anchor(b: &mut [u8]) {
    let mut hash = Sha256::new();
    hash.update(ANCHOR_DOMAIN);
    hash.update(&b[..72]);
    let sum: [u8; 32] = hash.finalize().into();
    b[72..104].copy_from_slice(&sum);
}

#[test]
fn local_witness_anchor_digest_valid_mutations() {
    let seed = 0xA4C4_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    // tmpfs keeps the re-publish fsyncs of every accepted open cheap.
    let base = if std::path::Path::new("/dev/shm").is_dir() {
        tempfile::tempdir_in("/dev/shm").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let dir = base.path();
    let (mut tried, mut accepted) = (0u64, 0u64);
    let mut failures = Vec::new();
    for i in 0..3000 {
        let mut image = anchor_image([3; 16], rng.random_range(0..100), [5; 32]).to_vec();
        match i % 3 {
            0 => {
                for _ in 0..rng.random_range(1..3) {
                    match rng.random_range(0..6u32) {
                        0 => image[8..10].copy_from_slice(&rng.random::<u16>().to_le_bytes()),
                        1 => image[10 + rng.random_range(0..6)] = rng.random(),
                        2 => image[16..32].fill(if rng.random_bool(0.5) { 0 } else { rng.random() }),
                        3 => {
                            let g = interesting_u64(&mut rng, 5);
                            image[32..40].copy_from_slice(&g.to_le_bytes())
                        }
                        4 => image[40 + rng.random_range(0..32)] = rng.random(),
                        _ => image[rng.random_range(0..8)] = rng.random(),
                    }
                }
                resign_anchor(&mut image);
            }
            1 => {
                // wrong length, re-signed where possible
                if rng.random_bool(0.5) {
                    image.push(0);
                } else {
                    let n = rng.random_range(0..image.len());
                    image.truncate(n);
                }
            }
            _ => {
                image = (0..rng.random_range(0..130)).map(|_| rng.random()).collect();
            }
        }
        std::fs::write(dir.join("anchor"), &image).unwrap();
        tried += 1;
        let r = catch_unwind(AssertUnwindSafe(|| FileWitness::open(dir)));
        match r {
            Err(p) => failures.push(format!("open panicked: {}", panic_text(p))),
            Ok(Err(e)) if e.kind() == io::ErrorKind::InvalidData => {}
            Ok(Err(e)) => failures.push(format!("unexpected error kind {:?}: {e}", e.kind())),
            Ok(Ok(witness)) => {
                accepted += 1;
                let a: &Anchor = witness.anchor();
                let expect = anchor_image(a.identity, a.generation, a.root);
                if image != expect {
                    failures.push(format!("non-canonical anchor accepted: {:02x?}", &image[..40]));
                }
                if a.identity == [0; 16] || a.generation > i64::MAX as u64 {
                    failures.push(format!("invalid anchor accepted: {a:?}"));
                }
                drop(witness);
                // Re-publish must not have changed the bytes.
                let after = std::fs::read(dir.join("anchor")).unwrap();
                if after != image {
                    failures.push("open rewrote a different anchor".into());
                }
            }
        }
        let _ = std::fs::remove_file(dir.join("anchor.next"));
    }
    eprintln!(
        "[audit2 witness] local anchor: seed {seed:#x} tried {tried} accepted {accepted}"
    );
    failures.truncate(6);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `Record::validate` slices namespace strings by byte index; feed it
/// 56-byte strings with multi-byte characters at every position.
#[test]
fn namespace_validation_never_panics_on_multibyte_names() {
    let mut failures = 0;
    let base = namespace(1, [0xab; 16]);
    let mut checked = 0;
    for ch in ["é", "€", "𝄞", "\u{0}", "/"] {
        for at in 0..base.len() {
            let mut s = base.clone();
            let w = ch.len();
            if at + w > s.len() || !s.is_char_boundary(at) || !s.is_char_boundary(at + w) {
                continue;
            }
            s.replace_range(at..at + w, ch);
            let mut record = Record {
                identity: ID,
                current: Some(Descriptor {
                    anchor: Anchor {
                        identity: ID,
                        generation: 1,
                        root: [1; 32],
                    },
                    epoch: 0,
                    namespace: s.clone(),
                }),
                fence: 1,
                session: [0xab; 16],
                phase: Phase::Claimed,
                restore_source: None,
                last_operation: [1; 16],
            };
            checked += 1;
            if catch_unwind(AssertUnwindSafe(|| record.validate())).is_err() {
                failures += 1;
            }
            record.phase = Phase::RestoreClaimed;
            record.restore_source = record.current.clone();
            if catch_unwind(AssertUnwindSafe(|| record.validate())).is_err() {
                failures += 1;
            }
        }
    }
    eprintln!("[audit2 witness] namespace multibyte: {checked} names");
    assert_eq!(failures, 0);
}
