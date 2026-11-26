//! The fuzz harness's way into the witness's readers of what a peer sends
//! (`fuzz/harness`, targets `witness_rpc` and `witness_etcd`). Built only
//! with the `fuzzing` feature, which only the harness enables: nothing here
//! is part of the witness.
//!
//! - [`rpc`]: the bytes one RPC connection carries after TLS. A client
//!   reads the server's answer (`read_frame`, `parse_response`, `answer`,
//!   then `Record::validate` as `Rpc::call` does). A server reads a request
//!   (`read_frame`, `parse_request`) and hands its operation to the file
//!   authority's own handler (`state_handler` over a `StateStore` in memory);
//!   the client must then read the answer the server writes as it was sent.
//! - [`etcd`]: the body of etcd's answer to the quorum store's range and
//!   transaction requests (`etcd::fuzzing`, which describes the input).
//!
//! An input's first byte selects the side ([`CLIENT`] or [`SERVER`] in its
//! low bit). For the server, bits 1-2 are the role its certificate maps to
//! (writer, admin, or none: a trusted certificate the allow-list does not
//! name) and bits 3-4 the authority's state before the request (released,
//! claimed, active, claimed for a restore). The rest is what the peer sent.

use std::io;
use std::sync::Arc;

use maki_backing::remote_witness::{
    namespace, Action, Descriptor, Record, Request, Role, SessionAuthorization, StateStore,
};
use maki_backing::witness::Anchor;
use maki_backing::MemBacking;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    answer, operation, parse_request, parse_response, read_frame, serialize_frame, state_handler,
    unlisted, wire_error, write_frame, WireError, WireRequest, WireResponse, MAX_FRAME_BYTES,
    WIRE_VERSION,
};

pub use crate::etcd::fuzzing::{etcd, seeds as etcd_seeds};

/// The client reads the server's answer.
pub const CLIENT: u8 = 0;
/// The server reads a request.
pub const SERVER: u8 = 1;
/// Server: the certificate maps to the admin role (bit 1) or to none
/// (bit 2).
pub const ADMIN: u8 = 0x02;
pub const UNLISTED: u8 = 0x04;
/// Server: the authority's state before the request (bits 3-4).
pub const CLAIMED: u8 = 0x08;
pub const ACTIVE: u8 = 0x10;
pub const RESTORE_CLAIMED: u8 = 0x18;

/// The request id the client waits for.
pub const ID: Uuid = Uuid::from_u128(0x4d41_4b49_7769_4000_8000_0000_0000_0001);
/// The authority's storage identity.
pub const IDENTITY: [u8; 16] = [0x5a; 16];

const WRITER_SESSION: [u8; 32] = [0x21; 32];
const ADMIN_SESSION: [u8; 32] = [0x22; 32];

/// Feed `data` to the side its first byte selects, and return whether that
/// side accepted it: the client a valid record, the server a request its
/// handler answered with a record. Panics where a side read beyond its
/// frame, or where the client does not read back exactly what the server
/// answered.
pub fn rpc(data: &[u8]) -> bool {
    let Some((&selector, stream)) = data.split_first() else {
        return false;
    };
    if selector & 1 == CLIENT {
        client(stream)
    } else {
        server(selector, stream)
    }
}

/// One frame from `stream`, checked to be all that was read.
fn one_frame(stream: &[u8]) -> Option<maki_crypto::SecretBuffer> {
    let mut reader = stream;
    let frame = read_frame(&mut reader).ok()?;
    assert!(
        (1..=MAX_FRAME_BYTES).contains(&frame.len()),
        "a frame of {} bytes",
        frame.len()
    );
    assert_eq!(
        stream.len() - reader.len(),
        4 + frame.len(),
        "the frame reader read beyond its frame"
    );
    Some(frame)
}

fn client(stream: &[u8]) -> bool {
    let Some(frame) = one_frame(stream) else {
        return false;
    };
    let Ok(response) = parse_response::<Record>(frame.expose()) else {
        return false;
    };
    let record = match answer(response, ID) {
        Ok(record) => record,
        Err(error) => {
            // The kinds a caller acts on: failover and the remote session
            // treat each of them differently.
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidInput
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::Other
                ),
                "{error:?}"
            );
            return false;
        }
    };
    if record.validate().is_err() {
        return false;
    }
    let again = serde_json::to_vec(&record).expect("an accepted record encodes");
    assert_eq!(
        serde_json::from_slice::<Record>(&again).expect("an accepted record decodes again"),
        record,
        "an accepted record changed in a round trip"
    );
    true
}

/// The kind the client must report for a handler's error: a conflict, a
/// denial and a refused request keep their meaning across the wire, and
/// anything else is an authority that could not answer.
fn reported(error: &io::Error) -> io::ErrorKind {
    match error.kind() {
        io::ErrorKind::WouldBlock => io::ErrorKind::WouldBlock,
        io::ErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    }
}

fn server(selector: u8, stream: &[u8]) -> bool {
    let role = match selector & (ADMIN | UNLISTED) {
        0 => Some(Role::Writer),
        ADMIN => Some(Role::Admin),
        _ => None,
    };
    let (store, _) = authority(selector & RESTORE_CLAIMED);
    let handler = state_handler(store);
    let Some(frame) = one_frame(stream) else {
        return false;
    };
    let Ok(request) = parse_request(&frame) else {
        return false;
    };
    let outcome = match role {
        Some(role) => handler(role, request.request.get().as_bytes()),
        None => Err(unlisted()),
    };
    let (response, error) = match &outcome {
        Ok(response) => (Some(response.clone()), None),
        Err(error) => (None, Some(wire_error(error))),
    };
    let bytes = serialize_frame(&WireResponse {
        version: WIRE_VERSION,
        id: request.id,
        response,
        error,
    })
    .expect("an answer fits a frame");
    let mut wire = Vec::new();
    write_frame(&mut wire, bytes.expose()).expect("an answer is written");
    let read = one_frame(&wire).expect("the client reads the server's frame");
    let read = parse_response::<Record>(read.expose())
        .map(|response| answer(response, request.id))
        .expect("the client reads the server's answer");
    match (outcome, read) {
        (Ok(value), Ok(record)) => {
            assert_eq!(
                serde_json::from_value::<Record>(value).expect("the handler answers a record"),
                record,
                "the client read another record than the server sent"
            );
            record
                .validate()
                .expect("the authority answers a valid record");
            let operation = operation(request.request.get().as_bytes())
                .expect("a handled request has an operation");
            if operation.action != Action::Inspect {
                assert_eq!(record.last_operation, operation.operation_id);
            }
            true
        }
        (Err(error), Err(read)) => {
            assert_eq!(read.kind(), reported(&error), "{error:?} read as {read:?}");
            false
        }
        (sent, read) => panic!("the server answered {sent:?}, the client read {read:?}"),
    }
}

/// The writer's claim of a released authority, without its predecessor.
pub(crate) fn claim() -> Request {
    Request {
        operation_id: [0x11; 16],
        expected: None,
        action: Action::Claim,
        authorization: Some(SessionAuthorization::from_bytes(WRITER_SESSION)),
    }
}

fn descriptor(fence: u64, session: [u8; 16]) -> Descriptor {
    Descriptor {
        anchor: Anchor {
            identity: IDENTITY,
            generation: 0,
            root: [0x31; 32],
        },
        epoch: 0,
        namespace: namespace(fence, session),
    }
}

fn activate() -> Request {
    Request {
        operation_id: [0x12; 16],
        expected: None,
        action: Action::Activate {
            descriptor: descriptor(1, [0x11; 16]),
        },
        authorization: Some(SessionAuthorization::from_bytes(WRITER_SESSION)),
    }
}

fn claim_restore() -> Request {
    Request {
        operation_id: [0x13; 16],
        expected: None,
        action: Action::ClaimRestore {
            source: descriptor(1, [0x11; 16]),
        },
        authorization: Some(SessionAuthorization::from_bytes(ADMIN_SESSION)),
    }
}

/// An authority in memory in the state `state` selects, and its record.
/// Each state is reached by the requests a writer and an administrator
/// send: a claim, an activation, a claim for a restore.
fn authority(state: u8) -> (StateStore, Record) {
    let mut store = StateStore::create_backing(Arc::new(MemBacking::new()), IDENTITY)
        .expect("an authority in memory");
    let mut record = store
        .handle(
            Role::Writer,
            &Request {
                operation_id: [0; 16],
                expected: None,
                action: Action::Inspect,
                authorization: None,
            },
        )
        .expect("an inspection");
    let steps = [
        (Role::Writer, claim()),
        (Role::Writer, activate()),
        (Role::Admin, claim_restore()),
    ];
    for (role, mut request) in steps.into_iter().take(usize::from(state >> 3)) {
        request.expected = Some(record);
        record = store.handle(role, &request).expect("a sample transition");
    }
    (store, record)
}

/// The authority's record in the state `state` selects.
fn record(state: u8) -> Record {
    authority(state).1
}

/// One frame holding `value` as the witness serializes it.
fn framed(value: &impl Serialize) -> Vec<u8> {
    let bytes = serialize_frame(value).expect("a sample frame");
    let mut wire = Vec::new();
    write_frame(&mut wire, bytes.expose()).expect("a sample frame");
    wire
}

/// A frame holding `json` as it is.
fn raw(json: &str) -> Vec<u8> {
    let mut wire = (json.len() as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(json.as_bytes());
    wire
}

fn response(record: Option<&Record>, error: Option<WireError>) -> WireResponse<&Record> {
    WireResponse {
        version: WIRE_VERSION,
        id: ID,
        response: record,
        error,
    }
}

/// A client's request as it frames it.
fn request(request: &Request) -> Vec<u8> {
    framed(&WireRequest {
        version: WIRE_VERSION,
        id: ID,
        request,
    })
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

/// The committed seeds of `witness_rpc`. A seed's name says what [`rpc`]
/// returns for it (`valid-` true, `refused-` false, `noise-` either).
pub fn rpc_seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>| seeds.push((name.to_string(), bytes));

    let released = record(0);
    let active = record(ACTIVE);
    let restoring = record(RESTORE_CLAIMED);
    let answer = |record: &Record| framed(&response(Some(record), None));
    add("valid-client-released", input(CLIENT, &answer(&released)));
    add(
        "valid-client-claimed",
        input(CLIENT, &answer(&record(CLAIMED))),
    );
    add("valid-client-active", input(CLIENT, &answer(&active)));
    add(
        "valid-client-restore-claimed",
        input(CLIENT, &answer(&restoring)),
    );
    for (name, error) in [
        ("conflict", WireError::Conflict),
        ("denied", WireError::PermissionDenied),
        ("invalid-request", WireError::InvalidRequest),
        ("unavailable", WireError::Unavailable),
    ] {
        add(
            &format!("refused-client-{name}"),
            input(CLIENT, &framed(&response(None, Some(error)))),
        );
    }
    let active_json = serde_json::to_string(&response(Some(&active), None)).expect("JSON");
    add(
        "refused-client-other-request",
        input(
            CLIENT,
            &framed(&WireResponse {
                id: Uuid::from_u128(2),
                ..response(Some(&active), None)
            }),
        ),
    );
    add(
        "refused-client-other-version",
        input(
            CLIENT,
            &framed(&WireResponse {
                version: 1,
                ..response(Some(&active), None)
            }),
        ),
    );
    add(
        "refused-client-record-and-error",
        input(
            CLIENT,
            &framed(&response(Some(&active), Some(WireError::Conflict))),
        ),
    );
    add(
        "refused-client-neither-record-nor-error",
        input(CLIENT, &framed(&response(None, None))),
    );
    add(
        "refused-client-unknown-field",
        input(CLIENT, &raw(&active_json.replacen('{', "{\"extra\":1,", 1))),
    );
    let mut nil = released.clone();
    nil.identity = [0; 16];
    add("refused-client-nil-identity", input(CLIENT, &answer(&nil)));
    let mut sessionless = active.clone();
    sessionless.session = [0; 16];
    add(
        "refused-client-active-without-session",
        input(CLIENT, &answer(&sessionless)),
    );
    add(
        "refused-client-not-json",
        input(CLIENT, &raw("{\"version\":2,")),
    );
    add("refused-client-empty-frame", input(CLIENT, &[0; 4]));
    add(
        "refused-client-frame-beyond-limit",
        input(CLIENT, &((MAX_FRAME_BYTES + 1) as u32).to_be_bytes()),
    );
    let whole = answer(&active);
    add(
        "refused-client-frame-cut",
        input(CLIENT, &whole[..whole.len() - 1]),
    );
    add("noise-client-active", input(CLIENT, &flipped(&whole, 40)));

    let inspect = Request {
        operation_id: [0x77; 16],
        expected: None,
        action: Action::Inspect,
        authorization: None,
    };
    let with = |mut request: Request, expected: &Record| {
        request.expected = Some(expected.clone());
        request
    };
    let claimed = record(CLAIMED);
    add(
        "valid-server-inspect",
        input(SERVER | ACTIVE, &request(&inspect)),
    );
    add(
        "valid-server-claim",
        input(SERVER, &request(&with(claim(), &released))),
    );
    add(
        "valid-server-claim-replayed",
        input(SERVER | CLAIMED, &request(&with(claim(), &released))),
    );
    add(
        "valid-server-activate",
        input(SERVER | CLAIMED, &request(&with(activate(), &claimed))),
    );
    add(
        "valid-server-claim-restore",
        input(
            SERVER | ADMIN | ACTIVE,
            &request(&with(claim_restore(), &active)),
        ),
    );
    add(
        "refused-server-claim-restore-by-writer",
        input(SERVER | ACTIVE, &request(&with(claim_restore(), &active))),
    );
    add(
        "refused-server-unlisted-certificate",
        input(SERVER | UNLISTED, &request(&inspect)),
    );
    let mut stale = with(activate(), &claimed);
    stale.operation_id = [0x14; 16];
    add(
        "refused-server-stale-predecessor",
        input(SERVER | ACTIVE, &request(&stale)),
    );
    let mut reused = with(activate(), &claimed);
    reused.operation_id = [0x11; 16];
    add(
        "refused-server-operation-reused",
        input(SERVER | CLAIMED, &request(&reused)),
    );
    let mut unauthorized = with(activate(), &claimed);
    unauthorized.authorization = Some(SessionAuthorization::from_bytes(ADMIN_SESSION));
    add(
        "refused-server-other-session",
        input(SERVER | CLAIMED, &request(&unauthorized)),
    );
    let inspect_json = serde_json::to_string(&WireRequest {
        version: WIRE_VERSION,
        id: ID,
        request: &inspect,
    })
    .expect("JSON");
    add(
        "refused-server-other-version",
        input(
            SERVER,
            &raw(&inspect_json.replacen("\"version\":2", "\"version\":3", 1)),
        ),
    );
    add(
        "refused-server-unknown-envelope-field",
        input(
            SERVER,
            &raw(&inspect_json.replacen('{', "{\"extra\":1,", 1)),
        ),
    );
    add(
        "refused-server-unknown-action",
        input(
            SERVER,
            &raw(&inspect_json.replacen("\"inspect\"", "\"format\"", 1)),
        ),
    );
    add("refused-server-not-json", input(SERVER, &raw("[")));
    add("refused-server-empty-frame", input(SERVER, &[0; 4]));
    let whole = request(&with(claim(), &released));
    add(
        "refused-server-frame-cut",
        input(SERVER, &whole[..whole.len() / 2]),
    );
    add("noise-server-claim", input(SERVER, &flipped(&whole, 30)));
    seeds
}
