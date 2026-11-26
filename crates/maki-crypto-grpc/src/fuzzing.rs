//! The fuzz harness's way into the gRPC provider's reading of a response
//! (`fuzz/harness`, target `grpc_response`). Built only with the `fuzzing`
//! feature, which only the harness enables: nothing here is part of the
//! provider.
//!
//! An input is one response, or a part of one. Its first byte selects the
//! part (modulo 3):
//!
//! - [`HEADERS`]: the initial headers. Two bytes give the HTTP status
//!   (100 to 599), the rest are header lines (`name:value`). They go
//!   through `initial_headers`, and where they carry a trailers-only status,
//!   through tonic's own reading of it (`Status::from_header_map`) to
//!   `map_status`.
//! - [`BODY`]: the body. Records follow: a byte below 0x80 is a DATA frame
//!   of that many bytes, which follow it; any other ends the body with
//!   trailers, whose header lines are the rest of the input. The frames go
//!   through the provider's `BoundedResponseBody` (a message limit of
//!   [`LIMIT`] bytes) as tonic polls it; the one message it passed is
//!   decoded as the response to a request of [`UNITS`], and the trailers'
//!   status, as tonic reads it, goes to `map_status`.
//! - [`MESSAGE`]: one message's protobuf bytes, after a byte that gives the
//!   number of items requested (one to four, units 30 upwards), through
//!   `decode_response` and the echo check (`echoed`).

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use http_body::Body as _;
use maki_crypto::{CryptoError, SecretBuffer};
use prost::Message as _;
use tonic::codegen::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use tonic::codegen::Bytes;

use crate::protected::{WireItem, WireResponse};
use crate::{
    decode_response, echoed, initial_headers, map_status, BoundedResponseBody,
    ReceiveContractError, ResponseFraming,
};

pub const HEADERS: u8 = 0;
pub const BODY: u8 = 1;
pub const MESSAGE: u8 = 2;
/// The largest message the target's provider accepts.
pub const LIMIT: usize = 256;
/// The units of the request a body answers.
pub const UNITS: [u64; 2] = [30, 31];

/// Read the part of a response `data` selects, and return whether the
/// provider accepted it: headers after which it reads the body, a body of
/// one message with OK trailers whose items answer the request, a message
/// whose items do. Panics where a status is classified from anything but
/// its code and the allowlisted metadata, or where the body passes on what
/// its framing refused.
pub fn response(data: &[u8]) -> bool {
    let Some((&selector, rest)) = data.split_first() else {
        return false;
    };
    match selector % 3 {
        HEADERS => headers(rest),
        BODY => body(rest),
        _ => {
            let Some((&count, message)) = rest.split_first() else {
                return false;
            };
            let expected: Vec<u64> = (0..1 + u64::from(count % 4)).map(|i| 30 + i).collect();
            items(message, &expected).is_some()
        }
    }
}

/// Header lines as `name:value`; lines that are not a header are skipped.
fn header_map(lines: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in lines.split(|byte| *byte == b'\n') {
        let Some(at) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(&line[..at]),
            HeaderValue::from_bytes(&line[at + 1..]),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

/// The error a status read from `headers` maps to, checked against what
/// the headers allow.
fn classified(headers: &HeaderMap) -> Option<CryptoError> {
    let status = tonic::Status::from_header_map(headers)?;
    let error = map_status(&status);
    let reasons: Vec<&[u8]> = headers
        .get_all("maki-crypto-error")
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    if matches!(
        error,
        CryptoError::Integrity(_) | CryptoError::UnsupportedContext(_)
    ) {
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(
            matches!(
                reasons.as_slice(),
                [b"auth-tag-mismatch"
                    | b"context-mismatch"
                    | b"unsupported-format-version"
                    | b"unsupported-compatibility-id"]
            ),
            "a refusal read from {reasons:?}"
        );
    }
    // Nothing a peer sends carries the provider's own provenance.
    assert!(
        !matches!(error, CryptoError::Contract(_)),
        "a remote status read as a local contract violation"
    );
    Some(error)
}

fn headers(data: &[u8]) -> bool {
    let [high, low, lines @ ..] = data else {
        return false;
    };
    let status = StatusCode::from_u16(100 + u16::from_be_bytes([*high, *low]) % 500)
        .expect("a three-digit status");
    let mut headers = header_map(lines);
    match initial_headers(status, &mut headers) {
        Ok(()) => {
            assert!(headers.get("grpc-message").is_none());
            assert!(headers.get("grpc-status-details-bin").is_none());
            // A trailers-only answer: tonic reads its status from these
            // headers, and it is never a success.
            if let Some(error) = classified(&headers) {
                drop(error);
                assert_ne!(headers["grpc-status"], "0");
            }
            true
        }
        Err(status) => {
            drop(status);
            false
        }
    }
}

/// A body's frames, delivered as they arrived.
struct Frames(VecDeque<http_body::Frame<Bytes>>);

impl http_body::Body for Frames {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }
}

fn body(mut data: &[u8]) -> bool {
    let mut frames = VecDeque::new();
    while let Some((&tag, rest)) = data.split_first() {
        if tag >= 0x80 {
            frames.push_back(http_body::Frame::trailers(header_map(rest)));
            break;
        }
        let (chunk, rest) = rest.split_at(usize::from(tag).min(rest.len()));
        frames.push_back(http_body::Frame::data(Bytes::copy_from_slice(chunk)));
        data = rest;
    }
    let mut body = BoundedResponseBody {
        inner: tonic::body::Body::new(Frames(frames)),
        framing: ResponseFraming::new(LIMIT),
        finished: false,
    };
    let mut context = Context::from_waker(Waker::noop());
    let mut message = Vec::new();
    let mut trailers = None;
    let mut refused = false;
    loop {
        let frame = match Pin::new(&mut body).poll_frame(&mut context) {
            Poll::Ready(frame) => frame,
            Poll::Pending => panic!("a body of ready frames is pending"),
        };
        match frame {
            None => break,
            Some(Err(status)) => {
                assert!(
                    std::error::Error::source(&status)
                        .is_some_and(|source| source.is::<ReceiveContractError>()),
                    "a refusal without the provider's own provenance: {status:?}"
                );
                assert!(matches!(map_status(&status), CryptoError::Contract(_)));
                refused = true;
            }
            Some(Ok(frame)) => {
                assert!(!refused, "a frame after the body refused");
                match frame.into_data() {
                    Ok(data) => message.extend_from_slice(&data),
                    Err(frame) => {
                        let found = frame.into_trailers().expect("data or trailers");
                        assert!(trailers.replace(found).is_none(), "trailers twice");
                    }
                }
            }
        }
        if refused || trailers.is_some() {
            assert!(body.is_end_stream(), "a finished body that does not say so");
        }
    }
    if refused {
        return false;
    }
    // The body passed trailers only after exactly one whole message within
    // the limit, or none.
    let trailers = trailers.expect("a body that ends passes its trailers or refuses");
    assert!(trailers.get("grpc-message").is_none());
    assert!(trailers.get("grpc-status-details-bin").is_none());
    let error = classified(&trailers).expect("passed trailers carry a status");
    let ok = trailers["grpc-status"] == "0";
    if message.is_empty() {
        assert!(!ok, "a success without a message");
        drop(error);
        return false;
    }
    assert_eq!(message[0], 0, "a compressed message");
    let length = u32::from_be_bytes(message[1..5].try_into().expect("a message header")) as usize;
    assert!(length <= LIMIT, "a message of {length} bytes passed");
    assert_eq!(message.len(), 5 + length, "more than one message passed");
    drop(error);
    ok && items(&message[5..], &UNITS).is_some()
}

/// The items of one message as the provider reads them for a request of
/// `expected` units.
fn items(message: &[u8], expected: &[u64]) -> Option<Vec<WireItem>> {
    let response = match decode_response(message, expected.len()) {
        Ok(response) => response,
        Err(status) => {
            assert!(matches!(map_status(&status), CryptoError::Contract(_)));
            return None;
        }
    };
    assert!(
        response.items.len() <= expected.len(),
        "an extra item decoded"
    );
    let again = response.encode_to_vec();
    let back = decode_response(again.as_slice(), expected.len())
        .expect("a decoded response decodes again");
    assert_eq!(back, response, "a response changed in a round trip");
    let items = echoed(response.items, expected).ok()?;
    for (item, unit) in items.iter().zip(expected) {
        assert_eq!(item.unit_index, *unit);
    }
    Some(items)
}

fn item(unit: u64, data: &[u8]) -> WireItem {
    WireItem {
        unit_index: unit,
        data: SecretBuffer::from_slice(data),
    }
}

fn message(items: Vec<WireItem>) -> Vec<u8> {
    WireResponse { items }.encode_to_vec()
}

/// A message as a gRPC body frames it.
fn framed(message: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&(message.len() as u32).to_be_bytes());
    bytes.extend_from_slice(message);
    bytes
}

/// `bytes` as DATA records of at most `chunk` bytes.
fn data(bytes: &[u8], chunk: usize) -> Vec<u8> {
    let mut records = Vec::new();
    for part in bytes.chunks(chunk) {
        records.push(part.len() as u8);
        records.extend_from_slice(part);
    }
    records
}

fn trailers(lines: &str) -> Vec<u8> {
    [&[0xff][..], lines.as_bytes()].concat()
}

/// `selector` followed by `parts`.
fn input(selector: u8, parts: &[&[u8]]) -> Vec<u8> {
    [&[selector][..], &parts.concat()].concat()
}

/// The committed seeds of `grpc_response`: what a server that speaks the
/// documented contract sends, through tonic's framing, and the shapes the
/// provider must refuse. A seed's name says what [`response`] returns for
/// it (`valid-` true, `refused-` false, `noise-` either).
pub fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>| seeds.push((name.to_string(), bytes));
    let payload = |i: u8| -> Vec<u8> { (0..32).map(|b| b ^ i).collect() };
    let status = |code: u16, lines: &str| -> Vec<u8> {
        input(HEADERS, &[&(code - 100).to_be_bytes(), lines.as_bytes()])
    };
    add(
        "valid-headers",
        status(200, "content-type:application/grpc"),
    );
    add(
        "valid-headers-trailers-only-error",
        status(
            200,
            "content-type:application/grpc\ngrpc-status:14\ngrpc-message:upstream%20down",
        ),
    );
    add(
        "valid-headers-integrity",
        status(
            200,
            "grpc-status:9\nmaki-crypto-error:auth-tag-mismatch\ngrpc-status-details-bin:!!",
        ),
    );
    add(
        "refused-headers-initial-success",
        status(200, "content-type:application/grpc\ngrpc-status:0"),
    );
    add(
        "refused-headers-two-statuses",
        status(200, "grpc-status:14\ngrpc-status:0"),
    );
    add(
        "refused-headers-invalid-status",
        status(200, "grpc-status:017"),
    );
    add(
        "refused-headers-intermediary",
        status(502, "content-type:text/html"),
    );
    add(
        "valid-headers-error-on-http-error",
        status(503, "grpc-status:8"),
    );

    let two = message(vec![item(30, &payload(1)), item(31, &payload(2))]);
    let ok = trailers("grpc-status:0");
    add("valid-body", input(BODY, &[&data(&framed(&two), 100), &ok]));
    add(
        "valid-body-split-header",
        input(BODY, &[&data(&framed(&two), 3), &ok]),
    );
    add(
        "valid-body-unknown-field-and-status-text",
        input(
            BODY,
            &[
                &data(
                    &framed(
                        &[
                            two.clone(),
                            vec![0x22, 3, b'a', b'b', b'c'],
                            vec![0x28, 0x05],
                        ]
                        .concat(),
                    ),
                    64,
                ),
                &trailers("grpc-status:0\ngrpc-message:%ff\ngrpc-status-details-bin:not base64!"),
            ],
        ),
    );
    add(
        "refused-body-error-status",
        input(
            BODY,
            &[
                &data(&framed(&two), 100),
                &trailers("grpc-status:9\nmaki-crypto-error:context-mismatch"),
            ],
        ),
    );
    add(
        "refused-body-two-messages",
        input(
            BODY,
            &[&data(&[framed(&two), framed(&two)].concat(), 100), &ok],
        ),
    );
    add(
        "refused-body-ends-inside-message",
        input(BODY, &[&data(&framed(&two)[..20], 100), &ok]),
    );
    add(
        "refused-body-without-trailers",
        input(BODY, &[&data(&framed(&two), 100)]),
    );
    add("refused-body-success-without-message", input(BODY, &[&ok]));
    add(
        "refused-body-compressed",
        input(
            BODY,
            &[&data(&[&[1][..], &framed(&two)[1..]].concat(), 100), &ok],
        ),
    );
    add(
        "refused-body-beyond-limit",
        input(
            BODY,
            &[
                &data(&framed(&message(vec![item(30, &[7; LIMIT])])), 100),
                &ok,
            ],
        ),
    );
    add(
        "refused-body-missing-status",
        input(BODY, &[&data(&framed(&two), 100), &trailers("x-other:1")]),
    );
    add(
        "refused-body-items-swapped",
        input(
            BODY,
            &[
                &data(
                    &framed(&message(vec![item(31, &payload(1)), item(30, &payload(2))])),
                    100,
                ),
                &ok,
            ],
        ),
    );

    let count = |n: u8| [n - 1];
    let units =
        |n: u64| -> Vec<WireItem> { (0..n).map(|i| item(30 + i, &payload(i as u8))).collect() };
    add(
        "valid-message-one",
        input(MESSAGE, &[&count(1), &message(units(1))]),
    );
    add(
        "valid-message-four",
        input(MESSAGE, &[&count(4), &message(units(4))]),
    );
    add(
        "valid-message-empty-payload",
        input(MESSAGE, &[&count(1), &message(vec![item(30, &[])])]),
    );
    add(
        "refused-message-fewer-items",
        input(MESSAGE, &[&count(3), &message(units(2))]),
    );
    add(
        "refused-message-extra-item",
        input(MESSAGE, &[&count(2), &message(units(3))]),
    );
    add(
        "refused-message-wrong-unit",
        input(MESSAGE, &[&count(1), &message(vec![item(29, &payload(0))])]),
    );
    let whole = message(units(2));
    add(
        "refused-message-cut",
        input(MESSAGE, &[&count(2), &whole[..whole.len() - 3]]),
    );
    add(
        "refused-message-length-beyond-message",
        input(
            MESSAGE,
            &[&count(1), &[0x0a, 0x10, 0x08, 0x1e, 0x12, 0x7f, 0x00]],
        ),
    );
    add(
        "refused-message-invalid-wire-type",
        input(MESSAGE, &[&count(1), &[0x0f, 0x00]]),
    );
    let mut noise = whole.clone();
    noise[3] ^= 0x40;
    add("noise-message-two", input(MESSAGE, &[&count(2), &noise]));
    seeds
}
