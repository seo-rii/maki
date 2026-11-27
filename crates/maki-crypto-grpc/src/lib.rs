//! `maki-crypto-grpc` — gRPC remote crypto transport (SPEC §18, §51).
//!
//! Message shapes are fixed (see `packaging/examples/maki-crypto.proto`);
//! method paths and metadata are runtime-configurable, so a vendor service
//! only needs to speak the documented contract at any package/service name.
//! Responses echo `unit_index`, giving native reorder detection. Message
//! sizes are bounded in both directions. Dynamic descriptor loading
//! (arbitrary message shapes) is not supported; see docs/configuration.md.
//!
//! An error is classified by its status code ([`map_status`]). An integrity
//! failure or a context refusal additionally needs exactly one
//! `maki-crypto-error` metadata value on `FailedPrecondition`:
//! `auth-tag-mismatch` or `context-mismatch`, or
//! `unsupported-format-version` or `unsupported-compatibility-id`. Remote
//! status text and details are never read. A status tonic made locally from
//! a TLS failure (its source holds a rustls error, as after a failed
//! reconnect inside a cached channel) is an endpoint failure whatever its
//! code. Nothing a peer sends can put one there: a status decoded from its
//! trailers has no source, and the chain of one made from an HTTP/2 reset
//! or GOAWAY ends in an `h2::Error`, which has no source of its own.
//!
//! The provider's private wire items erase their owned data on drop and field
//! replacement. This does not erase tonic's separate codec or HTTP/TLS buffers.

// Diagnostics go through `tracing`: the `print!` family panics when the
// write fails (a closed pipe, a full disk). Tests may print.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use prost::Message as _;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::metadata::{MetadataKey, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig, Identity};
use zeroize::Zeroize;

use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer,
};
// Validation and the provider share one method-path rule, so a validated
// path is exactly the one sent.
use maki_format::config::{check_grpc_metadata_keys, grpc_request_path};

mod connection;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
mod protected;
use connection::ConnectionCache;
use protected::{ResponseDecodeError, WireItem, WireRequest, WireResponse};

#[cfg(test)]
mod protected_tests;
#[cfg(test)]
mod tls_tests;
// A loopback address that never answers needs Linux: a listener whose
// accept queue is full drops the SYNs sent to it.
#[cfg(all(test, target_os = "linux"))]
mod connect_tests;

/// The TCP connector's name resolution: the system's. Tests substitute
/// [`test_resolver::TestResolver`], which resolves to addresses of their
/// own.
#[cfg(not(test))]
type Resolver = hyper_util::client::legacy::connect::dns::GaiResolver;
#[cfg(test)]
type Resolver = test_resolver::TestResolver;
#[cfg(test)]
mod test_resolver;

// ---------------------------------------------------------------- messages

/// One crypto unit on the wire.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CryptoItem {
    #[prost(uint64, tag = "1")]
    pub unit_index: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CryptoBatchRequest {
    #[prost(string, tag = "1")]
    pub volume_id: String,
    #[prost(string, tag = "2")]
    pub compatibility_id: String,
    #[prost(message, repeated, tag = "3")]
    pub items: Vec<CryptoItem>,
    /// The volume's on-disk format version: part of the crypto context a
    /// context-binding provider must tie ciphertext to (R3-006).
    #[prost(uint32, tag = "4")]
    pub format_version: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CryptoBatchResponse {
    #[prost(message, repeated, tag = "1")]
    pub items: Vec<CryptoItem>,
}

// ---------------------------------------------------------------- mapping

/// gRPC status → Maki error class (SPEC §31, §51 "status mapping").
pub fn map_status(status: &tonic::Status) -> CryptoError {
    use tonic::Code;
    // Local receive failures never crossed the wire. Only our private typed
    // source establishes that provenance; remote status text or metadata
    // cannot impersonate it (BUG-057).
    if let Some(local) = std::error::Error::source(status)
        .and_then(|source| source.downcast_ref::<ReceiveContractError>())
    {
        return CryptoError::Contract(local.0.into());
    }
    // tonic also dials inside an established channel: after the connection
    // under it closes, the next call reconnects, and a handshake that fails
    // there (a server restarted with a certificate this client does not
    // trust) reaches the call as a status with the transport error as its
    // source. Like a failed connection attempt it is an endpoint failure.
    // Nothing a peer sends can claim one: a status decoded from trailers has
    // no source, and the source chain of one made from an HTTP/2 reset or
    // GOAWAY ends in an `h2::Error`, which has no source of its own (h2
    // keeps an I/O error only as its kind and text). The same is why a TLS 1.3 server's
    // refusal of the client certificate, which also arrives inside the
    // call, is decided by its status's code.
    if let Some(error) = local_tls_failure(status) {
        return error;
    }
    // FailedPrecondition alone is a request error. Integrity additionally
    // requires exactly one allowlisted ASCII metadata value, never free text.
    if status.code() == Code::FailedPrecondition {
        let mut reasons = status.metadata().get_all("maki-crypto-error").iter();
        if let (Some(reason), None) = (reasons.next(), reasons.next()) {
            let error = match reason.as_encoded_bytes() {
                b"auth-tag-mismatch" => Some(CryptoError::Integrity(
                    "remote crypto provider rejected the authentication tag".into(),
                )),
                b"context-mismatch" => Some(CryptoError::Integrity(
                    "remote crypto provider rejected the crypto context".into(),
                )),
                b"unsupported-format-version" => Some(CryptoError::UnsupportedContext(
                    maki_crypto::ContextField::FormatVersion,
                )),
                b"unsupported-compatibility-id" => Some(CryptoError::UnsupportedContext(
                    maki_crypto::ContextField::CompatibilityId,
                )),
                _ => None,
            };
            if let Some(error) = error {
                return error;
            }
        }
    }
    // The remote status *text* is untrusted and may reflect secrets or inject
    // log lines: it is dropped entirely. Only the allowlisted gRPC code (an
    // enum, not free text) carries into the error and the logs (MAKI-016 /
    // FUP-006). The status code still drives the class mapping below.
    let message = format!(
        "grpc status {:?} from remote crypto provider",
        status.code()
    );
    match status.code() {
        Code::ResourceExhausted => CryptoError::Throttled(message),
        Code::Unavailable | Code::DeadlineExceeded | Code::Aborted | Code::Internal => {
            CryptoError::Retryable(message)
        }
        Code::Unauthenticated | Code::PermissionDenied => CryptoError::EndpointFatal(message),
        Code::InvalidArgument | Code::NotFound | Code::OutOfRange | Code::FailedPrecondition => {
            CryptoError::NonRetryableRequest(message)
        }
        Code::Unimplemented => CryptoError::EndpointFatal(message),
        _ => CryptoError::Retryable(message),
    }
}

/// The endpoint failure for a status whose source chain holds a rustls
/// error: one tonic made locally from a TLS failure of the connection.
fn local_tls_failure(status: &tonic::Status) -> Option<CryptoError> {
    std::error::Error::source(status).and_then(connection::tls_failure)
}

/// Convenience for tests/docs: class of a mapped code.
pub fn class_of_code(code: tonic::Code) -> ErrorClass {
    map_status(&tonic::Status::new(code, "x")).class()
}

// Tonic rejects oversized gRPC frames before calling the protobuf decoder,
// using the same OutOfRange code a server can legitimately return for a bad
// request, and its unary helper discards any extra messages while draining
// trailers. Observe framing before tonic consumes the body, so local size,
// truncation and unary cardinality errors have a private, unforgeable source.
// The payload stays in tonic's existing erased Bytes allocation and both
// tonic size limits remain enabled.
#[derive(Debug)]
struct ReceiveContractError(&'static str);

impl std::fmt::Display for ReceiveContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ReceiveContractError {}

fn receive_contract_status(message: &'static str) -> tonic::Status {
    let mut status = tonic::Status::internal(message);
    status.set_source(Arc::new(ReceiveContractError(message)));
    status
}

struct ResponseFraming {
    header: [u8; 5],
    header_bytes: usize,
    remaining: usize,
    limit: usize,
    /// Messages received completely.
    messages: usize,
}

impl ResponseFraming {
    fn new(limit: usize) -> Self {
        Self {
            header: [0; 5],
            header_bytes: 0,
            remaining: 0,
            limit,
            messages: 0,
        }
    }

    /// A length prefix or message body is still incomplete.
    fn inside_message(&self) -> bool {
        self.header_bytes > 0 || self.remaining > 0
    }

    fn observe(&mut self, mut bytes: &[u8]) -> Result<(), &'static str> {
        while !bytes.is_empty() {
            if self.remaining > 0 {
                let consumed = self.remaining.min(bytes.len());
                self.remaining -= consumed;
                bytes = &bytes[consumed..];
                if self.remaining == 0 {
                    self.messages += 1;
                }
                continue;
            }
            // There must be exactly one message in a successful unary
            // response. Reject even a partial second header instead of
            // allowing tonic's trailers() drain to discard another result.
            if self.messages > 0 {
                return Err("grpc unary response contains more than one message");
            }
            let consumed = (self.header.len() - self.header_bytes).min(bytes.len());
            self.header[self.header_bytes..self.header_bytes + consumed]
                .copy_from_slice(&bytes[..consumed]);
            self.header_bytes += consumed;
            bytes = &bytes[consumed..];
            if self.header_bytes == self.header.len() {
                // This provider does not enable response compression.
                if self.header[0] != 0 {
                    return Err("grpc response has an unsupported compression flag");
                }
                let length = u32::from_be_bytes(self.header[1..].try_into().unwrap()) as usize;
                if length > self.limit {
                    return Err("grpc response exceeds the message-size limit");
                }
                self.remaining = length;
                self.header_bytes = 0;
                if length == 0 {
                    self.messages += 1;
                }
            }
        }
        Ok(())
    }
}

struct BoundedResponseBody {
    inner: tonic::body::Body,
    framing: ResponseFraming,
    finished: bool,
}

/// Tonic reads the first status value. Reject ambiguous or malformed metadata
/// before that selection can hide a conflicting result (BUG-178).
fn response_status(
    headers: &tonic::codegen::http::HeaderMap,
) -> Result<Option<bool>, &'static str> {
    let mut statuses = headers.get_all("grpc-status").iter();
    let Some(status) = statuses.next() else {
        return Ok(None);
    };
    if statuses.next().is_some() {
        return Err("grpc response contains duplicate status values");
    }
    match status.as_bytes() {
        b"0" => Ok(Some(true)),
        b"1" | b"2" | b"3" | b"4" | b"5" | b"6" | b"7" | b"8" | b"9" | b"10" | b"11" | b"12"
        | b"13" | b"14" | b"15" | b"16" => Ok(Some(false)),
        _ => Err("grpc response contains an invalid status value"),
    }
}

/// Remote status text and details are ignored (SPEC §18), but tonic parses
/// both when it reads a status from these headers: it panics on details that
/// are not base64, and it replaces the code with `Unknown` when the message
/// does not percent-decode to UTF-8. Either would let peer bytes crash the
/// call or change its class. Remove both first, so the class follows only the
/// validated `grpc-status` value and the allowlisted metadata.
fn discard_remote_status_text(headers: &mut tonic::codegen::http::HeaderMap) {
    headers.remove("grpc-message");
    headers.remove("grpc-status-details-bin");
}

impl http_body::Body for BoundedResponseBody {
    type Data = tonic::codegen::Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        let mut frame = std::task::ready!(Pin::new(&mut self.inner).poll_frame(cx));
        // A response that ends inside a message, or reports success without
        // one, broke the receive contract; tonic would surface either as a
        // local `Internal` status, which maps to Retryable (BUG-121).
        let violation = match &mut frame {
            Some(Ok(frame)) => {
                if let Some(bytes) = frame.data_ref() {
                    self.framing.observe(bytes).err()
                } else if let Some(trailers) = frame.trailers_mut() {
                    discard_remote_status_text(trailers);
                    self.finished = true;
                    if self.framing.inside_message() {
                        Some("grpc response ended inside a message")
                    } else {
                        match response_status(trailers) {
                            Err(message) => Some(message),
                            Ok(None) => Some("grpc response is missing its final status"),
                            Ok(Some(true)) if self.framing.messages == 0 => {
                                Some("grpc response reported success without a message")
                            }
                            Ok(Some(_)) => None,
                        }
                    }
                } else {
                    None
                }
            }
            None if self.framing.inside_message() => Some("grpc response ended inside a message"),
            None => Some("grpc response is missing its final status"),
            _ => None,
        };
        if let Some(message) = violation {
            self.finished = true;
            return Poll::Ready(Some(Err(receive_contract_status(message))));
        }
        if matches!(frame, Some(Err(_))) {
            self.finished = true;
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        // An underlying DATA END_STREAM still needs one poll to reject its
        // missing status. Reporting it as ended lets tonic erase that check.
        self.finished
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// gRPC's HTTP-to-status table for a response that carries no gRPC status
/// (`doc/http-grpc-status-mapping.md`; tonic applies the same table only
/// when such a body ends without framing).
fn status_from_http(status: tonic::codegen::http::StatusCode) -> tonic::Status {
    use tonic::codegen::http::StatusCode;
    use tonic::Code;
    let code = match status {
        StatusCode::BAD_REQUEST => Code::Internal,
        StatusCode::UNAUTHORIZED => Code::Unauthenticated,
        StatusCode::FORBIDDEN => Code::PermissionDenied,
        StatusCode::NOT_FOUND => Code::Unimplemented,
        StatusCode::TOO_MANY_REQUESTS
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::GATEWAY_TIMEOUT => Code::Unavailable,
        _ => Code::Unknown,
    };
    tonic::Status::new(
        code,
        format!(
            "grpc-status missing; mapped from HTTP status {}",
            status.as_u16()
        ),
    )
}

struct BoundedResponseChannel {
    inner: Channel,
    limit: usize,
}

impl tonic::codegen::Service<tonic::codegen::http::Request<tonic::body::Body>>
    for BoundedResponseChannel
{
    type Response = tonic::codegen::http::Response<BoundedResponseBody>;
    type Error = tonic::codegen::StdError;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        tonic::codegen::Service::poll_ready(&mut self.inner, cx).map_err(Into::into)
    }

    fn call(&mut self, request: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
        let response = tonic::codegen::Service::call(&mut self.inner, request);
        let limit = self.limit;
        Box::pin(async move {
            let mut response = response.await?;
            let status = response.status();
            initial_headers(status, response.headers_mut())?;
            Ok(response.map(|inner| BoundedResponseBody {
                inner,
                framing: ResponseFraming::new(limit),
                finished: false,
            }))
        })
    }
}

/// The initial headers of a response, before its body is read: refused, or
/// mapped to the status of an intermediary's answer, or the body may follow.
#[allow(clippy::result_large_err)] // the status tonic's service and codec traits return
fn initial_headers(
    status: tonic::codegen::http::StatusCode,
    headers: &mut tonic::codegen::http::HeaderMap,
) -> Result<(), tonic::Status> {
    // Tonic reads a trailers-only status from these headers.
    discard_remote_status_text(headers);
    // A successful unary response needs a message followed by OK
    // trailers. Initial status belongs to a trailers-only error.
    // Tonic treats initial OK as an empty response and skips later
    // status checks, accepting data even after an error trailer.
    // Reject before its decoder sees the headers, including an
    // already-ended body that would never reach our framing checks.
    let initial_status = response_status(headers).map_err(receive_contract_status)?;
    if initial_status == Some(true) {
        return Err(receive_contract_status(
            "grpc unary response reported success in initial headers",
        ));
    }
    // A non-200 response without a gRPC status comes from an
    // intermediary (a proxy's 502 page during an upstream restart),
    // not from the gRPC peer: its body is not gRPC framing, and
    // framing it would turn a transient outage into a contract
    // violation (BUG-175). Map the HTTP status instead.
    if status != tonic::codegen::http::StatusCode::OK && !headers.contains_key("grpc-status") {
        return Err(status_from_http(status));
    }
    Ok(())
}

struct ResponseCodec {
    inner: tonic::codec::ProstCodec<WireRequest, WireResponse>,
    /// Items in the request; a response with more is refused while decoding.
    requested: usize,
}

struct ResponseDecoder {
    inner: <tonic::codec::ProstCodec<WireRequest, WireResponse> as tonic::codec::Codec>::Decoder,
    requested: usize,
}

impl tonic::codec::Codec for ResponseCodec {
    type Encode = WireRequest;
    type Decode = WireResponse;
    type Encoder =
        <tonic::codec::ProstCodec<WireRequest, WireResponse> as tonic::codec::Codec>::Encoder;
    type Decoder = ResponseDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        self.inner.encoder()
    }

    fn decoder(&mut self) -> Self::Decoder {
        ResponseDecoder {
            inner: self.inner.decoder(),
            requested: self.requested,
        }
    }
}

impl tonic::codec::Decoder for ResponseDecoder {
    type Item = WireResponse;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        source: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        decode_response(source, self.requested).map(Some)
    }

    fn buffer_settings(&self) -> tonic::codec::BufferSettings {
        self.inner.buffer_settings()
    }
}

/// The response message to a request of `requested` items.
#[allow(clippy::result_large_err)] // the status tonic's service and codec traits return
fn decode_response(
    source: impl prost::bytes::Buf,
    requested: usize,
) -> Result<WireResponse, tonic::Status> {
    WireResponse::decode_bounded(source, requested).map_err(|error| {
        receive_contract_status(match error {
            ResponseDecodeError::ExtraItem => "grpc response has more items than the request",
            ResponseDecodeError::Malformed => "grpc response protobuf decoding failed",
        })
    })
}

#[cfg(test)]
mod receive_contract_tests {
    use super::{BoundedResponseBody, ResponseFraming};
    use http_body::Body;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tonic::codegen::Bytes;

    #[test]
    fn size_check_handles_every_header_split_and_exact_limit() {
        for split in 0..=5 {
            let header = [0, 0, 0, 4, 1]; // 1025 bytes.
            let mut framing = ResponseFraming::new(1024);
            let first = framing.observe(&header[..split]);
            if split == 5 {
                assert!(first.is_err());
            } else {
                first.unwrap();
                assert!(framing.observe(&header[split..]).is_err());
            }
            let mut framing = ResponseFraming::new(1024);
            let header = [0, 0, 0, 4, 0]; // Exactly 1024 bytes.
            framing.observe(&header[..split]).unwrap();
            framing.observe(&header[split..]).unwrap();
        }
    }

    #[test]
    fn payload_is_skipped_and_every_split_second_header_is_rejected() {
        for split in 1..=5 {
            let mut framing = ResponseFraming::new(8);
            framing.observe(&[0, 0, 0, 0, 8]).unwrap();
            framing.observe(&[255; 3]).unwrap();
            framing.observe(&[255; 5]).unwrap();
            framing.observe(&[]).unwrap();
            assert_eq!(
                framing.observe(&[0, 0, 0, 0, 8][..split]),
                Err("grpc unary response contains more than one message")
            );
        }
    }

    #[test]
    fn a_zero_length_message_still_uses_the_one_unary_message() {
        let mut framing = ResponseFraming::new(8);
        framing.observe(&[0, 0, 0, 0, 0]).unwrap();
        assert_eq!(framing.messages, 1);
        assert!(framing.observe(&[0]).is_err());
    }

    #[test]
    fn unsupported_compression_is_also_local_receive_provenance() {
        for flag in [1, 2, 255] {
            assert!(ResponseFraming::new(8)
                .observe(&[flag, 0, 0, 0, 1])
                .is_err());
        }
    }

    struct Frames {
        frames: VecDeque<http_body::Frame<Bytes>>,
        dropped: super::Arc<AtomicBool>,
    }

    impl Drop for Frames {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl Body for Frames {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: super::Pin<&mut Self>,
            _: &mut super::Context<'_>,
        ) -> super::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            super::Poll::Ready(self.frames.pop_front().map(Ok))
        }
    }

    #[tokio::test]
    async fn split_frames_and_remote_trailers_pass_through_without_reclassification() {
        let mut trailers = tonic::codegen::http::HeaderMap::new();
        trailers.insert("grpc-status", "11".parse().unwrap());
        let dropped = super::Arc::new(AtomicBool::new(false));
        let frames = Frames {
            frames: VecDeque::from([
                http_body::Frame::data(Bytes::from_static(&[0, 0])),
                http_body::Frame::data(Bytes::from_static(&[0, 0, 1])),
                http_body::Frame::data(Bytes::from_static(&[0x11])),
                http_body::Frame::trailers(trailers),
            ]),
            dropped: dropped.clone(),
        };
        let mut body = BoundedResponseBody {
            inner: tonic::body::Body::new(frames),
            framing: ResponseFraming::new(1),
            finished: false,
        };
        for _ in 0..3 {
            let frame = std::future::poll_fn(|cx| super::Pin::new(&mut body).poll_frame(cx))
                .await
                .unwrap()
                .unwrap();
            assert!(frame.is_data());
        }
        let frame = std::future::poll_fn(|cx| super::Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.trailers_ref().unwrap()["grpc-status"], "11");
        drop(body);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancelling_an_incomplete_frame_drops_its_transport_body() {
        let dropped = super::Arc::new(AtomicBool::new(false));
        let frames = Frames {
            frames: VecDeque::from([http_body::Frame::data(Bytes::from_static(&[0, 0]))]),
            dropped: dropped.clone(),
        };
        let mut body = BoundedResponseBody {
            inner: tonic::body::Body::new(frames),
            framing: ResponseFraming::new(1),
            finished: false,
        };
        std::future::poll_fn(|cx| super::Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        drop(body);
        assert!(dropped.load(Ordering::SeqCst));
    }
}

// ---------------------------------------------------------------- provider

/// A connection attempt, TLS handshake included, is abandoned after this
/// many RPC timeouts (BUG-115).
const CONNECT_BOUND_RPC_TIMEOUTS: u32 = 4;

pub struct GrpcProviderSpec {
    /// e.g. `http://crypto.internal:7000` (or https with TLS config).
    pub url: String,
    /// e.g. `/maki.CryptoService/EncryptBatch`.
    pub encrypt_path: String,
    pub decrypt_path: String,
    /// Static metadata (ascii key/value), e.g. resolved credentials.
    pub metadata: Vec<(String, String)>,
    pub capabilities: CryptoCapabilities,
    pub timeout: Duration,
    pub max_message_bytes: usize,
}

impl Drop for GrpcProviderSpec {
    fn drop(&mut self) {
        // Every endpoint clone owns a separate resolved credential. Erase
        // both normal provider lifetimes and specs rejected during setup.
        for (_, value) in &mut self.metadata {
            value.zeroize();
        }
    }
}

impl Clone for GrpcProviderSpec {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            encrypt_path: self.encrypt_path.clone(),
            decrypt_path: self.decrypt_path.clone(),
            metadata: self.metadata.clone(),
            capabilities: self.capabilities.clone(),
            timeout: self.timeout,
            max_message_bytes: self.max_message_bytes,
        }
    }
}

/// Client certificate and private key used for mutual TLS.
pub struct GrpcClientIdentity {
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: SecretBuffer,
}

impl Clone for GrpcClientIdentity {
    fn clone(&self) -> Self {
        Self {
            certificate_pem: self.certificate_pem.clone(),
            private_key_pem: self.private_key_pem.duplicate(),
        }
    }
}

impl std::fmt::Debug for GrpcClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcClientIdentity")
            .field("certificate_pem", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

/// Verified TLS configuration. The server is verified against the roots
/// every remote transport trusts: the host's trust store, the compiled-in
/// public roots and `ca_certificate_pem`, which adds to them and replaces
/// neither.
#[derive(Clone, Default)]
pub struct GrpcTlsConfig {
    pub ca_certificate_pem: Option<Vec<u8>>,
    pub client_identity: Option<GrpcClientIdentity>,
}

impl std::fmt::Debug for GrpcTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcTlsConfig")
            .field(
                "ca_certificate_pem",
                &self.ca_certificate_pem.as_ref().map(|_| "<redacted>"),
            )
            .field("client_identity", &self.client_identity)
            .finish()
    }
}

/// Endpoint/method paths and resolved metadata can carry credentials: never
/// printed (C-11, BUG-174). Metadata names stay visible for diagnostics.
impl std::fmt::Debug for GrpcProviderSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = self
            .metadata
            .iter()
            .map(|(k, _)| format!("{k}: <redacted>"))
            .collect();
        f.debug_struct("GrpcProviderSpec")
            .field("url", &"<redacted>")
            .field("encrypt_path", &"<redacted>")
            .field("decrypt_path", &"<redacted>")
            .field("metadata", &keys)
            .field("capabilities", &self.capabilities)
            .field("timeout", &self.timeout)
            .field("max_message_bytes", &self.max_message_bytes)
            .finish()
    }
}

pub struct GrpcCryptoProvider {
    spec: GrpcProviderSpec,
    connections: ConnectionCache,
    encrypt_path: PathAndQuery,
    decrypt_path: PathAndQuery,
}

fn fatal(msg: impl Into<String>) -> CryptoError {
    CryptoError::ProviderFatal(msg.into())
}

/// The roots this transport trusts: the host's trust store, the compiled-in
/// public roots and the configured CA, the same for every remote transport
/// (`maki_crypto::tls_trust`). Read once, when the provider is built.
fn trusted_roots(tls: &GrpcTlsConfig) -> Result<rustls::RootCertStore, CryptoError> {
    maki_crypto::tls_trust::trusted_roots(tls.ca_certificate_pem.as_deref())
        .map_err(|error| fatal(error.to_string()))
}

/// A URI host without the brackets that enclose an IPv6 literal.
fn unbracketed(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

fn is_loopback_host(host: &str) -> bool {
    let host = unbracketed(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

impl GrpcCryptoProvider {
    pub fn new(spec: GrpcProviderSpec) -> Result<Self, CryptoError> {
        Self::build(spec, None)
    }

    pub fn new_with_tls(spec: GrpcProviderSpec, tls: GrpcTlsConfig) -> Result<Self, CryptoError> {
        Self::build(spec, Some(tls))
    }

    fn build(spec: GrpcProviderSpec, tls: Option<GrpcTlsConfig>) -> Result<Self, CryptoError> {
        Self::build_resolving(spec, tls, Resolver::new())
    }

    /// `build`, with the TCP connector resolving names through `resolver`.
    fn build_resolving(
        spec: GrpcProviderSpec,
        tls: Option<GrpcTlsConfig>,
        resolver: Resolver,
    ) -> Result<Self, CryptoError> {
        let mut endpoint = Channel::from_shared(spec.url.clone())
            .map_err(|e| fatal(format!("bad endpoint url: {e}")))?;
        match (endpoint.uri().scheme_str(), tls) {
            (Some("http"), None) => {
                let host = endpoint
                    .uri()
                    .host()
                    .ok_or_else(|| fatal("gRPC endpoint URL has no host"))?;
                if !is_loopback_host(host) {
                    return Err(fatal(
                        "plaintext gRPC endpoints are permitted only on loopback",
                    ));
                }
            }
            (Some("http"), Some(_)) => {
                return Err(fatal(
                    "TLS configuration cannot be used with an http endpoint",
                ));
            }
            (Some("https"), None) => {
                return Err(fatal("https endpoint requires explicit TLS configuration"));
            }
            (Some("https"), Some(tls)) => {
                // tonic gets the roots as trust anchors. Its own native-root
                // loader refuses an empty host store, which made a configured
                // CA useless on such a host (BUG-097), and its webpki feature
                // pulls a second webpki-roots line. The compiled-in roots
                // make the set non-empty, so the provider is built whatever
                // the host's store holds, and an endpoint none of the roots
                // vouches for is refused at the handshake (EndpointFatal).
                let roots = trusted_roots(&tls)?;
                // Left unset, tonic takes the TLS server name from the URI
                // host, which keeps an IPv6 literal's brackets ("[::1]"):
                // neither a DNS name nor an IP address to rustls, so such an
                // endpoint could never be built. Name the bare host instead.
                // rustls verifies a literal as an IP-address server name
                // against the certificate's IP SANs, exactly as it already
                // did for IPv4; a DNS name is passed unchanged.
                let server_name = endpoint
                    .uri()
                    .host()
                    .map(unbracketed)
                    .ok_or_else(|| fatal("gRPC endpoint URL has no host"))?
                    .to_owned();
                let mut config = ClientTlsConfig::new()
                    .domain_name(server_name)
                    .trust_anchors(roots.roots);
                if let Some(identity) = tls.client_identity {
                    if identity.certificate_pem.is_empty() || identity.private_key_pem.is_empty() {
                        return Err(fatal(
                            "mTLS client certificate and private key must both be non-empty",
                        ));
                    }
                    config = config.identity(Identity::from_pem(
                        identity.certificate_pem,
                        identity.private_key_pem.expose(),
                    ));
                }
                endpoint = endpoint
                    .tls_config(config)
                    .map_err(|e| fatal(format!("invalid TLS configuration: {e}")))?;
            }
            (Some(scheme), _) => {
                return Err(fatal(format!(
                    "unsupported gRPC endpoint scheme {scheme:?}"
                )));
            }
            (None, _) => return Err(fatal("gRPC endpoint URL has no scheme")),
        }
        // An explicit connector bounds TLS as well as the TCP connect
        // (BUG-115). ConnectionCache establishes the channel without an RPC
        // body, so cancelling a handshake waiter erases its own payload
        // immediately rather than leaving it in tonic's background queue.
        // The bound is several RPC timeouts: a slow but working handshake
        // still completes in the background for the next RPC, as before.
        // The TCP connector is configured like tonic's own: hyper-util
        // divides its timeout among the resolved addresses of each family
        // and starts the other family 300 ms after the first, so an
        // unreachable first address (`localhost` as `::1` on Windows) leaves
        // time for the next (`connect_tests.rs`).
        let mut tcp =
            hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(resolver);
        tcp.enforce_http(false);
        tcp.set_nodelay(true);
        tcp.set_connect_timeout(Some(spec.timeout));
        let endpoint = endpoint
            .timeout(spec.timeout)
            .connect_timeout(spec.timeout.saturating_mul(CONNECT_BOUND_RPC_TIMEOUTS));
        let connections = ConnectionCache::new(
            endpoint,
            tcp,
            spec.timeout.saturating_mul(CONNECT_BOUND_RPC_TIMEOUTS),
        );
        let encrypt_path = grpc_request_path(&spec.url, &spec.encrypt_path)
            .map_err(|reason| fatal(format!("bad encrypt path: {reason}")))?;
        let decrypt_path = grpc_request_path(&spec.url, &spec.decrypt_path)
            .map_err(|reason| fatal(format!("bad decrypt path: {reason}")))?;
        // Validate metadata eagerly: a bad credential/config fails closed.
        check_grpc_metadata_keys(spec.metadata.iter().map(|(name, _)| name.as_str()))
            .map_err(|e| fatal(e.to_string()))?;
        for (key, value) in &spec.metadata {
            value
                .parse::<MetadataValue<tonic::metadata::Ascii>>()
                .map_err(|e| fatal(format!("bad metadata value for {key:?}: {e}")))?;
        }
        Ok(Self {
            connections,
            encrypt_path,
            decrypt_path,
            spec,
        })
    }

    async fn call(
        &self,
        path: PathAndQuery,
        context: &CryptoContext,
        items: Vec<WireItem>,
    ) -> Result<Vec<WireItem>, CryptoError> {
        let expected: Vec<u64> = items.iter().map(|i| i.unit_index).collect();
        let message = WireRequest {
            volume_id: context.volume_uuid.to_string(),
            compatibility_id: context.crypto_compatibility_id.clone(),
            items,
            format_version: context.format_version,
        };
        // Include context strings, nested lengths and varints in the local
        // bound. A rough payload estimate could reject a fitting request or
        // let the encoder report a local overflow as a retryable peer error.
        if message.encoded_len() > self.spec.max_message_bytes {
            return Err(CryptoError::NonRetryableRequest(format!(
                "request exceeds message-size limit {}",
                self.spec.max_message_bytes
            )));
        }

        let mut connection = self.connections.exchange();
        let mut request = tonic::Request::new(message);
        for (key, value) in &self.spec.metadata {
            let key = MetadataKey::<tonic::metadata::Ascii>::from_bytes(key.as_bytes())
                .expect("validated at construction");
            let value = value
                .parse::<MetadataValue<tonic::metadata::Ascii>>()
                .expect("validated at construction");
            request.metadata_mut().insert(key, value);
        }

        let codec = ResponseCodec {
            inner: Default::default(),
            requested: expected.len(),
        };

        // `Channel::timeout` bounds the connection, not the whole exchange:
        // a server that stalls after the response headers, or between the
        // message and the trailers, would hold this RPC open indefinitely,
        // pinning its inflight slot and blocking that request's retry and
        // failover (BUG-017). Bound readiness plus the unary call together
        // by the configured operation timeout. The `bounded-error` policy's
        // outer deadline (BUG-013) is separate and still applies.
        //
        // Until `handed_over` is set, the request is still owned here: the
        // connection is established without an RPC body, and readiness only
        // reserves capacity. A failure (or the timeout) before that point
        // proves that no byte of the request was sent; it is marked so the
        // dispatcher may send the request to a peer (SPEC §18).
        let handed_over = AtomicBool::new(false);
        // A TLS failure inside the call is an endpoint failure, but unlike a
        // completed error response it leaves no working connection: retire
        // the channel, so the next call reconnects through the payload-free
        // attempt above instead of tonic's own reconnect with its request
        // queued (see `preserve` below).
        let tls_failed = AtomicBool::new(false);
        let exchange = async {
            let channel = connection.channel().await?;
            let mut grpc = tonic::client::Grpc::new(BoundedResponseChannel {
                inner: channel,
                limit: self.spec.max_message_bytes,
            })
            .max_decoding_message_size(self.spec.max_message_bytes)
            .max_encoding_message_size(self.spec.max_message_bytes);
            grpc.ready()
                .await
                .map_err(|e| CryptoError::Retryable(format!("grpc endpoint not ready: {e}")))?;
            handed_over.store(true, Ordering::SeqCst);
            grpc.unary(request, path, codec).await.map_err(|status| {
                if local_tls_failure(&status).is_some() {
                    tls_failed.store(true, Ordering::SeqCst);
                }
                map_status(&status)
            })
        };
        let result = tokio::time::timeout(self.spec.timeout, exchange).await;
        let unsent = |error: CryptoError| {
            if handed_over.load(Ordering::SeqCst) {
                error
            } else {
                error.not_sent()
            }
        };
        let response = match result {
            Ok(Ok(response)) => {
                connection.succeeded();
                response.into_inner()
            }
            Ok(Err(error)) => {
                // A completed error response keeps the connection; a local
                // TLS failure does not (see `tls_failed`).
                if error.class() != ErrorClass::Retryable && !tls_failed.load(Ordering::SeqCst) {
                    connection.preserve();
                }
                return Err(unsent(error));
            }
            Err(_) => {
                return Err(unsent(CryptoError::Retryable(format!(
                    "grpc operation exceeded the {:?} transport timeout",
                    self.spec.timeout
                ))));
            }
        };

        echoed(response.items, &expected)
    }
}

/// The items of a response, each of which must echo the unit of the request
/// item in its position.
fn echoed(items: Vec<WireItem>, expected: &[u64]) -> Result<Vec<WireItem>, CryptoError> {
    // The decoder already refused any item beyond the request's count.
    if items.len() != expected.len() {
        return Err(CryptoError::Contract(format!(
            "grpc response has {} item(s), expected {}",
            items.len(),
            expected.len()
        )));
    }
    for (i, (item, want)) in items.iter().zip(expected.iter()).enumerate() {
        if item.unit_index != *want {
            return Err(CryptoError::Contract(format!(
                "grpc response item {i} echoes unit {}, expected {want}",
                item.unit_index
            )));
        }
    }
    Ok(items)
}

#[async_trait]
impl CryptoProvider for GrpcCryptoProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(self.spec.capabilities.clone())
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let wire: Vec<WireItem> = items
            .iter()
            .map(|i| WireItem {
                unit_index: i.unit_index,
                data: i.data.duplicate(),
            })
            .collect();
        let out = self.call(self.encrypt_path.clone(), context, wire).await?;
        Ok(out
            .into_iter()
            .map(|i| CiphertextUnit {
                unit_index: i.unit_index,
                data: i.data.into_vec(),
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let wire: Vec<WireItem> = items
            .iter()
            .map(|i| WireItem {
                unit_index: i.unit_index,
                data: SecretBuffer::from_slice(&i.data),
            })
            .collect();
        let out = self.call(self.decrypt_path.clone(), context, wire).await?;
        Ok(out
            .into_iter()
            .map(|i| PlaintextUnit {
                unit_index: i.unit_index,
                data: i.data,
            })
            .collect())
    }
}
