//! `maki-crypto-http` — the HTTP/HTTPS remote crypto provider (SPEC §18–§19,
//! §50).
//!
//! Maki does not understand the vendor's cryptography; it drives a
//! *configured transport contract*: request field mappings (JSON pointer →
//! source), payload encodings, batch layout, response mappings, credentialed
//! headers, TLS settings, timeouts, and a response-size cap. Payloads are
//! never logged. Provider failure never falls back to another algorithm
//! (SPEC §12) — errors are classified (SPEC §31) and handled by the
//! dispatcher.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use maki_crypto::{
    Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};

#[cfg(test)]
mod sensitive_tests;

/// Bytes wiped when dropped: every copy of plaintext this crate makes on
/// the way to and from the wire (third review, F09) — payload copies, the
/// serialized request body, the response body, and decoded payloads.
/// Copies made inside reqwest, hyper, rustls and the kernel are outside
/// this crate's reach; the daemon's no-swap and no-core-dump posture is
/// what covers them.
pub type Sensitive = Zeroizing<Vec<u8>>;

/// A request body wiped once reqwest has released it: `Bytes::from_owner`
/// keeps the zeroizing vector alive while any clone of the body exists and
/// drops (wipes) it afterwards, instead of copying it into a plain buffer.
struct WipedOnDrop(Sensitive);

impl AsRef<[u8]> for WipedOnDrop {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn body_from(bytes: Sensitive) -> reqwest::Body {
    reqwest::Body::from(bytes::Bytes::from_owner(WipedOnDrop(bytes)))
}

fn append_response_chunk(
    out: &mut Sensitive,
    chunk: &[u8],
    limit: usize,
) -> Result<(), CryptoError> {
    let length = out
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| CryptoError::NonRetryableRequest("response size overflow".into()))?;
    if length > limit {
        return Err(CryptoError::NonRetryableRequest(format!(
            "response exceeds limit {limit}"
        )));
    }
    if length <= out.capacity() {
        out.extend_from_slice(chunk);
        return Ok(());
    }

    // Vec growth copies before releasing its previous allocation, without
    // giving its owner a chance to wipe that allocation. Move through a new
    // fixed-capacity guard and erase the replaced owner explicitly instead.
    let capacity = out.capacity().saturating_mul(2).max(length).min(limit);
    let mut grown = Zeroizing::new(Vec::new());
    grown.try_reserve_exact(capacity).map_err(|_| {
        CryptoError::NonRetryableRequest(format!(
            "response of {length} bytes cannot be held within limit {limit}"
        ))
    })?;
    grown.extend_from_slice(out);
    grown.extend_from_slice(chunk);
    out.zeroize();
    *out = grown;
    Ok(())
}

/// Wipe every string in a JSON document in place. Payload encodings are
/// reversible, so an encoded payload is plaintext; the document is wiped
/// as soon as it has been serialized (request) or read (response).
pub fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_json),
        Value::Object(map) => {
            // `serde_json::Map` exposes mutable values but not mutable keys.
            // Drain the object so each owned key can be wiped before its
            // allocation is released, while recursively wiping every value.
            for (mut key, mut child) in std::mem::take(map) {
                key.zeroize();
                zeroize_json(&mut child);
            }
        }
        _ => {}
    }
}

/// Own a JSON tree while it can still contain reversible plaintext. Any
/// early return or unwind wipes the complete tree before releasing it.
struct WipedJson(Value);

impl WipedJson {
    fn new(value: Value) -> Self {
        Self(value)
    }

    fn take(&mut self) -> Value {
        std::mem::take(&mut self.0)
    }
}

impl Drop for WipedJson {
    fn drop(&mut self) {
        zeroize_json(&mut self.0);
    }
}

// ---------------------------------------------------------------- spec types

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEncoding {
    Base64,
    Base64Url,
    HexLower,
    HexUpper,
}

impl PayloadEncoding {
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        match s {
            "base64" => Ok(Self::Base64),
            "base64url" => Ok(Self::Base64Url),
            "hex-lower" | "hex" => Ok(Self::HexLower),
            "hex-upper" => Ok(Self::HexUpper),
            other => Err(CryptoError::ProviderFatal(format!(
                "unknown payload encoding {other:?}"
            ))),
        }
    }

    pub fn encode(&self, data: &[u8]) -> String {
        match self {
            Self::Base64 => base64::engine::general_purpose::STANDARD.encode(data),
            Self::Base64Url => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data),
            Self::HexLower => data.iter().map(|b| format!("{b:02x}")).collect(),
            Self::HexUpper => data.iter().map(|b| format!("{b:02X}")).collect(),
        }
    }

    pub fn decode(&self, s: &str) -> Result<Sensitive, CryptoError> {
        let bad = |e: String| CryptoError::Contract(format!("payload decode failed: {e}"));
        let bytes = s.as_bytes();
        let decoded_len = match self {
            Self::Base64 => {
                if !bytes.len().is_multiple_of(4) {
                    return Err(bad("invalid base64 length".to_string()));
                }
                let padding =
                    usize::from(bytes.ends_with(b"=")) + usize::from(bytes.ends_with(b"=="));
                (bytes.len() / 4)
                    .checked_mul(3)
                    .and_then(|length| length.checked_sub(padding))
                    .ok_or_else(|| bad("invalid base64 padding".to_string()))?
            }
            Self::Base64Url => {
                let remainder = bytes.len() % 4;
                if remainder == 1 {
                    return Err(bad("invalid base64url length".to_string()));
                }
                (bytes.len() / 4)
                    .checked_mul(3)
                    .and_then(|length| {
                        length.checked_add(match remainder {
                            2 => 1,
                            3 => 2,
                            _ => 0,
                        })
                    })
                    .ok_or_else(|| bad("decoded payload length overflow".to_string()))?
            }
            Self::HexLower | Self::HexUpper => {
                if !bytes.len().is_multiple_of(2) {
                    return Err(bad("odd hex length".to_string()));
                }
                bytes.len() / 2
            }
        };
        // Own the zeroization guard before writing the first decoded byte.
        // A malformed symbol near the end must wipe the partial plaintext,
        // and a fixed-size allocation cannot abandon plaintext while growing.
        let mut decoded = Zeroizing::new(vec![0u8; decoded_len]);
        match self {
            Self::Base64 => {
                let written = base64::engine::general_purpose::STANDARD
                    .decode_slice(s, &mut decoded)
                    .map_err(|e| bad(e.to_string()))?;
                if written != decoded_len {
                    return Err(bad("decoded payload length mismatch".to_string()));
                }
            }
            Self::Base64Url => {
                let written = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode_slice(s, &mut decoded)
                    .map_err(|e| bad(e.to_string()))?;
                if written != decoded_len {
                    return Err(bad("decoded payload length mismatch".to_string()));
                }
            }
            Self::HexLower | Self::HexUpper => {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => Some(byte - b'0'),
                    b'a'..=b'f' => Some(byte - b'a' + 10),
                    b'A'..=b'F' => Some(byte - b'A' + 10),
                    _ => None,
                };
                for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
                    let high = digit(pair[0]).ok_or_else(|| bad("invalid hex digit".into()))?;
                    let low = digit(pair[1]).ok_or_else(|| bad("invalid hex digit".into()))?;
                    decoded[index] = high << 4 | low;
                }
            }
        }
        Ok(decoded)
    }
}

#[derive(Debug, Clone)]
pub enum FieldSource {
    Payload(PayloadEncoding),
    UnitIndex,
    VolumeId,
    CompatibilityId,
    /// The volume's on-disk format version (part of the crypto context).
    FormatVersion,
    BatchIndex,
}

impl FieldSource {
    pub fn parse(source: &str, encoding: Option<&str>) -> Result<Self, CryptoError> {
        match source {
            "payload" => Ok(Self::Payload(PayloadEncoding::parse(
                encoding.unwrap_or("base64"),
            )?)),
            "unit_index" => Ok(Self::UnitIndex),
            "volume_id" => Ok(Self::VolumeId),
            "compatibility_id" => Ok(Self::CompatibilityId),
            "format_version" => Ok(Self::FormatVersion),
            "batch_index" => Ok(Self::BatchIndex),
            other => Err(CryptoError::ProviderFatal(format!(
                "unknown field source {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BodySpec {
    /// Body bytes are the payload itself (one request per item).
    Raw,
    Json {
        fields: Vec<(String, FieldSource)>,
        /// Batch: pointer to the array of per-item objects. Absent = one
        /// request per item.
        items_path: Option<String>,
        item_fields: Vec<(String, FieldSource)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespKind {
    Raw,
    Json,
}

#[derive(Debug, Clone)]
pub struct RespSpec {
    pub kind: RespKind,
    /// Payload pointer (whole document, or within each batch element).
    pub data_path: Option<String>,
    pub encoding: PayloadEncoding,
    pub items_path: Option<String>,
    /// Optional per-element unit-index echo, validated when configured.
    pub item_index_path: Option<String>,
}

#[derive(Clone)]
pub struct OpSpec {
    pub method: String,
    pub path: String,
    /// Fully resolved header values (credentials already loaded).
    pub headers: Vec<(String, String)>,
    pub query: Vec<(String, String)>,
    pub body: BodySpec,
    pub response: RespSpec,
}

fn zeroize_pair_values(pairs: &mut [(String, String)]) {
    for (_, value) in pairs {
        value.zeroize();
    }
}

impl Drop for OpSpec {
    fn drop(&mut self) {
        zeroize_pair_values(&mut self.headers);
        zeroize_pair_values(&mut self.query);
    }
}

/// Header and query *values* are resolved credentials: never printed
/// (C-11). Names stay visible for diagnostics.
impl std::fmt::Debug for OpSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |pairs: &[(String, String)]| -> Vec<String> {
            pairs
                .iter()
                .map(|(k, _)| format!("{k}: <redacted>"))
                .collect()
        };
        f.debug_struct("OpSpec")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("headers", &redact(&self.headers))
            .field("query", &redact(&self.query))
            .field("body", &self.body)
            .field("response", &self.response)
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct TlsSpec {
    /// PEM CA bundle to trust (replaces nothing; added as a root).
    pub ca_pem: Option<Vec<u8>>,
    /// PEM client certificate + key for mTLS.
    pub identity_pem: Option<Vec<u8>>,
}

impl Drop for TlsSpec {
    fn drop(&mut self) {
        if let Some(identity) = &mut self.identity_pem {
            identity.zeroize();
        }
    }
}

/// The identity PEM carries the client's private key: never printed.
impl std::fmt::Debug for TlsSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSpec")
            .field(
                "ca_pem",
                &self.ca_pem.as_ref().map(|c| format!("{} bytes", c.len())),
            )
            .field(
                "identity_pem",
                &self.identity_pem.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct HttpProviderSpec {
    pub base_url: String,
    pub encrypt: OpSpec,
    pub decrypt: OpSpec,
    pub capabilities: CryptoCapabilities,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub tls: Option<TlsSpec>,
}

// ---------------------------------------------------------------- provider

pub struct HttpCryptoProvider {
    client: reqwest::Client,
    spec: HttpProviderSpec,
}

impl std::fmt::Debug for HttpCryptoProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpCryptoProvider")
            .field("base_url", &self.spec.base_url)
            .finish_non_exhaustive()
    }
}

fn fatal(msg: impl Into<String>) -> CryptoError {
    CryptoError::ProviderFatal(msg.into())
}

/// Own header values while an operation specification is being assembled.
/// Parsing a later field can fail before `OpSpec` takes over the wipe duty.
#[derive(Default)]
struct PendingHeaders(Vec<(String, String)>);

impl PendingHeaders {
    fn take(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for PendingHeaders {
    fn drop(&mut self) {
        zeroize_pair_values(&mut self.0);
    }
}

/// Own a combined client certificate/private-key PEM before `TlsSpec` is
/// complete. Once private-key bytes are appended, every early return must
/// erase them.
struct PendingIdentityPem(Vec<u8>);

impl PendingIdentityPem {
    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for PendingIdentityPem {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Decode one JSON Pointer reference token (RFC 6901 §4): `~1` is `/` and
/// `~0` is `~`, in that order, so `~01` decodes to `~1` and a literal
/// slash or tilde in a field name round-trips. The response side reads
/// with `serde_json`'s `Value::pointer`, which decodes the same way; the
/// request side must match it or a vendor field named `key/slot` is sent
/// as the wrong field `key~1slot` (BUG-024).
fn decode_pointer_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

/// Insert `value` at a JSON pointer, creating intermediate objects.
fn pointer_set(root: &mut Value, pointer: &str, value: Value) -> Result<(), CryptoError> {
    // Keep ownership under a wipe guard until insertion succeeds. This also
    // covers malformed pointers rejected before the tree is traversed.
    let mut value = WipedJson::new(value);
    let mut current = root;
    let tokens: Vec<&str> = pointer
        .strip_prefix('/')
        .ok_or_else(|| fatal(format!("JSON pointer {pointer:?} must start with '/'")))?
        .split('/')
        .collect();
    for (i, token) in tokens.iter().enumerate() {
        if !current.is_object() {
            zeroize_json(current);
            *current = Value::Object(serde_json::Map::new());
        }
        let map = current.as_object_mut().unwrap();
        let key = decode_pointer_token(token);
        if i + 1 == tokens.len() {
            if let Some(mut replaced) = map.insert(key, value.take()) {
                zeroize_json(&mut replaced);
            }
            return Ok(());
        }
        current = map
            .entry(key)
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }
    Err(fatal(format!("empty JSON pointer {pointer:?}")))
}

/// Classify a transport error (SPEC §31).
fn classify_transport(e: reqwest::Error) -> CryptoError {
    // Transport errors include the request URL in Display and Debug. Drop
    // it before either classification or logging can expose query secrets.
    let e = e.without_url();
    if e.is_timeout() {
        return CryptoError::Retryable(format!("request timeout: {e}"));
    }
    let debug = format!("{e:?}");
    if debug.contains("certificate")
        || debug.contains("Certificate")
        || debug.contains("Handshake")
        || debug.contains("handshake")
        || debug.contains("NotValidForName")
        || debug.contains("UnknownIssuer")
    {
        return CryptoError::EndpointFatal(format!("TLS failure: {e}"));
    }
    CryptoError::Retryable(format!("transport error: {e}"))
}

fn classify_status(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Option<CryptoError> {
    if status.is_success() {
        return None;
    }
    // Only the explicit wire contract proves cryptographic rejection. Do
    // not infer integrity from a generic 4xx or reflect a remote body/header.
    if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        let mut reasons = headers.get_all("maki-crypto-error").iter();
        if let (Some(reason), None) = (reasons.next(), reasons.next()) {
            let error = match reason.as_bytes() {
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
                return Some(error);
            }
        }
    }
    let code = status.as_u16();
    Some(match code {
        // A redirect is never followed (see `new`): the endpoint is
        // misconfigured or hijacked, and a request must not be re-sent to
        // a server-chosen URL. Fail over to another endpoint instead.
        300..=399 => CryptoError::EndpointFatal(format!(
            "HTTP {code}: redirects are refused (the request is never re-sent elsewhere)"
        )),
        429 => CryptoError::Throttled(format!("HTTP {code}")),
        401 | 403 | 407 => CryptoError::EndpointFatal(format!("HTTP {code}")),
        408 => CryptoError::Retryable(format!("HTTP {code}")),
        400..=499 => CryptoError::NonRetryableRequest(format!("HTTP {code}")),
        _ => CryptoError::Retryable(format!("HTTP {code}")),
    })
}

impl HttpCryptoProvider {
    pub fn new(spec: HttpProviderSpec) -> Result<Self, CryptoError> {
        // Never follow redirects: reqwest would replay the body (plaintext
        // on encrypt) to whatever `Location` the server names — possibly a
        // different host, possibly over plaintext HTTP — and turn a POST
        // into a GET on 301/302/303 (C-01, SPEC §18 no transport resend).
        let mut builder = reqwest::Client::builder()
            .timeout(spec.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .use_rustls_tls();
        if let Some(tls) = &spec.tls {
            if let Some(ca) = &tls.ca_pem {
                let cert = reqwest::Certificate::from_pem(ca)
                    .map_err(|e| fatal(format!("bad CA certificate: {e}")))?;
                builder = builder.add_root_certificate(cert);
            }
            if let Some(identity) = &tls.identity_pem {
                let identity = reqwest::Identity::from_pem(identity)
                    .map_err(|e| fatal(format!("bad client identity: {e}")))?;
                builder = builder.identity(identity);
            }
        }
        let client = builder
            .build()
            .map_err(|e| fatal(format!("http client build failed: {e}")))?;
        Ok(Self { client, spec })
    }

    fn scalar(
        source: &FieldSource,
        context: &CryptoContext,
        unit_index: u64,
        batch_index: usize,
        payload: &[u8],
    ) -> Value {
        match source {
            FieldSource::Payload(encoding) => Value::String(encoding.encode(payload)),
            FieldSource::UnitIndex => Value::from(unit_index),
            FieldSource::VolumeId => Value::String(context.volume_uuid.to_string()),
            FieldSource::CompatibilityId => Value::String(context.crypto_compatibility_id.clone()),
            FieldSource::FormatVersion => Value::from(u64::from(context.format_version)),
            FieldSource::BatchIndex => Value::from(batch_index as u64),
        }
    }

    async fn send(
        &self,
        op: &OpSpec,
        body: reqwest::Body,
        json: bool,
    ) -> Result<Sensitive, CryptoError> {
        let method = reqwest::Method::from_bytes(op.method.as_bytes())
            .map_err(|_| fatal(format!("bad method {:?}", op.method)))?;
        let url = format!("{}{}", self.spec.base_url, op.path);
        let mut request = self.client.request(method, &url).query(&op.query);
        for (name, value) in &op.headers {
            request = request.header(name, value);
        }
        if json {
            request = request.header("content-type", "application/json");
        }
        let response = request
            .body(body)
            .send()
            .await
            .map_err(classify_transport)?;

        if let Some(err) = classify_status(response.status(), response.headers()) {
            return Err(err);
        }
        if let Some(len) = response.content_length() {
            if len as usize > self.spec.max_response_bytes {
                return Err(CryptoError::NonRetryableRequest(format!(
                    "response of {len} bytes exceeds limit {}",
                    self.spec.max_response_bytes
                )));
            }
        }
        // Stream with a hard cap regardless of the declared length.
        let mut out = Zeroizing::new(Vec::new());
        let mut response = response;
        while let Some(chunk) = response.chunk().await.map_err(classify_transport)? {
            append_response_chunk(&mut out, &chunk, self.spec.max_response_bytes)?;
        }
        Ok(out)
    }

    fn parse_single(&self, op: &OpSpec, body: &[u8]) -> Result<Sensitive, CryptoError> {
        match op.response.kind {
            RespKind::Raw => Ok(Zeroizing::new(body.to_vec())),
            RespKind::Json => {
                let mut value: Value = serde_json::from_slice(body)
                    .map_err(|e| CryptoError::Contract(format!("invalid JSON response: {e}")))?;
                let result = (|| {
                    let path = op
                        .response
                        .data_path
                        .as_deref()
                        .ok_or_else(|| fatal("response data_path missing"))?;
                    let data = value
                        .pointer(path)
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            CryptoError::Contract(format!("response missing string at {path:?}"))
                        })?;
                    op.response.encoding.decode(data)
                })();
                zeroize_json(&mut value);
                result
            }
        }
    }

    /// Serialize a request document and wipe it.
    fn encode_and_wipe(root: &mut Value) -> Sensitive {
        let encoded = Zeroizing::new(serde_json::to_vec(root).expect("JSON value serializes"));
        zeroize_json(root);
        encoded
    }

    /// One request per item.
    async fn run_per_item(
        &self,
        op: &OpSpec,
        context: &CryptoContext,
        items: &[(u64, Sensitive)],
    ) -> Result<Vec<Sensitive>, CryptoError> {
        let mut out = Vec::with_capacity(items.len());
        for (batch_index, (unit_index, payload)) in items.iter().enumerate() {
            let (body, json): (reqwest::Body, bool) = match &op.body {
                BodySpec::Raw => (body_from(payload.clone()), false),
                BodySpec::Json { fields, .. } => {
                    let mut root = WipedJson::new(Value::Object(serde_json::Map::new()));
                    for (pointer, source) in fields {
                        let v = Self::scalar(source, context, *unit_index, batch_index, payload);
                        pointer_set(&mut root.0, pointer, v)?;
                    }
                    (body_from(Self::encode_and_wipe(&mut root.0)), true)
                }
            };
            let response = self.send(op, body, json).await?;
            out.push(self.parse_single(op, &response)?);
        }
        Ok(out)
    }

    /// Single request carrying the whole batch.
    async fn run_batched(
        &self,
        op: &OpSpec,
        context: &CryptoContext,
        items: &[(u64, Sensitive)],
        items_path: &str,
        fields: &[(String, FieldSource)],
        item_fields: &[(String, FieldSource)],
    ) -> Result<Vec<Sensitive>, CryptoError> {
        let mut root = WipedJson::new(Value::Object(serde_json::Map::new()));
        for (pointer, source) in fields {
            let v = Self::scalar(source, context, 0, 0, &[]);
            pointer_set(&mut root.0, pointer, v)?;
        }
        let mut array = WipedJson::new(Value::Array(Vec::with_capacity(items.len())));
        for (batch_index, (unit_index, payload)) in items.iter().enumerate() {
            let mut element = WipedJson::new(Value::Object(serde_json::Map::new()));
            for (pointer, source) in item_fields {
                let v = Self::scalar(source, context, *unit_index, batch_index, payload);
                pointer_set(&mut element.0, pointer, v)?;
            }
            array
                .0
                .as_array_mut()
                .expect("batch request remains an array")
                .push(element.take());
        }
        pointer_set(&mut root.0, items_path, array.take())?;

        let response = self
            .send(op, body_from(Self::encode_and_wipe(&mut root.0)), true)
            .await?;
        let mut value: Value = serde_json::from_slice(&response)
            .map_err(|e| CryptoError::Contract(format!("invalid JSON response: {e}")))?;
        let result = Self::extract_batch(op, &value, items);
        zeroize_json(&mut value);
        result
    }

    /// Pull the per-item payloads out of a parsed batch response.
    fn extract_batch(
        op: &OpSpec,
        value: &Value,
        items: &[(u64, Sensitive)],
    ) -> Result<Vec<Sensitive>, CryptoError> {
        let resp_items_path = op
            .response
            .items_path
            .as_deref()
            .ok_or_else(|| fatal("response items_path missing for batch layout"))?;
        let elements = value
            .pointer(resp_items_path)
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                CryptoError::Contract(format!("response missing array at {resp_items_path:?}"))
            })?;
        if elements.len() != items.len() {
            return Err(CryptoError::Contract(format!(
                "batch response has {} element(s) for {} item(s)",
                elements.len(),
                items.len()
            )));
        }
        let mut out = Vec::with_capacity(items.len());
        for (i, element) in elements.iter().enumerate() {
            if let Some(index_path) = &op.response.item_index_path {
                let echoed = element.pointer(index_path).and_then(|v| v.as_u64());
                if echoed != Some(items[i].0) {
                    return Err(CryptoError::Contract(format!(
                        "batch element {i} echoes unit {echoed:?}, expected {}",
                        items[i].0
                    )));
                }
            }
            let data = match &op.response.data_path {
                Some(path) => element.pointer(path).and_then(|v| v.as_str()),
                None => element.as_str(),
            }
            .ok_or_else(|| {
                CryptoError::Contract(format!("batch element {i} missing payload string"))
            })?;
            out.push(op.response.encoding.decode(data)?);
        }
        Ok(out)
    }

    async fn run_op(
        &self,
        op: &OpSpec,
        context: &CryptoContext,
        items: &[(u64, Sensitive)],
    ) -> Result<Vec<Sensitive>, CryptoError> {
        match &op.body {
            BodySpec::Json {
                fields,
                items_path: Some(items_path),
                item_fields,
            } => {
                self.run_batched(op, context, items, items_path, fields, item_fields)
                    .await
            }
            _ => self.run_per_item(op, context, items).await,
        }
    }

    /// Build from validated configuration (SPEC §19), resolving credentialed
    /// headers via `keys`.
    pub fn from_config(
        config: &maki_format::config::VolumeConfig,
        endpoint_url: &str,
        keys: &dyn maki_crypto_local::keysource::KeySource,
    ) -> Result<Self, CryptoError> {
        use maki_format::config::HeaderValue;

        let http = config
            .crypto
            .http
            .as_ref()
            .ok_or_else(|| fatal("missing [crypto.http] section"))?;
        let build_op = |op_cfg: &maki_format::config::HttpOpConfig| -> Result<OpSpec, CryptoError> {
            let mut headers = PendingHeaders::default();
            for (name, value) in &op_cfg.headers {
                let resolved = match value {
                    HeaderValue::Literal(v) => v.clone(),
                    HeaderValue::Credential(cred) => {
                        let secret = keys.load(&cred.name)?;
                        let text = std::str::from_utf8(secret.expose())
                            .map_err(|_| fatal("credential is not valid UTF-8"))?;
                        match &cred.format {
                            Some(template) => template.replace("{}", text.trim()),
                            None => text.trim().to_string(),
                        }
                    }
                };
                headers.0.push((name.clone(), resolved));
            }
            let body = match &op_cfg.body {
                None => BodySpec::Raw,
                Some(body_cfg) if body_cfg.body_type == "raw" => BodySpec::Raw,
                Some(body_cfg) => {
                    let parse_fields = |m: &std::collections::BTreeMap<
                        String,
                        maki_format::config::FieldMapping,
                    >|
                     -> Result<Vec<(String, FieldSource)>, CryptoError> {
                        m.iter()
                            .map(|(pointer, mapping)| {
                                FieldSource::parse(&mapping.source, mapping.encoding.as_deref())
                                    .map(|s| (pointer.clone(), s))
                            })
                            .collect()
                    };
                    BodySpec::Json {
                        fields: parse_fields(&body_cfg.fields)?,
                        items_path: body_cfg.items_path.clone(),
                        item_fields: parse_fields(&body_cfg.item_fields)?,
                    }
                }
            };
            let response = match &op_cfg.response {
                None => RespSpec {
                    kind: RespKind::Raw,
                    data_path: None,
                    encoding: PayloadEncoding::Base64,
                    items_path: None,
                    item_index_path: None,
                },
                Some(r) => RespSpec {
                    kind: if r.response_type == "raw" {
                        RespKind::Raw
                    } else {
                        RespKind::Json
                    },
                    data_path: r.data_path.clone(),
                    encoding: PayloadEncoding::parse(r.encoding.as_deref().unwrap_or("base64"))?,
                    items_path: r.items_path.clone(),
                    item_index_path: r.item_index_path.clone(),
                },
            };
            Ok(OpSpec {
                method: op_cfg.method.clone(),
                path: op_cfg.path.clone(),
                headers: headers.take(),
                query: op_cfg
                    .query
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                body,
                response,
            })
        };

        let encrypt = build_op(
            http.encrypt
                .as_ref()
                .ok_or_else(|| fatal("missing [crypto.http.encrypt]"))?,
        )?;
        let decrypt = build_op(
            http.decrypt
                .as_ref()
                .ok_or_else(|| fatal("missing [crypto.http.decrypt]"))?,
        )?;

        let caps_cfg = &config.crypto.capabilities;
        let capability = |s: &str| match s {
            "verified" => Capability::Contractual,
            "contractual" => Capability::Contractual,
            _ => Capability::Absent,
        };
        let capabilities = CryptoCapabilities {
            provider_id: "remote-http".to_string(),
            crypto_compatibility_id: config.crypto.crypto_compatibility_id.clone(),
            supported_plaintext_sizes: caps_cfg.supported_plaintext_sizes.clone(),
            max_ciphertext_size: caps_cfg.max_ciphertext_size,
            stateless: caps_cfg.stateless,
            retry_safe: caps_cfg.retry_safe,
            batch: maki_crypto::BatchCapability {
                supported: true,
                max_items: config.crypto.batch.max_items,
                max_bytes: config.crypto.batch.max_bytes.0,
            },
            integrity: capability(&caps_cfg.integrity),
            context_binding: capability(&caps_cfg.context_binding),
            replay_protection: capability(&caps_cfg.replay_protection),
        };

        // TLS material is fail-closed (review M-015): an unreadable CA or
        // client certificate refuses attach instead of silently falling
        // back to default trust or no client identity.
        let tls = match http.tls.as_ref() {
            None => None,
            Some(t) => {
                if let Some(name) = &t.server_name {
                    return Err(fatal(format!(
                        "[crypto.http.tls] server_name {name:?} is not supported; \
                         put the certificate's name in the endpoint url"
                    )));
                }
                let read = |what: &str, path: &str| -> Result<Vec<u8>, CryptoError> {
                    std::fs::read(path)
                        .map_err(|e| fatal(format!("[crypto.http.tls] {what} {path:?}: {e}")))
                };
                let ca_pem = match &t.ca_file {
                    Some(path) => Some(read("ca_file", path)?),
                    None => None,
                };
                let identity_pem = match &t.client_cert_file {
                    Some(path) => {
                        let mut pem = PendingIdentityPem(read("client_cert_file", path)?);
                        if let Some(key) = &t.client_key {
                            // Private key from its credential source, appended
                            // to the certificate PEM for the client identity.
                            let secret = keys.load(&key.name)?;
                            if !pem.0.ends_with(b"\n") {
                                pem.0.push(b'\n');
                            }
                            pem.0.extend_from_slice(secret.expose());
                        }
                        Some(pem.take())
                    }
                    None => {
                        if t.client_key.is_some() {
                            return Err(fatal(
                                "[crypto.http.tls] client_key requires client_cert_file",
                            ));
                        }
                        None
                    }
                };
                Some(TlsSpec {
                    ca_pem,
                    identity_pem,
                })
            }
        };

        Self::new(HttpProviderSpec {
            base_url: endpoint_url.trim_end_matches('/').to_string(),
            encrypt,
            decrypt,
            capabilities,
            timeout: http.timeout.map(|d| d.0).unwrap_or(Duration::from_secs(10)),
            max_response_bytes: http
                .max_response_bytes
                .map(|b| b.0 as usize)
                .unwrap_or(8 << 20),
            tls,
        })
    }
}

#[async_trait]
impl CryptoProvider for HttpCryptoProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(self.spec.capabilities.clone())
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let payloads: Vec<(u64, Sensitive)> = items
            .iter()
            .map(|i| (i.unit_index, Zeroizing::new(i.data.expose().to_vec())))
            .collect();
        let results = self.run_op(&self.spec.encrypt, context, &payloads).await?;
        Ok(results
            .into_iter()
            .zip(items.iter())
            .map(|(data, item)| CiphertextUnit {
                unit_index: item.unit_index,
                data: data.to_vec(),
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let payloads: Vec<(u64, Sensitive)> = items
            .iter()
            .map(|i| (i.unit_index, Zeroizing::new(i.data.clone())))
            .collect();
        let results = self.run_op(&self.spec.decrypt, context, &payloads).await?;
        Ok(results
            .into_iter()
            .zip(items.iter())
            .map(|(data, item)| PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_slice(&data),
            })
            .collect())
    }
}

#[cfg(test)]
mod pointer_tests {
    use super::{decode_pointer_token, pointer_set};
    use serde_json::{json, Value};

    /// BUG-024: request pointers must decode RFC 6901 escapes (`~1` → `/`,
    /// `~0` → `~`) the same way `Value::pointer` does on the response side.
    /// A vendor field literally named `key/slot` is addressed as `/key~1slot`
    /// and must land in the field `key/slot`, not `key~1slot`.
    #[test]
    fn pointer_set_decodes_rfc6901_escapes() {
        let mut root = Value::Object(Default::default());
        pointer_set(&mut root, "/key~1slot", json!(1)).unwrap();
        pointer_set(&mut root, "/tilde~0field", json!(2)).unwrap();
        pointer_set(&mut root, "/nested/~01combo", json!(3)).unwrap();
        pointer_set(&mut root, "/a/b", json!(4)).unwrap();

        // The written field names are the decoded ones.
        assert_eq!(root["key/slot"], json!(1));
        assert_eq!(root["tilde~field"], json!(2));
        assert_eq!(root["nested"]["~1combo"], json!(3));
        assert_eq!(root["a"]["b"], json!(4));
        assert!(root.get("key~1slot").is_none(), "escape was not decoded");

        // Request and response rules agree: what pointer_set wrote is exactly
        // what Value::pointer reads back for the same pointer string.
        for (p, v) in [
            ("/key~1slot", json!(1)),
            ("/tilde~0field", json!(2)),
            ("/nested/~01combo", json!(3)),
            ("/a/b", json!(4)),
        ] {
            assert_eq!(root.pointer(p), Some(&v), "round-trip mismatch for {p}");
        }
    }

    #[test]
    fn decode_pointer_token_matches_rfc6901_order() {
        assert_eq!(decode_pointer_token("~01"), "~1");
        assert_eq!(decode_pointer_token("~1~0"), "/~");
        assert_eq!(decode_pointer_token("plain"), "plain");
    }
}
