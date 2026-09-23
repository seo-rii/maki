//! `maki-crypto-grpc` — gRPC remote crypto transport (SPEC §18, §51).
//!
//! Message shapes are fixed (see `packaging/examples/maki-crypto.proto`);
//! method paths and metadata are runtime-configurable, so a vendor service
//! only needs to speak the documented contract at any package/service name.
//! Responses echo `unit_index`, giving native reorder detection. Message
//! sizes are bounded in both directions. Dynamic descriptor loading
//! (arbitrary message shapes) is not supported; see docs/configuration.md.
//!
//! The provider's private wire items erase their owned data on drop and field
//! replacement. This does not erase tonic's separate codec or HTTP/TLS buffers.

use std::time::Duration;

use async_trait::async_trait;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::metadata::{MetadataKey, MetadataValue};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer,
};

mod protected;
use protected::{WireItem, WireRequest, WireResponse};

#[cfg(test)]
mod protected_tests;
#[cfg(test)]
mod tls_tests;

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
        Code::Unimplemented => CryptoError::ProviderFatal(message),
        _ => CryptoError::Retryable(message),
    }
}

/// Convenience for tests/docs: class of a mapped code.
pub fn class_of_code(code: tonic::Code) -> ErrorClass {
    map_status(&tonic::Status::new(code, "x")).class()
}

// ---------------------------------------------------------------- provider

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

/// Verified TLS configuration. Native platform roots remain enabled when a
/// custom CA is supplied; the custom CA augments rather than replaces them.
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

/// Metadata values are resolved credentials: never printed (C-11).
impl std::fmt::Debug for GrpcProviderSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = self
            .metadata
            .iter()
            .map(|(k, _)| format!("{k}: <redacted>"))
            .collect();
        f.debug_struct("GrpcProviderSpec")
            .field("url", &self.url)
            .field("encrypt_path", &self.encrypt_path)
            .field("decrypt_path", &self.decrypt_path)
            .field("metadata", &keys)
            .field("capabilities", &self.capabilities)
            .field("timeout", &self.timeout)
            .field("max_message_bytes", &self.max_message_bytes)
            .finish()
    }
}

pub struct GrpcCryptoProvider {
    spec: GrpcProviderSpec,
    channel: Channel,
    encrypt_path: PathAndQuery,
    decrypt_path: PathAndQuery,
}

fn fatal(msg: impl Into<String>) -> CryptoError {
    CryptoError::ProviderFatal(msg.into())
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
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
                let mut config = ClientTlsConfig::new().with_native_roots();
                if let Some(ca) = tls.ca_certificate_pem {
                    if ca.is_empty() {
                        return Err(fatal("custom TLS CA certificate is empty"));
                    }
                    config = config.ca_certificate(Certificate::from_pem(ca));
                }
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
        let channel = endpoint
            .timeout(spec.timeout)
            .connect_timeout(spec.timeout)
            .connect_lazy();
        let encrypt_path = PathAndQuery::try_from(spec.encrypt_path.clone())
            .map_err(|e| fatal(format!("bad encrypt path: {e}")))?;
        let decrypt_path = PathAndQuery::try_from(spec.decrypt_path.clone())
            .map_err(|e| fatal(format!("bad decrypt path: {e}")))?;
        // Validate metadata eagerly: a bad credential/config fails closed.
        for (key, value) in &spec.metadata {
            MetadataKey::<tonic::metadata::Ascii>::from_bytes(key.as_bytes())
                .map_err(|e| fatal(format!("bad metadata key {key:?}: {e}")))?;
            value
                .parse::<MetadataValue<tonic::metadata::Ascii>>()
                .map_err(|e| fatal(format!("bad metadata value for {key:?}: {e}")))?;
        }
        Ok(Self {
            channel,
            encrypt_path,
            decrypt_path,
            spec,
        })
    }

    fn request_bytes(items: &[WireItem]) -> usize {
        items.iter().map(|i| i.data.len() + 16).sum::<usize>() + 64
    }

    async fn call(
        &self,
        path: PathAndQuery,
        context: &CryptoContext,
        items: Vec<WireItem>,
    ) -> Result<Vec<WireItem>, CryptoError> {
        if Self::request_bytes(&items) > self.spec.max_message_bytes {
            return Err(CryptoError::NonRetryableRequest(format!(
                "request exceeds message-size limit {}",
                self.spec.max_message_bytes
            )));
        }
        let expected: Vec<u64> = items.iter().map(|i| i.unit_index).collect();
        let message = WireRequest {
            volume_id: context.volume_uuid.to_string(),
            compatibility_id: context.crypto_compatibility_id.clone(),
            items,
            format_version: context.format_version,
        };

        let mut grpc = tonic::client::Grpc::new(self.channel.clone())
            .max_decoding_message_size(self.spec.max_message_bytes)
            .max_encoding_message_size(self.spec.max_message_bytes);

        let mut request = tonic::Request::new(message);
        for (key, value) in &self.spec.metadata {
            let key = MetadataKey::<tonic::metadata::Ascii>::from_bytes(key.as_bytes())
                .expect("validated at construction");
            let value = value
                .parse::<MetadataValue<tonic::metadata::Ascii>>()
                .expect("validated at construction");
            request.metadata_mut().insert(key, value);
        }

        let codec: tonic::codec::ProstCodec<WireRequest, WireResponse> =
            tonic::codec::ProstCodec::default();

        // `Channel::timeout` bounds the connection, not the whole exchange:
        // a server that stalls after the response headers, or between the
        // message and the trailers, would hold this RPC open indefinitely,
        // pinning its inflight slot and blocking that request's retry and
        // failover (BUG-017). Bound readiness plus the unary call together
        // by the configured operation timeout. The `bounded-error` policy's
        // outer deadline (BUG-013) is separate and still applies.
        let exchange = async {
            grpc.ready()
                .await
                .map_err(|e| CryptoError::Retryable(format!("grpc endpoint not ready: {e}")))?;
            grpc.unary(request, path, codec)
                .await
                .map_err(|status| map_status(&status))
        };
        let response = tokio::time::timeout(self.spec.timeout, exchange)
            .await
            .map_err(|_| {
                CryptoError::Retryable(format!(
                    "grpc operation exceeded the {:?} transport timeout",
                    self.spec.timeout
                ))
            })??
            .into_inner();

        if response.items.len() != expected.len() {
            return Err(CryptoError::Contract(format!(
                "grpc response has {} item(s), expected {}",
                response.items.len(),
                expected.len()
            )));
        }
        for (i, (item, want)) in response.items.iter().zip(expected.iter()).enumerate() {
            if item.unit_index != *want {
                return Err(CryptoError::Contract(format!(
                    "grpc response item {i} echoes unit {}, expected {want}",
                    item.unit_index
                )));
            }
        }
        Ok(response.items)
    }
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
