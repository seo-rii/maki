//! `maki-crypto-grpc` — gRPC remote crypto transport (SPEC §18, §51).
//!
//! Message shapes are fixed (see `packaging/examples/maki-crypto.proto`);
//! method paths and metadata are runtime-configurable, so a vendor service
//! only needs to speak the documented contract at any package/service name.
//! Responses echo `unit_index`, giving native reorder detection. Message
//! sizes are bounded in both directions. Dynamic descriptor loading
//! (arbitrary message shapes) is milestone M7 — see docs/phase-9.md.

use std::time::Duration;

use async_trait::async_trait;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::metadata::{MetadataKey, MetadataValue};
use tonic::transport::Channel;

use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer,
};

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
    let message = format!("grpc {:?}: {}", status.code(), status.message());
    match status.code() {
        Code::ResourceExhausted => CryptoError::Throttled(message),
        Code::Unavailable | Code::DeadlineExceeded | Code::Aborted | Code::Internal => {
            CryptoError::Retryable(message)
        }
        Code::Unauthenticated | Code::PermissionDenied => CryptoError::EndpointFatal(message),
        Code::InvalidArgument
        | Code::NotFound
        | Code::OutOfRange
        | Code::FailedPrecondition => CryptoError::NonRetryableRequest(message),
        Code::Unimplemented => CryptoError::ProviderFatal(message),
        _ => CryptoError::Retryable(message),
    }
}

/// Convenience for tests/docs: class of a mapped code.
pub fn class_of_code(code: tonic::Code) -> ErrorClass {
    map_status(&tonic::Status::new(code, "x")).class()
}

// ---------------------------------------------------------------- provider

#[derive(Debug, Clone)]
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

pub struct GrpcCryptoProvider {
    spec: GrpcProviderSpec,
    channel: Channel,
    encrypt_path: PathAndQuery,
    decrypt_path: PathAndQuery,
}

fn fatal(msg: impl Into<String>) -> CryptoError {
    CryptoError::ProviderFatal(msg.into())
}

impl GrpcCryptoProvider {
    pub fn new(spec: GrpcProviderSpec) -> Result<Self, CryptoError> {
        let channel = Channel::from_shared(spec.url.clone())
            .map_err(|e| fatal(format!("bad endpoint url: {e}")))?
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

    fn request_bytes(items: &[CryptoItem]) -> usize {
        items.iter().map(|i| i.data.len() + 16).sum::<usize>() + 64
    }

    async fn call(
        &self,
        path: PathAndQuery,
        context: &CryptoContext,
        items: Vec<CryptoItem>,
    ) -> Result<Vec<CryptoItem>, CryptoError> {
        if Self::request_bytes(&items) > self.spec.max_message_bytes {
            return Err(CryptoError::NonRetryableRequest(format!(
                "request exceeds message-size limit {}",
                self.spec.max_message_bytes
            )));
        }
        let expected: Vec<u64> = items.iter().map(|i| i.unit_index).collect();
        let message = CryptoBatchRequest {
            volume_id: context.volume_uuid.to_string(),
            compatibility_id: context.crypto_compatibility_id.clone(),
            items,
        };

        let mut grpc = tonic::client::Grpc::new(self.channel.clone())
            .max_decoding_message_size(self.spec.max_message_bytes)
            .max_encoding_message_size(self.spec.max_message_bytes);
        grpc.ready()
            .await
            .map_err(|e| CryptoError::Retryable(format!("grpc endpoint not ready: {e}")))?;

        let mut request = tonic::Request::new(message);
        for (key, value) in &self.spec.metadata {
            let key = MetadataKey::<tonic::metadata::Ascii>::from_bytes(key.as_bytes())
                .expect("validated at construction");
            let value = value
                .parse::<MetadataValue<tonic::metadata::Ascii>>()
                .expect("validated at construction");
            request.metadata_mut().insert(key, value);
        }

        let codec: tonic::codec::ProstCodec<CryptoBatchRequest, CryptoBatchResponse> =
            tonic::codec::ProstCodec::default();
        let response = grpc
            .unary(request, path, codec)
            .await
            .map_err(|status| map_status(&status))?
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
        let wire: Vec<CryptoItem> = items
            .iter()
            .map(|i| CryptoItem {
                unit_index: i.unit_index,
                data: i.data.expose().to_vec(),
            })
            .collect();
        let out = self.call(self.encrypt_path.clone(), context, wire).await?;
        Ok(out
            .into_iter()
            .map(|i| CiphertextUnit {
                unit_index: i.unit_index,
                data: i.data,
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let wire: Vec<CryptoItem> = items
            .iter()
            .map(|i| CryptoItem {
                unit_index: i.unit_index,
                data: i.data.clone(),
            })
            .collect();
        let out = self.call(self.decrypt_path.clone(), context, wire).await?;
        Ok(out
            .into_iter()
            .map(|i| PlaintextUnit {
                unit_index: i.unit_index,
                data: SecretBuffer::from_vec(i.data),
            })
            .collect())
    }
}
