//! Config-driven daemon assembly: backing + provider + engine.

use std::sync::Arc;

use maki_backing::{Backing, FileBacking};
use maki_core::engine::{AttachError, Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_crypto::CryptoProvider;
use maki_crypto_local::keysource::{
    systemd_credential_source, EnvKeySource, FileKeySource, KeySource,
};
use maki_crypto_local::{AesGcmSivProvider, AesXtsProvider};
use maki_format::config::{parse_config, ConfigError, CredentialRef, VolumeConfig};
use maki_format::superblock::Superblock;
use maki_format::{init, FormatError};

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Attach(#[from] AttachError),
    #[error(transparent)]
    Crypto(#[from] maki_crypto::CryptoError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

pub fn parse_and_validate(raw: &str) -> Result<VolumeConfig, ConfigError> {
    let config = parse_config(raw)?;
    config.validate()?;
    Ok(config)
}

pub fn build_backing(config: &VolumeConfig) -> Result<Arc<dyn Backing>, DaemonError> {
    Ok(Arc::new(FileBacking::new(&config.backing.root)?))
}

fn resolve_key_source(cred: &CredentialRef) -> Result<(Box<dyn KeySource>, String), DaemonError> {
    match cred.source.as_str() {
        "env" => Ok((Box::new(EnvKeySource), cred.name.clone())),
        "file" => {
            let path = std::path::Path::new(&cred.name);
            let dir = path.parent().unwrap_or(std::path::Path::new("."));
            let name = path
                .file_name()
                .ok_or_else(|| DaemonError::Unsupported("bad credential path".into()))?
                .to_string_lossy()
                .into_owned();
            Ok((Box::new(FileKeySource::new(dir)), name))
        }
        "credential" => {
            let source = systemd_credential_source().ok_or_else(|| {
                DaemonError::Unsupported(
                    "CREDENTIALS_DIRECTORY not set — credential unavailable, failing closed"
                        .to_string(),
                )
            })?;
            Ok((Box::new(source), cred.name.clone()))
        }
        other => Err(DaemonError::Unsupported(format!(
            "credential source {other:?}"
        ))),
    }
}

/// Build the configured crypto provider (SPEC §12: profile mismatch is
/// caught later by the attach self-test).
pub async fn build_provider(config: &VolumeConfig) -> Result<Arc<dyn CryptoProvider>, DaemonError> {
    let unit = config.volume.crypto_unit_size;
    let compat = config.crypto.crypto_compatibility_id.as_str();
    match config.crypto.provider.as_str() {
        #[cfg(feature = "fake-provider")]
        "fake" => Ok(Arc::new(
            maki_test_support::FakeCryptoProvider::new(unit).with_compat_id(compat),
        )),
        "local-aes-gcm-siv" | "local-aes-xts" => {
            let cred = config.crypto.key.as_ref().ok_or_else(|| {
                DaemonError::Unsupported("local provider requires [crypto].key".to_string())
            })?;
            let (source, name) = resolve_key_source(cred)?;
            if config.crypto.provider == "local-aes-gcm-siv" {
                Ok(Arc::new(AesGcmSivProvider::new(
                    source.as_ref(),
                    &name,
                    unit,
                    compat,
                )?))
            } else {
                Ok(Arc::new(AesXtsProvider::new(
                    source.as_ref(),
                    &name,
                    unit,
                    compat,
                )?))
            }
        }
        "remote-http" => remote_http_provider(config).await,
        "remote-websocket" => remote_websocket_provider(config).await,
        "remote-grpc" => remote_grpc_provider(config).await,
        other => Err(DaemonError::Unsupported(format!("provider {other:?}"))),
    }
}

/// Credential router for header secrets: systemd credentials directory when
/// available, environment variables as the development fallback (SPEC §9).
struct RoutedKeySource;

impl KeySource for RoutedKeySource {
    fn load(&self, name: &str) -> Result<maki_crypto::SecretBuffer, maki_crypto::CryptoError> {
        if let Some(source) = systemd_credential_source() {
            if let Ok(secret) = source.load(name) {
                return Ok(secret);
            }
        }
        EnvKeySource.load(name)
    }
}

/// Assemble the multi-endpoint HTTP provider: per-endpoint transports,
/// cross-endpoint interchangeability check (SPEC §34), and the dispatcher
/// (retry/budget/breaker/failover) from configuration.
async fn remote_http_provider(
    config: &VolumeConfig,
) -> Result<Arc<dyn CryptoProvider>, DaemonError> {
    let http = config
        .crypto
        .http
        .as_ref()
        .ok_or_else(|| DaemonError::Unsupported("missing [crypto.http]".to_string()))?;
    if http.endpoint.is_empty() {
        return Err(DaemonError::Unsupported(
            "remote-http requires at least one [[crypto.http.endpoint]]".to_string(),
        ));
    }
    let mut endpoints: Vec<(String, Arc<dyn CryptoProvider>)> = Vec::new();
    for endpoint in &http.endpoint {
        let provider = maki_crypto_http::HttpCryptoProvider::from_config(
            config,
            &endpoint.url,
            &RoutedKeySource,
        )?;
        endpoints.push((endpoint.name.clone(), Arc::new(provider)));
    }
    dispatch_endpoint_set(config, endpoints).await
}

/// `remote-websocket`: per-endpoint WS transports through the shared
/// dispatcher. The transport build has no TLS support yet, so `wss://` or a
/// `[crypto.websocket.tls]` section refuses attach — fail closed, never a
/// silent downgrade.
async fn remote_websocket_provider(
    config: &VolumeConfig,
) -> Result<Arc<dyn CryptoProvider>, DaemonError> {
    let ws = config
        .crypto
        .websocket
        .as_ref()
        .ok_or_else(|| DaemonError::Unsupported("missing [crypto.websocket]".to_string()))?;
    if ws.endpoint.is_empty() {
        return Err(DaemonError::Unsupported(
            "remote-websocket requires at least one [[crypto.websocket.endpoint]]".to_string(),
        ));
    }
    if ws.tls.is_some() {
        return Err(DaemonError::Unsupported(
            "TLS for the websocket transport is not compiled in; \
             remove [crypto.websocket.tls] or use remote-http"
                .to_string(),
        ));
    }
    let mut endpoints: Vec<(String, Arc<dyn CryptoProvider>)> = Vec::new();
    for endpoint in &ws.endpoint {
        if !endpoint.url.starts_with("ws://") {
            return Err(DaemonError::Unsupported(format!(
                "websocket endpoint {:?} must be ws:// (TLS/wss is not compiled in)",
                endpoint.url
            )));
        }
        let provider =
            maki_crypto_websocket::WsCryptoProvider::new(maki_crypto_websocket::WsProviderSpec {
                url: endpoint.url.clone(),
                capabilities: capabilities_from_config(config, "remote-websocket"),
                timeout: ws
                    .timeout
                    .map(|d| d.0)
                    .unwrap_or(std::time::Duration::from_secs(10)),
                max_frame_bytes: ws.max_frame_bytes.map(|b| b.0 as usize).unwrap_or(8 << 20),
            });
        endpoints.push((endpoint.name.clone(), Arc::new(provider)));
    }
    dispatch_endpoint_set(config, endpoints).await
}

/// `remote-grpc`: fixed reference contract
/// (`packaging/examples/maki-crypto.proto`) at configurable method paths,
/// with credential-resolved ascii metadata. Same TLS fail-closed rule as the
/// websocket transport.
async fn remote_grpc_provider(
    config: &VolumeConfig,
) -> Result<Arc<dyn CryptoProvider>, DaemonError> {
    let grpc = config
        .crypto
        .grpc
        .as_ref()
        .ok_or_else(|| DaemonError::Unsupported("missing [crypto.grpc]".to_string()))?;
    if grpc.endpoint.is_empty() {
        return Err(DaemonError::Unsupported(
            "remote-grpc requires at least one [[crypto.grpc.endpoint]]".to_string(),
        ));
    }
    if grpc.tls.is_some() {
        return Err(DaemonError::Unsupported(
            "TLS for the grpc transport is not compiled in; \
             remove [crypto.grpc.tls] or use remote-http"
                .to_string(),
        ));
    }
    let mut metadata = Vec::new();
    for (name, value) in &grpc.metadata {
        metadata.push((name.clone(), resolve_metadata_value(value)?));
    }
    let mut endpoints: Vec<(String, Arc<dyn CryptoProvider>)> = Vec::new();
    for endpoint in &grpc.endpoint {
        if !endpoint.url.starts_with("http://") {
            return Err(DaemonError::Unsupported(format!(
                "grpc endpoint {:?} must be http:// (TLS/https is not compiled in)",
                endpoint.url
            )));
        }
        let provider =
            maki_crypto_grpc::GrpcCryptoProvider::new(maki_crypto_grpc::GrpcProviderSpec {
                url: endpoint.url.clone(),
                encrypt_path: grpc
                    .encrypt_path
                    .clone()
                    .unwrap_or_else(|| "/maki.CryptoService/EncryptBatch".to_string()),
                decrypt_path: grpc
                    .decrypt_path
                    .clone()
                    .unwrap_or_else(|| "/maki.CryptoService/DecryptBatch".to_string()),
                metadata: metadata.clone(),
                capabilities: capabilities_from_config(config, "remote-grpc"),
                timeout: grpc
                    .timeout
                    .map(|d| d.0)
                    .unwrap_or(std::time::Duration::from_secs(10)),
                max_message_bytes: grpc
                    .max_message_bytes
                    .map(|b| b.0 as usize)
                    .unwrap_or(4 << 20),
            })?;
        endpoints.push((endpoint.name.clone(), Arc::new(provider)));
    }
    dispatch_endpoint_set(config, endpoints).await
}

/// Declared `[crypto.capabilities]` as `CryptoCapabilities` (the same
/// mapping the HTTP provider applies inside `from_config`).
fn capabilities_from_config(
    config: &VolumeConfig,
    provider_id: &str,
) -> maki_crypto::CryptoCapabilities {
    let caps_cfg = &config.crypto.capabilities;
    let capability = |s: &str| match s {
        "verified" => maki_crypto::Capability::Verified,
        "contractual" => maki_crypto::Capability::Contractual,
        _ => maki_crypto::Capability::Absent,
    };
    maki_crypto::CryptoCapabilities {
        provider_id: provider_id.to_string(),
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
    }
}

/// Resolve a metadata value: literal as-is (validation already rejected
/// literals for sensitive keys, SPEC §9), credential via the key router.
fn resolve_metadata_value(value: &maki_format::config::HeaderValue) -> Result<String, DaemonError> {
    match value {
        maki_format::config::HeaderValue::Literal(v) => Ok(v.clone()),
        maki_format::config::HeaderValue::Credential(cred) => {
            let secret = RoutedKeySource.load(&cred.name)?;
            let text = String::from_utf8(secret.expose().to_vec()).map_err(|_| {
                DaemonError::Unsupported("credential is not valid UTF-8".to_string())
            })?;
            Ok(match &cred.format {
                Some(template) => template.replace("{}", text.trim()),
                None => text.trim().to_string(),
            })
        }
    }
}

/// Cross-endpoint interchangeability check (SPEC §34) plus the dispatcher
/// (retry/budget/breaker/failover) shared by every remote transport.
async fn dispatch_endpoint_set(
    config: &VolumeConfig,
    endpoints: Vec<(String, Arc<dyn CryptoProvider>)>,
) -> Result<Arc<dyn CryptoProvider>, DaemonError> {
    use maki_crypto::clock::SystemClock;
    use maki_crypto::endpoint::{DispatchConfig, EndpointSet};

    // Cross-endpoint encrypt/decrypt self-tests before attach (SPEC §34).
    // The synthetic context uses the configured profile; the volume UUID is
    // bound later by the attach-time self-test.
    if endpoints.len() > 1 {
        let context = maki_crypto::CryptoContext {
            volume_uuid: uuid::Uuid::nil(),
            format_version: 1,
            crypto_compatibility_id: config.crypto.crypto_compatibility_id.clone(),
        };
        let unit = config.volume.crypto_unit_size as usize;
        for other in &endpoints[1..] {
            match maki_crypto::selftest::cross_endpoint_self_test(
                endpoints[0].1.as_ref(),
                other.1.as_ref(),
                &context,
                unit,
            )
            .await
            {
                Ok(()) => {}
                // A transport failure only proves the endpoint is down right
                // now — its circuit breaker will gate it. Proven
                // non-interchangeability (ProviderFatal / contract) refuses
                // attach (SPEC §12, §34).
                Err(e)
                    if matches!(
                        e.class(),
                        maki_crypto::ErrorClass::Retryable
                            | maki_crypto::ErrorClass::Throttled
                            | maki_crypto::ErrorClass::EndpointFatal
                    ) =>
                {
                    tracing::warn!(
                        "cross-endpoint self-test vs {:?} skipped (endpoint unavailable): {e}",
                        other.0
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    let retry = &config.crypto.retry;
    let budget = &config.crypto.retry_budget;
    let breaker = &config.crypto.circuit_breaker;
    let limits = &config.limits;
    let max_attempts = match config.crypto.availability_policy {
        maki_format::config::AvailabilityPolicy::Stall => None,
        maki_format::config::AvailabilityPolicy::BoundedError => {
            // Rough bound: enough passes to span max_operation_time at the
            // initial delay (jitter shortens real delays).
            let op_time = config
                .crypto
                .max_operation_time
                .map(|d| d.0)
                .unwrap_or(std::time::Duration::from_secs(30));
            let initial = retry
                .initial_delay
                .0
                .max(std::time::Duration::from_millis(1));
            Some((op_time.as_millis() / initial.as_millis()).clamp(1, 1000) as u32)
        }
    };
    let dispatch = DispatchConfig {
        retry: maki_crypto::retry::RetryPolicy {
            initial_delay: retry.initial_delay.0,
            max_delay: retry.max_delay.0,
        },
        budget: maki_crypto::retry::RetryBudgetConfig {
            retry_ratio: budget.retry_ratio,
            burst: budget.burst,
            min_probe_per_sec: budget.minimum_probe_rate.0,
        },
        breaker: maki_crypto::breaker::BreakerConfig {
            failure_threshold: breaker.failure_threshold,
            open_initial: breaker.open_initial.0,
            open_max: breaker.open_max.0,
            half_open_max_requests: breaker.half_open_max_requests,
            success_threshold: breaker.success_threshold,
        },
        global_max_inflight_batches: limits.max_crypto_inflight_batches,
        global_max_inflight_bytes: limits.max_crypto_inflight_bytes.0,
        per_endpoint_max_inflight: limits.max_inflight_per_endpoint,
        per_endpoint_max_bytes: limits.max_inflight_bytes_per_endpoint.0,
        max_attempts,
    };
    Ok(Arc::new(EndpointSet::new(
        endpoints,
        dispatch,
        Arc::new(SystemClock::new()),
    )))
}

pub fn engine_options(config: &VolumeConfig) -> EngineOptions {
    EngineOptions {
        volume: VolumeOptions {
            journal_segment_size: config.backing.journal_segment_size.0,
        },
        limits: EngineLimits {
            max_active_callbacks: config.limits.max_active_callbacks,
            max_plaintext_bytes: config.limits.max_plaintext_bytes.0,
        },
        cache: match config.cache.mode {
            maki_format::config::CacheMode::Off => None,
            maki_format::config::CacheMode::Read => Some(maki_core::engine::EngineCacheConfig {
                max_bytes: config.cache.max_bytes.0,
                ttl: config.cache.ttl.0,
            }),
        },
    }
}

/// Recovery + provider verification + ready engine (SPEC §27).
pub async fn attach_from_config(config: &VolumeConfig) -> Result<Engine, DaemonError> {
    let backing = build_backing(config)?;
    let provider = build_provider(config).await?;
    Ok(Engine::attach(backing, provider, engine_options(config)).await?)
}

/// `maki volume create`: initialize the on-disk layout for a configured
/// volume.
pub fn create_volume_from_config_str(raw: &str) -> Result<Superblock, DaemonError> {
    let config = parse_and_validate(raw)?;
    let backing = build_backing(&config)?;
    let geometry = config.geometry()?;
    let superblock = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::new_v4(),
        provider_type: config.crypto.provider.clone(),
        crypto_compatibility_id: config.crypto.crypto_compatibility_id.clone(),
        key_identity: config
            .crypto
            .key
            .as_ref()
            .map(|k| k.name.clone())
            .unwrap_or_default(),
        geometry,
        format_version: 1,
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    Ok(init::create_volume(backing.as_ref(), superblock)?)
}
