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
    check_provider_available(&config, cfg!(feature = "fake-provider"))?;
    Ok(config)
}

/// Providers a build can actually construct. The non-cryptographic `fake`
/// provider exists only behind the `fake-provider` feature (review M-008);
/// a release build must refuse it at validation time, not at attach.
pub fn check_provider_available(
    config: &VolumeConfig,
    fake_enabled: bool,
) -> Result<(), ConfigError> {
    if config.crypto.provider == "fake" && !fake_enabled {
        return Err(ConfigError::Invalid(
            "provider \"fake\" is not compiled into this build (feature `fake-provider`); \
             it is a test-only, non-cryptographic provider"
                .to_string(),
        ));
    }
    Ok(())
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
    // Public callers can supply an unvalidated configuration. Refuse name
    // collisions before the name-only credential router loads any secret.
    config.validate_credential_sources()?;
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

/// Credential router for header, metadata and TLS-key secrets (SPEC 9).
/// Every credential is loaded from exactly the source its reference
/// declares — `credential` (systemd credentials directory, failing closed
/// when it is unset), `file`, or `env` — never from a fallback (O-06: a
/// production daemon must not attach on a stray environment variable).
struct RoutedKeySource {
    /// credential name -> declared source
    sources: std::collections::HashMap<String, String>,
}

impl RoutedKeySource {
    fn from_config(config: &VolumeConfig) -> Self {
        Self {
            sources: config
                .credential_refs()
                .into_iter()
                .map(|c| (c.name.clone(), c.source.clone()))
                .collect(),
        }
    }
}

impl KeySource for RoutedKeySource {
    fn load(&self, name: &str) -> Result<maki_crypto::SecretBuffer, maki_crypto::CryptoError> {
        let fatal = |m: String| maki_crypto::CryptoError::ProviderFatal(m);
        let Some(source) = self.sources.get(name) else {
            return Err(fatal(format!(
                "credential {name:?} is not declared in the configuration"
            )));
        };
        match source.as_str() {
            "env" => EnvKeySource.load(name),
            "file" => {
                let path = std::path::Path::new(name);
                let dir = path.parent().unwrap_or(std::path::Path::new("."));
                let file = path
                    .file_name()
                    .ok_or_else(|| fatal(format!("credential path {name:?} has no file name")))?
                    .to_string_lossy()
                    .into_owned();
                FileKeySource::new(dir).load(&file)
            }
            "credential" => systemd_credential_source()
                .ok_or_else(|| {
                    fatal(format!(
                        "credential {name:?}: CREDENTIALS_DIRECTORY not set, failing closed"
                    ))
                })?
                .load(name),
            other => Err(fatal(format!(
                "credential {name:?}: unsupported source {other:?}"
            ))),
        }
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
            &RoutedKeySource::from_config(config),
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
        metadata.push((
            name.clone(),
            resolve_metadata_value(&RoutedKeySource::from_config(config), value)?,
        ));
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
fn resolve_metadata_value(
    keys: &RoutedKeySource,
    value: &maki_format::config::HeaderValue,
) -> Result<String, DaemonError> {
    match value {
        maki_format::config::HeaderValue::Literal(v) => Ok(v.clone()),
        maki_format::config::HeaderValue::Credential(cred) => {
            let secret = keys.load(&cred.name)?;
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

/// Cross-endpoint interchangeability check (SPEC 34) plus the dispatcher
/// (retry/budget/breaker/failover) shared by every remote transport.
///
/// Each endpoint is first probed on its own (a single-endpoint self-test):
/// endpoints that are unreachable right now are *quarantined* (review
/// M-011) and enter the set unvalidated; they only start serving once the
/// cross-endpoint check succeeds against a validated endpoint under the real
/// volume context. Reachable endpoints are cross-checked against the first
/// reachable one; proven non-interchangeability (or a misconfigured
/// endpoint) refuses attach. At least one endpoint must be reachable.
async fn dispatch_endpoint_set(
    config: &VolumeConfig,
    endpoints: Vec<(String, Arc<dyn CryptoProvider>)>,
) -> Result<Arc<dyn CryptoProvider>, DaemonError> {
    use maki_crypto::clock::SystemClock;
    use maki_crypto::endpoint::{DispatchConfig, EndpointSet, EndpointValidator};
    use maki_crypto::selftest::{cross_endpoint_self_test, provider_self_test};

    let unit = config.volume.crypto_unit_size as usize;
    let compat = config.crypto.crypto_compatibility_id.clone();
    let transport_failure = |e: &maki_crypto::CryptoError| {
        matches!(
            e.class(),
            maki_crypto::ErrorClass::Retryable
                | maki_crypto::ErrorClass::Throttled
                | maki_crypto::ErrorClass::EndpointFatal
        )
    };
    // Synthetic context with the configured profile; the volume UUID is
    // bound by the attach-time self-test and by later revalidation.
    let context = maki_crypto::CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: compat.clone(),
    };

    // 1. Reachability: every endpoint on its own, tolerating a few transient
    //    failures. A single endpoint has nothing to cross-validate against:
    //    the engine self-test (through the retrying dispatcher) covers it.
    let mut reachable: Vec<(String, Arc<dyn CryptoProvider>)> = Vec::new();
    let mut quarantined: Vec<(String, Arc<dyn CryptoProvider>)> = Vec::new();
    let single = endpoints.len() == 1;
    let probe_delay = config.crypto.retry.initial_delay.0;
    for (name, provider) in endpoints {
        if single {
            reachable.push((name, provider));
            break;
        }
        let mut last: Option<maki_crypto::CryptoError> = None;
        for attempt in 0..3 {
            match provider_self_test(provider.as_ref(), &context, unit, &compat).await {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(e) if transport_failure(&e) => {
                    last = Some(e);
                    if attempt < 2 {
                        tokio::time::sleep(probe_delay).await;
                    }
                }
                Err(e) => {
                    return Err(DaemonError::Unsupported(format!(
                        "endpoint {name:?} failed its self-test: {e}"
                    )))
                }
            }
        }
        match last {
            None => reachable.push((name, provider)),
            Some(e) => {
                tracing::warn!("endpoint {name:?} quarantined: unreachable at attach ({e})");
                quarantined.push((name, provider));
            }
        }
    }
    if reachable.is_empty() {
        return Err(DaemonError::Unsupported(
            "no remote endpoint is reachable; attach refused".to_string(),
        ));
    }

    // 2. Interchangeability among the reachable ones (SPEC 34).
    let mut flagged: Vec<(String, Arc<dyn CryptoProvider>, bool)> = Vec::new();
    let reference = reachable[0].1.clone();
    for (index, (name, provider)) in reachable.into_iter().enumerate() {
        if index == 0 {
            flagged.push((name, provider, true));
            continue;
        }
        match cross_endpoint_self_test(reference.as_ref(), provider.as_ref(), &context, unit).await
        {
            Ok(()) => flagged.push((name, provider, true)),
            Err(e) if transport_failure(&e) => {
                tracing::warn!(
                    "endpoint {name:?} quarantined: cross-endpoint self-test could not run ({e})"
                );
                flagged.push((name, provider, false));
            }
            // Proven non-interchangeability (ProviderFatal / contract)
            // refuses attach (SPEC 12, 34).
            Err(e) => return Err(e.into()),
        }
    }
    for (name, provider) in quarantined {
        flagged.push((name, provider, false));
    }

    let validator: EndpointValidator = Arc::new(move |reference, candidate, context| {
        Box::pin(async move {
            cross_endpoint_self_test(reference.as_ref(), candidate.as_ref(), &context, unit).await
        })
    });

    let retry = &config.crypto.retry;
    let budget = &config.crypto.retry_budget;
    let breaker = &config.crypto.circuit_breaker;
    let limits = &config.limits;
    let (max_attempts, max_operation_time) = match config.crypto.availability_policy {
        maki_format::config::AvailabilityPolicy::Stall => (None, None),
        maki_format::config::AvailabilityPolicy::BoundedError => {
            // The absolute deadline is the contract (SPEC 35); the pass
            // bound is a belt-and-braces cap derived from it.
            let op_time = config
                .crypto
                .max_operation_time
                .map(|d| d.0)
                .unwrap_or(std::time::Duration::from_secs(30));
            let initial = retry
                .initial_delay
                .0
                .max(std::time::Duration::from_millis(1));
            (
                Some((op_time.as_millis() / initial.as_millis()).clamp(1, 1000) as u32),
                Some(op_time),
            )
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
        max_operation_time,
        retry_safe: config.crypto.capabilities.retry_safe,
        validation_interval: breaker.open_initial.0,
    };
    Ok(Arc::new(EndpointSet::with_quarantine(
        flagged,
        Some(validator),
        dispatch,
        Arc::new(SystemClock::new()),
    )))
}

pub fn engine_options(config: &VolumeConfig) -> EngineOptions {
    EngineOptions {
        checkpoint: maki_core::engine::CheckpointPolicy {
            journal_high_watermark_bytes: config.backing.journal_max_bytes.0 / 2,
            journal_max_bytes: config.backing.journal_max_bytes.0,
            max_pending_bytes: config.limits.max_journal_pending_bytes.0,
            emergency_reserve_bytes: config.backing.journal_emergency_reserve_bytes.0,
            low_space_checkpoint_bytes: config.backing.checkpoint_reserve_bytes.0,
            interval: std::time::Duration::from_secs(30),
        },
        clock: None,
        identity: Some(maki_core::engine::AttachIdentity {
            provider_type: config.crypto.provider.clone(),
            key_identity: config
                .crypto
                .key
                .as_ref()
                .map(|k| k.name.clone())
                .unwrap_or_default(),
        }),
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
    Ok(attach_from_config_with_stats(config).await?.0)
}

/// Like [`attach_from_config`], also returning the batch scheduler's stats
/// handle when the provider is remote (SPEC 30: remote calls are coalesced
/// through a bounded batch scheduler; local providers are called directly).
pub async fn attach_from_config_with_stats(
    config: &VolumeConfig,
) -> Result<(Engine, Option<Arc<maki_crypto::scheduler::SchedulerStats>>), DaemonError> {
    // Process hardening first (SPEC 36-37): nothing secret exists yet.
    crate::security::apply(config)?;
    let backing = build_backing(config)?;
    let provider = build_provider(config).await?;
    let (provider, stats) = if config.crypto.provider.starts_with("remote-") {
        let scheduler = maki_crypto::scheduler::BatchScheduler::new(
            provider,
            scheduler_config(config),
            Arc::new(maki_crypto::SystemClock::new()),
        );
        let stats = scheduler.stats();
        (Arc::new(scheduler) as Arc<dyn CryptoProvider>, Some(stats))
    } else {
        (provider, None)
    };
    let engine = Engine::attach(backing, provider, engine_options(config)).await?;
    Ok((engine, stats))
}

/// `[crypto.batch]` targets and maxima plus the `[limits]` pending bounds
/// (`max_pending_crypto_items`, `max_pending_crypto_bytes` for plaintext,
/// `max_ciphertext_bytes` for ciphertext).
pub fn scheduler_config(config: &VolumeConfig) -> maki_crypto::scheduler::SchedulerConfig {
    let batch = &config.crypto.batch;
    let limits = &config.limits;
    maki_crypto::scheduler::SchedulerConfig {
        target_items: batch.target_items as usize,
        target_bytes: batch.target_bytes.0,
        max_items: batch.max_items as usize,
        max_bytes: batch.max_bytes.0,
        max_wait: batch.max_wait.0,
        max_pending_items: limits.max_pending_crypto_items,
        max_pending_plaintext_bytes: limits.max_pending_crypto_bytes.0,
        max_pending_ciphertext_bytes: limits.max_ciphertext_bytes.0,
        max_inflight_batches: limits.max_crypto_inflight_batches,
    }
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

/// The per-volume control socket path (SPEC §7): `control.socket`, or
/// `/run/maki-control/<volume>/control.sock`.
pub fn control_socket_path(config: &VolumeConfig) -> String {
    config
        .control
        .socket
        .clone()
        .unwrap_or_else(|| format!("/run/maki-control/{}/control.sock", config.volume.name))
}
