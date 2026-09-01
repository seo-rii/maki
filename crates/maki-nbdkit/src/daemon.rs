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
pub fn build_provider(config: &VolumeConfig) -> Result<Arc<dyn CryptoProvider>, DaemonError> {
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
        "remote-http" => crate::daemon::remote_http_provider(config),
        other => Err(DaemonError::Unsupported(format!("provider {other:?}"))),
    }
}

/// Placeholder until Phase 8 wires the HTTP transport.
#[allow(unused_variables)]
pub(crate) fn remote_http_provider(
    config: &VolumeConfig,
) -> Result<Arc<dyn CryptoProvider>, DaemonError> {
    Err(DaemonError::Unsupported(
        "remote-http provider lands in Phase 8".to_string(),
    ))
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
    }
}

/// Recovery + provider verification + ready engine (SPEC §27).
pub async fn attach_from_config(config: &VolumeConfig) -> Result<Engine, DaemonError> {
    let backing = build_backing(config)?;
    let provider = build_provider(config)?;
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
