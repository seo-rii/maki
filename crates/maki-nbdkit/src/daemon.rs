//! Config-driven daemon assembly: backing + provider + engine.

use std::path::Path;
use std::sync::Arc;

use maki_backing::{Backing, FileBacking, WitnessAnswer};
#[cfg(target_os = "linux")]
use maki_backing::{ReadOnlyRollbackBacking, RollbackBacking};
use maki_core::engine::{AttachError, Engine, EngineLimits, EngineOptions};
use maki_core::volume::{Volume, VolumeOptions};
use maki_crypto::endpoint::EndpointSet;
use maki_crypto::CryptoProvider;
use maki_crypto_local::keysource::{
    systemd_credential_source, EnvKeySource, FileKeySource, KeySource,
};
use maki_crypto_local::{AesGcmSivProvider, AesXtsProvider};
use maki_format::checker::CheckReport;
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
    #[cfg(not(target_os = "linux"))]
    if config.backing.rollback_protection.is_some() {
        return Err(ConfigError::Invalid(
            "backing rollback protection is supported only on Linux".to_string(),
        ));
    }
    check_provider_compiled(&config)?;
    Ok(config)
}

/// [`check_provider_available`] for the providers compiled into this build.
/// Every entry point that initializes a volume records the configured
/// provider in its superblock, so it calls this before changing the backing
/// or the remote authority.
pub fn check_provider_compiled(config: &VolumeConfig) -> Result<(), ConfigError> {
    check_provider_available(config, cfg!(feature = "fake-provider"))
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

/// Construct the authenticated remote authority shared by volume lifecycle
/// operations and explicit administrative recovery commands.
pub fn remote_witness_client(
    remote: &maki_format::config::RemoteWitnessSection,
) -> Result<Arc<dyn maki_backing::remote_witness::Rpc>, DaemonError> {
    let addresses = if remote.addresses.is_empty() {
        std::slice::from_ref(&remote.address)
    } else {
        remote.addresses.as_slice()
    };
    let options = addresses
        .iter()
        .map(|address| {
            Ok(maki_witness::ClientOptions {
                address: address.parse().map_err(|_| {
                    DaemonError::Unsupported(
                        "remote witness requires a numeric socket address".into(),
                    )
                })?,
                server_name: remote.server_name.clone(),
                timeout_ms: remote.timeout_ms,
                tls: maki_witness::TlsFiles {
                    ca_file: (&remote.ca_file).into(),
                    cert_file: (&remote.client_cert_file).into(),
                    key_file: (&remote.client_key_file).into(),
                },
            })
        })
        .collect::<Result<Vec<_>, DaemonError>>()?;
    if let Some(identity) = remote.storage_identity {
        Ok(Arc::new(maki_witness::failover::FailoverClient::new(
            options,
            *identity.as_bytes(),
            remote.timeout_ms,
        )?))
    } else if options.len() == 1 && remote.addresses.is_empty() {
        Ok(Arc::new(maki_witness::Client::new(
            options.into_iter().next().expect("checked singleton"),
        )?))
    } else {
        Err(DaemonError::Unsupported(
            "witness failover requires an explicit storage_identity".into(),
        ))
    }
}

pub fn build_backing(config: &VolumeConfig) -> Result<Arc<dyn Backing>, DaemonError> {
    open_backing(config, false)
}

/// [`build_backing`] for a writer that then compares the configuration with
/// the recovered volume ([`refuse_configuration_mismatch`]): attach, and a
/// remote provider built on its own. With remote rollback protection,
/// opening the backing claims a writer at the authority and copies the
/// current generation into a namespace of its own; the configuration is
/// compared with that generation first, and one that differs is refused with
/// nothing claimed ([`refuse_before_claim`]).
fn build_backing_to_attach(config: &VolumeConfig) -> Result<Arc<dyn Backing>, DaemonError> {
    open_backing(config, true)
}

fn open_backing(
    config: &VolumeConfig,
    compare_before_claim: bool,
) -> Result<Arc<dyn Backing>, DaemonError> {
    if let Some(rollback) = &config.backing.rollback_protection {
        #[cfg(target_os = "linux")]
        {
            let backing = match &rollback.remote {
                Some(remote) => RollbackBacking::open_remote_checked(
                    Path::new(&config.backing.root),
                    remote_witness_client(remote)?,
                    |current| {
                        if compare_before_claim {
                            refuse_before_claim(config, rollback, current)
                        } else {
                            Ok(())
                        }
                    },
                )?,
                None => RollbackBacking::open(
                    Path::new(&config.backing.root),
                    Path::new(&rollback.witness_root),
                )?,
            };
            if rollback.remote.is_none() {
                refuse_unfinished_creation(&backing)?;
            }
            check_protected_capacity(rollback, backing.capacity()?)?;
            return Ok(Arc::new(backing));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rollback, compare_before_claim);
            return Err(DaemonError::Unsupported(
                "backing rollback protection is supported only on Linux".to_string(),
            ));
        }
    }

    // A protected root is never silently reinterpreted as a plain directory
    // if its configuration stanza is accidentally removed.
    if Path::new(&config.backing.root)
        .join("rollback.format")
        .try_exists()?
    {
        return Err(DaemonError::Unsupported(
            "protected backing requires [backing.rollback_protection]".to_string(),
        ));
    }
    Ok(Arc::new(FileBacking::new(&config.backing.root)?))
}

/// A local creation that stopped after its witness anchor left a pair that
/// opens and holds no volume. Say so, and what continues it, in place of a
/// bare "no valid superblock", and before the capacity is compared: there
/// is no volume yet whose capacity a configuration could contradict, and
/// `create` names both values when it continues the pair.
#[cfg(target_os = "linux")]
fn refuse_unfinished_creation(backing: &dyn Backing) -> Result<(), DaemonError> {
    if init::unfinished_creation(backing)? {
        return Err(DaemonError::Format(FormatError::Invalid(
            "no valid superblock: this volume's creation did not complete (its \
             rollback-protected backing holds only an unfinished creation); run `maki \
             volume create` again, which continues it"
                .to_string(),
        )));
    }
    Ok(())
}

/// What attach refuses once it has opened and recovered a remote-protected
/// volume, refused before it claims a writer: a configured capacity that is
/// not the stored one, then a setting fixed at creation that the superblock
/// of the authority's `current` generation does not store. That superblock
/// is the one recovery selects after the claim, which copies the generation
/// unchanged, and its fixed settings are the same in every valid copy;
/// attach compares again after recovery all the same.
///
/// Only the two superblock copies are read, each page authenticated against
/// the manifest the authority selects (at most two 4 KiB pages), and
/// nothing else: the open has already sent its one inspection and read and
/// authenticated the manifest, as it did before. A read that fails (a page
/// that does not authenticate) is refused here too, where the claim would
/// otherwise have been sent and the copy then failed. A generation that
/// holds no valid superblock has nothing to compare with: recovery refuses
/// it after the claim, as before.
#[cfg(target_os = "linux")]
fn refuse_before_claim(
    config: &VolumeConfig,
    rollback: &maki_format::config::RollbackProtectionSection,
    current: &ReadOnlyRollbackBacking,
) -> Result<(), DaemonError> {
    check_protected_capacity(rollback, current.capacity()?)?;
    match maki_format::superblock::load_volume_superblock(current) {
        Ok(envelope) => refuse_configuration_mismatch(config, &envelope.superblock),
        Err(error @ FormatError::Io(_)) => Err(error.into()),
        Err(_) => Ok(()),
    }
}

/// Refuse a configured capacity that differs from the `stored` one.
#[cfg(target_os = "linux")]
fn check_protected_capacity(
    rollback: &maki_format::config::RollbackProtectionSection,
    stored: u64,
) -> Result<(), DaemonError> {
    if rollback.capacity.0 != stored {
        return Err(DaemonError::Unsupported(format!(
            "protected backing capacity mismatch: configuration {}, stored {stored}; migration is required",
            rollback.capacity.0
        )));
    }
    Ok(())
}

/// The backing of an existing volume for a command that only reads it
/// (`maki check`, `maki check --deep`, `maki volume inspect`).
///
/// Where this process may write the backing root (and, with local rollback
/// protection, the witness directory) this is [`build_backing`], exactly as
/// before. Where it may not ([`FileBacking::may_write`], Linux only: a read-only
/// mount, a read-only bind mount, a directory it may not write, an immutable
/// one), a plain root opens as a [`FileBacking::read_only`] view, which
/// creates, writes, syncs and removes nothing; a check through it says so
/// and claims less (`maki_format::checker::READ_ONLY_CHECK`). The commands
/// cannot work through a writable backing there: every file would be opened
/// read-write, which such a root refuses.
///
/// A local rollback-protected backing whose root or witness directory this
/// process may not write, either of them, opens as a
/// [`ReadOnlyRollbackBacking`]: the same authentication against the witness
/// as [`build_backing`]'s open, without its rewrites of the authenticated
/// state and of the witness anchor (the failed writeback rule, K-01), with
/// the locks taken shared. The directories decide, as the root does for a
/// plain backing: beside a root it may write, in a witness directory it may
/// not write, that open fails at the witness, when it takes `witness.lock`
/// or publishes the anchor (after taking the root's `rollback.lock`, which
/// it creates if it is missing), and a root it may not write is read
/// read-only even where its files could be rewritten. Where both can be
/// written it is [`build_backing`], as before. A remote one always opens as
/// a [`ReadOnlyRollbackBacking`], which sends the authority only
/// inspections: [`build_backing`] claims a writer at the authority and
/// copies the current generation into a namespace of its own, which a
/// command that only reads must never do. That view asks the authority
/// again only when it is asked ([`Backing::check_freshness`]): a command
/// that reports what it read through the backing returned here calls it
/// once it has read everything, before it reports.
pub fn build_backing_to_read(config: &VolumeConfig) -> Result<Arc<dyn Backing>, DaemonError> {
    use maki_backing::configured::BACKING_ROOT;
    let root = Path::new(&config.backing.root);
    if let Some(rollback) = &config.backing.rollback_protection {
        #[cfg(target_os = "linux")]
        {
            use maki_backing::configured::WITNESS_ROOT;
            let backing = match &rollback.remote {
                Some(remote) => {
                    ReadOnlyRollbackBacking::open_remote(root, remote_witness_client(remote)?)?
                }
                None => {
                    let witness = Path::new(&rollback.witness_root);
                    BACKING_ROOT.reachable(root)?;
                    WITNESS_ROOT.reachable(witness)?;
                    if BACKING_ROOT.may_write(root)? && WITNESS_ROOT.may_write(witness)? {
                        return build_backing(config);
                    }
                    let backing = ReadOnlyRollbackBacking::open(root, witness)?;
                    refuse_unfinished_creation(&backing)
                        .map_err(|error| refused_after_reading(&backing, error))?;
                    backing
                }
            };
            check_protected_capacity(rollback, backing.capacity()?)
                .map_err(|error| refused_after_reading(&backing, error))?;
            return Ok(Arc::new(backing));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = rollback;
            return build_backing(config);
        }
    }
    // Ask about the view that is then read, through its pinned descriptor:
    // the directory found unwritable is the one checked. A root that becomes
    // unwritable before `build_backing` opens it again fails there, as it
    // did before; nothing is opened for writing on the read-only path.
    let view = FileBacking::read_only(root).map_err(|error| BACKING_ROOT.refusal(root, error))?;
    if view
        .may_write()
        .map_err(|error| BACKING_ROOT.refusal(root, error))?
    {
        return build_backing(config);
    }
    // As `build_backing` refuses it: a protected root is never read as a
    // plain one because its configuration stanza went missing.
    if view.exists("rollback.format")? {
        return Err(DaemonError::Unsupported(
            "protected backing requires [backing.rollback_protection]".to_string(),
        ));
    }
    Ok(Arc::new(view))
}

/// How a command that reads a backing through [`build_backing_to_read`]
/// reports `failure`, met after the backing was opened. A remote view asks
/// its authority only while it opens and when asked, and a command asks it
/// before it reports what it read (SPEC §27); it asks before it reports a
/// failure too ([`Backing::ask_witness_again`]), also when the failure
/// stopped the view (a page that no longer authenticates). If the witness no
/// longer selects what was read, or answered so that the view stopped (a
/// denial, an invalid answer), that answer is reported instead of the
/// failure; if it cannot be asked, the failure is, saying so. A view that
/// stopped on what it read is reported by its stop reason, which names
/// that. Any other backing answers as it answers before each of its
/// operations.
pub fn read_failure(backing: &dyn Backing, failure: String) -> String {
    match backing.ask_witness_again() {
        WitnessAnswer::Selects => backing.session_stopped().unwrap_or(failure),
        WitnessAnswer::Stopped(reason) => reason,
        WitnessAnswer::Unanswered(error) => unanswered(
            &backing.session_stopped().unwrap_or(failure),
            &error.to_string(),
        ),
    }
}

/// Whether the witness still selects what a command read through a backing
/// that [`build_backing_to_read`] opened, asked once the command has read
/// everything it reports, before it reports (SPEC §27): one inspection of a
/// remote authority, however much was read. A record that changed since the
/// view was opened fails the command, and so does a view that stopped, after
/// its witness has been asked again as for any failure ([`read_failure`]).
pub fn still_current(backing: &dyn Backing) -> Result<(), String> {
    match backing.check_freshness() {
        Ok(()) => Ok(()),
        Err(error) => Err(match backing.session_stopped() {
            None => error.to_string(),
            Some(_) => read_failure(backing, error.to_string()),
        }),
    }
}

/// [`read_failure`] for a refusal of [`build_backing_to_read`] itself.
#[cfg(target_os = "linux")]
fn refused_after_reading(backing: &dyn Backing, refusal: DaemonError) -> DaemonError {
    match backing.ask_witness_again() {
        WitnessAnswer::Selects => match backing.session_stopped() {
            Some(reason) => {
                DaemonError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, reason))
            }
            None => refusal,
        },
        WitnessAnswer::Stopped(reason) => {
            DaemonError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, reason))
        }
        WitnessAnswer::Unanswered(error) => DaemonError::Io(std::io::Error::other(unanswered(
            &backing
                .session_stopped()
                .unwrap_or_else(|| refusal.to_string()),
            &error.to_string(),
        ))),
    }
}

fn unanswered(failure: &dyn std::fmt::Display, error: &str) -> String {
    format!(
        "{failure}; the witness could not be asked again whether it still selects what was \
         read: {error}"
    )
}

/// Check for volume markers without opening a writer session or contacting the witness.
/// A marker is sufficient to require explicit authorization before benchmarking.
pub fn volume_layout_present(config: &VolumeConfig) -> Result<bool, DaemonError> {
    config.validate()?;
    let root = Path::new(&config.backing.root);
    // A missing root holds no volume, and creation makes it. Any other root
    // that cannot be looked at is refused with its path and setting.
    match std::fs::metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        _ => maki_backing::configured::BACKING_ROOT.reachable(root)?,
    }
    let present = |name: &str| {
        root.join(name)
            .try_exists()
            .map_err(|error| maki_backing::configured::BACKING_ROOT.refusal(root, error))
    };
    Ok(present("rollback.format")?
        || present(maki_format::layout::SUPERBLOCK_A)?
        || present(maki_format::layout::SUPERBLOCK_B)?)
}

/// Open and validate an existing volume before a tool chooses creation or
/// explicitly authorized reuse. Protected backing must be opened through its
/// witness; trying enrollment first cannot classify its AlreadyExists error.
/// A present format marker with incomplete contents is an error, never a reset.
pub fn existing_volume_from_config(
    config: &VolumeConfig,
) -> Result<Option<Superblock>, DaemonError> {
    if !volume_layout_present(config)? {
        return Ok(None);
    }
    let backing = build_backing(config)?;
    let envelope = maki_format::superblock::load_volume_superblock(backing.as_ref())?;
    Ok(Some(envelope.superblock))
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

/// Build the configured crypto provider. A remote provider's endpoints are
/// probed against the volume, which is recovered for them and compared with
/// the configuration ([`configuration_mismatches`]) before any probe; a local
/// provider is only built, and attach compares the configuration before it
/// builds one.
pub async fn build_provider(config: &VolumeConfig) -> Result<Arc<dyn CryptoProvider>, DaemonError> {
    Ok(build_provider_with_endpoints(config).await?.0)
}

/// Build the configured provider; for remote providers also return the
/// endpoint dispatcher itself, whose per-endpoint state and retry counters
/// the control plane reports (SPEC §40).
pub async fn build_provider_with_endpoints(
    config: &VolumeConfig,
) -> Result<(Arc<dyn CryptoProvider>, Option<Arc<EndpointSet>>), DaemonError> {
    prepare_provider(config).await?.verify(config, None).await
}

enum PreparedProvider {
    Local(Arc<dyn CryptoProvider>),
    Remote(Vec<NamedEndpoint>),
}

impl PreparedProvider {
    async fn verify(
        self,
        config: &VolumeConfig,
        volume: Option<&Arc<Volume>>,
    ) -> Result<(Arc<dyn CryptoProvider>, Option<Arc<EndpointSet>>), DaemonError> {
        let set = match self {
            Self::Local(provider) => return Ok((provider, None)),
            Self::Remote(endpoints) => dispatch_endpoint_set(config, endpoints, volume).await?,
        };
        // Expand before entering the dispatcher, so retry and admission account
        // for the actual provider payload and reuse one prepared prefix per call.
        let provider = apply_random_prefix(
            set.clone(),
            config.volume.crypto_unit_size,
            config.crypto.random_prefix_bytes,
            &config.crypto.effective_compatibility_id(),
        )
        .await?;
        Ok((provider, Some(set)))
    }
}

async fn prepare_provider(config: &VolumeConfig) -> Result<PreparedProvider, DaemonError> {
    // Public callers can supply an unvalidated configuration. Refuse name
    // collisions before the name-only credential router loads any secret.
    config.validate_credential_sources()?;
    let unit = config.provider_plaintext_size()?;
    let compat = config.crypto.crypto_compatibility_id.as_str();
    let provider: Arc<dyn CryptoProvider> = match config.crypto.provider.as_str() {
        #[cfg(feature = "fake-provider")]
        "fake" => Arc::new(maki_test_support::FakeCryptoProvider::new(unit).with_compat_id(compat)),
        "local-aes-gcm-siv" | "local-aes-xts" => {
            let cred = config.crypto.key.as_ref().ok_or_else(|| {
                DaemonError::Unsupported("local provider requires [crypto].key".to_string())
            })?;
            let (source, name) = resolve_key_source(cred)?;
            if config.crypto.provider == "local-aes-gcm-siv" {
                Arc::new(AesGcmSivProvider::new(
                    source.as_ref(),
                    &name,
                    unit,
                    compat,
                )?)
            } else {
                Arc::new(AesXtsProvider::new(source.as_ref(), &name, unit, compat)?)
            }
        }
        "remote-http" => return Ok(PreparedProvider::Remote(http_endpoints(config)?)),
        "remote-websocket" => return Ok(PreparedProvider::Remote(websocket_endpoints(config)?)),
        "remote-grpc" => return Ok(PreparedProvider::Remote(grpc_endpoints(config)?)),
        other => return Err(DaemonError::Unsupported(format!("provider {other:?}"))),
    };
    Ok(PreparedProvider::Local(
        apply_random_prefix(
            provider,
            config.volume.crypto_unit_size,
            config.crypto.random_prefix_bytes,
            &config.crypto.effective_compatibility_id(),
        )
        .await?,
    ))
}

async fn apply_random_prefix(
    provider: Arc<dyn CryptoProvider>,
    logical_unit_size: u32,
    prefix_bytes: u32,
    compatibility_id: &str,
) -> Result<Arc<dyn CryptoProvider>, maki_crypto::CryptoError> {
    if prefix_bytes == 0 {
        return Ok(provider);
    }
    Ok(Arc::new(
        maki_crypto::RandomPrefixProvider::new(
            provider,
            logical_unit_size,
            prefix_bytes,
            compatibility_id.to_owned(),
        )
        .await?,
    ))
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
        let (source, leaf) = self.route(name)?;
        source.load(&leaf)
    }

    fn load_text(&self, name: &str) -> Result<maki_crypto::SecretBuffer, maki_crypto::CryptoError> {
        let (source, leaf) = self.route(name)?;
        source.load_text(&leaf)
    }
}

impl RoutedKeySource {
    /// The source a credential name is declared with, and the name to look
    /// up in it.
    fn route(&self, name: &str) -> Result<(Box<dyn KeySource>, String), maki_crypto::CryptoError> {
        let fatal = |m: String| maki_crypto::CryptoError::ProviderFatal(m);
        let Some(source) = self.sources.get(name) else {
            return Err(fatal(format!(
                "credential {name:?} is not declared in the configuration"
            )));
        };
        match source.as_str() {
            "env" => Ok((Box::new(EnvKeySource), name.to_string())),
            "file" => {
                let path = std::path::Path::new(name);
                let dir = path.parent().unwrap_or(std::path::Path::new("."));
                let file = path
                    .file_name()
                    .ok_or_else(|| fatal(format!("credential path {name:?} has no file name")))?
                    .to_string_lossy()
                    .into_owned();
                Ok((Box::new(FileKeySource::new(dir)), file))
            }
            "credential" => {
                let source = systemd_credential_source().ok_or_else(|| {
                    fatal(format!(
                        "credential {name:?}: CREDENTIALS_DIRECTORY not set, failing closed"
                    ))
                })?;
                Ok((Box::new(source), name.to_string()))
            }
            other => Err(fatal(format!(
                "credential {name:?}: unsupported source {other:?}"
            ))),
        }
    }
}

/// Construct the HTTP transports and resolve their local configuration.
fn http_endpoints(config: &VolumeConfig) -> Result<Vec<NamedEndpoint>, DaemonError> {
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
    let mut endpoints: Vec<NamedEndpoint> = Vec::new();
    for endpoint in &http.endpoint {
        let provider = maki_crypto_http::HttpCryptoProvider::from_config(
            config,
            &endpoint.url,
            &RoutedKeySource::from_config(config),
        )?;
        endpoints.push((endpoint.name.clone(), Arc::new(provider)));
    }
    Ok(endpoints)
}

fn read_tls_file(
    section: &str,
    field: &str,
    path: Option<&String>,
) -> Result<Option<Vec<u8>>, DaemonError> {
    // WebSocket and gRPC take the private key from a credential, so these
    // files are certificates or CA bundles: regular files, read without
    // blocking on a FIFO (same rules as HTTP).
    path.map(|path| {
        maki_crypto_http::read_tls_file(section, field, path, false)
            .map_err(|error| DaemonError::Unsupported(error.to_string()))
    })
    .transpose()
}

/// Construct the WS/WSS transports and verify their TLS configuration.
fn websocket_endpoints(config: &VolumeConfig) -> Result<Vec<NamedEndpoint>, DaemonError> {
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
    let max_frame_bytes = ws.frame_byte_limit()?;
    let tls = ws
        .tls
        .as_ref()
        .map(|tls| -> Result<_, DaemonError> {
            Ok(maki_crypto_websocket::WsTlsOptions {
                ca_pem: read_tls_file("websocket", "ca_file", tls.ca_file.as_ref())?,
                client_cert_pem: read_tls_file(
                    "websocket",
                    "client_cert_file",
                    tls.client_cert_file.as_ref(),
                )?,
                client_key_pem: tls
                    .client_key
                    .as_ref()
                    .map(|key| RoutedKeySource::from_config(config).load_text(&key.name))
                    .transpose()?
                    .map(Arc::new),
            })
        })
        .transpose()?;
    let mut endpoints: Vec<NamedEndpoint> = Vec::new();
    for endpoint in &ws.endpoint {
        let provider = maki_crypto_websocket::WsCryptoProvider::new_checked(
            maki_crypto_websocket::WsProviderSpec {
                url: endpoint.url.clone(),
                capabilities: capabilities_from_config(config, "remote-websocket"),
                timeout: ws
                    .timeout
                    .map(|d| d.0)
                    .unwrap_or(std::time::Duration::from_secs(10)),
                max_frame_bytes,
                tls: tls.clone(),
            },
        )?;
        endpoints.push((endpoint.name.clone(), Arc::new(provider)));
    }
    Ok(endpoints)
}

/// `remote-grpc`: fixed reference contract
/// (`packaging/examples/maki-crypto.proto`) at configurable method paths,
/// with credential-resolved ASCII metadata and verified HTTPS/mTLS support.
fn grpc_endpoints(config: &VolumeConfig) -> Result<Vec<NamedEndpoint>, DaemonError> {
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
    let keys = std::cell::LazyCell::new(|| RoutedKeySource::from_config(config));
    let tls = grpc
        .tls
        .as_ref()
        .map(|tls| -> Result<_, DaemonError> {
            let client_identity = match (&tls.client_cert_file, &tls.client_key) {
                (Some(cert), Some(key)) => Some(maki_crypto_grpc::GrpcClientIdentity {
                    certificate_pem: read_tls_file("grpc", "client_cert_file", Some(cert))?
                        .expect("certificate path is present"),
                    private_key_pem: keys.load_text(&key.name)?,
                }),
                (None, None) => None,
                _ => return Err(DaemonError::Unsupported(
                    "[crypto.grpc.tls] client certificate and private key must be configured together".into(),
                )),
            };
            Ok(maki_crypto_grpc::GrpcTlsConfig {
                ca_certificate_pem: read_tls_file("grpc", "ca_file", tls.ca_file.as_ref())?,
                client_identity,
            })
        })
        .transpose()?;
    // The template owns and erases the original resolved metadata, including
    // early errors while resolving later keys or building another endpoint.
    let mut template = maki_crypto_grpc::GrpcProviderSpec {
        url: String::new(),
        encrypt_path: grpc
            .encrypt_path
            .clone()
            .unwrap_or_else(|| maki_format::config::DEFAULT_GRPC_ENCRYPT_PATH.to_string()),
        decrypt_path: grpc
            .decrypt_path
            .clone()
            .unwrap_or_else(|| maki_format::config::DEFAULT_GRPC_DECRYPT_PATH.to_string()),
        metadata: Vec::new(),
        capabilities: capabilities_from_config(config, "remote-grpc"),
        timeout: grpc
            .timeout
            .map(|d| d.0)
            .unwrap_or(std::time::Duration::from_secs(10)),
        max_message_bytes: grpc.message_byte_limit()?,
    };
    for (name, value) in &grpc.metadata {
        template
            .metadata
            .push((name.clone(), resolve_metadata_value(&keys, value)?));
    }
    let mut endpoints: Vec<NamedEndpoint> = Vec::new();
    for endpoint in &grpc.endpoint {
        let mut spec = template.clone();
        spec.url = endpoint.url.clone();
        let encrypted = endpoint
            .url
            .split_once("://")
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"));
        let provider = if encrypted || tls.is_some() {
            maki_crypto_grpc::GrpcCryptoProvider::new_with_tls(
                spec,
                tls.clone().unwrap_or_default(),
            )?
        } else {
            maki_crypto_grpc::GrpcCryptoProvider::new(spec)?
        };
        endpoints.push((endpoint.name.clone(), Arc::new(provider)));
    }
    Ok(endpoints)
}

/// Declared `[crypto.capabilities]` as `CryptoCapabilities` (the same
/// mapping the HTTP provider applies inside `from_config`).
fn capabilities_from_config(
    config: &VolumeConfig,
    provider_id: &str,
) -> maki_crypto::CryptoCapabilities {
    let caps_cfg = &config.crypto.capabilities;
    let capability = |s: &str| match s {
        "verified" => maki_crypto::Capability::Contractual,
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
            max_items: config.effective_batch_max_items(),
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
            let secret = keys.load_text(&cred.name)?;
            // Borrow the guarded key bytes, including on invalid UTF-8. A
            // temporary String/from_utf8 error would release an unguarded copy.
            let text = std::str::from_utf8(secret.expose())
                .map_err(|_| DaemonError::Unsupported("credential is not valid UTF-8".to_string()))?
                .trim();
            match &cred.format {
                Some(template) => {
                    let replacements = template.matches("{}").count();
                    let length = replacements
                        .checked_mul(text.len())
                        .and_then(|bytes| bytes.checked_add(template.len() - replacements * 2))
                        .ok_or_else(|| {
                            DaemonError::Unsupported("formatted credential is too large".into())
                        })?;
                    // Allocate the final size once: growing String::replace
                    // can free earlier allocations containing credential bytes.
                    let mut value = String::with_capacity(length);
                    for (index, part) in template.split("{}").enumerate() {
                        if index != 0 {
                            value.push_str(text);
                        }
                        value.push_str(part);
                    }
                    Ok(value)
                }
                None => Ok(text.to_string()),
            }
        }
    }
}

fn transport_failure(e: &maki_crypto::CryptoError) -> bool {
    matches!(
        e.class(),
        maki_crypto::ErrorClass::Retryable
            | maki_crypto::ErrorClass::Throttled
            | maki_crypto::ErrorClass::EndpointFatal
    )
}

type NamedEndpoint = (String, Arc<dyn CryptoProvider>);

/// Record one failed reachability probe attempt: keep the first endpoint
/// failure among the attempts, and note whether the attempt may have reached
/// the endpoint.
fn note_probe_failure(
    error: &maki_crypto::CryptoError,
    endpoint_fatal: &mut Option<maki_crypto::CryptoError>,
    maybe_sent: &mut bool,
) {
    if endpoint_fatal.is_none() && error.class() == maki_crypto::ErrorClass::EndpointFatal {
        *endpoint_fatal = Some(error.duplicate());
    }
    *maybe_sent |= !error.is_not_sent();
}

type CheckedEndpoint = (String, Arc<dyn CryptoProvider>, bool);

async fn cross_validate_reachable(
    reachable: Vec<NamedEndpoint>,
    context: &maki_crypto::CryptoContext,
    unit: usize,
    prefix_bytes: u32,
) -> Result<Vec<CheckedEndpoint>, maki_crypto::CryptoError> {
    use maki_crypto::selftest::{cross_endpoint_self_test_attributed, CrossCheckSide};
    let mut quarantined = Vec::new();
    let mut verified = Vec::new();
    let mut remaining = std::collections::VecDeque::from(reachable);
    let mut reference = remaining.pop_front().expect("at least one reachable peer");
    while let Some(candidate) = remaining.pop_front() {
        let a = apply_random_prefix(
            reference.1.clone(),
            unit as u32,
            prefix_bytes,
            &context.crypto_compatibility_id,
        )
        .await?;
        let b = apply_random_prefix(
            candidate.1.clone(),
            unit as u32,
            prefix_bytes,
            &context.crypto_compatibility_id,
        )
        .await?;
        match cross_endpoint_self_test_attributed(a.as_ref(), b.as_ref(), context, unit).await {
            Ok(()) => verified.push(candidate),
            Err((side, error)) if transport_failure(&error) => {
                let unavailable = match side {
                    CrossCheckSide::Candidate => candidate,
                    CrossCheckSide::Reference => {
                        // Compare the candidate with a surviving verified peer when one
                        // exists. Otherwise use its successful individual check to start
                        // a new reference and cross-check the remaining peers against it.
                        let next = match verified.pop() {
                            Some(peer) => {
                                remaining.push_front(candidate);
                                peer
                            }
                            None => candidate,
                        };
                        std::mem::replace(&mut reference, next)
                    }
                };
                tracing::warn!(endpoint = %unavailable.0, "quarantined: cross-endpoint self-test could not run ({error})");
                quarantined.push(unavailable);
            }
            Err((_, error)) => return Err(error),
        }
    }
    let mut flagged: Vec<_> = std::iter::once(reference)
        .chain(verified)
        .map(|(name, provider)| (name, provider, true))
        .collect();
    for (name, provider) in quarantined {
        flagged.push((name, provider, false));
    }

    Ok(flagged)
}

/// Cross-endpoint interchangeability check (SPEC 34) plus the dispatcher
/// (retry/budget/breaker/failover) shared by every remote transport.
///
/// Each endpoint, a lone one included, is first probed on its own (a
/// single-endpoint self-test): endpoints that are unreachable right now are
/// *quarantined* (review M-011) and enter the set unvalidated; they only
/// start serving once the cross-endpoint check succeeds against a validated
/// endpoint under the real volume context. Reachable endpoints are
/// cross-checked against the first reachable one; proven
/// non-interchangeability (or a misconfigured endpoint) refuses attach. At
/// least one endpoint must be reachable, and the refusal names each
/// endpoint's failure. The one exception is a lone endpoint that failed
/// only transiently and whose probe request may be sent again: it is
/// retried under the availability policy.
async fn dispatch_endpoint_set(
    config: &VolumeConfig,
    endpoints: Vec<(String, Arc<dyn CryptoProvider>)>,
    volume: Option<&Arc<Volume>>,
) -> Result<Arc<EndpointSet>, DaemonError> {
    // Provider-only construction still needs a real, exclusively held volume;
    // constructing transports first retains early credential/config errors.
    let recovered;
    let volume = match volume {
        Some(volume) => volume,
        None => {
            let backing = build_backing_to_attach(config)?;
            let options = engine_options(config).volume;
            recovered = Arc::new(
                tokio::task::spawn_blocking(move || Volume::recover(backing, options))
                    .await
                    .map_err(|e| DaemonError::Unsupported(format!("recovery worker failed: {e}")))?
                    .map_err(AttachError::from)?,
            );
            &recovered
        }
    };
    refuse_configuration_mismatch(config, volume.superblock())?;
    use maki_crypto::checked::CheckedProvider;
    use maki_crypto::clock::SystemClock;
    use maki_crypto::endpoint::{DispatchConfig, EndpointValidator};
    use maki_crypto::selftest::{cross_endpoint_self_test, provider_self_test};

    let unit = config.volume.crypto_unit_size as usize;
    let prefix_bytes = config.crypto.random_prefix_bytes;
    let compat = config.crypto.effective_compatibility_id();
    let superblock = volume.superblock();
    let context = maki_crypto::CryptoContext {
        volume_uuid: superblock.volume_uuid,
        format_version: superblock.format_version,
        crypto_compatibility_id: superblock.crypto_compatibility_id.clone(),
    };

    // 1. Reachability: every endpoint on its own, a lone one included,
    //    tolerating a few transient failures only when it permits resending
    //    a request. Left to the engine self-test, which runs through the
    //    dispatcher, a lone endpoint that cannot serve as configured made
    //    `stall` wait at attach forever, with nothing logged and no control
    //    socket to ask.
    let mut reachable: Vec<(String, Arc<dyn CryptoProvider>)> = Vec::new();
    // A failed endpoint with the failure to report and whether the
    // dispatcher may send the probe's request to it again.
    let mut failed: Vec<(
        String,
        Arc<dyn CryptoProvider>,
        maki_crypto::CryptoError,
        bool,
    )> = Vec::new();
    let lone = endpoints.len() == 1;
    let probe_delay = config.crypto.retry.initial_delay.0;
    for (name, provider) in endpoints {
        let validation_provider =
            apply_random_prefix(provider.clone(), unit as u32, prefix_bytes, &compat).await?;
        // Self-tests and canary checks make real RPCs. A lost response does
        // not prove the operation was unapplied, so the whole probe must not
        // be restarted for a provider that does not promise retry safety.
        let retry_safe = validation_provider.capabilities().await?.retry_safe;
        let probe_attempts = if retry_safe { 3 } else { 1 };
        let mut last: Option<maki_crypto::CryptoError> = None;
        // Across the attempts: the first endpoint failure, and whether any
        // attempt may have reached the endpoint.
        let mut endpoint_fatal: Option<maki_crypto::CryptoError> = None;
        let mut maybe_sent = false;
        for attempt in 0..probe_attempts {
            match provider_self_test(validation_provider.as_ref(), &context, unit, &compat).await {
                Ok(()) => {
                    let caps = validation_provider.capabilities().await?;
                    let checked = CheckedProvider::pinned(validation_provider.clone(), unit as u32);
                    match maki_core::engine::verify_key_canary(
                        volume.clone(),
                        &checked,
                        &context,
                        caps.integrity.present(),
                    )
                    .await
                    {
                        Ok(()) => {
                            last = None;
                            break;
                        }
                        Err(AttachError::Crypto(e)) if transport_failure(&e) => {
                            note_probe_failure(&e, &mut endpoint_fatal, &mut maybe_sent);
                            last = Some(e);
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(e) if transport_failure(&e) => {
                    note_probe_failure(&e, &mut endpoint_fatal, &mut maybe_sent);
                    last = Some(e);
                }
                Err(e) => {
                    return Err(DaemonError::Unsupported(format!(
                        "endpoint {name:?} failed its self-test: {e}"
                    )))
                }
            }
            if attempt + 1 < probe_attempts {
                tokio::time::sleep(probe_delay).await;
            }
        }
        match last {
            None => reachable.push((name, provider)),
            Some(last) => {
                let resendable = endpoint_fatal.is_none() && (retry_safe || !maybe_sent);
                failed.push((name, provider, endpoint_fatal.unwrap_or(last), resendable));
            }
        }
    }
    // A lone endpoint has no peer to serve while it is away. When no probe
    // attempt gave an endpoint failure and the dispatcher may send the
    // probe's request again (the provider is retry-safe, or no attempt may
    // have reached the endpoint), the engine self-test retries it through
    // the dispatcher under the availability policy: `stall` waits for it,
    // `bounded-error` gives up at `max_operation_time`. Otherwise the
    // probe's failure is final, as the dispatcher would make it: an endpoint
    // failure (TLS authentication, a refused or misrouted request) in any
    // attempt shows the endpoint cannot serve as configured, and a request of
    // a provider that is not retry-safe that may have reached the endpoint
    // is never sent again (SPEC §18).
    if lone && matches!(&failed[..], [(_, _, _, true)]) {
        let (name, provider, e, _) = failed.pop().expect("one failed endpoint");
        let policy = match config.crypto.availability_policy {
            maki_format::config::AvailabilityPolicy::Stall => "stall",
            maki_format::config::AvailabilityPolicy::BoundedError => "bounded-error",
        };
        tracing::warn!(
            "endpoint {name:?} unreachable at attach ({e}); it is the only endpoint, so the \
             attach keeps retrying it under the `{policy}` availability policy"
        );
        reachable.push((name, provider));
    }
    let mut quarantined: Vec<(String, Arc<dyn CryptoProvider>)> = Vec::new();
    let mut unreachable: Vec<String> = Vec::new();
    for (name, provider, e, _) in failed {
        // A lone endpoint left here refuses the attach, whose error says why.
        if !lone {
            tracing::warn!("endpoint {name:?} quarantined: unreachable at attach ({e})");
        }
        unreachable.push(format!("{name:?}: {e}"));
        quarantined.push((name, provider));
    }
    if reachable.is_empty() {
        return Err(DaemonError::Unsupported(format!(
            "no remote endpoint is reachable; attach refused ({})",
            unreachable.join("; ")
        )));
    }

    // 2. Interchangeability among the reachable ones (SPEC 34).
    let mut flagged = cross_validate_reachable(reachable, &context, unit, prefix_bytes).await?;
    flagged.extend(
        quarantined
            .into_iter()
            .map(|(name, provider)| (name, provider, false)),
    );

    // Snapshot the canary for later endpoint revalidation without blocking
    // the async dispatcher; cancellation retains the recovered volume lock.
    let reading = volume.clone();
    let canary = tokio::task::spawn_blocking(move || {
        maki_format::ab::AbStore::new(
            maki_format::layout::KEY_CANARY_A,
            maki_format::layout::KEY_CANARY_B,
        )
        .load::<maki_format::canary::KeyCanary>(reading.backing().as_ref())
    })
    .await
    .map_err(|e| DaemonError::Unsupported(format!("canary storage worker failed: {e}")))??;
    // The set excludes the candidate for good when this validation fails
    // with `ProviderFatal` or `UnsupportedContext` (`EndpointValidator`).
    // `reference` and `candidate` are the set's validation views, which
    // relabel every failure an endpoint returns that proves nothing, so the
    // checks below reach such a verdict only from the candidate's own
    // replies. The random-prefix wrapper stacked on the views here has
    // errors of its own, but none that a configuration attach accepted can
    // produce: it checks the capabilities, unit size and RPC byte budgets
    // that configuration validation, the reachability probe and `verify`
    // already checked, and the checks split their requests by its batch
    // limits. Its one runtime failure, an operating-system random source
    // that fails, fails every encrypt the volume serves as well.
    let validation_context = context.clone();
    let validator: EndpointValidator = Arc::new(move |reference, candidate, _request_context| {
        let context = validation_context.clone();
        let canary = canary.clone();
        Box::pin(async move {
            let candidate = apply_random_prefix(
                candidate,
                unit as u32,
                prefix_bytes,
                &context.crypto_compatibility_id,
            )
            .await?;
            let reference = apply_random_prefix(
                reference,
                unit as u32,
                prefix_bytes,
                &context.crypto_compatibility_id,
            )
            .await?;
            provider_self_test(
                candidate.as_ref(),
                &context,
                unit,
                &context.crypto_compatibility_id,
            )
            .await?;
            if let Some(canary) = canary {
                let checked = CheckedProvider::pinned(candidate.clone(), unit as u32);
                let plain = checked
                    .decrypt_batch(
                        &context,
                        &[maki_crypto::CiphertextUnit {
                            unit_index: canary.unit_index,
                            data: canary.ciphertext,
                        }],
                    )
                    .await
                    .map_err(|error| match error {
                        // The validated endpoints authenticated this canary
                        // under the volume context at attach, so its
                        // refusal proves another key, like a wrong
                        // plaintext below. Any other failure only shows a
                        // failed exchange and is validated again later.
                        maki_crypto::CryptoError::Integrity(reason) => {
                            maki_crypto::CryptoError::ProviderFatal(format!(
                                "quarantined endpoint does not match the volume key canary: \
                                 {reason}"
                            ))
                        }
                        other => other,
                    })?;
                if plain[0].data.expose()
                    != maki_format::canary::canary_plaintext(&context.volume_uuid, unit)
                {
                    return Err(maki_crypto::CryptoError::ProviderFatal(
                        "quarantined endpoint does not match the volume key canary".into(),
                    ));
                }
            }
            cross_endpoint_self_test(reference.as_ref(), candidate.as_ref(), &context, unit).await
        })
    });

    let retry = &config.crypto.retry;
    let budget = &config.crypto.retry_budget;
    let breaker = &config.crypto.circuit_breaker;
    let limits = &config.limits;
    let max_operation_time = match config.crypto.availability_policy {
        maki_format::config::AvailabilityPolicy::Stall => None,
        maki_format::config::AvailabilityPolicy::BoundedError => Some(
            config
                .crypto
                .max_operation_time
                .map(|d| d.0)
                .unwrap_or(std::time::Duration::from_secs(30)),
        ),
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
        max_attempts: None,
        max_operation_time,
        retry_safe: config.crypto.capabilities.retry_safe,
        validation_interval: breaker.open_initial.0,
    };
    Ok(Arc::new(
        EndpointSet::with_quarantine(
            flagged,
            Some(validator),
            dispatch,
            Arc::new(SystemClock::new()),
        )
        .with_plaintext_size(config.provider_plaintext_size()?),
    ))
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
            max_request_bytes: config.nbd.maximum_io.0,
            max_overlay_bytes: config.limits.max_overlay_bytes.0,
            max_overlay_entries: config.limits.max_overlay_entries,
        },
        cache: match config.cache.mode {
            maki_format::config::CacheMode::Off => None,
            maki_format::config::CacheMode::Read => Some(maki_core::engine::EngineCacheConfig {
                max_bytes: config.cache.max_bytes.0,
                ttl: config.cache.ttl.0,
                verify_on_hit: config.cache.verify_on_hit,
            }),
        },
    }
}

/// A setting fixed at creation (SPEC §20) whose configured value differs
/// from what the volume's superblock stores. Attach refuses the
/// configuration at the first one, before it loads any provider credential
/// or builds a provider transport, and
/// `maki check` reports every one: both go through
/// [`configuration_mismatches`], so the check cannot pass a configuration
/// that attach refuses for its identity or geometry. The values are sizes,
/// provider names, credential names and compatibility ids, which the
/// configuration and the superblock hold in plain text; never key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationMismatch {
    /// The setting, as the configuration file names it.
    pub setting: &'static str,
    /// The configured value, as a volume created now would store it.
    pub configured: String,
    /// What the volume stores.
    pub stored: String,
    refusal: Refusal,
}

/// How attach refuses a [`ConfigurationMismatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    /// Geometry, or an NBD size the stored geometry cannot serve.
    Unsupported(String),
    /// The crypto identity: provider type, key identity, compatibility id.
    Identity(String),
}

impl std::fmt::Display for ConfigurationMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is {} in the configuration, the volume has {}",
            self.setting, self.configured, self.stored
        )
    }
}

impl From<ConfigurationMismatch> for DaemonError {
    fn from(mismatch: ConfigurationMismatch) -> Self {
        match mismatch.refusal {
            Refusal::Unsupported(message) => DaemonError::Unsupported(message),
            Refusal::Identity(message) => {
                DaemonError::Attach(AttachError::IdentityMismatch(message))
            }
        }
    }
}

/// Every setting fixed at creation whose configured value `superblock`
/// does not store, in the order attach compares them: the geometry, the NBD
/// sizes it must serve, the provider type, the key identity and the
/// compatibility id. Nothing here loads a credential or contacts a provider.
pub fn configuration_mismatches(
    config: &VolumeConfig,
    superblock: &Superblock,
) -> Result<Vec<ConfigurationMismatch>, DaemonError> {
    let mut mismatches = Vec::new();
    let expected = config.geometry()?;
    let stored = &superblock.geometry;
    for (field, setting, configured, recovered) in [
        (
            "device_block_size",
            "volume.device_block_size",
            u64::from(expected.device_block_size),
            u64::from(stored.device_block_size),
        ),
        (
            "crypto_unit_size",
            "volume.crypto_unit_size",
            u64::from(expected.crypto_unit_size),
            u64::from(stored.crypto_unit_size),
        ),
        (
            "shard_logical_size",
            "volume.shard_logical_size",
            expected.shard_logical_size,
            stored.shard_logical_size,
        ),
        (
            "slot_alignment",
            "backing.slot_alignment",
            u64::from(expected.slot_alignment),
            u64::from(stored.slot_alignment),
        ),
        (
            "max_ciphertext_size",
            "crypto.capabilities.max_ciphertext_size",
            u64::from(expected.max_ciphertext_size),
            u64::from(stored.max_ciphertext_size),
        ),
        (
            "max_virtual_size",
            "volume.max_virtual_size",
            expected.max_virtual_size,
            stored.max_virtual_size,
        ),
    ] {
        if configured != recovered {
            mismatches.push(ConfigurationMismatch {
                setting,
                configured: configured.to_string(),
                stored: recovered.to_string(),
                refusal: Refusal::Unsupported(format!(
                    "volume geometry {field} mismatch: configuration {configured}, stored \
                     {recovered}; migration is required"
                )),
            });
        }
    }
    // Validation ties the NBD sizes to the configured geometry, so only a
    // configuration that did not go through it can fail these once the
    // geometry matches; with a geometry mismatch they would say it again.
    if mismatches.is_empty() {
        let block = stored.device_block_size;
        let minimum = config.nbd.minimum_io;
        if minimum < block || !minimum.is_multiple_of(block) {
            mismatches.push(ConfigurationMismatch {
                setting: "nbd.minimum_io",
                configured: minimum.to_string(),
                stored: format!("device_block_size {block}, which it must be a multiple of"),
                refusal: Refusal::Unsupported(format!(
                    "NBD minimum_io {minimum} is incompatible with stored volume geometry \
                     device_block_size {block}"
                )),
            });
        }
        if !stored.max_virtual_size.is_multiple_of(u64::from(minimum)) {
            mismatches.push(ConfigurationMismatch {
                setting: "nbd.minimum_io",
                configured: minimum.to_string(),
                stored: format!(
                    "max_virtual_size {}, which it must divide",
                    stored.max_virtual_size
                ),
                refusal: Refusal::Unsupported(format!(
                    "NBD minimum_io {minimum} is incompatible with stored volume geometry \
                     max_virtual_size {}; every exported byte must be accessible",
                    stored.max_virtual_size
                )),
            });
        }
    }
    if config.crypto.provider != superblock.provider_type {
        mismatches.push(ConfigurationMismatch {
            setting: "crypto.provider",
            configured: format!("{:?}", config.crypto.provider),
            stored: format!("{:?}", superblock.provider_type),
            refusal: Refusal::Identity(format!(
                "volume was created with provider {:?}, configuration says {:?}",
                superblock.provider_type, config.crypto.provider
            )),
        });
    }
    // A remote configuration has no `[crypto].key` (validation refuses one)
    // and a volume it created stores an empty key identity: say which side
    // has none rather than show an empty name.
    let key_identity = configured_key_identity(config, &superblock.key_identity);
    if key_identity != superblock.key_identity {
        let name = |identity: &str, missing: &str| match identity {
            "" => missing.to_owned(),
            identity => format!("{identity:?}"),
        };
        mismatches.push(ConfigurationMismatch {
            setting: "crypto.key.name",
            configured: name(&key_identity, "unset"),
            stored: name(&superblock.key_identity, "none"),
            refusal: Refusal::Identity(format!(
                "volume was created with key identity {:?}, configuration says {:?}",
                superblock.key_identity, key_identity
            )),
        });
    }
    // The provider reports the configured id, derived with the prefix
    // length; its self-test then compares it with the volume's. Name the
    // setting that differs.
    let compatibility_id = config.crypto.effective_compatibility_id();
    if compatibility_id != superblock.crypto_compatibility_id {
        let refusal = Refusal::Identity(format!(
            "volume was created with compatibility id {:?}, configuration says \
             {compatibility_id:?}",
            superblock.crypto_compatibility_id
        ));
        let (prefix, base) = split_random_prefix(&superblock.crypto_compatibility_id);
        let prefix_differs = config.crypto.random_prefix_bytes != prefix;
        if prefix_differs {
            mismatches.push(ConfigurationMismatch {
                setting: "crypto.random_prefix_bytes",
                configured: config.crypto.random_prefix_bytes.to_string(),
                stored: prefix.to_string(),
                refusal: refusal.clone(),
            });
        }
        if config.crypto.crypto_compatibility_id != base {
            mismatches.push(ConfigurationMismatch {
                setting: "crypto.crypto_compatibility_id",
                configured: format!("{:?}", config.crypto.crypto_compatibility_id),
                stored: format!("{base:?}"),
                refusal,
            });
        } else if !prefix_differs {
            // A derived id this build would spell otherwise: both in full.
            mismatches.push(ConfigurationMismatch {
                setting: "crypto.crypto_compatibility_id",
                configured: format!("{compatibility_id:?}"),
                stored: format!("{:?}", superblock.crypto_compatibility_id),
                refusal,
            });
        }
    }
    Ok(mismatches)
}

/// The prefix length and base id of a stored compatibility id, as
/// [`maki_format::config::CryptoSection::effective_compatibility_id`]
/// derives it; an id without a prefix has length 0. Validation keeps a
/// configured base id out of the reserved namespace.
fn split_random_prefix(id: &str) -> (u32, &str) {
    id.strip_prefix("maki-random-prefix-v1:")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(bytes, base)| Some((bytes.parse().ok()?, base)))
        .unwrap_or((0, id))
}

/// The key identity attach compares with `stored`: the configured key's
/// name, or `stored` itself when it is that file path followed only by the
/// trailing directory syntax older builds persisted (`key/`, `key/.`) and
/// opened as `key`. The caller still supplies the validated file path and
/// the engine still verifies the key canary.
fn configured_key_identity(config: &VolumeConfig, stored: &str) -> String {
    let Some(key) = &config.crypto.key else {
        return String::new();
    };
    let legacy = key.source == "file"
        && stored.strip_prefix(&key.name).is_some_and(|suffix| {
            suffix.starts_with(std::path::is_separator)
                && suffix
                    .split(std::path::is_separator)
                    .all(|part| part.is_empty() || part == ".")
        });
    if legacy {
        stored.to_owned()
    } else {
        key.name.clone()
    }
}

/// Refuse a configuration that does not match the recovered volume, with
/// the first [`ConfigurationMismatch`]. Compare before constructing any
/// provider.
fn refuse_configuration_mismatch(
    config: &VolumeConfig,
    superblock: &Superblock,
) -> Result<(), DaemonError> {
    match configuration_mismatches(config, superblock)?
        .into_iter()
        .next()
    {
        Some(mismatch) => Err(mismatch.into()),
        None => Ok(()),
    }
}

/// Add every [`ConfigurationMismatch`] between `config` and the volume in
/// `backing` to `report` as an error, as `maki check` and `maki check
/// --deep` do after the format checks, and the configuration's own
/// warnings ([`VolumeConfig::warnings`]) as warnings. The report's other
/// lines, and the deep check's verdict, describe the volume; a mismatch
/// means the configuration is wrong for it. A backing without a valid
/// superblock has nothing to compare with, and the format checks have said
/// so.
pub fn report_configuration_mismatches(
    config: &VolumeConfig,
    backing: &dyn Backing,
    report: &mut CheckReport,
) -> Result<(), DaemonError> {
    report.warnings.extend(config.warnings());
    let superblock = match maki_format::superblock::load_volume_superblock(backing) {
        Ok(envelope) => envelope.superblock,
        Err(error @ FormatError::Io(_)) => return Err(error.into()),
        Err(error) => {
            if report.ok() {
                report.errors.push(format!("superblock: {error}"));
            }
            return Ok(());
        }
    };
    let mismatches = configuration_mismatches(config, &superblock)?;
    if mismatches.is_empty() {
        report.info.push(
            "configuration matches the volume's provider, key identity, compatibility id and \
             geometry"
                .to_string(),
        );
    }
    for mismatch in mismatches {
        report.errors.push(format!(
            "configuration mismatch: {mismatch}; attach refuses this configuration"
        ));
    }
    Ok(())
}

/// Recovery + provider verification + ready engine (SPEC §27).
pub async fn attach_from_config(config: &VolumeConfig) -> Result<Engine, DaemonError> {
    Ok(attach_from_config_with_stats(config).await?.0)
}

/// Like [`attach_from_config`], also returning the batch scheduler's stats
/// handle and the endpoint dispatcher when the provider is remote (SPEC
/// 30: remote calls are coalesced through a bounded batch scheduler; local
/// providers are called directly). Both feed the control plane's metrics.
pub async fn attach_from_config_with_stats(
    config: &VolumeConfig,
) -> Result<
    (
        Engine,
        Option<Arc<maki_crypto::scheduler::SchedulerStats>>,
        Option<Arc<EndpointSet>>,
    ),
    DaemonError,
> {
    attach_from_config_with_progress(config, None).await
}

pub(crate) async fn attach_from_config_with_progress(
    config: &VolumeConfig,
    progress: Option<Arc<maki_core::recovery::RecoveryProgress<'static>>>,
) -> Result<
    (
        Engine,
        Option<Arc<maki_crypto::scheduler::SchedulerStats>>,
        Option<Arc<EndpointSet>>,
    ),
    DaemonError,
> {
    // Process hardening first (SPEC 36-37): nothing secret exists yet.
    crate::security::apply(config)?;
    attach_hardened(config, progress, None).await
}

async fn attach_hardened(
    config: &VolumeConfig,
    progress: Option<Arc<maki_core::recovery::RecoveryProgress<'static>>>,
    prepared: Option<PreparedProvider>,
) -> Result<
    (
        Engine,
        Option<Arc<maki_crypto::scheduler::SchedulerStats>>,
        Option<Arc<EndpointSet>>,
    ),
    DaemonError,
> {
    // Every cataloged shard keeps a descriptor (BUG-124). A refusal leaves
    // the inherited limit; an open that then fails reports EMFILE.
    if let Err(e) = maki_backing::raise_open_file_limit() {
        tracing::warn!("cannot raise the open-file soft limit: {e}");
    }
    let backing = build_backing_to_attach(config)?;
    let mut options = engine_options(config);
    let recovery_options = options.volume.clone();
    let volume = Arc::new(
        tokio::task::spawn_blocking(move || match progress {
            Some(progress) => {
                Volume::recover_with_progress(backing, recovery_options, progress.as_ref())
            }
            None => Volume::recover(backing, recovery_options),
        })
        .await
        .map_err(|e| DaemonError::Unsupported(format!("recovery worker failed: {e}")))?
        .map_err(AttachError::from)?,
    );
    // Everything the configuration fixes at creation, before any provider
    // credential is loaded or transport built; `maki check` reports the same
    // comparison. Opening the backing and recovery come first: the
    // superblock is inside the backing. With a remote witness the open
    // (which loads the witness client's TLS identity to ask the authority)
    // has compared already, before its writer claim.
    refuse_configuration_mismatch(config, volume.superblock())?;
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }
    if let Some(identity) = &mut options.identity {
        identity.key_identity = configured_key_identity(config, &volume.superblock().key_identity);
    }
    let prepared = match prepared {
        Some(provider) => provider,
        None => prepare_provider(config).await?,
    };
    let (provider, endpoints) = prepared.verify(config, Some(&volume)).await?;
    let (provider, stats) = if config.crypto.provider.starts_with("remote-") {
        let scheduler = maki_crypto::scheduler::BatchScheduler::with_unit_size(
            provider,
            scheduler_config(config),
            Arc::new(maki_crypto::SystemClock::new()),
            config.volume.crypto_unit_size,
        );
        let stats = scheduler.stats();
        (Arc::new(scheduler) as Arc<dyn CryptoProvider>, Some(stats))
    } else {
        (provider, None)
    };
    let volume = Arc::try_unwrap(volume).map_err(|_| {
        DaemonError::Unsupported("endpoint verification retained the recovered volume".into())
    })?;
    let engine = Engine::attach_recovered(volume, provider, options).await?;
    crate::security::recheck_memory_budget(config)?;
    Ok((engine, stats, endpoints))
}

/// `[crypto.batch]` targets and maxima plus the `[limits]` pending bounds
/// (`max_pending_crypto_items`, `max_pending_crypto_bytes` for plaintext,
/// `max_ciphertext_bytes` for ciphertext).
pub fn scheduler_config(config: &VolumeConfig) -> maki_crypto::scheduler::SchedulerConfig {
    let batch = &config.crypto.batch;
    let limits = &config.limits;
    // The scheduler holds logical plaintext; its inner prefix wrapper exposes
    // fewer usable bytes/items than the raw provider. Cap aggregation as well
    // as individual callers, or concurrent valid groups can form an oversized
    // expanded batch. Configuration validation guarantees one unit fits.
    let (max_items, max_bytes, max_pending_plaintext_bytes) =
        if config.crypto.random_prefix_bytes == 0 {
            (
                batch.max_items as usize,
                batch.max_bytes.0,
                limits.max_pending_crypto_bytes.0,
            )
        } else {
            let logical = u64::from(config.volume.crypto_unit_size);
            let expanded = logical + u64::from(config.crypto.random_prefix_bytes);
            let items = u64::from(batch.max_items).min(batch.max_bytes.0 / expanded);
            (
                items as usize,
                items * logical,
                // Reserve each queued unit's expanded cost even though its prefix
                // is generated only once this group enters the wrapper.
                (limits.max_pending_crypto_bytes.0 / expanded) * logical,
            )
        };
    maki_crypto::scheduler::SchedulerConfig {
        // A per-item provider gains nothing from coalescing: dispatch each
        // single-unit call at once (R5-039).
        target_items: (batch.target_items as usize)
            .min(max_items)
            .min(config.effective_batch_max_items() as usize),
        target_bytes: batch.target_bytes.0.min(max_bytes),
        max_items,
        max_bytes,
        max_wait: batch.max_wait.0,
        max_pending_items: limits.max_pending_crypto_items,
        max_pending_plaintext_bytes,
        max_pending_ciphertext_bytes: limits.max_ciphertext_bytes.0,
        max_inflight_batches: limits.max_crypto_inflight_batches,
    }
}

/// Configuration checked for volume creation with the providers in this build.
/// Keep it immutable so the options inspected by the CLI are those used on disk.
pub struct VolumeCreationConfig(VolumeConfig);

impl VolumeCreationConfig {
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        parse_and_validate(raw).map(Self)
    }

    pub fn config(&self) -> &VolumeConfig {
        &self.0
    }

    /// Initialize the layout. Discard support is chosen only at creation.
    pub fn create(&self, discard: bool) -> Result<Superblock, DaemonError> {
        create_volume_from_config(&self.0, discard)
    }

    /// Resolve credentials and construct transports before publishing the layout.
    /// Remote endpoint self-tests then use the recovered volume's identity.
    pub async fn create_and_attach(&self) -> Result<Engine, DaemonError> {
        crate::security::apply(&self.0)?;
        let prepared = prepare_provider(&self.0).await?;
        self.create(false)?;
        Ok(attach_hardened(&self.0, None, Some(prepared)).await?.0)
    }
}

/// Initialize the on-disk layout for a configured volume.
pub fn create_volume_from_config_str(raw: &str) -> Result<Superblock, DaemonError> {
    VolumeCreationConfig::parse(raw)?.create(false)
}

/// Initialize a new v3 volume with discard support.
pub fn create_volume_with_discard_from_config_str(raw: &str) -> Result<Superblock, DaemonError> {
    VolumeCreationConfig::parse(raw)?.create(true)
}

/// Create and attach a new volume using the supplied configuration.
pub async fn create_and_attach_from_config_str(raw: &str) -> Result<Engine, DaemonError> {
    VolumeCreationConfig::parse(raw)?.create_and_attach().await
}

fn create_volume_from_config(
    config: &VolumeConfig,
    discard: bool,
) -> Result<Superblock, DaemonError> {
    let backing: Arc<dyn Backing> = match &config.backing.rollback_protection {
        Some(rollback) => {
            #[cfg(target_os = "linux")]
            {
                match &rollback.remote {
                    Some(remote) => Arc::new(RollbackBacking::create_remote(
                        Path::new(&config.backing.root),
                        remote_witness_client(remote)?,
                        rollback.capacity.0,
                    )?),
                    None => {
                        let root = Path::new(&config.backing.root);
                        let witness = Path::new(&rollback.witness_root);
                        let capacity = rollback.capacity.0;
                        return init::create_in_rollback_backing(
                            || RollbackBacking::create(root, witness, capacity),
                            || RollbackBacking::open(root, witness),
                            capacity,
                            new_superblock(config)?,
                            discard,
                        )
                        .map(|(_, superblock)| superblock)
                        .map_err(|error| match error {
                            init::RollbackCreateError::Backing(error) => DaemonError::Io(error),
                            init::RollbackCreateError::Volume(error) => DaemonError::Format(error),
                        });
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = rollback;
                return Err(DaemonError::Unsupported(
                    "backing rollback protection is supported only on Linux".to_string(),
                ));
            }
        }
        None => build_backing(config)?,
    };
    initialize_volume(config, backing.as_ref(), discard)
}

/// Finish initial registration only after an explicitly approved, never-active
/// witness recovery. Existing witnessed roots are never reset by this entrypoint.
pub fn resume_enrollment_from_config(
    config: &VolumeConfig,
    rpc: Arc<dyn maki_backing::remote_witness::Rpc>,
    expected: &maki_backing::remote_witness::Record,
    discard: bool,
) -> Result<Superblock, DaemonError> {
    resume_enrollment(
        config,
        rpc,
        expected,
        discard,
        cfg!(feature = "fake-provider"),
    )
}

fn resume_enrollment(
    config: &VolumeConfig,
    rpc: Arc<dyn maki_backing::remote_witness::Rpc>,
    expected: &maki_backing::remote_witness::Record,
    discard: bool,
    fake_enabled: bool,
) -> Result<Superblock, DaemonError> {
    config.validate()?;
    // Recovery consumes the enrollment and initialization records the
    // provider: refuse one this build cannot construct before either (M-008).
    check_provider_available(config, fake_enabled)?;
    let rollback = config
        .backing
        .rollback_protection
        .as_ref()
        .filter(|rollback| rollback.remote.is_some())
        .ok_or_else(|| {
            DaemonError::Unsupported(
                "enrollment recovery requires remote rollback protection".into(),
            )
        })?;
    let backing = maki_backing::RollbackBacking::recover_enrollment_remote(
        Path::new(&config.backing.root),
        rpc,
        rollback.capacity.0,
        expected,
    )?;
    initialize_volume(config, &backing, discard)
}

fn initialize_volume(
    config: &VolumeConfig,
    backing: &dyn Backing,
    discard: bool,
) -> Result<Superblock, DaemonError> {
    let superblock = new_superblock(config)?;
    Ok(if discard {
        init::create_volume_with_discard(backing, superblock)?
    } else {
        init::create_volume(backing, superblock)?
    })
}

/// The superblock of a new volume for `config`, with a new identity.
fn new_superblock(config: &VolumeConfig) -> Result<Superblock, DaemonError> {
    let geometry = config.geometry()?;
    Ok(Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::new_v4(),
        provider_type: config.crypto.provider.clone(),
        crypto_compatibility_id: config.crypto.effective_compatibility_id(),
        key_identity: config
            .crypto
            .key
            .as_ref()
            .map(|k| k.name.clone())
            .unwrap_or_default(),
        geometry,
        format_version: maki_format::superblock::CRYPTO_FORMAT_VERSION,
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
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

#[cfg(all(test, target_os = "linux"))]
mod resume_enrollment_provider_tests {
    use super::*;
    use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Authority {
        store: Arc<std::sync::Mutex<StateStore>>,
        role: Role,
        lose_claims: AtomicBool,
        calls: AtomicUsize,
    }

    impl Rpc for Authority {
        fn call(&self, request: &Request) -> std::io::Result<Record> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let record = self.store.lock().unwrap().handle(self.role, request)?;
            if request.action == Action::Claim && self.lose_claims.load(Ordering::SeqCst) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "lost claim reply",
                ));
            }
            Ok(record)
        }
    }

    fn inspect(rpc: &dyn Rpc) -> Record {
        rpc.call(&Request {
            authorization: None,
            operation_id: *uuid::Uuid::new_v4().as_bytes(),
            expected: None,
            action: Action::Inspect,
        })
        .unwrap()
    }

    #[test]
    fn resume_enrollment_refuses_an_unavailable_provider_before_any_witness_call() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(std::sync::Mutex::new(
            StateStore::create_backing(Arc::new(maki_backing::MemBacking::new()), [1; 16]).unwrap(),
        ));
        let authority = |role, lose_claims| {
            Arc::new(Authority {
                store: store.clone(),
                role,
                lose_claims: AtomicBool::new(lose_claims),
                calls: AtomicUsize::new(0),
            })
        };
        let writer = authority(Role::Writer, true);
        assert!(RollbackBacking::create_remote(root.path(), writer.clone(), 64 * 1024).is_err());
        let admin = authority(Role::Admin, false);
        let expected = inspect(admin.as_ref());
        assert!(expected.current.is_none());
        let config = parse_config(&format!(
            r#"config_schema_version=1
[volume]
name="fake-enroll"
max_virtual_size="1MiB"
shard_logical_size="64KiB"
[crypto]
provider="fake"
crypto_compatibility_id="test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes=[4096]
max_ciphertext_size=4104
[backing]
root={:?}
journal_segment_size="64KiB"
journal_max_bytes="2MiB"
checkpoint_reserve_bytes="0B"
journal_emergency_reserve_bytes="0B"
[backing.rollback_protection]
capacity="64KiB"
[backing.rollback_protection.remote]
address="127.0.0.1:9"
server_name="localhost"
timeout_ms=2000
ca_file="/unused/ca.pem"
client_cert_file="/unused/admin.pem"
client_key_file="/unused/admin.key"
"#,
            root.path().to_str().unwrap()
        ))
        .unwrap();
        let entries = || {
            let mut names: Vec<_> = std::fs::read_dir(root.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let before = entries();
        let calls = admin.calls.load(Ordering::SeqCst);
        let error = resume_enrollment(&config, admin.clone(), &expected, false, false).unwrap_err();
        assert!(
            matches!(&error, DaemonError::Config(ConfigError::Invalid(message)) if message.contains("not compiled")),
            "{error}"
        );
        assert_eq!(
            admin.calls.load(Ordering::SeqCst),
            calls,
            "witness was called"
        );
        assert_eq!(inspect(admin.as_ref()), expected);
        assert_eq!(entries(), before);
        // The availability check is the only difference: a build that has
        // the provider completes the same approved recovery.
        let created = resume_enrollment(&config, admin.clone(), &expected, false, true).unwrap();
        assert_eq!(created.provider_type, "fake");
        assert!(inspect(admin.as_ref()).current.is_some());
    }
}

#[cfg(test)]
mod capability_mode_tests {
    use super::*;
    use maki_crypto::Capability;

    #[test]
    fn websocket_and_grpc_security_declarations_are_at_most_contractual() {
        let mut config = maki_format::config::parse_config(include_str!(
            "../../maki-format/tests/data/full_config.toml"
        ))
        .unwrap();
        for provider in ["remote-websocket", "remote-grpc"] {
            for (level, expected) in [
                ("none", Capability::Absent),
                ("contractual", Capability::Contractual),
                ("verified", Capability::Contractual),
            ] {
                config.crypto.capabilities.integrity = level.into();
                config.crypto.capabilities.context_binding = level.into();
                config.crypto.capabilities.replay_protection = level.into();
                let capabilities = capabilities_from_config(&config, provider);
                assert_eq!(capabilities.integrity, expected, "{provider}: {level}");
                assert_eq!(
                    capabilities.context_binding, expected,
                    "{provider}: {level}"
                );
                assert_eq!(
                    capabilities.replay_protection, expected,
                    "{provider}: {level}"
                );
            }
        }
    }

    #[tokio::test]
    async fn intrinsic_local_verification_remains_verified() {
        let mut keys = maki_crypto_local::keysource::MapKeySource::new();
        keys.insert("test", vec![0x42; 32]);
        let provider =
            maki_crypto_local::AesGcmSivProvider::new(&keys, "test", 512, "test-v1").unwrap();
        let capabilities = provider.capabilities().await.unwrap();
        assert_eq!(capabilities.integrity, Capability::Verified);
        assert_eq!(capabilities.context_binding, Capability::Verified);
        assert_eq!(capabilities.replay_protection, Capability::Absent);
    }
}

#[cfg(all(test, feature = "fake-provider"))]
mod startup_reference_tests {
    use super::*;
    use maki_test_support::fake_provider::FakeCryptoProvider;

    #[tokio::test]
    async fn elects_a_healthy_pair_after_the_reference_goes_offline() {
        let context = maki_crypto::CryptoContext {
            volume_uuid: uuid::Uuid::nil(),
            format_version: 1,
            crypto_compatibility_id: "test-profile-v1".into(),
        };
        let a = Arc::new(FakeCryptoProvider::new(512));
        a.fail_next([maki_crypto::CryptoError::Retryable("offline".into())]);
        let peers: Vec<NamedEndpoint> = vec![
            ("a".into(), a),
            ("b".into(), Arc::new(FakeCryptoProvider::new(512))),
            ("c".into(), Arc::new(FakeCryptoProvider::new(512))),
        ];
        let checked = cross_validate_reachable(peers, &context, 512, 0)
            .await
            .unwrap();
        let flags: std::collections::BTreeMap<_, _> = checked
            .into_iter()
            .map(|(name, _, accepted)| (name, accepted))
            .collect();
        assert!(!flags["a"]);
        assert!(flags["b"] && flags["c"]);
    }
}

#[cfg(test)]
mod configuration_mismatch_tests {
    use super::*;

    fn config(prefix: u32) -> VolumeConfig {
        let config = parse_config(&format!(
            r#"
config_schema_version = 1
[volume]
name = "mismatch"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-profile-v1"
random_prefix_bytes = {prefix}
key = {{ source = "env", name = "mismatch-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [{}]
max_ciphertext_size = 4384
[backing]
root = "/unused-mismatch"
"#,
            4096 + prefix
        ))
        .unwrap();
        config.validate().unwrap();
        config
    }

    fn settings(config: &VolumeConfig, superblock: &Superblock) -> Vec<String> {
        configuration_mismatches(config, superblock)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn a_configuration_matches_the_superblock_its_creation_writes() {
        for prefix in [0, 32] {
            let config = config(prefix);
            let superblock = new_superblock(&config).unwrap();
            assert_eq!(settings(&config, &superblock), Vec::<String>::new());
        }
    }

    #[test]
    fn attach_refuses_with_the_words_and_kinds_it_used_before() {
        let config = config(0);
        let mut superblock = new_superblock(&config).unwrap();
        superblock.geometry.max_virtual_size = 2 << 20;
        superblock.provider_type = "local-aes-xts".into();
        let error = refuse_configuration_mismatch(&config, &superblock).unwrap_err();
        assert!(
            matches!(&error, DaemonError::Unsupported(message) if message ==
                "volume geometry max_virtual_size mismatch: configuration 1048576, stored \
                 2097152; migration is required"),
            "{error}"
        );
        superblock.geometry = config.geometry().unwrap();
        let error = refuse_configuration_mismatch(&config, &superblock).unwrap_err();
        assert!(
            matches!(&error, DaemonError::Attach(AttachError::IdentityMismatch(message))
                if message == "volume was created with provider \"local-aes-xts\", \
                               configuration says \"local-aes-gcm-siv\""),
            "{error}"
        );
    }

    /// Validation keeps the NBD sizes within the configured geometry, so
    /// these refusals are reached only by a configuration that skipped it.
    #[test]
    fn nbd_sizes_are_compared_once_the_geometry_matches() {
        let mut config = config(0);
        let superblock = new_superblock(&config).unwrap();
        config.nbd.minimum_io = 256;
        assert_eq!(
            settings(&config, &superblock),
            [
                "nbd.minimum_io is 256 in the configuration, the volume has device_block_size \
              512, which it must be a multiple of"
            ]
        );
        config.nbd.minimum_io = 3 << 20;
        assert_eq!(
            settings(&config, &superblock),
            [
                "nbd.minimum_io is 3145728 in the configuration, the volume has \
              max_virtual_size 1048576, which it must divide"
            ]
        );
        assert!(matches!(
            refuse_configuration_mismatch(&config, &superblock),
            Err(DaemonError::Unsupported(message)) if message.contains("minimum_io 3145728")
        ));
        // A geometry mismatch says what is wrong; the sizes would repeat it.
        config.volume.device_block_size = 4096;
        assert_eq!(
            settings(&config, &superblock),
            ["volume.device_block_size is 4096 in the configuration, the volume has 512"]
        );
    }

    #[test]
    fn a_derived_id_spelled_otherwise_is_named_in_full() {
        let config = config(16);
        let mut superblock = new_superblock(&config).unwrap();
        superblock.crypto_compatibility_id = "maki-random-prefix-v1:016:local-profile-v1".into();
        assert_eq!(
            settings(&config, &superblock),
            [
                "crypto.crypto_compatibility_id is \"maki-random-prefix-v1:16:local-profile-v1\" \
              in the configuration, the volume has \
              \"maki-random-prefix-v1:016:local-profile-v1\""
            ]
        );
        // Both parts differ: both settings are named, with the base ids.
        superblock.crypto_compatibility_id = "maki-random-prefix-v1:32:local-profile-v0".into();
        assert_eq!(
            settings(&config, &superblock),
            [
                "crypto.random_prefix_bytes is 16 in the configuration, the volume has 32",
                "crypto.crypto_compatibility_id is \"local-profile-v1\" in the configuration, \
                 the volume has \"local-profile-v0\"",
            ]
        );
    }

    #[test]
    fn a_stored_id_is_split_only_where_the_derivation_put_a_prefix() {
        for (id, split) in [
            ("local-profile-v1", (0, "local-profile-v1")),
            ("maki-random-prefix-v1:32:local", (32, "local")),
            ("maki-random-prefix-v1:32:a:b", (32, "a:b")),
            (
                "maki-random-prefix-v1:local",
                (0, "maki-random-prefix-v1:local"),
            ),
            (
                "maki-random-prefix-v1:x:local",
                (0, "maki-random-prefix-v1:x:local"),
            ),
            (
                "x-maki-random-prefix-v1:32:local",
                (0, "x-maki-random-prefix-v1:32:local"),
            ),
        ] {
            assert_eq!(split_random_prefix(id), split, "{id}");
        }
    }
}
