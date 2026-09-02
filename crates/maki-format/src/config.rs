//! Volume configuration schema (SPEC §57), TOML-backed.
//!
//! Rules enforced here:
//! - unknown fields are rejected everywhere (typo safety, and the reason an
//!   inline `token = "…"` cannot even parse),
//! - secrets are never accepted as literals in sensitive headers — they must
//!   be `{ source = "credential", name = "…" }` references (SPEC §9),
//! - human-friendly sizes ("128MiB"), durations ("150us"), rates ("1/s").

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::FormatError;
use crate::geometry::Geometry;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("config invalid: {0}")]
    Invalid(String),
}

pub fn parse_config(input: &str) -> Result<VolumeConfig, ConfigError> {
    let cfg: VolumeConfig = toml::from_str(input)?;
    Ok(cfg)
}

// ---------------------------------------------------------------- ByteSize

/// A byte count, parsed from `"128MiB"`-style strings or plain integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ByteSize(pub u64);

impl FromStr for ByteSize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (num, suffix) = s.split_at(split);
        if num.is_empty() {
            return Err(format!("byte size {s:?}: missing number"));
        }
        let value: u64 = num.parse().map_err(|e| format!("byte size {s:?}: {e}"))?;
        let mult: u64 = match suffix.trim() {
            "" | "B" => 1,
            "KiB" => 1 << 10,
            "MiB" => 1 << 20,
            "GiB" => 1 << 30,
            "TiB" => 1 << 40,
            other => return Err(format!("byte size {s:?}: unknown unit {other:?}")),
        };
        value
            .checked_mul(mult)
            .map(ByteSize)
            .ok_or_else(|| format!("byte size {s:?}: overflow"))
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = ByteSize;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a byte size string like \"128MiB\" or an integer")
            }
            fn visit_u64<E: DeError>(self, v: u64) -> Result<ByteSize, E> {
                Ok(ByteSize(v))
            }
            fn visit_i64<E: DeError>(self, v: i64) -> Result<ByteSize, E> {
                u64::try_from(v)
                    .map(ByteSize)
                    .map_err(|_| E::custom("negative byte size"))
            }
            fn visit_str<E: DeError>(self, v: &str) -> Result<ByteSize, E> {
                v.parse().map_err(E::custom)
            }
        }
        d.deserialize_any(V)
    }
}

// ---------------------------------------------------------------- Duration

/// A duration parsed from `"150us"`, `"50ms"`, `"5s"`, `"2m"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MakiDuration(pub Duration);

impl FromStr for MakiDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let split = s
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("duration {s:?}: missing unit"))?;
        let (num, suffix) = s.split_at(split);
        if num.is_empty() {
            return Err(format!("duration {s:?}: missing number"));
        }
        let value: u64 = num.parse().map_err(|e| format!("duration {s:?}: {e}"))?;
        let dur = match suffix.trim() {
            "us" => Duration::from_micros(value),
            "ms" => Duration::from_millis(value),
            "s" => Duration::from_secs(value),
            "m" => Duration::from_secs(value.checked_mul(60).ok_or("overflow")?),
            other => return Err(format!("duration {s:?}: unknown unit {other:?}")),
        };
        Ok(MakiDuration(dur))
    }
}

impl<'de> Deserialize<'de> for MakiDuration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------- Rate

/// Events per second, parsed from `"1/s"` or a number.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate(pub f64);

impl<'de> Deserialize<'de> for Rate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Rate;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a rate like \"1/s\" or a number")
            }
            fn visit_f64<E: DeError>(self, v: f64) -> Result<Rate, E> {
                Ok(Rate(v))
            }
            fn visit_i64<E: DeError>(self, v: i64) -> Result<Rate, E> {
                Ok(Rate(v as f64))
            }
            fn visit_str<E: DeError>(self, v: &str) -> Result<Rate, E> {
                let body = v
                    .strip_suffix("/s")
                    .ok_or_else(|| E::custom(format!("rate {v:?}: expected \"N/s\"")))?;
                body.trim()
                    .parse::<f64>()
                    .map(Rate)
                    .map_err(|e| E::custom(format!("rate {v:?}: {e}")))
            }
        }
        d.deserialize_any(V)
    }
}

// ---------------------------------------------------------------- sections

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeConfig {
    pub config_schema_version: u32,
    pub volume: VolumeSection,
    pub crypto: CryptoSection,
    #[serde(default)]
    pub limits: LimitsSection,
    pub backing: BackingSection,
    #[serde(default)]
    pub cache: CacheSection,
    #[serde(default)]
    pub nbd: NbdSection,
    #[serde(default)]
    pub control: ControlSection,
    #[serde(default)]
    pub security: SecuritySection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeSection {
    pub name: String,
    pub max_virtual_size: ByteSize,
    #[serde(default = "d_4096")]
    pub device_block_size: u32,
    #[serde(default = "d_4096")]
    pub crypto_unit_size: u32,
    #[serde(default = "d_shard_logical")]
    pub shard_logical_size: ByteSize,
}

fn d_4096() -> u32 {
    4096
}
fn d_shard_logical() -> ByteSize {
    ByteSize(64 << 30)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AvailabilityPolicy {
    #[default]
    Stall,
    BoundedError,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoSection {
    pub provider: String,
    pub crypto_compatibility_id: String,
    #[serde(default)]
    pub availability_policy: AvailabilityPolicy,
    /// Maximum operation time for `bounded-error` (SPEC §35).
    #[serde(default)]
    pub max_operation_time: Option<MakiDuration>,
    pub capabilities: CapabilitiesSection,
    #[serde(default)]
    pub http: Option<HttpSection>,
    #[serde(default)]
    pub websocket: Option<TransportSection>,
    #[serde(default)]
    pub grpc: Option<GrpcSection>,
    #[serde(default)]
    pub batch: BatchSection,
    #[serde(default)]
    pub retry: RetrySection,
    #[serde(default)]
    pub retry_budget: RetryBudgetSection,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerSection,
    /// Local-provider key source (e.g. `{ source = "credential", name = "vol-key" }`).
    #[serde(default)]
    pub key: Option<CredentialRef>,
}

impl CryptoSection {
    pub fn availability_policy_default(&self) -> &'static str {
        match self.availability_policy {
            AvailabilityPolicy::Stall => "stall",
            AvailabilityPolicy::BoundedError => "bounded-error",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesSection {
    /// "declared" (trust config), "hybrid" (verify what we can), "probed".
    #[serde(default = "d_mode")]
    pub mode: String,
    pub supported_plaintext_sizes: Vec<u32>,
    pub max_ciphertext_size: u32,
    #[serde(default = "d_true")]
    pub stateless: bool,
    #[serde(default = "d_true")]
    pub retry_safe: bool,
    #[serde(default = "d_none")]
    pub integrity: String,
    #[serde(default = "d_none")]
    pub context_binding: String,
    #[serde(default = "d_none")]
    pub replay_protection: String,
}

fn d_mode() -> String {
    "declared".to_string()
}
fn d_true() -> bool {
    true
}
fn d_none() -> String {
    "none".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSection {
    #[serde(default)]
    pub endpoint: Vec<EndpointConfig>,
    #[serde(default)]
    pub encrypt: Option<HttpOpConfig>,
    #[serde(default)]
    pub decrypt: Option<HttpOpConfig>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub timeout: Option<MakiDuration>,
    /// Response size cap.
    #[serde(default)]
    pub max_response_bytes: Option<ByteSize>,
}

/// WebSocket transport (SPEC §18).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportSection {
    #[serde(default)]
    pub endpoint: Vec<EndpointConfig>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub timeout: Option<MakiDuration>,
    #[serde(default)]
    pub max_frame_bytes: Option<ByteSize>,
}

/// gRPC transport (SPEC §18). Method paths default to the reference contract
/// (`packaging/examples/maki-crypto.proto`); metadata values follow the same
/// SPEC §9 rules as HTTP headers (sensitive keys must be credential refs).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcSection {
    #[serde(default)]
    pub endpoint: Vec<EndpointConfig>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub timeout: Option<MakiDuration>,
    #[serde(default)]
    pub max_message_bytes: Option<ByteSize>,
    /// e.g. `/maki.CryptoService/EncryptBatch`.
    #[serde(default)]
    pub encrypt_path: Option<String>,
    #[serde(default)]
    pub decrypt_path: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, HeaderValue>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub ca_file: Option<String>,
    #[serde(default)]
    pub client_cert_file: Option<String>,
    #[serde(default)]
    pub client_key: Option<CredentialRef>,
    #[serde(default)]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpOpConfig {
    #[serde(default = "d_post")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, HeaderValue>,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<BodyConfig>,
    #[serde(default)]
    pub response: Option<ResponseConfig>,
}

fn d_post() -> String {
    "POST".to_string()
}

/// A header value: literal string or credential reference.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HeaderValue {
    Credential(CredentialRef),
    Literal(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    /// "credential" (systemd), "file", "keyring", "env" (dev only).
    pub source: String,
    pub name: String,
    /// Optional template, e.g. `"Bearer {}"`.
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyConfig {
    #[serde(rename = "type", default = "d_json")]
    pub body_type: String,
    /// Top-level fields (JSON pointers → sources).
    #[serde(default)]
    pub fields: BTreeMap<String, FieldMapping>,
    /// Batch layout: pointer to a JSON array receiving one object per item.
    /// Absent = one HTTP request per item.
    #[serde(default)]
    pub items_path: Option<String>,
    /// Per-item fields within `items_path` elements.
    #[serde(default)]
    pub item_fields: BTreeMap<String, FieldMapping>,
}

fn d_json() -> String {
    "json".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldMapping {
    /// "payload", "unit_index", "volume_id", "compatibility_id", "batch_index".
    pub source: String,
    #[serde(default)]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseConfig {
    #[serde(rename = "type", default = "d_json")]
    pub response_type: String,
    /// Pointer to the payload (single-item), or within each batch element.
    #[serde(default)]
    pub data_path: Option<String>,
    #[serde(default)]
    pub encoding: Option<String>,
    /// Batch: pointer to the response array.
    #[serde(default)]
    pub items_path: Option<String>,
    /// Optional per-element echo of the unit index, validated when present.
    #[serde(default)]
    pub item_index_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsSection {
    pub max_active_callbacks: u32,
    pub max_plaintext_bytes: ByteSize,
    pub max_ciphertext_bytes: ByteSize,
    pub max_pending_crypto_items: u32,
    pub max_pending_crypto_bytes: ByteSize,
    pub max_crypto_inflight_batches: u32,
    pub max_crypto_inflight_bytes: ByteSize,
    pub max_inflight_per_endpoint: u32,
    pub max_inflight_bytes_per_endpoint: ByteSize,
    pub max_journal_pending_bytes: ByteSize,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_active_callbacks: 64,
            max_plaintext_bytes: ByteSize(128 << 20),
            max_ciphertext_bytes: ByteSize(160 << 20),
            max_pending_crypto_items: 4096,
            max_pending_crypto_bytes: ByteSize(128 << 20),
            max_crypto_inflight_batches: 32,
            max_crypto_inflight_bytes: ByteSize(32 << 20),
            max_inflight_per_endpoint: 8,
            max_inflight_bytes_per_endpoint: ByteSize(8 << 20),
            max_journal_pending_bytes: ByteSize(64 << 20),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BatchSection {
    pub target_items: u32,
    pub target_bytes: ByteSize,
    pub max_items: u32,
    pub max_bytes: ByteSize,
    pub max_wait: MakiDuration,
}

impl Default for BatchSection {
    fn default() -> Self {
        Self {
            target_items: 64,
            target_bytes: ByteSize(256 << 10),
            max_items: 128,
            max_bytes: ByteSize(1 << 20),
            max_wait: MakiDuration(Duration::from_micros(150)),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RetrySection {
    pub strategy: String,
    pub initial_delay: MakiDuration,
    pub max_delay: MakiDuration,
}

impl Default for RetrySection {
    fn default() -> Self {
        Self {
            strategy: "exponential-full-jitter".to_string(),
            initial_delay: MakiDuration(Duration::from_millis(50)),
            max_delay: MakiDuration(Duration::from_secs(5)),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RetryBudgetSection {
    pub retry_ratio: f64,
    pub burst: u32,
    pub minimum_probe_rate: Rate,
}

impl Default for RetryBudgetSection {
    fn default() -> Self {
        Self {
            retry_ratio: 0.20,
            burst: 16,
            minimum_probe_rate: Rate(1.0),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CircuitBreakerSection {
    pub failure_threshold: u32,
    pub open_initial: MakiDuration,
    pub open_max: MakiDuration,
    pub half_open_max_requests: u32,
    pub success_threshold: u32,
}

impl Default for CircuitBreakerSection {
    fn default() -> Self {
        Self {
            failure_threshold: 8,
            open_initial: MakiDuration(Duration::from_secs(1)),
            open_max: MakiDuration(Duration::from_secs(30)),
            half_open_max_requests: 2,
            success_threshold: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackingSection {
    pub root: String,
    #[serde(default = "d_512")]
    pub slot_alignment: u32,
    #[serde(default = "d_seg")]
    pub journal_segment_size: ByteSize,
    #[serde(default = "d_jmax")]
    pub journal_max_bytes: ByteSize,
    #[serde(default = "d_ckres")]
    pub checkpoint_reserve_bytes: ByteSize,
    #[serde(default = "d_jres")]
    pub journal_emergency_reserve_bytes: ByteSize,
}

fn d_512() -> u32 {
    512
}
fn d_seg() -> ByteSize {
    ByteSize(256 << 20)
}
fn d_jmax() -> ByteSize {
    ByteSize(4 << 30)
}
fn d_ckres() -> ByteSize {
    ByteSize(4 << 30)
}
fn d_jres() -> ByteSize {
    ByteSize(1 << 30)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheMode {
    Off,
    Read,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CacheSection {
    pub mode: CacheMode,
    pub max_bytes: ByteSize,
    pub ttl: MakiDuration,
    pub lock_memory: bool,
    pub zeroize_on_evict: bool,
}

impl Default for CacheSection {
    fn default() -> Self {
        Self {
            mode: CacheMode::Off,
            max_bytes: ByteSize(256 << 20),
            ttl: MakiDuration(Duration::from_secs(30)),
            lock_memory: true,
            zeroize_on_evict: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NbdSection {
    pub socket: Option<String>,
    pub device_block_size: u32,
    pub minimum_io: u32,
    pub preferred_io: u32,
    pub maximum_io: ByteSize,
    pub threads: u32,
    pub connections: u32,
}

impl Default for NbdSection {
    fn default() -> Self {
        Self {
            socket: None,
            device_block_size: 4096,
            minimum_io: 4096,
            preferred_io: 4096,
            maximum_io: ByteSize(1 << 20),
            threads: 64,
            connections: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ControlSection {
    pub socket: Option<String>,
    pub group: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecuritySection {
    pub memory_lock_mode: String,
    pub disable_core_dump: bool,
    pub madv_dontdump: bool,
    pub require_secure_swap_policy: bool,
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            memory_lock_mode: "secure-buffers".to_string(),
            disable_core_dump: true,
            madv_dontdump: true,
            require_secure_swap_policy: true,
        }
    }
}

// ---------------------------------------------------------------- validation

const KNOWN_PROVIDERS: &[&str] = &[
    "local-aes-gcm-siv",
    "local-aes-xts",
    "remote-http",
    "remote-websocket",
    "remote-grpc",
    "fake",
];

/// Header names whose value must never be a literal.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "token",
    "cookie",
    "x-secret",
    "secret",
];

impl VolumeConfig {
    pub fn geometry(&self) -> Result<Geometry, FormatError> {
        Geometry::compute(
            self.volume.device_block_size,
            self.volume.crypto_unit_size,
            self.backing.slot_alignment,
            self.crypto.capabilities.max_ciphertext_size,
            self.volume.max_virtual_size.0,
            self.volume.shard_logical_size.0,
        )
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.config_schema_version != 1 {
            return Err(ConfigError::Invalid(format!(
                "unsupported config_schema_version {}",
                self.config_schema_version
            )));
        }
        if self.volume.name.is_empty()
            || !self
                .volume
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ConfigError::Invalid(format!(
                "volume name {:?} must be non-empty [A-Za-z0-9_-]",
                self.volume.name
            )));
        }
        if !KNOWN_PROVIDERS.contains(&self.crypto.provider.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "unknown crypto provider {:?}",
                self.crypto.provider
            )));
        }
        self.geometry()
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        if !self
            .crypto
            .capabilities
            .supported_plaintext_sizes
            .contains(&self.volume.crypto_unit_size)
        {
            return Err(ConfigError::Invalid(format!(
                "crypto_unit_size {} not in supported_plaintext_sizes",
                self.volume.crypto_unit_size
            )));
        }
        for s in [
            &self.crypto.capabilities.integrity,
            &self.crypto.capabilities.context_binding,
            &self.crypto.capabilities.replay_protection,
        ] {
            if !["none", "contractual", "verified"].contains(&s.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "capability level {s:?} must be none|contractual|verified"
                )));
            }
        }
        if self.crypto.availability_policy == AvailabilityPolicy::BoundedError
            && self.crypto.max_operation_time.is_none()
        {
            return Err(ConfigError::Invalid(
                "availability_policy = \"bounded-error\" requires max_operation_time".to_string(),
            ));
        }
        if self.nbd.connections != 1 {
            return Err(ConfigError::Invalid(
                "nbd.connections must be 1 (multi-connection is disabled)".to_string(),
            ));
        }
        if self.crypto.provider == "remote-http" {
            if let Some(http) = &self.crypto.http {
                for op in [&http.encrypt, &http.decrypt].into_iter().flatten() {
                    for (name, value) in &op.headers {
                        let sensitive = SENSITIVE_HEADERS.contains(&name.to_lowercase().as_str());
                        if sensitive {
                            match value {
                                HeaderValue::Literal(_) => {
                                    return Err(ConfigError::Invalid(format!(
                                        "header {name:?} must use a credential reference, \
                                         not a literal secret (SPEC §9)"
                                    )));
                                }
                                HeaderValue::Credential(c) => validate_credential(c)?,
                            }
                        }
                    }
                }
            }
        }
        if let Some(grpc) = &self.crypto.grpc {
            for (name, value) in &grpc.metadata {
                if SENSITIVE_HEADERS.contains(&name.to_lowercase().as_str()) {
                    match value {
                        HeaderValue::Literal(_) => {
                            return Err(ConfigError::Invalid(format!(
                                "gRPC metadata {name:?} must use a credential reference, \
                                 not a literal secret (SPEC §9)"
                            )));
                        }
                        HeaderValue::Credential(c) => validate_credential(c)?,
                    }
                }
            }
        }
        if let Some(key) = &self.crypto.key {
            validate_credential(key)?;
        }
        Ok(())
    }
}

fn validate_credential(c: &CredentialRef) -> Result<(), ConfigError> {
    if !["credential", "file", "keyring", "env"].contains(&c.source.as_str()) {
        return Err(ConfigError::Invalid(format!(
            "credential source {:?} must be credential|file|keyring|env",
            c.source
        )));
    }
    if c.name.is_empty() {
        return Err(ConfigError::Invalid("credential name is empty".to_string()));
    }
    Ok(())
}
