//! Quorum-backed authority using the etcd v3 linearizable KV API.

use std::collections::BTreeSet;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use maki_backing::remote_witness::{CanonicalState, Record, Request, Role};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{Handler, TlsFiles};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EtcdEndpoint {
    pub address: SocketAddr,
    pub server_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EtcdOptions {
    pub endpoints: Vec<EtcdEndpoint>,
    /// Decimal string in configuration: TOML cannot represent every uint64 ID.
    #[serde(with = "cluster_id")]
    pub cluster_id: u64,
    pub storage_identity: Uuid,
    pub key: String,
    pub timeout_ms: u64,
    pub tls: TlsFiles,
}

mod cluster_id {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(id: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty()
            || (text.len() > 1 && text.starts_with('0'))
            || !text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom(
                "cluster_id must be a canonical decimal string",
            ));
        }
        text.parse()
            .map_err(|_| serde::de::Error::custom("cluster_id is outside uint64 range"))
    }
}

const MAX_STATE_BYTES: usize = 64 * 1024;
const MAX_JSON_BYTES: usize = 256 * 1024;
const MAX_ENDPOINTS: usize = 8;

struct Endpoint {
    client: reqwest::blocking::Client,
    base: reqwest::Url,
}

/// Stateless frontends share exactly this key on the pinned etcd quorum.
///
/// No witness state is cached, leased, or recovered from a local replica. An
/// operator restoring etcd itself must create a new cluster identity and must
/// never silently replace this pin with a rolled-back authority snapshot.
pub struct EtcdStore {
    endpoints: Vec<Endpoint>,
    cluster_id: u64,
    identity: [u8; 16],
    key: String,
    timeout: Duration,
    cursor: AtomicUsize,
}

struct Snapshot {
    state: CanonicalState,
    bytes: Vec<u8>,
    revision: i64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn corrupt(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn network(error: reqwest::Error) -> io::Error {
    // Never include upstream errors, URLs, configuration, or response bodies.
    let mut sources: Vec<&(dyn std::error::Error + 'static)> = vec![&error];
    for _ in 0..32 {
        let Some(source) = sources.pop() else { break };
        if source.is::<rustls::Error>() {
            return corrupt("etcd TLS authentication or protocol failed");
        }
        if let Some(inner) = source
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
        {
            sources.push(inner);
        }
        if let Some(inner) = source.source() {
            sources.push(inner);
        }
    }
    if error.is_timeout() {
        io::Error::new(io::ErrorKind::TimedOut, "etcd quorum RPC deadline expired")
    } else if error.is_connect() {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "etcd quorum connection failed",
        )
    } else {
        io::Error::other("etcd quorum RPC failed; durable outcome may be unknown")
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "etcd operation deadline expired"))
}

fn retryable(error: &io::Error) -> bool {
    !matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData | io::ErrorKind::PermissionDenied
    )
}

fn decimal(value: &Value) -> io::Result<u64> {
    let text = value
        .as_str()
        .ok_or_else(|| corrupt("invalid etcd integer encoding"))?;
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(corrupt("invalid etcd integer encoding"));
    }
    text.parse()
        .map_err(|_| corrupt("etcd integer outside range"))
}

fn encoded(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

impl EtcdStore {
    fn configured(options: EtcdOptions) -> io::Result<Self> {
        let timeout = crate::timeout(options.timeout_ms)?;
        if options.cluster_id == 0 || options.storage_identity.is_nil() {
            return Err(invalid(
                "etcd cluster and storage identity pins are required",
            ));
        }
        if !(1..=MAX_ENDPOINTS).contains(&options.endpoints.len()) {
            return Err(invalid("etcd needs one to eight distinct endpoints"));
        }
        if options.key.len() > 1024
            || !options.key.starts_with("/maki/witness/")
            || options.key.len() == "/maki/witness/".len()
            || options.key.contains("//")
            || !options
                .key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_".contains(&b))
        {
            return Err(invalid(
                "etcd witness key must be a bounded /maki/witness/ path",
            ));
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(crate::tls_error)?
        .with_root_certificates(crate::roots(&options.tls.ca_file)?)
        .with_client_cert_resolver(crate::identity(&options.tls)?);
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut addresses = BTreeSet::new();
        let mut endpoints = Vec::with_capacity(options.endpoints.len());
        for endpoint in options.endpoints {
            if endpoint.address.port() == 0 || !addresses.insert(endpoint.address) {
                return Err(invalid(
                    "etcd endpoints must have distinct nonzero socket addresses",
                ));
            }
            let name = rustls::pki_types::ServerName::try_from(endpoint.server_name.clone())
                .map_err(|_| invalid("invalid etcd certificate server name"))?;
            if let rustls::pki_types::ServerName::IpAddress(ip) = name {
                if std::net::IpAddr::from(ip) != endpoint.address.ip() {
                    return Err(invalid(
                        "etcd IP certificate identity must match its pinned socket IP",
                    ));
                }
            }
            let host = if endpoint.server_name.contains(':') {
                format!("[{}]", endpoint.server_name)
            } else {
                endpoint.server_name.clone()
            };
            let base = reqwest::Url::parse(&format!("https://{host}:{}/", endpoint.address.port()))
                .map_err(|_| invalid("invalid etcd endpoint URL"))?;
            let client = reqwest::blocking::Client::builder()
                .use_preconfigured_tls(tls.clone())
                .http1_only()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(0)
                .resolve(
                    base.host_str().expect("validated endpoint host"),
                    endpoint.address,
                )
                .connect_timeout(timeout)
                .timeout(timeout)
                .build()
                .map_err(|_| invalid("invalid etcd TLS client configuration"))?;
            endpoints.push(Endpoint { client, base });
        }
        Ok(Self {
            endpoints,
            cluster_id: options.cluster_id,
            identity: *options.storage_identity.as_bytes(),
            key: encoded(options.key.as_bytes()),
            timeout,
            cursor: AtomicUsize::new(0),
        })
    }

    /// Initialize only an absent key. Ambiguous enrollment errors require open
    /// and inspection; initialization never overwrites an existing value.
    pub fn create(options: EtcdOptions, identity: [u8; 16]) -> io::Result<Self> {
        if identity != *options.storage_identity.as_bytes() {
            return Err(invalid(
                "initialization identity differs from configured pin",
            ));
        }
        let state = CanonicalState::initial(identity)?;
        let store = Self::configured(options)?;
        let deadline = Instant::now() + store.timeout;
        let (current, endpoint) = store.load(deadline)?;
        if current.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "etcd witness key already enrolled",
            ));
        }
        let body = json!({
            "compare":[{"key":store.key,"target":"VERSION","result":"EQUAL","version":"0"}],
            "success":[{"request_put":{"key":store.key,"value":encoded(&state.encode()?)}}],
            "failure":[{"request_range":{"key":store.key,"serializable":false}}]
        });
        // The preceding Range authenticated the cluster on this exact endpoint.
        let response = store.post(endpoint, "/v3/kv/txn", &body, remaining(deadline)?)?;
        if response.get("succeeded").and_then(Value::as_bool) != Some(true) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "etcd witness initialization comparison failed",
            ));
        }
        remaining(deadline)?;
        Ok(store)
    }

    /// Serving performs a quorum read and refuses missing or mismatched state.
    pub fn open(options: EtcdOptions) -> io::Result<Self> {
        let store = Self::configured(options)?;
        store
            .load(Instant::now() + store.timeout)?
            .0
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "etcd witness key is not enrolled")
            })?;
        Ok(store)
    }

    /// Execute the shared state machine against one linearizable quorum key.
    /// A retry uses the identical role and operation body, never a new claim.
    pub fn handle(&self, role: Role, request: &Request) -> io::Result<Record> {
        let deadline = Instant::now() + self.timeout;
        let attempts = self.endpoints.len() * 2 + 2;
        let mut uncertain = None;
        for attempt in 0..attempts {
            let (current, endpoint) = self.load(deadline)?;
            let current = current.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "etcd witness key disappeared")
            })?;
            let candidate = current.state.apply(role, request)?;
            let bytes = candidate.encode()?;
            if bytes == current.bytes {
                remaining(deadline)?;
                return Ok(candidate.record().clone());
            }
            let body = json!({
                "compare":[
                    {"key":self.key,"target":"MOD","result":"EQUAL","mod_revision":current.revision.to_string()},
                    {"key":self.key,"target":"VALUE","result":"EQUAL","value":encoded(&current.bytes)}
                ],
                "success":[{"request_put":{"key":self.key,"value":encoded(&bytes)}}],
                "failure":[{"request_range":{"key":self.key,"serializable":false}}]
            });
            let budget = remaining(deadline)? / (attempts - attempt) as u32;
            match self.post(endpoint, "/v3/kv/txn", &body, budget) {
                Ok(response) => {
                    // protobuf JSON omits fields holding their default false.
                    match response
                        .get("succeeded")
                        .map(Value::as_bool)
                        .unwrap_or(Some(false))
                    {
                        Some(true) => {
                            remaining(deadline)?;
                            return Ok(candidate.record().clone());
                        }
                        Some(false) => {
                            let response = response
                                .get("responses")
                                .and_then(Value::as_array)
                                .filter(|responses| responses.len() == 1)
                                .and_then(|responses| responses[0].get("response_range"))
                                .ok_or_else(|| {
                                    corrupt("etcd comparison returned no exact predecessor")
                                })?;
                            let observed = self.snapshot(response)?.ok_or_else(|| {
                                corrupt("etcd witness key vanished during comparison")
                            })?;
                            let replay = observed.state.apply(role, request)?;
                            if replay.encode()? == observed.bytes {
                                remaining(deadline)?;
                                return Ok(replay.record().clone());
                            }
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "etcd witness predecessor comparison failed",
                            ));
                        }
                        None => return Err(corrupt("invalid etcd transaction response")),
                    }
                }
                Err(error) if retryable(&error) => {
                    // Commit may have occurred. The next fresh Range resolves the
                    // persisted operation digest before any mutation is retried.
                    uncertain = Some(error);
                    self.cursor
                        .store((endpoint + 1) % self.endpoints.len(), Ordering::Relaxed);
                }
                Err(error) => return Err(error),
            }
        }
        Err(uncertain
            .unwrap_or_else(|| io::Error::other("etcd witness operation remains uncertain")))
    }

    fn post(
        &self,
        endpoint: usize,
        path: &str,
        body: &Value,
        budget: Duration,
    ) -> io::Result<Value> {
        if budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "etcd RPC budget exhausted",
            ));
        }
        let bytes = serde_json::to_vec(body).map_err(|_| invalid("invalid etcd request"))?;
        if bytes.len() > MAX_JSON_BYTES {
            return Err(invalid("etcd request exceeds size limit"));
        }
        let endpoint = &self.endpoints[endpoint];
        let url = endpoint
            .base
            .join(path)
            .map_err(|_| invalid("invalid etcd request path"))?;
        let response = endpoint
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONNECTION, "close")
            .body(bytes)
            .timeout(budget)
            .send()
            .map_err(network)?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                401 | 403 => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "etcd backend authentication denied",
                ),
                400 => invalid("etcd backend rejected request"),
                300..=399 => corrupt("etcd redirects are forbidden"),
                _ => io::Error::other("etcd backend unavailable"),
            });
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_JSON_BYTES as u64)
        {
            return Err(corrupt("etcd response exceeds size limit"));
        }
        let mut bytes = Vec::new();
        response
            .take((MAX_JSON_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                io::Error::other("etcd response failed; durable outcome may be unknown")
            })?;
        if bytes.len() > MAX_JSON_BYTES {
            return Err(corrupt("etcd response exceeds size limit"));
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| corrupt("invalid etcd response JSON"))?;
        if decimal(&value["header"]["cluster_id"])? != self.cluster_id {
            return Err(corrupt(
                "etcd response differs from pinned cluster identity",
            ));
        }
        Ok(value)
    }

    fn load(&self, deadline: Instant) -> io::Result<(Option<Snapshot>, usize)> {
        let start = self.cursor.load(Ordering::Relaxed) % self.endpoints.len();
        let body = json!({"key":self.key,"serializable":false,"limit":"1"});
        let mut last = None;
        for offset in 0..self.endpoints.len() {
            let endpoint = (start + offset) % self.endpoints.len();
            let budget = remaining(deadline)? / (self.endpoints.len() - offset) as u32;
            match self.post(endpoint, "/v3/kv/range", &body, budget) {
                Ok(response) => {
                    let state = self.snapshot(&response)?;
                    remaining(deadline)?;
                    self.cursor.store(endpoint, Ordering::Relaxed);
                    return Ok((state, endpoint));
                }
                Err(error) if retryable(&error) => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("etcd quorum is unavailable")))
    }

    fn snapshot(&self, response: &Value) -> io::Result<Option<Snapshot>> {
        if response.get("more").and_then(Value::as_bool) == Some(true) {
            return Err(corrupt("etcd exact key read was truncated"));
        }
        let count = response.get("count").map(decimal).transpose()?.unwrap_or(0);
        let entries = response.get("kvs").and_then(Value::as_array);
        if count == 0 && entries.is_none_or(Vec::is_empty) {
            return Ok(None);
        }
        let entry = entries
            .filter(|entries| count == 1 && entries.len() == 1)
            .map(|entries| &entries[0])
            .ok_or_else(|| corrupt("invalid etcd exact key response"))?;
        if entry.get("key").and_then(Value::as_str) != Some(&self.key) {
            return Err(corrupt(
                "etcd response key differs from configured authority",
            ));
        }
        if entry.get("lease").map(decimal).transpose()?.unwrap_or(0) != 0 {
            return Err(corrupt(
                "etcd witness authority must never have an expiring lease",
            ));
        }
        let value = entry
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| corrupt("etcd witness value is absent"))?;
        if value.len() > MAX_STATE_BYTES.div_ceil(3) * 4 {
            return Err(corrupt("etcd witness value exceeds size limit"));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| corrupt("invalid etcd witness base64"))?;
        if bytes.len() > MAX_STATE_BYTES || encoded(&bytes) != value {
            return Err(corrupt("invalid or oversized etcd witness encoding"));
        }
        let revision = decimal(&entry["mod_revision"])?;
        let revision = i64::try_from(revision)
            .ok()
            .filter(|revision| *revision > 0)
            .ok_or_else(|| corrupt("invalid etcd authority modification revision"))?;
        let state = CanonicalState::decode(&bytes)?;
        if state.record().identity != self.identity {
            return Err(corrupt("etcd value differs from pinned storage identity"));
        }
        Ok(Some(Snapshot {
            state,
            bytes,
            revision,
        }))
    }
}

pub fn state_handler(store: EtcdStore) -> Arc<Handler> {
    Arc::new(move |role, value| {
        let request: Request =
            serde_json::from_value(value).map_err(|_| invalid("invalid witness operation"))?;
        serde_json::to_value(store.handle(role, &request)?)
            .map_err(|_| corrupt("invalid witness state"))
    })
}
