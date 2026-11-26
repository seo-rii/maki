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
        if !created(&response) {
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
                Ok(response) => match transaction(&response)? {
                    Transaction::Committed => {
                        remaining(deadline)?;
                        return Ok(candidate.record().clone());
                    }
                    Transaction::Compared(response) => {
                        let record = compared(self.snapshot(response)?, role, request)?;
                        remaining(deadline)?;
                        return Ok(record);
                    }
                },
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
        answer(&bytes, self.cluster_id)
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
        snapshot(response, &self.key, &self.identity)
    }
}

/// The body of etcd's answer to a request: JSON, within the size limit,
/// from the pinned cluster.
fn answer(bytes: &[u8], cluster_id: u64) -> io::Result<Value> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(corrupt("etcd response exceeds size limit"));
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| corrupt("invalid etcd response JSON"))?;
    if decimal(&value["header"]["cluster_id"])? != cluster_id {
        return Err(corrupt(
            "etcd response differs from pinned cluster identity",
        ));
    }
    Ok(value)
}

/// Whether the answer to the creating transaction says it put the state.
fn created(response: &Value) -> bool {
    response.get("succeeded").and_then(Value::as_bool) == Some(true)
}

/// What etcd's answer to a compare-and-put transaction says.
enum Transaction<'a> {
    /// The comparison held and the state was put.
    Committed,
    /// The comparison failed: the range answer that shows the key's value.
    Compared(&'a Value),
}

fn transaction(response: &Value) -> io::Result<Transaction<'_>> {
    // protobuf JSON omits fields holding their default false.
    match response
        .get("succeeded")
        .map(Value::as_bool)
        .unwrap_or(Some(false))
    {
        Some(true) => Ok(Transaction::Committed),
        Some(false) => response
            .get("responses")
            .and_then(Value::as_array)
            .filter(|responses| responses.len() == 1)
            .and_then(|responses| responses[0].get("response_range"))
            .map(Transaction::Compared)
            .ok_or_else(|| corrupt("etcd comparison returned no exact predecessor")),
        None => Err(corrupt("invalid etcd transaction response")),
    }
}

/// After a failed comparison: the record of `request` if the state the key
/// holds is the one this exact request already produced (a retry of a
/// commit whose answer was lost), and a conflict otherwise.
fn compared(observed: Option<Snapshot>, role: Role, request: &Request) -> io::Result<Record> {
    let observed =
        observed.ok_or_else(|| corrupt("etcd witness key vanished during comparison"))?;
    let replay = observed.state.apply(role, request)?;
    if replay.encode()? == observed.bytes {
        return Ok(replay.record().clone());
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "etcd witness predecessor comparison failed",
    ))
}

/// The witness state a range answer for the exact key `key` (its base64
/// encoding) holds, if any, pinned to the storage identity `identity`.
fn snapshot(response: &Value, key: &str, identity: &[u8; 16]) -> io::Result<Option<Snapshot>> {
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
    if entry.get("key").and_then(Value::as_str) != Some(key) {
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
    if state.record().identity != *identity {
        return Err(corrupt("etcd value differs from pinned storage identity"));
    }
    Ok(Some(Snapshot {
        state,
        bytes,
        revision,
    }))
}

pub fn state_handler(store: EtcdStore) -> Arc<Handler> {
    Arc::new(move |role, value| {
        let request = crate::operation(value)?;
        serde_json::to_value(store.handle(role, &request)?)
            .map_err(|_| corrupt("invalid witness state"))
    })
}

/// The quorum store's reading of etcd's answers, for the fuzz harness
/// ([`crate::fuzzing`]).
///
/// An input is the body of one answer: its first byte selects the request
/// it answers (modulo 3: the range read of the witness key, the
/// compare-and-put transaction of an operation, the creating transaction),
/// and the rest is the body as etcd's JSON gateway sends it. The body goes
/// through [`answer`], then to the reader of that request's answer.
#[cfg(feature = "fuzzing")]
pub(crate) mod fuzzing {
    use super::*;

    /// The pinned cluster.
    pub(crate) const CLUSTER: u64 = 14_841_639_068_965_178_418;
    /// The witness key.
    pub(crate) const KEY: &str = "/maki/witness/volume-a";

    pub const RANGE: u8 = 0;
    pub const TRANSACTION: u8 = 1;
    pub const CREATE: u8 = 2;

    /// The operation the transaction answers: the writer's claim of the
    /// released authority.
    fn claim() -> (Request, CanonicalState) {
        let initial = CanonicalState::initial(crate::fuzzing::IDENTITY).expect("an initial state");
        let mut request = crate::fuzzing::claim();
        request.expected = Some(initial.record().clone());
        let claimed = initial
            .apply(Role::Writer, &request)
            .expect("the claim of a released authority");
        (request, claimed)
    }

    /// Feed the answer in `data` to the reader of the request it answers,
    /// and return whether the store accepted it: a range answer it reads, a
    /// committed transaction, a failed comparison this exact operation had
    /// already won, a creation. Panics where an accepted state is not what
    /// the store would write.
    pub fn etcd(data: &[u8]) -> bool {
        let Some((&selector, body)) = data.split_first() else {
            return false;
        };
        let Ok(response) = answer(body, CLUSTER) else {
            return false;
        };
        let key = encoded(KEY.as_bytes());
        match selector % 3 {
            RANGE => match snapshot(&response, &key, &crate::fuzzing::IDENTITY) {
                Ok(Some(snapshot)) => {
                    checked(&snapshot);
                    true
                }
                Ok(None) => true,
                Err(_) => false,
            },
            TRANSACTION => match transaction(&response) {
                Ok(Transaction::Committed) => true,
                Ok(Transaction::Compared(range)) => {
                    let Ok(observed) = snapshot(range, &key, &crate::fuzzing::IDENTITY) else {
                        return false;
                    };
                    if let Some(observed) = &observed {
                        checked(observed);
                    }
                    let (request, claimed) = claim();
                    let Ok(record) = compared(observed, Role::Writer, &request) else {
                        return false;
                    };
                    assert_eq!(&record, claimed.record(), "a replay of another operation");
                    true
                }
                Err(_) => false,
            },
            _ => created(&response),
        }
    }

    /// A state read from etcd is what the store writes: its canonical
    /// encoding, of the pinned identity, at a positive revision.
    fn checked(snapshot: &Snapshot) {
        assert_eq!(
            snapshot.state.encode().expect("an accepted state encodes"),
            snapshot.bytes,
            "an accepted state is not its own encoding"
        );
        assert_eq!(snapshot.state.record().identity, crate::fuzzing::IDENTITY);
        assert!(snapshot.revision > 0, "revision {}", snapshot.revision);
    }

    fn header(cluster: &str) -> Value {
        json!({
            "cluster_id": cluster,
            "member_id": "10276657743932975437",
            "revision": "7",
            "raft_term": "2"
        })
    }

    fn entry(key: &str, state: &[u8]) -> Value {
        json!({
            "key": encoded(key.as_bytes()),
            "create_revision": "2",
            "mod_revision": "7",
            "version": "3",
            "value": encoded(state)
        })
    }

    fn range(entries: Vec<Value>) -> Value {
        let count = entries.len();
        let mut range = json!({ "header": header(&CLUSTER.to_string()) });
        if count > 0 {
            range["kvs"] = Value::Array(entries);
            range["count"] = Value::String(count.to_string());
        }
        range
    }

    fn compared_with(range: Value) -> Value {
        json!({
            "header": header(&CLUSTER.to_string()),
            "responses": [{ "response_range": range }]
        })
    }

    /// `selector` followed by the JSON `body`.
    fn input(selector: u8, body: &Value) -> Vec<u8> {
        input_bytes(selector, &serde_json::to_vec(body).expect("JSON"))
    }

    fn input_bytes(selector: u8, body: &[u8]) -> Vec<u8> {
        [&[selector][..], body].concat()
    }

    /// The committed seeds of `witness_etcd`: etcd's answers as its JSON
    /// gateway sends them, and copies changed where the store must refuse
    /// them. A seed's name says what [`etcd`] returns for it (`valid-` true,
    /// `refused-` false, `noise-` either).
    pub fn seeds() -> Vec<(String, Vec<u8>)> {
        let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
        let mut add = |name: &str, bytes: Vec<u8>| seeds.push((name.to_string(), bytes));

        let initial = CanonicalState::initial(crate::fuzzing::IDENTITY)
            .and_then(|state| state.encode())
            .expect("an initial state");
        let (_, claimed) = claim();
        let claimed = claimed.encode().expect("a claimed state");
        let one = |state: &[u8]| range(vec![entry(KEY, state)]);
        let valid = one(&claimed);
        add("valid-range-claimed", input(RANGE, &valid));
        add("valid-range-released", input(RANGE, &one(&initial)));
        add("valid-range-absent", input(RANGE, &range(Vec::new())));
        let mut changed = valid.clone();
        changed["header"]["cluster_id"] = Value::String((CLUSTER - 1).to_string());
        add("refused-range-other-cluster", input(RANGE, &changed));
        let mut changed = valid.clone();
        changed["header"]["cluster_id"] = Value::String(format!("0{CLUSTER}"));
        add(
            "refused-range-cluster-not-canonical",
            input(RANGE, &changed),
        );
        let mut changed = valid.clone();
        changed["header"]["cluster_id"] = json!(1u64);
        add("refused-range-cluster-a-number", input(RANGE, &changed));
        let mut changed = valid.clone();
        changed["more"] = Value::Bool(true);
        add("refused-range-truncated", input(RANGE, &changed));
        add(
            "refused-range-two-keys",
            input(
                RANGE,
                &range(vec![entry(KEY, &claimed), entry(KEY, &initial)]),
            ),
        );
        let mut changed = valid.clone();
        changed["count"] = Value::String("2".into());
        add("refused-range-count-differs", input(RANGE, &changed));
        add(
            "refused-range-other-key",
            input(
                RANGE,
                &range(vec![entry("/maki/witness/volume-b", &claimed)]),
            ),
        );
        let mut changed = valid.clone();
        changed["kvs"][0]["lease"] = Value::String("7587862072426521636".into());
        add("refused-range-lease", input(RANGE, &changed));
        let mut changed = valid.clone();
        changed["kvs"][0]["value"] = Value::String(format!(
            " {}",
            changed["kvs"][0]["value"].as_str().expect("a value")
        ));
        add("refused-range-value-not-base64", input(RANGE, &changed));
        let mut changed = valid.clone();
        changed["kvs"][0]
            .as_object_mut()
            .expect("an entry")
            .remove("value");
        add("refused-range-value-absent", input(RANGE, &changed));
        let mut changed = valid.clone();
        changed["kvs"][0]["mod_revision"] = Value::String("0".into());
        add("refused-range-revision-zero", input(RANGE, &changed));
        let mut changed = valid.clone();
        changed["kvs"][0]["mod_revision"] = Value::String(u64::MAX.to_string());
        add("refused-range-revision-beyond-i64", input(RANGE, &changed));
        let other = CanonicalState::initial([0x6b; 16])
            .and_then(|state| state.encode())
            .expect("a state of another identity");
        add("refused-range-other-identity", input(RANGE, &one(&other)));
        let mut damaged = claimed.clone();
        damaged[20] ^= 0x01;
        add("refused-range-damaged-state", input(RANGE, &one(&damaged)));
        let body = serde_json::to_vec(&valid).expect("JSON");
        add(
            "refused-range-not-json",
            input_bytes(RANGE, &body[..body.len() - 1]),
        );
        let mut noise = body.clone();
        noise[body.len() / 2] ^= 0x04;
        add("noise-range-claimed", input_bytes(RANGE, &noise));

        let committed = json!({
            "header": header(&CLUSTER.to_string()),
            "succeeded": true,
            "responses": [{ "response_put": { "header": header(&CLUSTER.to_string()) } }]
        });
        add(
            "valid-transaction-committed",
            input(TRANSACTION, &committed),
        );
        add(
            "valid-transaction-already-applied",
            input(TRANSACTION, &compared_with(one(&claimed))),
        );
        add(
            "refused-transaction-other-predecessor",
            input(TRANSACTION, &compared_with(one(&initial))),
        );
        add(
            "refused-transaction-key-vanished",
            input(TRANSACTION, &compared_with(range(Vec::new()))),
        );
        add(
            "refused-transaction-without-range",
            input(
                TRANSACTION,
                &json!({ "header": header(&CLUSTER.to_string()), "succeeded": false }),
            ),
        );
        let mut changed = committed.clone();
        changed["succeeded"] = Value::String("true".into());
        add(
            "refused-transaction-verdict-not-bool",
            input(TRANSACTION, &changed),
        );
        let mut two = compared_with(one(&claimed));
        let first = two["responses"][0].clone();
        two["responses"]
            .as_array_mut()
            .expect("responses")
            .push(first);
        add("refused-transaction-two-ranges", input(TRANSACTION, &two));

        add("valid-create", input(CREATE, &committed));
        add(
            "refused-create-key-exists",
            input(CREATE, &compared_with(one(&initial))),
        );
        seeds
    }
}
