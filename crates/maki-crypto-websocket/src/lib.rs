//! `maki-crypto-websocket` — WebSocket/WSS remote crypto transport
//! (SPEC §18, §51).
//!
//! Protocol: one JSON object per text frame.
//! Request:  `{"id": n, "op": "encrypt"|"decrypt", "profile": …,
//!             "volume": …, "items": [{"unit": u, "data": base64}, …]}`
//! Response: `{"id": n, "items": [{"data": base64}, …]}`
//!        or `{"id": n, "error": {"class": …, "message": …}}`
//!
//! Concurrency-safe request/response correlation by `id`: responses may
//! arrive out of order; responses with unknown ids (stale, from an earlier
//! connection generation) are dropped. On connection failure, pending
//! requests fail `Retryable` and the next call reconnects transparently.
//! Frame sizes are bounded in both directions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio::task::AbortHandle;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};

#[derive(Clone)]
pub struct WsProviderSpec {
    pub url: String,
    pub capabilities: CryptoCapabilities,
    pub timeout: Duration,
    pub max_frame_bytes: usize,
}

/// A URL may carry userinfo or a token query: print scheme and host only
/// (C-11).
pub fn redacted_url(url: &str) -> String {
    let no_query = url.split(['?', '#']).next().unwrap_or("");
    match no_query.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split('/').next().unwrap_or("");
            let host = authority.rsplit('@').next().unwrap_or("");
            format!("{scheme}://{host}/<redacted>")
        }
        None => "<redacted>".to_string(),
    }
}

impl std::fmt::Debug for WsProviderSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsProviderSpec")
            .field("url", &redacted_url(&self.url))
            .field("capabilities", &self.capabilities)
            .field("timeout", &self.timeout)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .finish()
    }
}

/// id → (connection generation the request was sent on, responder).
/// The generation lets a dying connection's sweep fail only *its own*
/// requests — never ones already in flight on a successor connection.
type Pending =
    Arc<parking_lot::Mutex<HashMap<u64, (u64, oneshot::Sender<Result<Value, CryptoError>>)>>>;

struct Connection {
    sender: mpsc::Sender<Message>,
    generation: u64,
    cancellation: ConnectionCancellation,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.cancellation.retire();
    }
}

#[derive(Clone)]
struct ConnectionCancellation {
    task: AbortHandle,
    pending: Pending,
    dead_generation: Arc<AtomicU64>,
    generation: u64,
}

impl ConnectionCancellation {
    fn retire(&self) {
        // Mark before sweeping, so a racing request never registers on a
        // generation whose response reader can no longer deliver it.
        self.dead_generation
            .fetch_max(self.generation, Ordering::SeqCst);
        self.task.abort();
        WsCryptoProvider::fail_pending_generation(&self.pending, self.generation, "retired");
    }
}

struct PendingRequest {
    id: u64,
    pending: Pending,
    cancellation: Option<ConnectionCancellation>,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.pending.lock().remove(&self.id);
        if let Some(cancellation) = &self.cancellation {
            cancellation.retire();
        }
    }
}

struct MarkDeadOnDrop {
    pending: Pending,
    dead_generation: Arc<AtomicU64>,
    generation: u64,
}

impl Drop for MarkDeadOnDrop {
    fn drop(&mut self) {
        self.dead_generation
            .fetch_max(self.generation, Ordering::SeqCst);
        WsCryptoProvider::fail_pending_generation(&self.pending, self.generation, "closed");
    }
}

pub struct WsCryptoProvider {
    spec: WsProviderSpec,
    connection: AsyncMutex<Option<Connection>>,
    pending: Pending,
    next_id: AtomicU64,
    generation: AtomicU64,
    /// Highest connection generation whose reader has exited. A registered
    /// connection at or below this is a corpse: requests must reconnect
    /// instead of sending into it (its responses can never arrive).
    dead_generation: Arc<AtomicU64>,
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn retryable(msg: impl std::fmt::Display) -> CryptoError {
    CryptoError::Retryable(msg.to_string())
}

impl WsCryptoProvider {
    pub fn new(spec: WsProviderSpec) -> Self {
        Self {
            spec,
            connection: AsyncMutex::new(None),
            pending: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            generation: AtomicU64::new(0),
            dead_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Fail only the requests owned by the retiring connection generation.
    fn fail_pending_generation(pending: &Pending, generation: u64, why: &str) {
        let mut map = pending.lock();
        let ids: Vec<u64> = map
            .iter()
            .filter(|(_, (g, _))| *g == generation)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some((_, tx)) = map.remove(&id) {
                let _ = tx.send(Err(retryable(format!("connection lost: {why}"))));
            }
        }
    }

    async fn connect(&self) -> Result<Connection, CryptoError> {
        let config = WebSocketConfig::default()
            .max_message_size(Some(self.spec.max_frame_bytes))
            .max_frame_size(Some(self.spec.max_frame_bytes));
        // TCP connect and the HTTP upgrade have no timeout of their own: a
        // peer that accepts and never answers would hold the connection
        // mutex forever, and with it every request on this provider (C-05).
        let (ws, _response) = tokio::time::timeout(
            self.spec.timeout,
            tokio_tungstenite::connect_async_with_config(&self.spec.url, Some(config), false),
        )
        .await
        .map_err(|_| retryable("websocket connect timeout"))?
        .map_err(|e| retryable(format!("websocket connect failed: {e}")))?;

        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let (mut sink, mut source) = ws.split();
        let (tx, mut rx) = mpsc::channel::<Message>(64);

        // One task owns both halves. Completion of either future drops the
        // other, and aborting the owner always releases the whole socket.
        let writer = async move {
            while let Some(msg) = rx.recv().await {
                if sink.send(msg).await.is_err() {
                    return;
                }
            }
        };

        // Correlate responses only with requests on this generation.
        let pending = self.pending.clone();
        let dead_generation = self.dead_generation.clone();
        let reader_pending = self.pending.clone();
        let reader = async move {
            loop {
                match source.next().await {
                    Some(Ok(msg)) => {
                        let Ok(text) = msg.into_text() else { continue };
                        let Ok(value) = serde_json::from_str::<Value>(&text) else {
                            tracing::warn!("websocket: unparseable frame dropped");
                            continue;
                        };
                        let Some(id) = value.get("id").and_then(|v| v.as_u64()) else {
                            continue;
                        };
                        let response = {
                            let mut pending = reader_pending.lock();
                            if pending.get(&id).is_some_and(|(g, _)| *g == generation) {
                                pending.remove(&id)
                            } else {
                                None
                            }
                        };
                        match response {
                            Some((_, tx)) => {
                                let _ = tx.send(Ok(value));
                            }
                            None => {
                                // Stale or foreign response (SPEC §51):
                                // never delivered to a caller.
                                tracing::debug!("websocket: stale response id {id} dropped");
                            }
                        }
                    }
                    Some(Err(e)) => {
                        tracing::debug!("websocket: reader exited: {e}");
                        return;
                    }
                    None => {
                        return;
                    }
                }
            }
        };
        let task = tokio::spawn(async move {
            // Natural exit and abort share the same generation-scoped
            // cleanup, including failure of the writer before a response.
            let _mark_dead = MarkDeadOnDrop {
                pending,
                dead_generation,
                generation,
            };
            tokio::select! {
                _ = writer => {},
                _ = reader => {},
            }
        });

        Ok(Connection {
            sender: tx,
            generation,
            cancellation: ConnectionCancellation {
                task: task.abort_handle(),
                pending: self.pending.clone(),
                dead_generation: self.dead_generation.clone(),
                generation,
            },
        })
    }

    async fn request_once(&self, body: &Value) -> Result<Value, CryptoError> {
        let id = body["id"].as_u64().expect("id set");
        let encoded = body.to_string();
        if encoded.len() > self.spec.max_frame_bytes {
            return Err(CryptoError::NonRetryableRequest(format!(
                "request of {} bytes exceeds frame limit {}",
                encoded.len(),
                self.spec.max_frame_bytes
            )));
        }

        let (tx, rx) = oneshot::channel();
        let mut pending_request = {
            let mut guard = self.connection.lock().await;
            // Discard a connection whose reader has already exited.
            if let Some(conn) = guard.as_ref() {
                if self.dead_generation.load(Ordering::SeqCst) >= conn.generation {
                    *guard = None;
                }
            }
            if guard.is_none() {
                *guard = Some(self.connect().await?);
            }
            let conn = guard.as_ref().unwrap();
            let generation = conn.generation;
            // Register under this connection's generation before sending, so
            // a fast response cannot be "stale" and a dying connection's
            // sweep can target exactly its own requests.
            self.pending.lock().insert(id, (generation, tx));
            let pending_request = PendingRequest {
                id,
                pending: self.pending.clone(),
                cancellation: Some(conn.cancellation.clone()),
            };
            let sent =
                tokio::time::timeout(self.spec.timeout, conn.sender.send(Message::text(encoded)))
                    .await;
            if !matches!(sent, Ok(Ok(()))) {
                // Writer gone or wedged: drop this connection if it's still
                // the registered one.
                if guard.as_ref().map(|c| c.generation) == Some(generation) {
                    *guard = None;
                }
                return Err(retryable("websocket send failed"));
            }
            pending_request
        };

        match tokio::time::timeout(self.spec.timeout, rx).await {
            Ok(Ok(result)) => {
                if result.is_ok() {
                    // A completed exchange leaves the connection reusable.
                    // Any error or future cancellation instead retires only
                    // this request's generation via the guard.
                    pending_request.cancellation = None;
                }
                result
            }
            Ok(Err(_)) => Err(retryable("websocket response channel closed")),
            Err(_) => {
                // A peer that stopped answering (half-open TCP session,
                // hung service) must not be reused: every later request
                // would burn the full timeout on the same corpse (C-05).
                Err(retryable("websocket request timeout"))
            }
        }
    }

    /// One logical request with a single transparent reconnect attempt on
    /// transport failure. A provider that is not `retry_safe` is never sent
    /// the same request twice (review M-010): the transport failure is
    /// surfaced as-is.
    async fn request(
        &self,
        op: &str,
        context: &CryptoContext,
        items: &[(u64, &[u8])],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        let mut last_err = None;
        let attempts = if self.spec.capabilities.retry_safe {
            2
        } else {
            1
        };
        for _attempt in 0..attempts {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            let body = json!({
                "id": id,
                "op": op,
                "profile": context.crypto_compatibility_id,
                "volume": context.volume_uuid.to_string(),
                "items": items
                    .iter()
                    .map(|(unit, data)| json!({"unit": unit, "data": b64(data)}))
                    .collect::<Vec<_>>(),
            });
            match self.request_once(&body).await {
                Ok(response) => return self.parse_response(&response, items),
                Err(e) if e.is_retryable() => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap())
    }

    /// Every response item must echo its request unit, in request order
    /// (review M-012): a reordered, duplicated, dropped, or foreign item is
    /// a contract violation, never silently re-labelled by position.
    fn parse_response(
        &self,
        response: &Value,
        requested: &[(u64, &[u8])],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        let expected = requested.len();
        if let Some(error) = response.get("error") {
            let class = error.get("class").and_then(|c| c.as_str()).unwrap_or("");
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("provider error")
                .to_string();
            return Err(match class {
                "throttled" => CryptoError::Throttled(message),
                "retryable" => CryptoError::Retryable(message),
                "bad-request" => CryptoError::NonRetryableRequest(message),
                _ => CryptoError::ProviderFatal(message),
            });
        }
        let items = response
            .get("items")
            .and_then(|i| i.as_array())
            .ok_or_else(|| CryptoError::Contract("response missing items array".to_string()))?;
        if items.len() != expected {
            return Err(CryptoError::Contract(format!(
                "response has {} item(s), expected {expected}",
                items.len()
            )));
        }
        items
            .iter()
            .zip(requested.iter())
            .enumerate()
            .map(|(position, (item, (unit, _)))| {
                let echoed = item.get("unit").and_then(|u| u.as_u64());
                if echoed != Some(*unit) {
                    return Err(CryptoError::Contract(format!(
                        "response item {position} echoes unit {echoed:?}, expected {unit}"
                    )));
                }
                let data = item
                    .get("data")
                    .and_then(|d| d.as_str())
                    .ok_or_else(|| CryptoError::Contract("item missing data".to_string()))?;
                base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|e| CryptoError::Contract(format!("bad base64: {e}")))
            })
            .collect()
    }
}

#[async_trait]
impl CryptoProvider for WsCryptoProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(self.spec.capabilities.clone())
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let payloads: Vec<(u64, &[u8])> = items
            .iter()
            .map(|i| (i.unit_index, i.data.expose()))
            .collect();
        let results = self.request("encrypt", context, &payloads).await?;
        Ok(results
            .into_iter()
            .zip(items.iter())
            .map(|(data, item)| CiphertextUnit {
                unit_index: item.unit_index,
                data,
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let payloads: Vec<(u64, &[u8])> = items
            .iter()
            .map(|i| (i.unit_index, i.data.as_slice()))
            .collect();
        let results = self.request("decrypt", context, &payloads).await?;
        Ok(results
            .into_iter()
            .zip(items.iter())
            .map(|(data, item)| PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_vec(data),
            })
            .collect())
    }
}
