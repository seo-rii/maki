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
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};

#[derive(Debug, Clone)]
pub struct WsProviderSpec {
    pub url: String,
    pub capabilities: CryptoCapabilities,
    pub timeout: Duration,
    pub max_frame_bytes: usize,
}

type Pending = Arc<parking_lot::Mutex<HashMap<u64, oneshot::Sender<Result<Value, CryptoError>>>>>;

struct Connection {
    sender: mpsc::Sender<Message>,
    generation: u64,
}

pub struct WsCryptoProvider {
    spec: WsProviderSpec,
    connection: AsyncMutex<Option<Connection>>,
    pending: Pending,
    next_id: AtomicU64,
    generation: AtomicU64,
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
        }
    }

    /// Fail every pending request (connection died).
    fn fail_all_pending(pending: &Pending, why: &str) {
        let mut map = pending.lock();
        for (_, tx) in map.drain() {
            let _ = tx.send(Err(retryable(format!("connection lost: {why}"))));
        }
    }

    async fn connect(&self) -> Result<Connection, CryptoError> {
        let config = WebSocketConfig::default()
            .max_message_size(Some(self.spec.max_frame_bytes))
            .max_frame_size(Some(self.spec.max_frame_bytes));
        let (ws, _response) = tokio_tungstenite::connect_async_with_config(
            &self.spec.url,
            Some(config),
            false,
        )
        .await
        .map_err(|e| retryable(format!("websocket connect failed: {e}")))?;

        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let (mut sink, mut source) = ws.split();
        let (tx, mut rx) = mpsc::channel::<Message>(64);

        // Writer task.
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if sink.send(msg).await.is_err() {
                    return;
                }
            }
        });

        // Reader task: correlate responses; drop stale ids.
        let pending = self.pending.clone();
        tokio::spawn(async move {
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
                        match pending.lock().remove(&id) {
                            Some(tx) => {
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
                        Self::fail_all_pending(&pending, &e.to_string());
                        return;
                    }
                    None => {
                        Self::fail_all_pending(&pending, "closed");
                        return;
                    }
                }
            }
        });

        Ok(Connection {
            sender: tx,
            generation,
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

        // Register before sending so a fast response cannot be "stale".
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id, tx);

        let send_result = {
            let mut guard = self.connection.lock().await;
            if guard.is_none() {
                match self.connect().await {
                    Ok(conn) => *guard = Some(conn),
                    Err(e) => {
                        self.pending.lock().remove(&id);
                        return Err(e);
                    }
                }
            }
            let conn = guard.as_ref().unwrap();
            let generation = conn.generation;
            match conn.sender.send(Message::text(encoded)).await {
                Ok(()) => Ok(()),
                Err(_) => {
                    // Writer gone: drop this connection if it's still the
                    // registered one.
                    if guard.as_ref().map(|c| c.generation) == Some(generation) {
                        *guard = None;
                    }
                    Err(())
                }
            }
        };
        if send_result.is_err() {
            self.pending.lock().remove(&id);
            return Err(retryable("websocket send failed"));
        }

        match tokio::time::timeout(self.spec.timeout, rx).await {
            Ok(Ok(result)) => {
                // On a connection-loss error, clear the dead connection so
                // the next call reconnects.
                if result.is_err() {
                    let mut guard = self.connection.lock().await;
                    *guard = None;
                }
                result
            }
            Ok(Err(_)) => Err(retryable("websocket response channel closed")),
            Err(_) => {
                self.pending.lock().remove(&id);
                Err(retryable("websocket request timeout"))
            }
        }
    }

    /// One logical request with a single transparent reconnect attempt on
    /// transport failure.
    async fn request(&self, op: &str, context: &CryptoContext, items: &[(u64, &[u8])])
        -> Result<Vec<Vec<u8>>, CryptoError>
    {
        let mut last_err = None;
        for _attempt in 0..2 {
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
                Ok(response) => return self.parse_response(&response, items.len()),
                Err(e) if e.is_retryable() => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap())
    }

    fn parse_response(&self, response: &Value, expected: usize) -> Result<Vec<Vec<u8>>, CryptoError> {
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
            .map(|item| {
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
