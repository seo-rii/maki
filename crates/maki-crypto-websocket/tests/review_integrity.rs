//! R3-001: explicit authenticated WebSocket errors and engine integration.
#[path = "common/integrity.rs"]
mod common;

use base64::Engine as _;
use common::*;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::{
    CiphertextUnit, CryptoError, CryptoProvider, ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
enum Mode {
    Authenticated(u8),
    Error(String),
    Stall,
}
async fn response(request: &Value, seed: u8) -> Value {
    let context = maki_crypto::CryptoContext {
        volume_uuid: request["volume"].as_str().unwrap().parse().unwrap(),
        format_version: request["format"].as_u64().unwrap() as u32,
        crypto_compatibility_id: request["profile"].as_str().unwrap().into(),
    };
    let provider = local(seed);
    let items: Vec<_> = request["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| CiphertextUnit {
            unit_index: item["unit"].as_u64().unwrap(),
            data: base64::engine::general_purpose::STANDARD
                .decode(item["data"].as_str().unwrap())
                .unwrap(),
        })
        .collect();
    let result = if request["op"] == "decrypt" {
        provider.decrypt_batch(&context, &items).await.map(|items| {
            items
                .into_iter()
                .map(|i| (i.unit_index, i.data.expose().to_vec()))
                .collect::<Vec<_>>()
        })
    } else {
        let items: Vec<_> = items
            .into_iter()
            .map(|i| PlaintextUnit {
                unit_index: i.unit_index,
                data: SecretBuffer::from_vec(i.data),
            })
            .collect();
        provider
            .encrypt_batch(&context, &items)
            .await
            .map(|items| items.into_iter().map(|i| (i.unit_index, i.data)).collect())
    };
    match result {
        Ok(items) => {
            json!({"id": request["id"], "items": items.into_iter().map(|(unit, data)| json!({"unit": unit, "data": base64::engine::general_purpose::STANDARD.encode(data)})).collect::<Vec<_>>() })
        }
        // A foreign compatibility id is refused as a plain bad request (the
        // self-test's compatibility-id probe); only a failed authentication
        // is an integrity error.
        Err(CryptoError::ProviderFatal(_)) => {
            json!({"id": request["id"], "error": {"class": "bad-request", "message": REMOTE_SECRET}})
        }
        Err(error) => {
            assert!(matches!(error, CryptoError::Integrity(_)), "{error}");
            json!({"id": request["id"], "error": {"class": "integrity", "reason": "auth-tag-mismatch", "message": REMOTE_SECRET}})
        }
    }
}
async fn server(mode: Mode) -> (String, Arc<Mutex<Mode>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(mode));
    let shared = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let state = shared.clone();
            tokio::spawn(async move {
                let socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let (mut sink, mut source) = socket.split();
                while let Some(Ok(message)) = source.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let mode = state.lock().unwrap().clone();
                    let response = match mode {
                        Mode::Authenticated(seed) => response(&request, seed).await.to_string(),
                        Mode::Error(error) => {
                            format!(r#"{{"id":{},"error":{error}}}"#, request["id"])
                        }
                        Mode::Stall => {
                            std::future::pending::<()>().await;
                            unreachable!()
                        }
                    };
                    if sink.send(response.into()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (url, state)
}
async fn provider(url: &str, timeout: Duration) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url: url.into(),
        capabilities: capabilities().await,
        timeout,
        max_frame_bytes: 1 << 20,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_websocket_engine_pipeline() {
    let (url, _) = server(Mode::Authenticated(1)).await;
    let (wrong_url, _) = server(Mode::Authenticated(2)).await;
    let remote = Arc::new(provider(&url, Duration::from_secs(2)).await);
    verify_engine(
        remote,
        Arc::new(provider(&wrong_url, Duration::from_secs(2)).await),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_integrity_requires_an_allowlisted_unambiguous_reason() {
    let (url, state) = server(Mode::Authenticated(1)).await;
    let provider = provider(&url, Duration::from_millis(200)).await;
    for reason in ["auth-tag-mismatch", "context-mismatch"] {
        *state.lock().unwrap() = Mode::Error(
            json!({"class":"integrity", "reason":reason, "message":REMOTE_SECRET}).to_string(),
        );
        let error = provider
            .decrypt_batch(
                &context(),
                &[CiphertextUnit {
                    unit_index: 7,
                    data: vec![0; UNIT + 28],
                }],
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, CryptoError::Integrity(_)),
            "{reason}: {error}"
        );
        assert_private(&error);
    }
    for error in [
        json!({"class":"bad-request", "reason":"auth-tag-mismatch", "message":REMOTE_SECRET})
            .to_string(),
        json!({"class":"retryable", "reason":"auth-tag-mismatch", "message":REMOTE_SECRET})
            .to_string(),
        json!({"class":"integrity", "message":REMOTE_SECRET}).to_string(),
        json!({"class":"integrity", "reason":null, "message":REMOTE_SECRET}).to_string(),
        json!({"class":"integrity", "reason":"unknown", "message":REMOTE_SECRET}).to_string(),
        json!({"class":"integrity", "reason":"SECRET".repeat(1024), "message":REMOTE_SECRET})
            .to_string(),
        r#"{"class":"integrity","reason":"unknown","reason":"auth-tag-mismatch"}"#.into(),
        r#"{"class":"integrity","reason":"auth-tag-mismatch","reason":"auth-tag-mismatch"}"#.into(),
        r#"{"class":"bad-request","class":"integrity","reason":"auth-tag-mismatch"}"#.into(),
    ] {
        *state.lock().unwrap() = Mode::Error(error);
        let error = provider
            .encrypt_batch(&context(), &[plaintext()])
            .await
            .unwrap_err();
        assert!(
            !matches!(error, CryptoError::Integrity(_)),
            "ambiguous signal became integrity proof: {error}"
        );
        assert_private(&error);
    }
    *state.lock().unwrap() =
        Mode::Error(json!({"class":"bad-request", "message":REMOTE_SECRET}).to_string());
    let error = provider
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap_err();
    assert_eq!(error.class(), ErrorClass::NonRetryableRequest);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_timeout_remains_inconclusive_through_scheduler() {
    let (url, _) = server(Mode::Stall).await;
    let provider = pipeline(Arc::new(provider(&url, Duration::from_millis(50)).await));
    let error = provider
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap_err();
    assert_eq!(error.class(), ErrorClass::Retryable);
    assert_private(&error);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_websocket_tamper_and_context_probes() {
    let (url, _) = server(Mode::Authenticated(1)).await;
    verify_probes(&provider(&url, Duration::from_secs(2)).await).await;
}
