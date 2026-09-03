//! C-05: the WebSocket transport must honour its timeout on *every* step
//! (TCP/handshake, send, response) and must retire a connection whose
//! peer stopped answering, so the next request reconnects instead of
//! burning the timeout again on the same dead socket.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::net::TcpListener;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};

const UNIT: usize = 64;

fn caps() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "remote-websocket".into(),
        crypto_compatibility_id: "vendor-profile-v1".into(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: BatchCapability {
            supported: true,
            max_items: 64,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(5),
        format_version: 1,
        crypto_compatibility_id: "vendor-profile-v1".into(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&[i as u8; UNIT]),
    }
}

fn provider(addr: SocketAddr, timeout: Duration) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url: format!("ws://{addr}"),
        capabilities: caps(),
        timeout,
        max_frame_bytes: 1 << 20,
    })
}

/// Accepts TCP and then never speaks: no handshake ever completes.
async fn silent_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _keep = socket;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            });
        }
    });
    addr
}

/// Completes the WebSocket handshake, then swallows every message.
async fn silent_ws_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(socket).await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let (_sink, mut source) = ws.split();
                while let Some(Ok(_)) = source.next().await {}
            });
        }
    });
    (addr, connections)
}

#[tokio::test]
async fn connect_to_a_silent_peer_fails_within_the_timeout() {
    let addr = silent_tcp_server().await;
    let provider = provider(addr, Duration::from_millis(300));
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        provider.encrypt_batch(&ctx(), &[pt(1)]),
    )
    .await
    .expect("request hung far past its timeout on a silent peer");
    let err = result.unwrap_err();
    assert!(err.is_retryable(), "{err}");
}

#[tokio::test]
async fn request_timeout_retires_the_connection_so_the_next_request_reconnects() {
    let (addr, connections) = silent_ws_server().await;
    let provider = provider(addr, Duration::from_millis(200));
    for _ in 0..2 {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            provider.encrypt_batch(&ctx(), &[pt(1)]),
        )
        .await
        .expect("request hung");
        assert!(result.unwrap_err().is_retryable());
    }
    // Each logical request (two transport attempts each, retry_safe) must
    // have given up on the silent socket and opened a fresh one.
    assert!(
        connections.load(Ordering::SeqCst) >= 2,
        "requests kept reusing a connection that never answers ({} connection(s))",
        connections.load(Ordering::SeqCst)
    );
}

/// Credentials-bearing configuration must not print through `Debug`.
#[test]
fn spec_debug_output_is_redacted() {
    let spec = WsProviderSpec {
        url: "wss://user:hunter2@example.invalid/v1?token=SECRET-TOKEN".into(),
        capabilities: caps(),
        timeout: Duration::from_secs(1),
        max_frame_bytes: 1 << 20,
    };
    let text = format!("{spec:?}");
    assert!(
        !text.contains("hunter2") && !text.contains("SECRET-TOKEN"),
        "{text}"
    );
}
