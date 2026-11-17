//! A WebSocket endpoint whose upgrade is refused with a generic 4xx (a proxy
//! in front of it answers 400 or 426) is unreachable, not proof that the
//! volume's requests are bad. Attach must quarantine it and serve through a
//! healthy peer, exactly as for a connection failure, instead of refusing the
//! whole attach as a failed self-test.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::{CryptoContext, PlaintextUnit, SecretBuffer};
use maki_nbdkit::daemon::{
    build_provider_with_endpoints, create_volume_from_config_str, parse_and_validate,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const UNIT: usize = 512;
const XOR: u8 = 0x5a;

/// Answers every upgrade request with `status` and closes the connection.
async fn refusing(status: u16) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/crypto", listener.local_addr().unwrap());
    let upgrades = Arc::new(AtomicUsize::new(0));
    let count = upgrades.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0; 4096];
            let mut used = 0;
            loop {
                assert!(
                    used < request.len(),
                    "upgrade request header exceeded fixture limit"
                );
                let Ok(received) = socket.read(&mut request[used..]).await else {
                    break;
                };
                if received == 0 {
                    break;
                }
                used += received;
                if request[..used].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    count.fetch_add(1, Ordering::SeqCst);
                    let _ = socket
                        .write_all(
                            format!(
                                "HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\n\
                                 Connection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .await;
                    break;
                }
            }
        }
    });
    (url, upgrades)
}

/// An XOR "cipher" endpoint that counts the request frames it answers.
async fn healthy() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/crypto", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    let items: Vec<_> = request["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let data: Vec<u8> = base64::engine::general_purpose::STANDARD
                                .decode(item["data"].as_str().unwrap())
                                .unwrap()
                                .into_iter()
                                .map(|byte| byte ^ XOR)
                                .collect();
                            json!({
                                "unit": item["unit"],
                                "data": base64::engine::general_purpose::STANDARD.encode(data),
                            })
                        })
                        .collect();
                    let response = json!({"id": request["id"], "items": items});
                    if ws.send(response.to_string().into()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (url, requests)
}

fn config(root: &std::path::Path, urls: &[String], retry_safe: bool) -> String {
    let endpoints: String = urls
        .iter()
        .enumerate()
        .map(|(index, url)| {
            format!("[[crypto.websocket.endpoint]]\nname = \"ep{index}\"\nurl = \"{url}\"\n")
        })
        .collect();
    let root = root.to_string_lossy().replace('\\', "/");
    format!(
        r#"
config_schema_version = 1
[volume]
name = "ws-upgrade-quarantine"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-websocket"
crypto_compatibility_id = "ws-upgrade-quarantine-v1"
availability_policy = "bounded-error"
max_operation_time = "5s"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
retry_safe = {retry_safe}
stateless = true
[crypto.batch]
max_items = 1
target_items = 1
max_bytes = 512
target_bytes = 512
max_wait = "0ms"
[crypto.retry]
initial_delay = "1ms"
max_delay = "1ms"
[crypto.websocket]
timeout = "2s"
max_frame_bytes = "64KiB"
{endpoints}
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#
    )
}

async fn attach_quarantines_refusing_endpoint(status: u16, retry_safe: bool) {
    let (refusing_url, upgrades) = refusing(status).await;
    let (healthy_url, served) = healthy().await;
    let directory = tempfile::tempdir().unwrap();
    let raw = config(
        &directory.path().join("volume"),
        &[refusing_url, healthy_url],
        retry_safe,
    );
    let cfg = parse_and_validate(&raw).unwrap();
    let superblock = create_volume_from_config_str(&raw).unwrap();
    let (provider, endpoints) = build_provider_with_endpoints(&cfg)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "HTTP {status} on upgrade (retry_safe = {retry_safe}) refused attach although \
                 a healthy endpoint is configured: {error}"
            )
        });
    assert!(
        upgrades.load(Ordering::SeqCst) > 0,
        "the refusing endpoint was never probed"
    );
    let states = endpoints.unwrap().endpoint_status();
    let state = |name: &str| states.iter().find(|state| state.name == name).unwrap();
    assert!(
        !state("ep0").validated,
        "HTTP {status}: refusing endpoint must be quarantined"
    );
    assert!(state("ep1").validated, "HTTP {status}");

    let context = CryptoContext {
        volume_uuid: superblock.volume_uuid,
        format_version: superblock.format_version,
        crypto_compatibility_id: superblock.crypto_compatibility_id,
    };
    let before = served.load(Ordering::SeqCst);
    let ciphertext = provider
        .encrypt_batch(
            &context,
            &[PlaintextUnit {
                unit_index: 3,
                data: SecretBuffer::from_slice(&[0x71; UNIT]),
            }],
        )
        .await
        .unwrap();
    let plaintext = provider.decrypt_batch(&context, &ciphertext).await.unwrap();
    assert_eq!(plaintext[0].data.expose(), &[0x71; UNIT]);
    assert!(served.load(Ordering::SeqCst) >= before + 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generic_4xx_upgrade_refusal_quarantines_the_endpoint_at_attach() {
    for status in [400, 426] {
        attach_quarantines_refusing_endpoint(status, true).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generic_4xx_upgrade_refusal_quarantines_a_non_retry_safe_endpoint_at_attach() {
    attach_quarantines_refusing_endpoint(400, false).await;
}
