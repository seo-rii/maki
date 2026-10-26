//! BUG-162: transport limits cover reachable batches, including serialization overhead.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use maki_format::config::{parse_config, ConfigError, VolumeConfig};
use serde_json::{json, Value};

const UNIT: usize = 4096;
const CIPHER: usize = 4384;
const LIMIT: usize = 16 << 10;
const PROFILE: &str = "effective-batch-v1";

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(162),
        format_version: u32::MAX,
        crypto_compatibility_id: PROFILE.into(),
    }
}

fn capabilities() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "effective-batch".into(),
        crypto_compatibility_id: PROFILE.into(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: CIPHER as u32,
        stateless: true,
        retry_safe: true,
        batch: BatchCapability {
            supported: true,
            max_items: 1,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

fn plain(unit: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: unit,
        data: SecretBuffer::from_vec((0..UNIT).map(|i| i as u8).collect()),
    }
}

fn transform(data: &[u8], decrypt: bool) -> Vec<u8> {
    if decrypt {
        assert_eq!(data.len(), CIPHER);
        data[CIPHER - UNIT..].iter().map(|b| b ^ 0x5a).collect()
    } else {
        assert_eq!(data.len(), UNIT);
        let mut result = vec![0xa5; CIPHER - UNIT];
        result.extend(data.iter().map(|b| b ^ 0x5a));
        result
    }
}

fn validated(raw: &str) -> Result<VolumeConfig, ConfigError> {
    let config = parse_config(raw)?;
    config.validate()?;
    Ok(config)
}

fn config(limit: &str, batch_bytes: &str, max_items: usize) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "effective-batch"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-websocket"
crypto_compatibility_id = "{PROFILE}"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
integrity = "none"
context_binding = "none"
replay_protection = "none"
[crypto.batch]
target_items = {max_items}
max_items = {max_items}
target_bytes = "{batch_bytes}"
max_bytes = "{batch_bytes}"
[crypto.websocket]
max_frame_bytes = "{limit}"
[[crypto.websocket.endpoint]]
name = "local-fixture"
url = "ws://127.0.0.1:7000"
[backing]
root = "/unused/batch-limits"
"#
    )
}

#[test]
fn singleton_configuration_accepts_a_limit_that_fits_its_largest_legal_item() {
    let result = validated(&config("16KiB", "1MiB", 1));
    assert!(
        result.is_ok(),
        "one 4096-byte unit / 4384-byte ciphertext fits a 16KiB transport limit: {result:?}"
    );
}

#[test]
fn increasing_transport_limit_preserves_an_otherwise_identical_configuration() {
    let parsed = validated(&config("2MiB", "1MiB", 1)).unwrap();
    assert_eq!(parsed.crypto.batch.max_items, 1);
    assert_eq!(parsed.crypto.batch.max_bytes.0, 1 << 20);
}

#[test]
fn reducing_unused_logical_byte_ceiling_makes_same_transport_limit_validate() {
    let parsed = validated(&config("16KiB", "4KiB", 1)).unwrap();
    assert_eq!(parsed.crypto.batch.max_items, 1);
    assert_eq!(parsed.crypto.capabilities.max_ciphertext_size, 4384);
}

#[test]
fn a_larger_legal_batch_really_requires_a_larger_transport_limit() {
    let error = validated(&config("16KiB", "1MiB", 32))
        .unwrap_err()
        .to_string();
    assert!(error.contains("max_frame_bytes"), "{error}");
}

#[test]
fn serialized_singleton_frame_limit_has_an_exact_boundary() {
    // Serialize the real request shape with the widest id/context and a
    // maximum-size ciphertext. This also includes this item's base64 padding.
    let bound = json!({
        "format": u32::MAX,
        "id": u64::MAX,
        "items": [{
            "data": base64::engine::general_purpose::STANDARD.encode(vec![0; CIPHER]),
            "unit": u64::MAX,
        }],
        "op": "decrypt",
        "profile": PROFILE,
        "volume": context().volume_uuid.to_string(),
    })
    .to_string()
    .len();
    let error = validated(&config(&(bound - 1).to_string(), "1MiB", 1))
        .unwrap_err()
        .to_string();
    assert!(error.contains("max_frame_bytes"), "{error}");
    for limit in [bound, bound + 1] {
        validated(&config(&limit.to_string(), "1MiB", 1)).unwrap();
    }
}

#[test]
fn byte_ceiling_counts_only_complete_provider_units() {
    // The transport holds one ciphertext, but not two. Up to one byte below
    // the second unit's plaintext budget, only a singleton is reachable.
    for bytes in [UNIT, 2 * UNIT - 1] {
        validated(&config("10000", &bytes.to_string(), 32)).unwrap();
    }
    let error = validated(&config("10000", &(2 * UNIT).to_string(), 32))
        .unwrap_err()
        .to_string();
    assert!(error.contains("max_frame_bytes"), "{error}");
}

#[test]
fn other_supported_unit_sizes_do_not_expand_this_volumes_batch() {
    let raw = config("16KiB", "1MiB", 1).replace(
        "supported_plaintext_sizes = [4096]",
        "supported_plaintext_sizes = [4096, 65536]",
    );
    let config = validated(&raw).unwrap();
    assert_eq!(config.provider_plaintext_size().unwrap(), UNIT as u32);
}

#[tokio::test]
async fn maximum_singleton_roundtrip_and_self_test_fit_and_oversized_batch_does_not() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let responses = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let rq = requests.clone();
    let rs = responses.clone();
    let n = calls.clone();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let owner = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        loop {
            tokio::select! {
                _ = &mut stopped => {
                    let _ = socket.close(None).await;
                    return;
                },
                message = socket.next() => {
                    let Some(Ok(message)) = message else { return; };
                    if !message.is_text() {
                        continue;
                    }
                    let text = message.into_text().unwrap();
                    rq.fetch_max(text.len(), Ordering::SeqCst);
                    n.fetch_add(1, Ordering::SeqCst);
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let decrypt = request["op"] == "decrypt";
                    let items: Vec<_> = request["items"].as_array().unwrap().iter().map(|item| {
                        let data = base64::engine::general_purpose::STANDARD
                            .decode(item["data"].as_str().unwrap()).unwrap();
                        json!({
                            "unit": item["unit"],
                            "data": base64::engine::general_purpose::STANDARD
                                .encode(transform(&data, decrypt)),
                        })
                    }).collect();
                    let response = json!({"id": request["id"], "items": items}).to_string();
                    rs.fetch_max(response.len(), Ordering::SeqCst);
                    socket.send(response.into()).await.unwrap();
                }
            }
        }
    });
    let provider = WsCryptoProvider::new(WsProviderSpec {
        url,
        capabilities: capabilities(),
        timeout: Duration::from_secs(3),
        max_frame_bytes: LIMIT,
        tls: None,
    });
    // Use the same valid singleton contract as the configuration regression.
    let config = validated(&config("16KiB", "1MiB", 1)).unwrap();
    assert_eq!(
        config.crypto.batch.max_items,
        provider.capabilities().await.unwrap().batch.max_items
    );
    let context = context();
    let items = [plain(u64::MAX)];
    let encrypted = provider.encrypt_batch(&context, &items).await.unwrap();
    assert_eq!(encrypted[0].data.len(), CIPHER);
    assert_eq!(
        provider.decrypt_batch(&context, &encrypted).await.unwrap()[0].data,
        items[0].data
    );
    maki_crypto::selftest::provider_self_test(&provider, &context, UNIT, PROFILE)
        .await
        .unwrap();
    let before = calls.load(Ordering::SeqCst);
    let oversized: Vec<_> = (0..32).map(plain).collect();
    let error = provider
        .encrypt_batch(&context, &oversized)
        .await
        .unwrap_err();
    assert!(
        matches!(error, maki_crypto::CryptoError::NonRetryableRequest(_)),
        "{error}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        before,
        "oversized local request must not reach server"
    );
    assert!(requests.load(Ordering::SeqCst) <= LIMIT);
    assert!(responses.load(Ordering::SeqCst) <= LIMIT);
    drop(provider);
    let _ = stop.send(());
    owner.await.unwrap();
}
