//! Full daemon-path coverage for random plaintext prefixes with remote crypto.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::{CiphertextUnit, CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_local::{keysource::MapKeySource, AesGcmSivProvider};
use maki_format::canary::CANARY_UNIT_INDEX;
use serde_json::json;
use tokio::sync::oneshot;

const LOGICAL_UNIT: usize = 1024;
const PREFIX: usize = 32;
const RAW_UNIT: usize = LOGICAL_UNIT + PREFIX;
const MAX_CIPHERTEXT: usize = RAW_UNIT + 28;
const RAW_BATCH_BYTES: usize = 2 * RAW_UNIT;
const BASE_PROFILE: &str = "prefix-test-v1";
const OUTER_PROFILE: &str = "maki-random-prefix-v1:32:prefix-test-v1";

#[derive(Clone, Debug)]
struct RequestRecord {
    op: String,
    profile: String,
    volume: String,
    format: u64,
    unit: u64,
    data: Vec<u8>,
    batch_items: usize,
}

struct WsFixture {
    url: String,
    records: Arc<Mutex<Vec<RequestRecord>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl WsFixture {
    async fn start(seed: u8) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let records = Arc::new(Mutex::new(Vec::new()));
        let server_records = records.clone();
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut keys = MapKeySource::new();
            keys.insert("fixture", vec![seed; 32]);
            let provider = Arc::new(
                AesGcmSivProvider::new(&keys, "fixture", RAW_UNIT as u32, BASE_PROFILE).unwrap(),
            );
            ready_tx.send(()).unwrap();
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let stream = tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => stream,
                        Err(_) => break,
                    },
                };
                let provider = provider.clone();
                let records = server_records.clone();
                connections.spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    while let Some(Ok(message)) = ws.next().await {
                        let Ok(text) = message.into_text() else {
                            continue;
                        };
                        let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                        let context = CryptoContext {
                            volume_uuid: request["volume"].as_str().unwrap().parse().unwrap(),
                            format_version: request["format"].as_u64().unwrap() as u32,
                            crypto_compatibility_id: request["profile"].as_str().unwrap().into(),
                        };
                        let mut captured = Vec::new();
                        for item in request["items"].as_array().unwrap() {
                            let data = base64::engine::general_purpose::STANDARD
                                .decode(item["data"].as_str().unwrap())
                                .unwrap();
                            captured.push((item["unit"].as_u64().unwrap(), data));
                        }
                        {
                            let batch_items = captured.len();
                            let mut log = records.lock().unwrap();
                            for (unit, data) in &captured {
                                log.push(RequestRecord {
                                    op: request["op"].as_str().unwrap().into(),
                                    profile: request["profile"].as_str().unwrap().into(),
                                    volume: request["volume"].as_str().unwrap().into(),
                                    format: request["format"].as_u64().unwrap(),
                                    unit: *unit,
                                    data: data.clone(),
                                    batch_items,
                                });
                            }
                        }
                        let result = if request["op"] == "encrypt" {
                            let items = captured
                                .iter()
                                .map(|(unit, data)| PlaintextUnit {
                                    unit_index: *unit,
                                    data: SecretBuffer::from_slice(data),
                                })
                                .collect::<Vec<_>>();
                            provider.encrypt_batch(&context, &items).await.map(|items| {
                                items
                                    .into_iter()
                                    .map(|item| (item.unit_index, item.data))
                                    .collect::<Vec<_>>()
                            })
                        } else {
                            let items = captured
                                .iter()
                                .map(|(unit, data)| CiphertextUnit {
                                    unit_index: *unit,
                                    data: data.clone(),
                                })
                                .collect::<Vec<_>>();
                            provider.decrypt_batch(&context, &items).await.map(|items| {
                                items
                                    .into_iter()
                                    .map(|item| (item.unit_index, item.data.expose().to_vec()))
                                    .collect::<Vec<_>>()
                            })
                        };
                        let Ok(items) = result else {
                            let response = json!({
                                "id": request["id"],
                                "error": {"class": "integrity", "reason": "auth-tag-mismatch"}
                            });
                            let _ = ws.send(response.to_string().into()).await;
                            continue;
                        };
                        let items = items
                            .into_iter()
                            .map(|(unit, data)| {
                                json!({
                                    "unit": unit,
                                    "data": base64::engine::general_purpose::STANDARD.encode(data),
                                })
                            })
                            .collect::<Vec<_>>();
                        let response = json!({"id": request["id"], "items": items});
                        if ws.send(response.to_string().into()).await.is_err() {
                            break;
                        }
                    }
                });
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), ready_rx)
            .await
            .expect("fixture READY timeout")
            .expect("fixture stopped before READY");
        Self {
            url: format!("ws://{addr}"),
            records,
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), &mut self.task)
            .await
            .expect("fixture shutdown timeout")
            .unwrap();
    }
}

impl Drop for WsFixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

fn config(root: &str, first: &WsFixture, second: &WsFixture) -> String {
    format!(
        r#"config_schema_version = 1
[volume]
name = "random-prefix-remote"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = {LOGICAL_UNIT}
shard_logical_size = "64KiB"
[crypto]
provider = "remote-websocket"
crypto_compatibility_id = "{BASE_PROFILE}"
random_prefix_bytes = {PREFIX}
availability_policy = "bounded-error"
max_operation_time = "2s"
[crypto.capabilities]
supported_plaintext_sizes = [{RAW_UNIT}]
max_ciphertext_size = {MAX_CIPHERTEXT}
integrity = "contractual"
context_binding = "contractual"
[crypto.batch]
target_items = 4
target_bytes = "{RAW_BATCH_BYTES}"
max_items = 4
max_bytes = "{RAW_BATCH_BYTES}"
[crypto.websocket]
timeout = "1s"
max_frame_bytes = "2MiB"
[[crypto.websocket.endpoint]]
name = "first"
url = "{}"
[[crypto.websocket.endpoint]]
name = "second"
url = "{}"
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
"#,
        first.url, second.url
    )
}

async fn exercise_daemon_remote_endpoints() {
    let first = WsFixture::start(0x6d).await;
    let second = WsFixture::start(0x6d).await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory
        .path()
        .join("volume")
        .to_string_lossy()
        .replace('\\', "/");
    let raw = config(&root, &first, &second);

    let superblock = maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    assert_eq!(superblock.crypto_compatibility_id, OUTER_PROFILE);
    let cfg = maki_nbdkit::daemon::parse_and_validate(&raw).unwrap();
    let engine = maki_nbdkit::daemon::attach_from_config(&cfg).await.unwrap();
    let body = vec![0xa5; LOGICAL_UNIT];
    engine.write(0, &body, true).await.unwrap();
    engine.write(0, &body, true).await.unwrap();
    assert_eq!(engine.read(0, LOGICAL_UNIT).await.unwrap(), body);
    engine.write(512, &[0x3c; 512], true).await.unwrap();
    let mut expected = vec![0xa5; LOGICAL_UNIT];
    expected[512..1024].fill(0x3c);
    assert_eq!(engine.read(0, LOGICAL_UNIT).await.unwrap(), expected);

    let mut four_units = Vec::with_capacity(4 * LOGICAL_UNIT);
    for value in [0x11, 0x22, 0x33, 0x44] {
        four_units.extend(std::iter::repeat_n(value, LOGICAL_UNIT));
    }
    engine
        .write(LOGICAL_UNIT as u64, &four_units, true)
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        engine.write((5 * LOGICAL_UNIT) as u64, &[0x55; LOGICAL_UNIT], true),
        engine.write((6 * LOGICAL_UNIT) as u64, &[0x66; LOGICAL_UNIT], true),
    );
    left.unwrap();
    right.unwrap();
    assert_eq!(
        engine
            .read(LOGICAL_UNIT as u64, four_units.len())
            .await
            .unwrap(),
        four_units
    );
    engine.flush().await.unwrap();
    drop(engine);

    let reopened = maki_nbdkit::daemon::attach_from_config(&cfg).await.unwrap();
    assert_eq!(reopened.read(0, LOGICAL_UNIT).await.unwrap(), expected);
    assert_eq!(
        reopened
            .read(LOGICAL_UNIT as u64, four_units.len())
            .await
            .unwrap(),
        four_units
    );
    assert_eq!(
        reopened
            .read((5 * LOGICAL_UNIT) as u64, 2 * LOGICAL_UNIT)
            .await
            .unwrap(),
        [vec![0x55; LOGICAL_UNIT], vec![0x66; LOGICAL_UNIT]].concat()
    );
    drop(reopened);

    let mut all = first.records.lock().unwrap().clone();
    all.extend(second.records.lock().unwrap().iter().cloned());
    assert!(
        !first.records.lock().unwrap().is_empty() && !second.records.lock().unwrap().is_empty(),
        "endpoint validation must reach both endpoints"
    );
    assert!(all.iter().all(|r| r.batch_items <= 2));
    assert!(
        all.iter().any(|r| r.op == "encrypt" && r.batch_items == 2),
        "the four-unit write must exercise the expanded-byte batch limit"
    );
    assert!(all
        .iter()
        .all(|r| r.data.len() == RAW_UNIT || r.op == "decrypt"));
    let application_writes = all
        .iter()
        .filter(|r| {
            r.op == "encrypt"
                && r.unit == 0
                && r.data.len() == RAW_UNIT
                && r.data[PREFIX..] == vec![0xa5; LOGICAL_UNIT]
        })
        .collect::<Vec<_>>();
    assert!(
        application_writes.len() >= 2,
        "both repeated writes must be observed"
    );
    assert_ne!(
        &application_writes[0].data[..PREFIX],
        &application_writes[1].data[..PREFIX],
        "each encryption must receive a fresh random prefix"
    );
    assert!(application_writes.iter().all(|r| {
        r.profile == BASE_PROFILE
            && r.profile != OUTER_PROFILE
            && r.format == u64::from(superblock.format_version)
            && r.volume == superblock.volume_uuid.to_string()
            && &r.data[PREFIX..] == body.as_slice()
    }));

    for (unit, value) in [
        (1, 0x11),
        (2, 0x22),
        (3, 0x33),
        (4, 0x44),
        (5, 0x55),
        (6, 0x66),
    ] {
        let write = all
            .iter()
            .find(|r| {
                r.op == "encrypt"
                    && r.unit == unit
                    && r.data.len() == RAW_UNIT
                    && r.data[PREFIX..] == vec![value; LOGICAL_UNIT]
            })
            .unwrap_or_else(|| panic!("missing application write for unit {unit}"));
        assert_eq!(write.profile, BASE_PROFILE);
        assert_eq!(write.volume, superblock.volume_uuid.to_string());
        assert_eq!(write.format, u64::from(superblock.format_version));
    }

    assert!(all
        .iter()
        .any(|r| r.volume != superblock.volume_uuid.to_string()));
    assert!(all
        .iter()
        .any(|r| r.format != u64::from(superblock.format_version)));
    assert!(
        all.iter().any(|original| {
            original.op == "decrypt"
                && original.unit == 0
                && all.iter().any(|moved| {
                    moved.op == "decrypt"
                        && moved.unit == 1
                        && moved.data == original.data
                        && moved.volume == original.volume
                        && moved.format == original.format
                        && moved.profile == original.profile
                })
        }),
        "context validation must try the same ciphertext at another unit index"
    );
    assert!(first.records.lock().unwrap().iter().any(|r| {
        r.op == "decrypt" && r.unit == CANARY_UNIT_INDEX && r.profile == BASE_PROFILE
    }));
    assert!(second.records.lock().unwrap().iter().any(|r| {
        r.op == "decrypt" && r.unit == CANARY_UNIT_INDEX && r.profile == BASE_PROFILE
    }));

    first.stop().await;
    second.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_remote_endpoints_receive_fresh_prefix_and_base_context() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        exercise_daemon_remote_endpoints(),
    )
    .await
    .expect("remote random-prefix fixture or connection cleanup hung");
}

async fn exercise_mismatched_endpoint_refusal() {
    let first = WsFixture::start(0x6d).await;
    let second = WsFixture::start(0x7e).await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory
        .path()
        .join("volume")
        .to_string_lossy()
        .replace('\\', "/");
    let raw = config(&root, &first, &second);

    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    let cfg = maki_nbdkit::daemon::parse_and_validate(&raw).unwrap();
    assert!(
        maki_nbdkit::daemon::attach_from_config(&cfg).await.is_err(),
        "endpoints with different keys must be refused before volume I/O"
    );
    assert!(second.records.lock().unwrap().iter().any(|r| {
        r.op == "decrypt" && r.unit == CANARY_UNIT_INDEX && r.profile == BASE_PROFILE
    }));

    first.stop().await;
    second.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_refuses_mismatched_remote_endpoint_key_before_io() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        exercise_mismatched_endpoint_refusal(),
    )
    .await
    .expect("mismatched-endpoint fixture or connection cleanup hung");
}
