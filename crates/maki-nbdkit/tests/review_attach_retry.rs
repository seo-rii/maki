//! Initial peer reachability probes must honor retry_safe after an RPC was sent.

use std::sync::Arc;

use maki_crypto::{CryptoContext, PlaintextUnit, SecretBuffer};
use maki_nbdkit::daemon::{
    build_provider_with_endpoints, create_volume_from_config_str, parse_and_validate,
};
use maki_test_support::http_chaos::{Handler, ResponseSpec, TestServer};

fn lost_response(canary_only: bool) -> Handler {
    Arc::new(move |request| {
        let mut response = ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect());
        if !canary_only || request.body.starts_with(b"MAKI-KEY-CANARY-V1") {
            // The server has processed the complete request, but the caller
            // never receives its response body. Repeating it is not safe.
            response.drop_after = Some(0);
        }
        response
    })
}

fn config(root: &std::path::Path, urls: &[String], retry_safe: bool) -> String {
    let endpoints: String = urls
        .iter()
        .enumerate()
        .map(|(index, url)| {
            format!("[[crypto.http.endpoint]]\nname=\"ep{index}\"\nurl=\"{url}\"\n")
        })
        .collect();
    let root = root.to_string_lossy().replace('\\', "/");
    format!(
        r#"
config_schema_version = 1
[volume]
name = "attach-retry"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "attach-retry-v1"
availability_policy = "bounded-error"
max_operation_time = "1s"
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
[crypto.http]
max_response_bytes = 512
timeout = "1s"
{endpoints}
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.decrypt]
path = "/decrypt"
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#
    )
}

async fn initial_probe_requests(retry_safe: bool, canary_only: bool) -> usize {
    let failed = TestServer::start(lost_response(canary_only)).await;
    let healthy = TestServer::start(Arc::new(|request| {
        ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
    }))
    .await;
    let directory = tempfile::tempdir().unwrap();
    let raw = config(
        &directory.path().join("volume"),
        &[failed.url(), healthy.url()],
        retry_safe,
    );
    let cfg = parse_and_validate(&raw).unwrap();
    let superblock = create_volume_from_config_str(&raw).unwrap();
    let (provider, endpoints) = build_provider_with_endpoints(&cfg).await.unwrap();
    let states = endpoints.unwrap().endpoint_status();
    assert!(
        !states
            .iter()
            .find(|state| state.name == "ep0")
            .unwrap()
            .validated
    );
    assert!(
        states
            .iter()
            .find(|state| state.name == "ep1")
            .unwrap()
            .validated
    );
    // Snapshot before normal dispatch, which may independently schedule a
    // later quarantine revalidation. Only initial attach attempts are counted.
    let requests: Vec<_> = failed
        .requests
        .lock()
        .iter()
        .filter(|request| !canary_only || request.body.starts_with(b"MAKI-KEY-CANARY-V1"))
        .cloned()
        .collect();
    assert!(!requests.is_empty());
    assert!(requests.iter().all(|request| request.path == "/encrypt"));
    assert!(requests
        .iter()
        .all(|request| request.body == requests[0].body));

    // The failed peer remains quarantined while the healthy peer can serve
    // actual calls through the constructed dispatcher.
    let context = CryptoContext {
        volume_uuid: superblock.volume_uuid,
        format_version: superblock.format_version,
        crypto_compatibility_id: superblock.crypto_compatibility_id,
    };
    let ciphertext = provider
        .encrypt_batch(
            &context,
            &[PlaintextUnit {
                unit_index: 17,
                data: SecretBuffer::from_slice(&[0x71; 512]),
            }],
        )
        .await
        .unwrap();
    let plaintext = provider.decrypt_batch(&context, &ciphertext).await.unwrap();
    assert_eq!(plaintext[0].data.expose(), &[0x71; 512]);
    assert!(healthy
        .requests
        .lock()
        .iter()
        .any(|request| request.path == "/encrypt" && request.body == [0x71; 512]));
    requests.len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_safe_initial_probe_is_retried_three_times() {
    assert_eq!(initial_probe_requests(true, false).await, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_retry_safe_initial_probe_must_be_sent_only_once() {
    assert_eq!(
        initial_probe_requests(false, false).await,
        1,
        "initial reachability probing re-sent an uncertain non-retry-safe encrypt request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normal_dispatch_does_not_resend_non_retry_safe_request() {
    let failed = TestServer::start(lost_response(false)).await;
    let directory = tempfile::tempdir().unwrap();
    let raw = config(&directory.path().join("volume"), &[failed.url()], false);
    let cfg = parse_and_validate(&raw).unwrap();
    create_volume_from_config_str(&raw).unwrap();
    let (provider, _endpoints) = build_provider_with_endpoints(&cfg).await.unwrap();
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x20261024),
        format_version: 1,
        crypto_compatibility_id: "attach-retry-v1".into(),
    };
    let result = provider
        .encrypt_batch(
            &context,
            &[PlaintextUnit {
                unit_index: 0,
                data: SecretBuffer::from_slice(&[0; 512]),
            }],
        )
        .await;
    assert!(result.unwrap_err().is_retryable());
    assert_eq!(failed.requests.lock().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_safe_initial_canary_probe_is_retried_three_times() {
    assert_eq!(initial_probe_requests(true, true).await, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_retry_safe_initial_canary_probe_must_be_sent_only_once() {
    assert_eq!(
        initial_probe_requests(false, true).await,
        1,
        "initial canary probing re-sent an uncertain non-retry-safe encrypt request"
    );
}
