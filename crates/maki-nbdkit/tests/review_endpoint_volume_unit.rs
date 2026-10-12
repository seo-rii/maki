//! BUG-058: dispatch uses the selected volume unit, including its prefix.

use std::sync::Arc;

use maki_crypto::breaker::CircuitState;
use maki_crypto::CryptoProvider;
use maki_nbdkit::daemon::{
    attach_from_config_with_stats, create_volume_from_config_str, parse_and_validate,
};
use maki_test_support::http_chaos::{Handler, ResponseSpec, TestServer};

fn reversible() -> Handler {
    Arc::new(|request| ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect()))
}

fn config(root: &std::path::Path, urls: &[String], prefix: u32) -> String {
    let provider_unit = 512 + prefix;
    let endpoints: String = urls
        .iter()
        .enumerate()
        .map(|(n, url)| format!("[[crypto.http.endpoint]]\nname=\"ep{n}\"\nurl=\"{url}\"\n"))
        .collect();
    let root = root.to_string_lossy().replace('\\', "/");
    format!(
        r#"
config_schema_version=1
[volume]
name="selected-unit"
max_virtual_size="1MiB"
device_block_size=512
crypto_unit_size=512
shard_logical_size="64KiB"
[crypto]
provider="remote-http"
crypto_compatibility_id="selected-unit-v1"
random_prefix_bytes={prefix}
availability_policy="bounded-error"
max_operation_time="2s"
[crypto.capabilities]
supported_plaintext_sizes=[{provider_unit},4096]
max_ciphertext_size=4104
retry_safe=true
stateless=true
[crypto.batch]
max_items=1
target_items=1
max_bytes={provider_unit}
target_bytes={provider_unit}
max_wait="0ms"
[crypto.circuit_breaker]
failure_threshold=1
open_initial="30s"
open_max="30s"
[crypto.http]
max_response_bytes=8192
{endpoints}
[crypto.http.encrypt]
path="/encrypt"
[crypto.http.encrypt.body]
type="raw"
[crypto.http.encrypt.response]
type="raw"
[crypto.http.decrypt]
path="/decrypt"
[crypto.http.decrypt.body]
type="raw"
[crypto.http.decrypt.response]
type="raw"
[backing]
root="{root}"
journal_emergency_reserve_bytes="0B"
[cache]
mode="off"
"#
    )
}

async fn roundtrip(prefix: u32) {
    let left = TestServer::start(reversible()).await;
    let right = TestServer::start(reversible()).await;
    let directory = tempfile::tempdir().unwrap();
    let raw = config(
        &directory.path().join("volume"),
        &[left.url(), right.url()],
        prefix,
    );
    let cfg = parse_and_validate(&raw).unwrap();
    create_volume_from_config_str(&raw).unwrap();
    let (engine, stats, set) = attach_from_config_with_stats(&cfg)
        .await
        .expect("a supported 512-byte volume must attach under its own valid byte limit");
    assert!(stats.is_some(), "use the actual remote scheduler at attach");
    let set = set.unwrap();
    assert_eq!(
        set.capabilities().await.unwrap().supported_plaintext_sizes,
        vec![512 + prefix, 4096]
    );
    let expected: Vec<_> = (0..1024).map(|n| (n % 251) as u8).collect();
    engine.write(0, &expected, true).await.unwrap();
    assert_eq!(engine.read(0, expected.len()).await.unwrap(), expected);
    // An allowed size for another volume is still a wrong runtime result for
    // this one. It must charge A's breaker inside dispatch, before stripping
    // a prefix or validating the scheduler's final result.
    left.requests.lock().clear();
    right.requests.lock().clear();
    left.set_handler(Arc::new(|_| ResponseSpec::raw(vec![0x11; 4096])));
    assert_eq!(engine.read(0, 512).await.unwrap(), expected[..512]);
    assert_eq!(set.endpoint_states()[0].1, CircuitState::Open);
    assert!(!right.requests.lock().is_empty());
    assert_eq!(set.global_inflight(), (0, 0));
    engine.checkpoint().await.unwrap();
    drop((engine, set));
    left.set_handler(reversible());
    let (engine, _, _) = attach_from_config_with_stats(&cfg).await.unwrap();
    assert_eq!(engine.read(0, 1024).await.unwrap(), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_supported_sizes_use_the_selected_unit_at_attach_and_runtime() {
    roundtrip(0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selected_provider_unit_includes_the_random_prefix() {
    roundtrip(16).await;
}
