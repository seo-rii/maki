//! BUG-056: HTTP 200 with a bad result is attributed to its endpoint.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};
use maki_test_support::http_chaos::{Handler, ResponseSpec, TestServer};
use maki_test_support::ManualClock;

const UNIT: usize = 512;

fn handler(size: Option<usize>) -> Handler {
    Arc::new(move |request| {
        let mut bytes: Vec<_> = request.body.iter().map(|byte| byte ^ 0x5a).collect();
        if let Some(size) = size {
            bytes.resize(size, 0x11);
        }
        ResponseSpec::raw(bytes)
    })
}

fn provider(server: &TestServer) -> Arc<dyn CryptoProvider> {
    let operation = OpSpec {
        method: "POST".into(),
        path: "/crypto".into(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Raw,
        response: RespSpec {
            kind: RespKind::Raw,
            data_path: None,
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    };
    Arc::new(
        HttpCryptoProvider::new(HttpProviderSpec {
            base_url: server.url(),
            encrypt: operation.clone(),
            decrypt: operation,
            capabilities: CryptoCapabilities {
                provider_id: "payload-contract".into(),
                crypto_compatibility_id: "payload-contract-v1".into(),
                supported_plaintext_sizes: vec![UNIT as u32],
                max_ciphertext_size: UNIT as u32,
                stateless: true,
                retry_safe: true,
                batch: BatchCapability {
                    supported: false,
                    max_items: 1,
                    max_bytes: UNIT as u64,
                },
                integrity: Capability::Absent,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout: Duration::from_secs(2),
            max_response_bytes: 4096,
            tls: None,
        })
        .unwrap(),
    )
}

fn dispatch_config(retry_safe: bool) -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 3,
            open_initial: Duration::from_secs(60),
            open_max: Duration::from_secs(60),
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        global_max_inflight_batches: 2,
        global_max_inflight_bytes: 4096,
        per_endpoint_max_inflight: 1,
        per_endpoint_max_bytes: 2048,
        max_attempts: Some(1),
        max_operation_time: None,
        retry_safe,
        validation_interval: Duration::from_secs(60),
    }
}

async fn exercise(decrypt: bool) {
    let a = TestServer::start(handler(None)).await;
    let b = TestServer::start(handler(None)).await;
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(56),
        format_version: 1,
        crypto_compatibility_id: "payload-contract-v1".into(),
    };
    let left = provider(&a);
    let right = provider(&b);
    for peer in [&left, &right] {
        maki_crypto::selftest::provider_self_test(
            peer.as_ref(),
            &context,
            UNIT,
            "payload-contract-v1",
        )
        .await
        .unwrap();
    }
    a.requests.lock().clear();
    b.requests.lock().clear();
    a.set_handler(handler(Some(if decrypt { UNIT - 1 } else { UNIT + 1 })));
    let set = EndpointSet::new(
        vec![("a".into(), left), ("b".into(), right)],
        dispatch_config(true),
        Arc::new(ManualClock::new()),
    );
    let plaintext = [PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::from_slice(&[0x11; UNIT]),
    }];
    let ciphertext = [CiphertextUnit {
        unit_index: 1,
        data: vec![0x11 ^ 0x5a; UNIT],
    }];
    for _ in 0..10 {
        let result = if decrypt {
            set.decrypt_batch(&context, &ciphertext).await.map(|out| {
                assert_eq!(out[0].data, plaintext[0].data);
            })
        } else {
            set.encrypt_batch(&context, &plaintext).await.map(|out| {
                assert_eq!(out[0].data, ciphertext[0].data);
            })
        };
        result.unwrap();
    }
    assert_eq!(set.endpoint_states()[0].1, CircuitState::Open);
    assert_eq!(set.endpoint_states()[1].1, CircuitState::Closed);
    assert_eq!(a.requests.lock().len(), 3);
    assert_eq!(b.requests.lock().len(), 10);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test]
async fn oversized_successful_http_ciphertext_uses_healthy_peer() {
    exercise(false).await;
}

#[tokio::test]
async fn short_successful_http_plaintext_uses_healthy_peer() {
    exercise(true).await;
}

#[tokio::test]
async fn unsafe_http_payload_violation_is_attributed_without_resend() {
    // One request is sufficient: after its circuit opens, a *new* request
    // may independently choose the healthy endpoint without being a resend.
    let a = TestServer::start(handler(Some(UNIT + 1))).await;
    let b = TestServer::start(handler(None)).await;
    let mut cfg = dispatch_config(false);
    cfg.breaker.failure_threshold = 1;
    let set = EndpointSet::new(
        vec![("a".into(), provider(&a)), ("b".into(), provider(&b))],
        cfg,
        Arc::new(ManualClock::new()),
    );
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(56),
        format_version: 1,
        crypto_compatibility_id: "payload-contract-v1".into(),
    };
    assert!(matches!(
        set.encrypt_batch(
            &context,
            &[PlaintextUnit {
                unit_index: 1,
                data: SecretBuffer::zeroed(UNIT),
            }],
        )
        .await,
        Err(CryptoError::Contract(_))
    ));
    assert_eq!(a.requests.lock().len(), 1);
    assert!(b.requests.lock().is_empty());
    assert_eq!(set.endpoint_states()[0].1, CircuitState::Open);
    assert_eq!(set.global_inflight(), (0, 0));
}
