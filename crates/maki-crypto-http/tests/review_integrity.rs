//! R3-001: authenticated crypto must survive the real HTTP error contract.
#[path = "common/integrity.rs"]
mod common;

use base64::Engine as _;
use common::*;
use futures_util::FutureExt;
use maki_crypto::{
    CiphertextUnit, CryptoError, CryptoProvider, ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind,
    RespSpec,
};
use maki_test_support::http_chaos::{Handler, RecordedRequest, ResponseSpec, TestServer};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

fn authenticated(seed: u8) -> Handler {
    let provider = local(seed);
    Arc::new(move |request: &RecordedRequest| {
        let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let context = maki_crypto::CryptoContext {
            volume_uuid: value["volume"].as_str().unwrap().parse().unwrap(),
            format_version: value["format"].as_u64().unwrap() as u32,
            crypto_compatibility_id: value["profile"].as_str().unwrap().into(),
        };
        let unit_index = value["unit"].as_u64().unwrap();
        let data = base64::engine::general_purpose::STANDARD
            .decode(value["data"].as_str().unwrap())
            .unwrap();
        let result = if request.path == "/encrypt" {
            provider
                .encrypt_batch(
                    &context,
                    &[PlaintextUnit {
                        unit_index,
                        data: SecretBuffer::from_vec(data),
                    }],
                )
                .now_or_never()
                .unwrap()
                .map(|mut out| out.remove(0).data)
        } else {
            provider
                .decrypt_batch(&context, &[CiphertextUnit { unit_index, data }])
                .now_or_never()
                .unwrap()
                .map(|mut out| out.remove(0).data.expose().to_vec())
        };
        match result {
            Ok(data) => ResponseSpec::json(
                &json!({"data": base64::engine::general_purpose::STANDARD.encode(data)}),
            ),
            Err(CryptoError::Integrity(_)) => {
                let mut response = ResponseSpec::status(422);
                response
                    .headers
                    .push(("maki-crypto-error".into(), "auth-tag-mismatch".into()));
                response.body = REMOTE_SECRET.as_bytes().to_vec();
                response
            }
            // A foreign compatibility id is a plain bad request (the
            // self-test's compatibility-id probe), never an integrity error.
            Err(CryptoError::ProviderFatal(_)) => {
                let mut response = ResponseSpec::status(400);
                response.body = REMOTE_SECRET.as_bytes().to_vec();
                response
            }
            Err(error) => panic!("unexpected fixture error: {error}"),
        }
    })
}
async fn provider(url: &str, timeout: Duration) -> HttpCryptoProvider {
    let op = |path: &str| OpSpec {
        method: "POST".into(),
        path: path.into(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Json {
            fields: vec![
                (
                    "/data".into(),
                    FieldSource::Payload(PayloadEncoding::Base64),
                ),
                ("/unit".into(), FieldSource::UnitIndex),
                ("/volume".into(), FieldSource::VolumeId),
                ("/format".into(), FieldSource::FormatVersion),
                ("/profile".into(), FieldSource::CompatibilityId),
            ],
            items_path: None,
            item_fields: vec![],
        },
        response: RespSpec {
            kind: RespKind::Json,
            data_path: Some("/data".into()),
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    };
    HttpCryptoProvider::new(HttpProviderSpec {
        base_url: url.into(),
        encrypt: op("/encrypt"),
        decrypt: op("/decrypt"),
        capabilities: capabilities().await,
        timeout,
        max_response_bytes: 1 << 20,
        tls: None,
    })
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_http_engine_pipeline() {
    let server = TestServer::start(authenticated(1)).await;
    let wrong = TestServer::start(authenticated(2)).await;
    let provider = Arc::new(provider(&server.url(), Duration::from_secs(2)).await);
    verify_engine(provider, Arc::new(provider_for(&wrong).await)).await;
}
async fn provider_for(server: &TestServer) -> HttpCryptoProvider {
    provider(&server.url(), Duration::from_secs(2)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_integrity_requires_exact_status_and_one_allowlisted_reason() {
    let server = TestServer::start(Arc::new(|_| ResponseSpec::status(400))).await;
    let provider = provider_for(&server).await;
    for reason in ["auth-tag-mismatch", "context-mismatch"] {
        let response = ResponseSpec {
            headers: vec![("maki-crypto-error".into(), reason.into())],
            body: REMOTE_SECRET.as_bytes().to_vec(),
            ..ResponseSpec::status(422)
        };
        server.set_handler(Arc::new(move |_| response.clone()));
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
    for (status, reasons) in [
        (400, vec!["auth-tag-mismatch".to_string()]),
        (503, vec!["auth-tag-mismatch".to_string()]),
        (422, vec![]),
        (422, vec!["unknown".into()]),
        (422, vec!["auth-tag-mismatch, context-mismatch".into()]),
        (
            422,
            vec!["auth-tag-mismatch".into(), "auth-tag-mismatch".into()],
        ),
        (422, vec!["context-mismatch".into(), "unknown".into()]),
        (422, vec!["SECRET".repeat(1024)]),
    ] {
        let response = ResponseSpec {
            headers: reasons
                .into_iter()
                .map(|reason| ("maki-crypto-error".into(), reason))
                .collect(),
            body: REMOTE_SECRET.as_bytes().to_vec(),
            ..ResponseSpec::status(status)
        };
        server.set_handler(Arc::new(move |_| response.clone()));
        let error = provider
            .encrypt_batch(&context(), &[plaintext()])
            .await
            .unwrap_err();
        assert!(
            !matches!(error, CryptoError::Integrity(_)),
            "ambiguous signal became integrity proof: {error}"
        );
        assert_private(&error);
        assert_eq!(
            error.class(),
            if status == 503 {
                ErrorClass::Retryable
            } else {
                ErrorClass::NonRetryableRequest
            }
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_timeout_remains_inconclusive_through_scheduler() {
    let server = TestServer::start(Arc::new(|_| ResponseSpec {
        delay: Duration::from_secs(1),
        ..ResponseSpec::status(422)
    }))
    .await;
    let provider = pipeline(Arc::new(
        provider(&server.url(), Duration::from_millis(50)).await,
    ));
    let error = provider
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap_err();
    assert_eq!(error.class(), ErrorClass::Retryable);
    assert_private(&error);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_http_tamper_and_context_probes() {
    let server = TestServer::start(authenticated(1)).await;
    verify_probes(&provider_for(&server).await).await;
}
