//! F04: HTTP upgrade failures retain their HTTP error class and retry policy.
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn f04_upgrade_status_controls_class_and_retry_count() {
    for (status, expected) in [
        (403, ErrorClass::EndpointFatal),
        (401, ErrorClass::EndpointFatal),
        (301, ErrorClass::EndpointFatal),
        (400, ErrorClass::NonRetryableRequest),
        (404, ErrorClass::EndpointFatal),
        (405, ErrorClass::EndpointFatal),
        (407, ErrorClass::EndpointFatal),
        (408, ErrorClass::Retryable),
        (410, ErrorClass::EndpointFatal),
        (422, ErrorClass::NonRetryableRequest),
        (429, ErrorClass::Throttled),
        (500, ErrorClass::Retryable),
        (503, ErrorClass::Retryable),
        (0, ErrorClass::Retryable), // Disconnect before an HTTP upgrade response.
    ] {
        for retry_safe in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let counter = calls.clone();
            let server = tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let mut header = vec![0; 4096];
                    socket.read(&mut header).await.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    if status == 0 {
                        continue;
                    }
                    socket.write_all(format!("HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\nRetry-After: 1\r\nConnection: close\r\nX-Private: response-secret\r\n\r\n").as_bytes()).await.unwrap();
                }
            });
            let provider = WsCryptoProvider::new(WsProviderSpec {
                url: format!("ws://{address}/crypto?token=query-secret"),
                capabilities: CryptoCapabilities {
                    provider_id: "review-f04".into(),
                    crypto_compatibility_id: "review-f04".into(),
                    supported_plaintext_sizes: vec![512],
                    max_ciphertext_size: 512,
                    stateless: true,
                    retry_safe,
                    batch: BatchCapability::default(),
                    integrity: Capability::Absent,
                    context_binding: Capability::Absent,
                    replay_protection: Capability::Absent,
                },
                timeout: Duration::from_secs(2),
                max_frame_bytes: 4096,
                tls: None,
            });
            let context = CryptoContext {
                volume_uuid: uuid::Uuid::nil(),
                format_version: 1,
                crypto_compatibility_id: "review-f04".into(),
            };
            let input = [PlaintextUnit {
                unit_index: 0,
                data: SecretBuffer::from_slice(&[0x42; 512]),
            }];
            let error = provider.encrypt_batch(&context, &input).await.unwrap_err();
            server.abort();
            assert_eq!(
                error.class(),
                expected,
                "HTTP {status}, retry_safe={retry_safe}"
            );
            let attempts = if retry_safe
                && matches!(expected, ErrorClass::Retryable | ErrorClass::Throttled)
            {
                2
            } else {
                1
            };
            assert_eq!(
                calls.load(Ordering::SeqCst),
                attempts,
                "HTTP {status}, retry_safe={retry_safe}"
            );
            let diagnostic = format!("{error:?}");
            assert!(
                !diagnostic.contains("query-secret") && !diagnostic.contains("response-secret")
            );
        }
    }
}
