//! BUG-186: a transport failure during TLS setup must not immediately open
//! the endpoint's circuit. Certificate identity controls live in phase8_tls.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::clock::SystemClock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn provider(url: String) -> HttpCryptoProvider {
    let op = OpSpec {
        method: "POST".into(),
        path: "/crypt".into(),
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
    HttpCryptoProvider::new(HttpProviderSpec {
        base_url: url,
        encrypt: op.clone(),
        decrypt: op,
        capabilities: CryptoCapabilities {
            provider_id: "tls-classification".into(),
            crypto_compatibility_id: "tls-classification-v1".into(),
            supported_plaintext_sizes: vec![512],
            max_ciphertext_size: 512,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(5),
        max_response_bytes: 4096,
        tls: None,
    })
    .unwrap()
}

enum SetupFailure {
    Close,
    #[cfg(unix)]
    Reset,
    InvalidRecord,
    FatalAlert,
}

async fn failing_server(
    tls: bool,
    failure: SetupFailure,
) -> (HttpCryptoProvider, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        if tls {
            // Consume the complete ClientHello record before closing so the
            // EOF control is distinct from an explicit TCP reset.
            let mut header = [0; 5];
            socket.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22, "the client must start a TLS handshake");
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut hello = vec![0; length];
            socket.read_exact(&mut hello).await.unwrap();
        } else {
            let mut bytes = [0; 4096];
            assert!(socket.read(&mut bytes).await.unwrap() > 0);
        }
        match failure {
            SetupFailure::Close => socket.shutdown().await.unwrap(),
            #[cfg(unix)]
            SetupFailure::Reset => {
                use std::os::fd::AsRawFd;
                let linger = libc::linger {
                    l_onoff: 1,
                    l_linger: 0,
                };
                // SAFETY: socket owns a live fd and linger has the size and
                // representation required by SO_LINGER. Dropping sends RST.
                assert_eq!(
                    unsafe {
                        libc::setsockopt(
                            socket.as_raw_fd(),
                            libc::SOL_SOCKET,
                            libc::SO_LINGER,
                            (&linger as *const libc::linger).cast(),
                            std::mem::size_of_val(&linger) as libc::socklen_t,
                        )
                    },
                    0
                );
            }
            SetupFailure::InvalidRecord => {
                socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            }
            SetupFailure::FatalAlert => {
                // TLS plaintext alert: fatal handshake_failure. This proves
                // a protocol refusal, unlike an unadorned EOF/reset.
                socket.write_all(&[21, 3, 3, 0, 2, 2, 40]).await.unwrap();
            }
        }
    });
    let scheme = if tls { "https" } else { "http" };
    (provider(format!("{scheme}://{address}")), server)
}

async fn encrypt_error(provider: &dyn CryptoProvider) -> CryptoError {
    provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::nil(),
                format_version: 1,
                crypto_compatibility_id: "tls-classification-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 0,
                data: SecretBuffer::from_slice(&[0x53; 512]),
            }],
        )
        .await
        .unwrap_err()
}

async fn setup_error(tls: bool, failure: SetupFailure) -> CryptoError {
    let (provider, server) = failing_server(tls, failure).await;
    let error = encrypt_error(&provider).await;
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the mock server must finish")
        .unwrap();
    error
}

#[tokio::test]
async fn plain_http_early_close_is_retryable_control() {
    let error = setup_error(false, SetupFailure::Close).await;
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
}

#[tokio::test]
async fn tls_early_close_without_any_certificate_must_remain_retryable() {
    let error = setup_error(true, SetupFailure::Close).await;
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn tls_setup_reset_is_retryable() {
    let error = setup_error(true, SetupFailure::Reset).await;
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
}

#[tokio::test]
async fn invalid_tls_record_is_endpoint_fatal() {
    let error = setup_error(true, SetupFailure::InvalidRecord).await;
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error:?}");
}

#[tokio::test]
async fn explicit_tls_protocol_refusal_is_endpoint_fatal() {
    let error = setup_error(true, SetupFailure::FatalAlert).await;
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error:?}");
}

#[tokio::test]
async fn transient_tls_close_does_not_open_the_endpoint_circuit() {
    let (provider, server) = failing_server(true, SetupFailure::Close).await;
    let set = EndpointSet::new(
        vec![("transient".into(), Arc::new(provider))],
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(10),
                max_delay: Duration::from_millis(100),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 8,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig::default(),
            global_max_inflight_batches: 1,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 1,
            per_endpoint_max_bytes: 4096,
            // Inspect the first failure without resending to the mock.
            max_attempts: Some(1),
            max_operation_time: Some(Duration::from_secs(5)),
            retry_safe: true,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    );
    let error = encrypt_error(&set).await;
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the mock server must finish")
        .unwrap();
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
    assert_eq!(set.metrics().rpc_count(), 1);
    assert_eq!(set.endpoint_status()[0].circuit, CircuitState::Closed);
}
