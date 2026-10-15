//! BUG-115: the channel was built with `connect_lazy`, whose connect timeout
//! covers only the TCP connect. A peer (or a TLS terminator in front of it)
//! that accepts TCP and never answers the ClientHello left the handshake
//! pending forever inside the channel's shared connection worker: each RPC
//! gave up after its own timeout (BUG-017), but every later one queued
//! behind the same handshake, the endpoint never reconnected, and a breaker
//! probe could never succeed. A connection attempt, TLS included, is now
//! abandoned after four RPC timeouts.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec, GrpcTlsConfig};

const UNIT: usize = 256;
const TIMEOUT: Duration = Duration::from_millis(250);

fn caps() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "remote-grpc-tls-stall".to_string(),
        crypto_compatibility_id: "grpc-profile-v1".to_string(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_never_answers_tls_does_not_pin_the_channel() {
    // This integration-test binary deliberately installs no global provider.
    // It must also run with both rustls backends enabled by feature unification
    // (for example, `--features rustls/aws-lc-rs`), where automatic selection
    // would panic before the first connection attempt.
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    // Accept every TCP connection and hold it open without a byte of TLS.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counted = accepts.clone();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for socket in listener.incoming() {
            counted.fetch_add(1, Ordering::SeqCst);
            held.push(socket);
        }
    });

    let provider = GrpcCryptoProvider::new_with_tls(
        GrpcProviderSpec {
            url: format!("https://127.0.0.1:{port}"),
            encrypt_path: "/maki.CryptoService/EncryptBatch".to_string(),
            decrypt_path: "/maki.CryptoService/DecryptBatch".to_string(),
            metadata: vec![],
            capabilities: caps(),
            timeout: TIMEOUT,
            max_message_bytes: 1 << 20,
        },
        GrpcTlsConfig::default(),
    )
    .unwrap();
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "gRPC must select its TLS provider without changing process-global state"
    );
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x115),
        format_version: 1,
        crypto_compatibility_id: "grpc-profile-v1".to_string(),
    };
    let item = PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[7; UNIT]),
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    while accepts.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
        let started = Instant::now();
        let result = provider
            .encrypt_batch(&context, std::slice::from_ref(&item))
            .await;
        assert!(
            matches!(result, Err(CryptoError::Retryable(_))),
            "a silent peer must fail the RPC as a transport error: {result:?}"
        );
        assert!(
            started.elapsed() < TIMEOUT * 4,
            "an RPC outlived its timeout"
        );
    }
    assert!(
        accepts.load(Ordering::SeqCst) >= 2,
        "the stalled TLS handshake was never abandoned: one connection attempt in 5 s"
    );
}
