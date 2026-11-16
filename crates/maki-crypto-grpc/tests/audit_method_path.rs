//! Audit: method paths are configurable but only parsed as an HTTP
//! path-and-query. A path without the leading '/' (a natural typo of
//! `maki.CryptoService/EncryptBatch`) passes configuration validation and
//! provider construction, then every RPC fails at runtime.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_grpc::{CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec};
use prost::Message;

fn spec(url: String, path: &str) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url,
        encrypt_path: path.into(),
        decrypt_path: path.into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "audit-path".into(),
            crypto_compatibility_id: "audit-path-v1".into(),
            supported_plaintext_sizes: vec![64],
            max_ciphertext_size: 64,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 4096,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(2),
        max_message_bytes: 4096,
    }
}

#[tokio::test]
async fn a_method_path_without_leading_slash_is_accepted_but_unusable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let record = seen.clone();
    let server = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let record = record.clone();
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(socket).await else {
                    record.lock().unwrap().push("<h2 handshake failed>".into());
                    return;
                };
                loop {
                    match connection.accept().await {
                        Some(Ok((request, mut respond))) => {
                            record
                                .lock()
                                .unwrap()
                                .push(request.uri().path().to_string());
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(())
                                .unwrap();
                            let mut stream = respond.send_response(response, false).unwrap();
                            let protobuf = CryptoBatchResponse {
                                items: vec![CryptoItem {
                                    unit_index: 1,
                                    data: vec![0x4a; 64],
                                }],
                            }
                            .encode_to_vec();
                            let mut frame = vec![0];
                            frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
                            frame.extend_from_slice(&protobuf);
                            let _ = stream.send_data(Bytes::from(frame), false);
                            let mut trailers = http::HeaderMap::new();
                            trailers.insert("grpc-status", "0".parse().unwrap());
                            let _ = stream.send_trailers(trailers);
                        }
                        Some(Err(error)) => {
                            record.lock().unwrap().push(format!("<h2 error: {error}>"));
                            return;
                        }
                        None => return,
                    }
                }
            });
        }
    });

    let built = GrpcCryptoProvider::new(spec(
        format!("http://{address}"),
        "maki.CryptoService/EncryptBatch",
    ));
    let provider = match built {
        Ok(provider) => provider,
        Err(error) => {
            server.abort();
            // Rejection at construction would be the fail-closed behavior.
            eprintln!("construction refused the path: {error}");
            return;
        }
    };
    let result = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(1),
                format_version: 1,
                crypto_compatibility_id: "audit-path-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 1,
                data: SecretBuffer::from_slice(&[7; 64]),
            }],
        )
        .await;
    server.abort();
    eprintln!(
        "result={:?} class={:?} server saw={:?}",
        result.as_ref().map(|_| ()),
        result.as_ref().err().map(|e| e.class()),
        seen.lock().unwrap()
    );
    assert!(
        result.is_ok(),
        "a path accepted at construction must be usable or refused there: {:?}",
        result.err()
    );
}
