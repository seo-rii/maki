//! Audit: an HTTP/1.x response without Content-Length or chunked framing is
//! delimited by connection close. A provider that dies (or is restarted)
//! mid-body sends FIN, which is indistinguishable from the end of the body.
//! With a raw response mapping the truncated bytes are accepted as the unit's
//! ciphertext; CheckedProvider only checks "non-empty and <= max".

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::checked::CheckedProvider;
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UNIT: usize = 4096;
const CIPHER: usize = UNIT + 28;

async fn read_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = socket.read(&mut buffer).await.unwrap();
        if n == 0 {
            return request;
        }
        request.extend_from_slice(&buffer[..n]);
        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&request[..end]).unwrap();
            let len = head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                .unwrap_or(0);
            if request.len() >= end + 4 + len {
                return request[end + 4..end + 4 + len].to_vec();
            }
        }
    }
}

/// Serve one "ciphertext" per connection: nonce || xor(plaintext) || tag,
/// but write only `sent` bytes of it before closing the socket cleanly.
async fn server(content_length: bool, sent: usize) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let body = read_request(&mut socket).await;
                let mut cipher = vec![0x11u8; 12];
                cipher.extend(body.iter().map(|b| b ^ 0x5a));
                cipher.extend([0x22u8; 16]);
                assert_eq!(cipher.len(), CIPHER);
                let head = if content_length {
                    format!("HTTP/1.1 200 OK\r\ncontent-length: {CIPHER}\r\n\r\n")
                } else {
                    // Close-delimited body (RFC 9112 §6.3 rule 8).
                    "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n".to_string()
                };
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&cipher[..sent]).await;
                // Provider process exits: the kernel sends FIN, not RST.
                let _ = socket.shutdown().await;
            });
        }
    });
    url
}

fn provider(url: &str) -> Arc<dyn CryptoProvider> {
    let op = OpSpec {
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
    let inner = HttpCryptoProvider::new(HttpProviderSpec {
        base_url: url.to_string(),
        encrypt: op.clone(),
        decrypt: op,
        capabilities: CryptoCapabilities {
            provider_id: "audit".into(),
            crypto_compatibility_id: "audit-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: CIPHER as u32,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 1,
                max_bytes: UNIT as u64,
            },
            integrity: Capability::Contractual,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(5),
        max_response_bytes: 1 << 20,
        tls: None,
    })
    .unwrap();
    Arc::new(CheckedProvider::new(Arc::new(inner)))
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(9),
        format_version: 1,
        crypto_compatibility_id: "audit-v1".into(),
    }
}

fn unit() -> Vec<PlaintextUnit> {
    vec![PlaintextUnit {
        unit_index: 3,
        data: SecretBuffer::from_vec(vec![0x42; UNIT]),
    }]
}

#[tokio::test]
async fn truncated_content_length_body_is_refused() {
    let url = server(true, 2000).await;
    let result = provider(&url).encrypt_batch(&context(), &unit()).await;
    assert!(result.is_err(), "Content-Length framing detects truncation");
}

#[tokio::test]
async fn truncated_close_delimited_raw_ciphertext_is_accepted() {
    let url = server(false, 2000).await;
    let result = provider(&url).encrypt_batch(&context(), &unit()).await;
    match result {
        Ok(out) => panic!(
            "AUDIT: a close-delimited response cut short by the provider's death was \
             accepted as ciphertext: {} of {CIPHER} bytes",
            out[0].data.len()
        ),
        Err(e) => eprintln!("refused: {e}"),
    }
}
