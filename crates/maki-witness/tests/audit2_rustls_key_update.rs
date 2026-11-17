//! Round-2 audit: the patched rustls TLS 1.3 key-update, close_notify and
//! plaintext-queue paths at a lowered confidentiality limit, through the
//! public buffered and unbuffered APIs.
use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::UnbufferedClientConnection;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::unbuffered::{ConnectionState, EncryptError};
use rustls::{
    CipherSuiteCommon, ClientConfig, ClientConnection, RootCertStore, ServerConfig,
    ServerConnection, SupportedCipherSuite, Tls13CipherSuite,
};

const LIMIT: u64 = 8;

fn provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    let suite = provider.cipher_suites[0].tls13().unwrap();
    provider.cipher_suites = vec![SupportedCipherSuite::Tls13(Box::leak(Box::new(
        Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: suite.common.suite,
                hash_provider: suite.common.hash_provider,
                confidentiality_limit: LIMIT,
            },
            hkdf_provider: suite.hkdf_provider,
            aead_alg: suite.aead_alg,
            quic: suite.quic,
        },
    )))];
    Arc::new(provider)
}

fn configs(fragment: Option<usize>) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let provider = provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.max_fragment_size = fragment;
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.cert.der().to_vec())],
            PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap(),
        )
        .unwrap();
    server.send_tls13_tickets = 0;
    server.max_fragment_size = fragment;
    (Arc::new(client), Arc::new(server))
}

fn unbuffered_pair(fragment: Option<usize>) -> (UnbufferedClientConnection, ServerConnection) {
    let (client_config, server_config) = configs(fragment);
    let mut client =
        UnbufferedClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    let mut incoming = Vec::new();
    let mut outgoing = Vec::new();
    for _ in 0..64 {
        let status = client.process_tls_records(&mut incoming);
        let discard = status.discard;
        let done = match status.state.unwrap() {
            ConnectionState::EncodeTlsData(mut encoder) => {
                let mut bytes = vec![0; 16 * 1024];
                let len = encoder.encode(&mut bytes).unwrap();
                outgoing.extend_from_slice(&bytes[..len]);
                false
            }
            ConnectionState::TransmitTlsData(transmit) => {
                transmit.done();
                server.read_tls(&mut outgoing.as_slice()).unwrap();
                server.process_new_packets().unwrap();
                outgoing.clear();
                false
            }
            ConnectionState::WriteTraffic(_) => true,
            ConnectionState::BlockedHandshake => false,
            other => panic!("unexpected handshake state: {other:?}"),
        };
        incoming.drain(..discard);
        if done {
            return (client, server);
        }
        server.write_tls(&mut incoming).unwrap();
    }
    panic!("handshake did not complete");
}

fn server_reads(server: &mut ServerConnection, wire: &[u8]) -> Vec<u8> {
    let mut wire = wire;
    while !wire.is_empty() {
        server.read_tls(&mut wire).unwrap();
        server.process_new_packets().unwrap();
    }
    let mut out = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        match server.reader().read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("server read failed: {e}"),
        }
    }
    out
}

fn encrypt(client: &mut UnbufferedClientConnection, data: &[u8]) -> Vec<u8> {
    let ConnectionState::WriteTraffic(mut traffic) =
        client.process_tls_records(&mut []).state.unwrap()
    else {
        panic!("not writable");
    };
    let mut wire = vec![0; 64 * 1024];
    let len = traffic.encrypt(data, &mut wire).unwrap();
    wire.truncate(len);
    wire
}

#[test]
fn audit2_unbuffered_multi_record_write_across_the_limit_keeps_every_record_decryptable() {
    let (mut client, mut server) = unbuffered_pair(Some(64));
    let mut expected = Vec::new();
    // Many rounds of multi-record writes: each call crosses the 8-record limit
    // at a different offset, so the automatic KeyUpdate lands mid-sequence.
    for round in 0..40u8 {
        let data: Vec<u8> = (0..(37 * (round as usize % 7 + 1)))
            .map(|i| round ^ (i as u8))
            .collect();
        let wire = encrypt(&mut client, &data);
        expected.extend_from_slice(&data);
        let got = server_reads(&mut server, &wire);
        assert_eq!(got, data, "round {round}");
    }
    assert!(!expected.is_empty());
}

#[test]
fn audit2_unbuffered_close_notify_after_insufficient_buffer_keeps_wire_order() {
    let (mut client, mut server) = unbuffered_pair(None);
    for _ in 0..(LIMIT - 1) {
        let wire = encrypt(&mut client, b"x");
        assert_eq!(server_reads(&mut server, &wire), b"x");
    }
    let ConnectionState::WriteTraffic(mut traffic) =
        client.process_tls_records(&mut []).state.unwrap()
    else {
        panic!("not writable");
    };
    // The write that triggers the KeyUpdate fails for lack of space; the
    // caller then closes instead of retrying.
    let mut tiny = [0u8; 8];
    assert!(matches!(
        traffic.encrypt(b"y", &mut tiny),
        Err(EncryptError::InsufficientSize(_))
    ));
    let mut wire = vec![0; 4096];
    let len = traffic.queue_close_notify(&mut wire).unwrap();
    wire.truncate(len);
    let got = server_reads(&mut server, &wire);
    assert!(got.is_empty());
    assert!(server.process_new_packets().unwrap().peer_has_closed());
}

#[test]
fn audit2_peer_requested_key_update_is_answered_and_both_directions_survive() {
    let (mut client, mut server) = unbuffered_pair(Some(64));
    for round in 0..30u8 {
        // Server asks for a key update and sends data under new keys.
        server.refresh_traffic_keys().unwrap();
        let message = vec![round; 200];
        server.writer().write_all(&message).unwrap();
        let mut incoming = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut incoming).unwrap();
        }
        let mut received = Vec::new();
        loop {
            let status = client.process_tls_records(&mut incoming);
            let discard = status.discard;
            let mut progressed = false;
            match status.state.unwrap() {
                ConnectionState::ReadTraffic(mut traffic) => {
                    while let Some(record) = traffic.next_record() {
                        received.extend_from_slice(record.unwrap().payload);
                    }
                    progressed = true;
                }
                ConnectionState::WriteTraffic(_) => {}
                ConnectionState::EncodeTlsData(mut encoder) => {
                    let mut bytes = vec![0; 4096];
                    let len = encoder.encode(&mut bytes).unwrap();
                    server_reads(&mut server, &bytes[..len]);
                    progressed = true;
                }
                ConnectionState::TransmitTlsData(transmit) => {
                    transmit.done();
                    progressed = true;
                }
                other => panic!("unexpected state {other:?}"),
            }
            incoming.drain(..discard);
            if !progressed && incoming.is_empty() {
                break;
            }
        }
        assert_eq!(received, message, "round {round}");
        // The client's next write carries its KeyUpdate notification.
        let reply = vec![round.wrapping_add(1); 150];
        let wire = encrypt(&mut client, &reply);
        assert_eq!(server_reads(&mut server, &wire), reply, "round {round}");
    }
}

#[test]
fn audit2_buffered_writes_across_the_limit_are_delivered_in_order() {
    let (client_config, server_config) = configs(Some(64));
    let mut client = ClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    // Queue plaintext during the handshake too (flush_plaintext path).
    let early: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    client.writer().write_all(&early).unwrap();
    let mut transferred = Vec::new();
    for _ in 0..64 {
        let mut wire = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut wire).unwrap();
        }
        transferred.extend(server_reads(&mut server, &wire));
        let mut back = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut back).unwrap();
        }
        let mut back = back.as_slice();
        while !back.is_empty() {
            client.read_tls(&mut back).unwrap();
            client.process_new_packets().unwrap();
        }
        if !client.is_handshaking() && !client.wants_write() {
            break;
        }
    }
    let mut expected = early.clone();
    for round in 0..50u32 {
        let data: Vec<u8> = (0..(round * 31 + 1)).map(|i| (i ^ round) as u8).collect();
        client.writer().write_all(&data).unwrap();
        expected.extend_from_slice(&data);
        let mut wire = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut wire).unwrap();
        }
        transferred.extend(server_reads(&mut server, &wire));
    }
    assert_eq!(transferred.len(), expected.len());
    assert!(transferred == expected, "buffered plaintext was reordered or corrupted");
}
