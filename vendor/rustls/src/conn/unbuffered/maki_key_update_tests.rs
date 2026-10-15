//! Verify the public unbuffered output order at the TLS 1.3 record limit.

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use alloc::{boxed::Box, vec, vec::Vec};
    use std::io::Read;

    use crate::client::UnbufferedClientConnection;
    use crate::crypto::CryptoProvider;
    use crate::pki_types::pem::PemObject;
    use crate::pki_types::{CertificateDer, PrivateKeyDer};
    use crate::sync::Arc;
    use crate::unbuffered::{ConnectionState, EncryptError};
    use crate::{
        version, CipherSuiteCommon, ClientConfig, RootCertStore, ServerConfig, ServerConnection,
        SupportedCipherSuite, Tls13CipherSuite,
    };

    fn connected_pair() -> (UnbufferedClientConnection, ServerConnection) {
        let mut provider = super::provider::default_provider();
        let suite = provider.cipher_suites[0].tls13().unwrap();
        provider.cipher_suites = vec![SupportedCipherSuite::Tls13(Box::leak(Box::new(
            Tls13CipherSuite {
                common: CipherSuiteCommon {
                    suite: suite.common.suite,
                    hash_provider: suite.common.hash_provider,
                    confidentiality_limit: 8,
                },
                hkdf_provider: suite.hkdf_provider,
                aead_alg: suite.aead_alg,
                quic: suite.quic,
            },
        )))];
        let provider: Arc<CryptoProvider> = Arc::new(provider);
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client_config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.cert.der().to_vec())],
                PrivateKeyDer::from_pem_slice(cert.signing_key.serialize_pem().as_bytes()).unwrap(),
            )
            .unwrap();
        server_config.send_tls13_tickets = 0;
        let mut client = UnbufferedClientConnection::new(
            Arc::new(client_config),
            "localhost".try_into().unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut incoming = Vec::new();
        let mut outgoing = Vec::new();
        for _ in 0..32 {
            let status = client.process_tls_records(&mut incoming);
            let discard = status.discard;
            let complete = match status.state.unwrap() {
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
            if complete {
                assert!(!server.is_handshaking());
                assert_eq!(client.core.common_state.record_layer.write_seq(), 0);
                return (client, server);
            }
            server.write_tls(&mut incoming).unwrap();
        }
        panic!("handshake did not complete");
    }

    fn roundtrip(server: &mut ServerConnection, wire: &[u8], expected: &[u8]) {
        server.read_tls(&mut &wire[..]).unwrap();
        server.process_new_packets().unwrap();
        let mut plaintext = vec![0; expected.len()];
        server.reader().read_exact(&mut plaintext).unwrap();
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn maki_unbuffered_automatic_key_update_precedes_application_data_in_same_output() {
        exercise_order(false);
    }

    #[test]
    fn maki_unbuffered_key_update_short_buffer_retry_preserves_output_order() {
        exercise_order(true);
    }

    fn exercise_order(short_buffer: bool) {
        let (mut client, mut server) = connected_pair();
        let payload = b"application data after the automatic key update";
        let mut ordinary_size = 0;
        for _ in 0..7 {
            let ConnectionState::WriteTraffic(mut traffic) =
                client.process_tls_records(&mut []).state.unwrap()
            else {
                panic!("connection not ready for application data");
            };
            let mut wire = vec![0; 1024];
            ordinary_size = traffic.encrypt(payload, &mut wire).unwrap();
            roundtrip(&mut server, &wire[..ordinary_size], payload);
        }
        assert_eq!(client.core.common_state.record_layer.write_seq(), 7);
        let mut wire = vec![0xa5; ordinary_size];
        let ConnectionState::WriteTraffic(mut traffic) =
            client.process_tls_records(&mut []).state.unwrap()
        else {
            panic!("connection not ready at the key-update boundary");
        };
        if short_buffer {
            let EncryptError::InsufficientSize(error) =
                traffic.encrypt(payload, &mut wire).unwrap_err()
            else {
                panic!("expected the size to include the queued KeyUpdate");
            };
            assert!(error.required_size > ordinary_size);
            assert!(wire.iter().all(|byte| *byte == 0xa5));
            wire.resize(error.required_size, 0xa5);
        } else {
            wire.resize(1024, 0xa5);
        }
        // Send exactly the bytes returned by encrypt, before calling
        // process_tls_records again, as permitted by the public API.
        let len = traffic.encrypt(payload, &mut wire).unwrap();
        assert!(len > ordinary_size, "KeyUpdate missing from returned bytes");
        roundtrip(&mut server, &wire[..len], payload);
        assert!(client.core.common_state.sendable_tls.is_empty());
        assert_eq!(client.core.common_state.record_layer.write_seq(), 1);
        assert_eq!(server.core.common_state.record_layer.read_seq(), 1);
        assert!(matches!(
            client.process_tls_records(&mut []).state.unwrap(),
            ConnectionState::WriteTraffic(_)
        ));
    }
}
