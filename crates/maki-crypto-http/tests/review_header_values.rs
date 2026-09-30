//! A credential resolved into a request header must be a valid header
//! value. A control character inside it (only the ends are trimmed) made
//! every request fail at send time with a builder error that was classified
//! as a *retryable transport* error: under the `stall` policy writes
//! retried forever and the breaker tripped, with no hint at the cause.
//! `from_config` now refuses it as `ProviderFatal`, without echoing it.

use maki_crypto::CryptoError;
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::parse_config;

fn provider_with_token(token: &[u8]) -> Result<HttpCryptoProvider, CryptoError> {
    let config = parse_config(include_str!(
        "../../../packaging/examples/postgres-prod.toml"
    ))
    .unwrap();
    config.validate().unwrap();
    let mut keys = MapKeySource::new();
    keys.insert("crypto-token", token.to_vec());
    HttpCryptoProvider::from_config(&config, "https://crypto.internal", &keys)
}

#[test]
fn a_header_credential_with_a_control_character_is_refused_at_attach() {
    for token in [&b"tok\x01en"[..], b"tok\nen", b"tok\ren"] {
        let Err(error) = provider_with_token(token) else {
            panic!("a control character in a header credential must be refused");
        };
        assert!(matches!(error, CryptoError::ProviderFatal(_)), "{error:?}");
        let message = error.to_string();
        assert!(
            !message.contains("tok"),
            "the value is never echoed: {message}"
        );
    }
    // Surrounding whitespace is trimmed, as before.
    provider_with_token(b"  test-token\n").unwrap();
}
