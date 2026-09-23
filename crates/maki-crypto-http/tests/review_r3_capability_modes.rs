//! R3-010: configuration declarations are contracts, not verification evidence.

use maki_crypto::{Capability, CryptoProvider};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::parse_config;

#[tokio::test]
async fn remote_security_declarations_are_at_most_contractual() {
    let mut config = parse_config(include_str!(
        "../../../packaging/examples/postgres-prod.toml"
    ))
    .unwrap();
    config.crypto.capabilities.mode = "declared".into();
    let mut keys = MapKeySource::new();
    keys.insert("crypto-token", b"test-token".to_vec());
    for (level, expected) in [
        ("none", Capability::Absent),
        ("contractual", Capability::Contractual),
        ("verified", Capability::Contractual),
    ] {
        config.crypto.capabilities.integrity = level.into();
        config.crypto.capabilities.context_binding = level.into();
        config.crypto.capabilities.replay_protection = level.into();
        config.validate().unwrap();
        let provider =
            HttpCryptoProvider::from_config(&config, "https://crypto.internal", &keys).unwrap();
        let capabilities = provider.capabilities().await.unwrap();
        assert_eq!(
            capabilities.integrity, expected,
            "integrity declaration: {level}"
        );
        assert_eq!(
            capabilities.context_binding, expected,
            "context declaration: {level}"
        );
        assert_eq!(
            capabilities.replay_protection, expected,
            "replay declaration: {level}"
        );
    }
}
