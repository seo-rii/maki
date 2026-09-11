//! R3-010: a discovery mode must never silently mean declared capabilities.

use maki_format::config::parse_config;

const FULL: &str = include_str!("data/full_config.toml");

#[test]
fn declared_is_the_only_supported_capability_mode() {
    let mut config = parse_config(FULL).unwrap();
    config.crypto.capabilities.mode = "declared".into();
    config.validate().unwrap();
    for unsupported in ["hybrid", "probed", "unknown"] {
        config.crypto.capabilities.mode = unsupported.into();
        let error = config
            .validate()
            .expect_err("unimplemented capability discovery must not be silently accepted")
            .to_string();
        assert!(error.contains("capabilities.mode"), "{error}");
        assert!(
            error.contains("declared"),
            "must identify the supported mode: {error}"
        );
        assert!(
            error.contains("discovery"),
            "must explain the missing behavior: {error}"
        );
    }
}

#[test]
fn an_omitted_capability_mode_uses_declared() {
    let raw = FULL
        .lines()
        .filter(|line| !line.starts_with("mode ="))
        .collect::<Vec<_>>()
        .join("\n");
    let config = parse_config(&raw).unwrap();
    assert_eq!(config.crypto.capabilities.mode, "declared");
    config.validate().unwrap();
}
