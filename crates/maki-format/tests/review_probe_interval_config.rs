use maki_format::config::parse_config;
const FULL: &str = include_str!("data/full_config.toml");

#[test]
fn probe_rate_requires_a_representable_duration() {
    for rate in ["1e-20", "1e-300", "4e-20"] {
        let raw = FULL.replace(
            "minimum_probe_rate = \"1/s\"",
            &format!("minimum_probe_rate = \"{rate}/s\""),
        );
        let config = parse_config(&raw).unwrap();
        let error = config
            .validate()
            .expect_err("a validated probe interval must not panic at runtime")
            .to_string();
        assert!(error.contains("minimum_probe_rate"), "{error}");
    }
    for rate in ["1e-18", "0.25", "1000"] {
        let raw = FULL.replace(
            "minimum_probe_rate = \"1/s\"",
            &format!("minimum_probe_rate = \"{rate}/s\""),
        );
        parse_config(&raw).unwrap().validate().unwrap();
    }
}
