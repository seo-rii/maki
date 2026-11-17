//! Audit probe (round 2, #151): the nightly "release build refuses
//! provider = fake" gate now requires the provider refusal text. That text is
//! produced only after `VolumeConfig::validate` succeeds, so the gate can only
//! pass if the heredoc config in ci.yml still validates under the current
//! rules. Extract it and check.

use maki_format::config::parse_config;

#[test]
fn the_ci_fake_provider_config_still_validates() {
    let ci = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/ci.yml"
    ))
    .unwrap();
    let start = ci
        .find("cat > /tmp/fake.toml <<'EOF'")
        .expect("fake.toml heredoc");
    let body_start = ci[start..].find('\n').unwrap() + start + 1;
    let end = ci[body_start..].find("EOF").unwrap() + body_start;
    let body: String = ci[body_start..end]
        .lines()
        .map(|line| line.trim_start())
        .collect::<Vec<_>>()
        .join("\n");
    println!("{body}");
    let config = parse_config(&body).expect("parses");
    config.validate().expect("validates");
    assert_eq!(config.crypto.provider, "fake");
}
