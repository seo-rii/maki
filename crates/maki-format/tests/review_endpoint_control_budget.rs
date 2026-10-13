//! BUG-075: validated endpoint lists must fit complete control snapshots.

use maki_format::config::{parse_config, EndpointConfig, VolumeConfig};

fn config(names: impl IntoIterator<Item = String>) -> VolumeConfig {
    let mut config = parse_config(include_str!("data/full_config.toml")).unwrap();
    config.crypto.http.as_mut().unwrap().endpoint = names
        .into_iter()
        .map(|name| EndpointConfig {
            name,
            url: "http://127.0.0.1:9000".into(),
        })
        .collect();
    config
}

#[test]
fn hundreds_of_named_endpoints_are_rejected_before_control_becomes_unreadable() {
    let config = config((0..400).map(|i| format!("endpoint_{i:04}_{}", "n".repeat(50))));
    let error = config
        .validate()
        .expect_err("400 endpoints broke both official snapshots");
    assert!(
        error.to_string().contains("control response budget"),
        "{error}"
    );
}

#[test]
fn json_escape_expansion_is_included_in_the_endpoint_budget() {
    // A single name occurs in status and the three metrics maps. Control
    // characters occupy six JSON bytes each, rather than one UTF-8 byte.
    let error = config(["\u{0001}".repeat(2_100)])
        .validate()
        .expect_err("JSON escaping must not exceed the snapshot budget");
    assert!(
        error.to_string().contains("control response budget"),
        "{error}"
    );
}

#[test]
fn endpoint_budget_rejects_one_huge_unescaped_name() {
    let error = config(["n".repeat(16_384)])
        .validate()
        .expect_err("one endpoint must not overflow a complete metrics snapshot");
    assert!(
        error.to_string().contains("control response budget"),
        "{error}"
    );
}

#[test]
fn endpoint_budget_boundary_is_accepted() {
    // 384 bytes for endpoint fields/numbers, four names including quotes.
    let name = "n".repeat((48 * 1024 - 384) / 4 - 2);
    config([name]).validate().unwrap();
}

#[test]
fn endpoint_budget_one_byte_beyond_boundary_is_rejected() {
    let name = "n".repeat((48 * 1024 - 384) / 4 - 1);
    let error = config([name])
        .validate()
        .expect_err("over-budget name accepted");
    assert!(
        error.to_string().contains("control response budget"),
        "{error}"
    );
}

#[test]
fn regular_unicode_and_escaped_endpoint_names_remain_supported() {
    config(["서울".into(), "quote\"slash\\tab\t".into()])
        .validate()
        .unwrap();
}
