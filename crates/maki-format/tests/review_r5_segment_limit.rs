//! R5-033: recovery bounds journal segment files by the largest segment size
//! a configuration may use, so the setting itself has an upper bound.

use maki_format::config::parse_config;
use maki_format::journal::MAX_JOURNAL_SEGMENT_SIZE;

fn config(segment: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "env", name = "k" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4128
[backing]
root = "/x"
journal_segment_size = "{segment}"
journal_max_bytes = "8GiB"
"#
    )
}

#[test]
fn the_segment_size_is_bounded_by_what_recovery_accepts() {
    assert_eq!(MAX_JOURNAL_SEGMENT_SIZE, 1 << 30);
    parse_config(&config("1GiB")).unwrap().validate().unwrap();
    let error = parse_config(&config("1025MiB"))
        .unwrap()
        .validate()
        .unwrap_err();
    assert!(error.to_string().contains("at most"), "{error}");
}
