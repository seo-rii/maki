//! BUG-113: configuration errors echoed the configuration. A TOML or schema
//! error printed the offending source line (and serde quoted the value
//! itself), and endpoint URL errors printed the whole URL, userinfo and
//! query included. These errors reach stderr and the systemd journal, so the
//! literal secrets SPEC §9 forbids leaked through the very error that
//! refused them. Errors expose only the parse classification and location.

use maki_format::config::parse_config;

const SECRET: &str = "S3NT1NEL0123456789abcdef";

const BASE: &str = r#"
config_schema_version = 1
[volume]
name = "secret-echo"
max_virtual_size = "1MiB"
[backing]
root = "/tmp/unused-secret-echo"
"#;

fn parse_error(document: &str) -> (String, String) {
    let error = parse_config(document).expect_err("the document must not parse");
    (error.to_string(), format!("{error:?}"))
}

fn assert_redacted(document: &str, still_says: &str) {
    let (display, debug) = parse_error(document);
    assert!(
        !display.contains(SECRET),
        "Display echoed the secret: {display}"
    );
    assert!(!debug.contains(SECRET), "Debug echoed the secret: {debug}");
    assert!(
        display.contains(still_says),
        "the error lost its diagnosis: {display}"
    );
}

#[test]
fn a_literal_key_where_a_reference_belongs_is_not_echoed() {
    let document = format!(
        "{BASE}[crypto]\nprovider = \"local-aes-gcm-siv\"\ncrypto_compatibility_id = \"x\"\nkey = \"{SECRET}\"\n"
    );
    assert_redacted(&document, "line ");
}

#[test]
fn an_unknown_field_holding_a_token_is_not_echoed() {
    let document = format!("{BASE}token = \"{SECRET}\"\n");
    assert_redacted(&document, "line ");
}

#[test]
fn a_pasted_private_key_is_not_echoed() {
    let document = format!(
        "{BASE}[crypto]\nprovider = \"remote-http\"\ncrypto_compatibility_id = \"x\"\n\
         client_key = \"\"\"-----BEGIN PRIVATE KEY-----\n{SECRET}\n-----END PRIVATE KEY-----\"\"\"\n"
    );
    assert_redacted(&document, "line ");
}

#[test]
fn a_syntax_error_on_a_secret_line_is_located_but_not_echoed() {
    let document = format!("{BASE}[crypto]\nkey = \"{SECRET}\n");
    assert_redacted(&document, "line ");
}

#[test]
fn endpoint_url_errors_never_print_userinfo_or_query() {
    for (url, still_says) in [
        (format!("https://svc:{SECRET}@kms.example"), "userinfo"),
        (format!("svc:{SECRET}@kms.example"), "scheme"),
        (format!("ws://kms.example/?token={SECRET}"), "loopback"),
        (format!("ftp://kms.example/?token={SECRET}"), "scheme"),
    ] {
        let document = format!(
            "{BASE}[crypto]\nprovider = \"remote-websocket\"\ncrypto_compatibility_id = \"x\"\n\
             [crypto.capabilities]\nsupported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4104\n\
             [[crypto.websocket.endpoint]]\nname = \"primary\"\nurl = \"{url}\"\n"
        );
        let config = parse_config(&document).unwrap();
        let error = config.validate().expect_err("the URL must be refused");
        let (display, debug) = (error.to_string(), format!("{error:?}"));
        assert!(!display.contains(SECRET), "{url}: {display}");
        assert!(!debug.contains(SECRET), "{url}: {debug}");
        assert!(display.contains(still_says), "{url}: {display}");
        assert!(display.contains("primary"), "names the endpoint: {display}");
    }
}

#[test]
fn untrusted_error_fragments_never_reach_display_or_debug() {
    for field in [
        format!("availability_policy = \"bad`{SECRET}\""),
        "key = 1234567890123456".to_string(),
        format!("\"{SECRET}\" = true"),
        format!(r#"key = "bad\\\"{SECRET}""#),
    ] {
        let document = format!("{BASE}[crypto]\nprovider = \"local-aes-gcm-siv\"\ncrypto_compatibility_id = \"x\"\n{field}\n");
        let (display, debug) = parse_error(&document);
        for output in [display, debug] {
            assert!(!output.contains(SECRET), "{output}");
            assert!(!output.contains("1234567890123456"), "{output}");
            assert!(
                output.contains("invalid TOML or configuration schema at line "),
                "{output}"
            );
        }
    }
}
