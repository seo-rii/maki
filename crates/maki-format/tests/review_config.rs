//! Review M-013 / M-014 / M-015: configuration validation must reject every
//! setting the runtime cannot honour, require the sections a provider needs,
//! refuse plaintext transports to non-loopback hosts, and prove the shipped
//! production sample is attachable as written.

use maki_format::config::{is_loopback_host, parse_config, parse_endpoint_url, VolumeConfig};

const SAMPLE: &str = include_str!("../../../packaging/examples/postgres-prod.toml");
const FULL: &str = include_str!("data/full_config.toml");

/// A complete, valid remote-http configuration; tests mutate it.
fn base() -> String {
    r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[[crypto.http.endpoint]]
name = "a"
url = "https://crypto.internal"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.encrypt.response]
data_path = "/ct"
encoding = "base64"
[crypto.http.decrypt]
path = "/decrypt"
[crypto.http.decrypt.response]
data_path = "/pt"
encoding = "base64"
[backing]
root = "/x"
"#
    .to_string()
}

fn local() -> String {
    r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = { source = "env", name = "k" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/x"
"#
    .to_string()
}

fn parse(raw: &str) -> VolumeConfig {
    parse_config(raw).unwrap_or_else(|e| panic!("parse: {e}\n{raw}"))
}

fn err(raw: &str) -> String {
    match parse_config(raw) {
        Err(e) => e.to_string(),
        Ok(cfg) => cfg
            .validate()
            .expect_err(&format!("expected rejection for:\n{raw}"))
            .to_string(),
    }
}

fn ok(raw: &str) {
    parse(raw)
        .validate()
        .unwrap_or_else(|e| panic!("{e}\n{raw}"));
}

fn with(section: &str) -> String {
    format!("{}\n{section}\n", base())
}

// ---------- shipped configurations ----------

#[test]
fn production_sample_and_full_fixture_validate() {
    ok(SAMPLE);
    ok(FULL);
    let sample = parse(SAMPLE);
    let http = sample.crypto.http.as_ref().unwrap();
    assert!(http.encrypt.is_some() && http.decrypt.is_some());
    for op in [
        http.encrypt.as_ref().unwrap(),
        http.decrypt.as_ref().unwrap(),
    ] {
        let response = op.response.as_ref().unwrap();
        assert!(response.items_path.is_some());
        assert!(
            response.item_index_path.is_some(),
            "batch results must echo the unit"
        );
    }
}

// ---------- provider sections (M-014) ----------

#[test]
fn remote_http_requires_endpoints_and_both_mappings() {
    let no_decrypt = base().replace(
        "[crypto.http.decrypt]\npath = \"/decrypt\"\n[crypto.http.decrypt.response]\ndata_path = \"/pt\"\nencoding = \"base64\"\n",
        "",
    );
    assert!(err(&no_decrypt).contains("crypto.http.decrypt"));
    let no_encrypt = base().replace(
        "[crypto.http.encrypt]\npath = \"/encrypt\"\n[crypto.http.encrypt.response]\ndata_path = \"/ct\"\nencoding = \"base64\"\n",
        "",
    );
    assert!(err(&no_encrypt).contains("crypto.http.encrypt"));
    let no_endpoint = base().replace(
        "[[crypto.http.endpoint]]\nname = \"a\"\nurl = \"https://crypto.internal\"\n",
        "",
    );
    assert!(err(&no_endpoint).contains("endpoint"));
}

#[test]
fn local_provider_requires_key_and_rejects_transport_sections() {
    let no_key = local().replace("key = { source = \"env\", name = \"k\" }\n", "");
    assert!(err(&no_key).contains("key"));
    let with_http = format!(
        "{}\n[[crypto.http.endpoint]]\nname = \"a\"\nurl = \"https://x\"\n",
        local()
    );
    assert!(err(&with_http).contains("not used by provider"));
    let remote_with_key = base().replace(
        "crypto_compatibility_id = \"v1\"\n",
        "crypto_compatibility_id = \"v1\"\nkey = { source = \"env\", name = \"k\" }\n",
    );
    assert!(err(&remote_with_key).contains("only used by local providers"));
}

#[test]
fn websocket_and_grpc_require_their_sections_and_reject_tls() {
    let ws = base()
        .replace(
            "provider = \"remote-http\"",
            "provider = \"remote-websocket\"",
        )
        .replace("[[crypto.http.endpoint]]", "[[crypto.websocket.endpoint]]")
        .replace(
            "url = \"https://crypto.internal\"",
            "url = \"ws://127.0.0.1:7000\"",
        );
    // Still carries the http mappings: not used by this provider.
    assert!(err(&ws).contains("not used by provider"));
    let ws_only = r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-websocket"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[[crypto.websocket.endpoint]]
name = "a"
url = "ws://127.0.0.1:7000"
[backing]
root = "/x"
"#;
    ok(ws_only);
    let wss = ws_only.replace("ws://127.0.0.1:7000", "wss://crypto.internal:7000");
    assert!(err(&wss).contains("TLS"));
    let ws_tls = format!("{ws_only}\n[crypto.websocket.tls]\nca_file = \"/etc/ca.pem\"\n");
    assert!(err(&ws_tls).contains("TLS"));

    let grpc = ws_only
        .replace("remote-websocket", "remote-grpc")
        .replace("[[crypto.websocket.endpoint]]", "[[crypto.grpc.endpoint]]")
        .replace("ws://127.0.0.1:7000", "http://localhost:7000");
    ok(&grpc);
    let grpcs = grpc.replace("http://localhost:7000", "https://crypto.internal:7000");
    assert!(err(&grpcs).contains("TLS"));
    let missing = "config_schema_version = 1\n[volume]\nname = \"t\"\nmax_virtual_size = \"1GiB\"\n[crypto]\nprovider = \"remote-grpc\"\ncrypto_compatibility_id = \"v1\"\n[crypto.capabilities]\nsupported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4384\n[backing]\nroot = \"/x\"\n";
    assert!(err(missing).contains("crypto.grpc"));
}

// ---------- plaintext transport policy (M-015) ----------

#[test]
fn plaintext_transports_are_loopback_only() {
    for url in [
        "http://127.0.0.1:8080",
        "http://localhost/api",
        "http://[::1]:9000",
        "https://crypto.internal",
    ] {
        ok(&base().replace("https://crypto.internal", url));
    }
    for url in [
        "http://crypto.internal",
        "http://10.0.0.5:8080",
        "http://127.0.0.1.evil.example",
    ] {
        let msg = err(&base().replace("https://crypto.internal", url));
        assert!(msg.contains("loopback"), "{url}: {msg}");
    }
    assert!(err(&base().replace("https://crypto.internal", "ftp://x")).contains("scheme"));
    assert!(
        err(&base().replace("https://crypto.internal", "https://user:pw@x")).contains("userinfo")
    );
    assert!(err(&base().replace("https://crypto.internal", "crypto.internal")).contains("scheme"));
}

#[test]
fn endpoint_url_parsing_and_loopback_detection() {
    assert_eq!(
        parse_endpoint_url("https://Host.Example:8443/v1?x=1").unwrap(),
        ("https".to_string(), "Host.Example".to_string())
    );
    assert_eq!(
        parse_endpoint_url("http://[::1]:7000").unwrap().1,
        "::1".to_string()
    );
    assert!(is_loopback_host("localhost"));
    assert!(is_loopback_host("LOCALHOST"));
    assert!(is_loopback_host("127.0.0.1"));
    assert!(is_loopback_host("127.8.9.10"));
    assert!(is_loopback_host("::1"));
    assert!(!is_loopback_host("127.0.0.1.evil"));
    assert!(!is_loopback_host("10.0.0.1"));
    assert!(!is_loopback_host("localhost.example"));
}

#[test]
fn duplicate_or_empty_endpoint_names_are_rejected() {
    let dup = format!(
        "{}\n[[crypto.http.endpoint]]\nname = \"a\"\nurl = \"https://b.internal\"\n",
        base()
    );
    assert!(err(&dup).contains("duplicated"));
    assert!(err(&base().replace("name = \"a\"", "name = \"\"")).contains("empty name"));
}

// ---------- TLS (M-015) ----------

#[test]
fn tls_files_must_exist_and_server_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, b"-----BEGIN CERTIFICATE-----\n").unwrap();
    let ca_path = ca.to_string_lossy().replace('\\', "/");
    ok(&with(&format!(
        "[crypto.http.tls]\nca_file = \"{ca_path}\""
    )));
    let missing = err(&with("[crypto.http.tls]\nca_file = \"/no/such/ca.pem\""));
    assert!(missing.contains("not readable"), "{missing}");
    let sni = err(&with(&format!(
        "[crypto.http.tls]\nca_file = \"{ca_path}\"\nserver_name = \"other\""
    )));
    assert!(sni.contains("server_name"), "{sni}");
    let key_without_cert = err(&with(
        "[crypto.http.tls]\nclient_key = { source = \"credential\", name = \"k\" }",
    ));
    assert!(
        key_without_cert.contains("client_cert_file"),
        "{key_without_cert}"
    );
}

// ---------- credentials ----------

#[test]
fn keyring_credential_source_is_refused() {
    let msg = err(&local().replace("source = \"env\"", "source = \"keyring\""));
    assert!(msg.contains("keyring"), "{msg}");
    let msg = err(&local().replace("source = \"env\"", "source = \"vault\""));
    assert!(msg.contains("credential|file|env"), "{msg}");
}

// ---------- batch identity (M-012) ----------

#[test]
fn http_batch_layout_requires_unit_echo() {
    let batch_without_echo = base().replace(
        "[crypto.http.encrypt]\npath = \"/encrypt\"\n[crypto.http.encrypt.response]\ndata_path = \"/ct\"\nencoding = \"base64\"\n",
        "[crypto.http.encrypt]\npath = \"/encrypt\"\n[crypto.http.encrypt.body]\nitems_path = \"/items\"\n[crypto.http.encrypt.body.item_fields]\n\"/data\" = { source = \"payload\", encoding = \"base64\" }\n[crypto.http.encrypt.response]\nitems_path = \"/items\"\ndata_path = \"/ct\"\nencoding = \"base64\"\n",
    );
    let msg = err(&batch_without_echo);
    assert!(msg.contains("item_index_path"), "{msg}");
    let with_echo = batch_without_echo.replace(
        "items_path = \"/items\"\ndata_path = \"/ct\"",
        "items_path = \"/items\"\nitem_index_path = \"/unit\"\ndata_path = \"/ct\"",
    );
    ok(&with_echo);
}

// ---------- numeric and duration settings (M-013) ----------

#[test]
fn zero_and_inverted_bounds_are_rejected() {
    let cases: &[(&str, &str)] = &[
        ("[limits]\nmax_active_callbacks = 0", "max_active_callbacks"),
        ("[limits]\nmax_pending_crypto_items = 0", "max_pending_crypto_items"),
        ("[limits]\nmax_plaintext_bytes = \"0\"", "max_plaintext_bytes"),
        ("[limits]\nmax_plaintext_bytes = \"1GiB\"\nmax_ciphertext_bytes = \"1MiB\"", "max_ciphertext_bytes"),
        ("[limits]\nmax_journal_pending_bytes = \"0\"", "max_journal_pending_bytes"),
        ("[crypto.retry]\ninitial_delay = \"0ms\"", "initial_delay"),
        ("[crypto.retry]\ninitial_delay = \"5s\"\nmax_delay = \"1s\"", "max_delay"),
        ("[crypto.retry]\nstrategy = \"constant\"", "strategy"),
        ("[crypto.retry_budget]\nburst = 0", "burst"),
        ("[crypto.retry_budget]\nretry_ratio = -1.0", "retry_ratio"),
        ("[crypto.retry_budget]\nminimum_probe_rate = \"0/s\"", "minimum_probe_rate"),
        ("[crypto.retry_budget]\nminimum_probe_rate = nan", "minimum_probe_rate"),
        ("[crypto.retry_budget]\nminimum_probe_rate = inf", "minimum_probe_rate"),
        ("[crypto.circuit_breaker]\nfailure_threshold = 0", "circuit_breaker"),
        ("[crypto.circuit_breaker]\nopen_initial = \"10s\"\nopen_max = \"1s\"", "open_max"),
        ("[crypto.circuit_breaker]\nhalf_open_max_requests = 0", "circuit_breaker"),
        ("[crypto.batch]\nmax_items = 0", "max_items"),
        ("[crypto.batch]\nmax_bytes = \"100\"", "max_bytes"),
        ("[crypto.batch]\ntarget_items = 1000", "target_items"),
        ("[crypto.batch]\ntarget_bytes = \"2MiB\"", "target_bytes"),
        ("[cache]\nmode = \"read\"\nmax_bytes = \"0\"", "cache.max_bytes"),
        ("[cache]\nmode = \"read\"\nttl = \"0s\"", "cache.ttl"),
        ("[nbd]\nthreads = 0", "nbd.threads"),
        ("[nbd]\nminimum_io = 4096\npreferred_io = 512", "nbd I/O sizes"),
        ("[nbd]\nminimum_io = 3000", "power of two"),
        ("[backing]\nroot = \"/x\"\njournal_segment_size = \"1MiB\"\njournal_max_bytes = \"1MiB\"", "journal_max_bytes"),
        ("[control]\ngroup = \" \"", "control.group"),
        ("[security]\nmemory_lock_mode = \"maybe\"", "memory_lock_mode"),
    ];
    for (section, needle) in cases {
        let raw = if section.starts_with("[backing]") {
            base().replace("[backing]\nroot = \"/x\"\n", &format!("{section}\n"))
        } else {
            with(section)
        };
        let msg = err(&raw);
        assert!(msg.contains(needle), "{section:?}: {msg}");
    }
}

#[test]
fn capability_mode_and_availability_policy_are_checked() {
    let bad_mode = base().replace(
        "[crypto.capabilities]\n",
        "[crypto.capabilities]\nmode = \"guess\"\n",
    );
    assert!(err(&bad_mode).contains("capabilities.mode"));
    let bounded_without_time = base().replace(
        "crypto_compatibility_id = \"v1\"\n",
        "crypto_compatibility_id = \"v1\"\navailability_policy = \"bounded-error\"\n",
    );
    assert!(err(&bounded_without_time).contains("max_operation_time"));
    let zero_time = base().replace(
        "crypto_compatibility_id = \"v1\"\n",
        "crypto_compatibility_id = \"v1\"\navailability_policy = \"bounded-error\"\nmax_operation_time = \"0s\"\n",
    );
    assert!(err(&zero_time).contains("max_operation_time"));
}

#[test]
fn defaults_still_validate() {
    ok(&base());
    ok(&local());
}

// ---------- follow-up audit: journal limit progress guarantee ----------

#[test]
fn journal_hard_limit_must_leave_room_for_a_reclaim_and_the_largest_request() {
    // 4 KiB units, 1 MiB requests: a request journals 257 records of
    // 32 + 4384 bytes; two 1 MiB segments alone are not enough.
    let too_small = base().replace(
        "[backing]\nroot = \"/x\"\n",
        "[backing]\nroot = \"/x\"\njournal_segment_size = \"1MiB\"\njournal_max_bytes = \"2MiB\"\n",
    );
    let msg = err(&too_small);
    assert!(msg.contains("largest request"), "{msg}");
    let enough = base().replace(
        "[backing]\nroot = \"/x\"\n",
        "[backing]\nroot = \"/x\"\njournal_segment_size = \"1MiB\"\njournal_max_bytes = \"4MiB\"\n",
    );
    ok(&enough);
}

// ---------- audit: geometries the format layer cannot serve ----------

#[test]
fn units_whose_ciphertext_exceeds_a_journal_record_are_rejected() {
    // 32 MiB crypto units: one unit's ciphertext is larger than the journal
    // scanner's per-record bound, so no write could ever be journaled.
    let raw = base()
        .replace(
            "max_virtual_size = \"1GiB\"\n",
            "max_virtual_size = \"1GiB\"\ncrypto_unit_size = 33554432\n",
        )
        .replace(
            "supported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4384",
            "supported_plaintext_sizes = [33554432]\nmax_ciphertext_size = 33554720",
        );
    let msg = err(&raw);
    assert!(
        msg.contains("max_ciphertext_size") && msg.contains("journal"),
        "{msg}"
    );
}

#[test]
fn shards_with_more_units_than_the_allocation_map_indexes_are_rejected() {
    // 32 TiB shards of 4 KiB units = 2^33 units per shard.
    let raw = base().replace(
        "max_virtual_size = \"1GiB\"\n",
        "max_virtual_size = \"1GiB\"\nshard_logical_size = \"32TiB\"\n",
    );
    let msg = err(&raw);
    assert!(msg.contains("units_per_shard"), "{msg}");
    // The documented default (64 GiB shards) stays valid.
    ok(&base());
}

// ---------- audit: documented nbd.device_block_size cross-check ----------

#[test]
fn nbd_device_block_size_must_match_the_volume() {
    let msg = err(&with("[nbd]\ndevice_block_size = 512"));
    assert!(msg.contains("nbd.device_block_size"), "{msg}");
    ok(&with("[nbd]\ndevice_block_size = 4096"));

    // Unset: the NBD export inherits the volume's block size.
    let small = base().replace(
        "max_virtual_size = \"1GiB\"\n",
        "max_virtual_size = \"1GiB\"\ndevice_block_size = 512\n",
    );
    ok(&small);
    assert_eq!(parse(&small).nbd_device_block_size(), 512);
    ok(&format!("{small}\n[nbd]\ndevice_block_size = 512\n"));
    let msg = err(&format!("{small}\n[nbd]\ndevice_block_size = 4096\n"));
    assert!(msg.contains("nbd.device_block_size"), "{msg}");
}
