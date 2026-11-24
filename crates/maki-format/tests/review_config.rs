//! Review M-013 / M-014 / M-015: configuration validation must reject every
//! setting the runtime cannot honour, require the sections a provider needs,
//! refuse plaintext transports to non-loopback hosts, and prove the shipped
//! production sample is attachable as written.

#[cfg(unix)]
#[path = "support/short_dir.rs"]
mod short_dir;

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

/// The rejection of `raw`. Every binary prints it after `error: ` and the
/// journal stores it as one record, so each rejection in this file is also
/// held to that layout: one line, without a run of spaces.
fn err(raw: &str) -> String {
    let message = match parse_config(raw) {
        Err(e) => e.to_string(),
        Ok(cfg) => cfg
            .validate()
            .expect_err(&format!("expected rejection for:\n{raw}"))
            .to_string(),
    };
    assert!(
        !message.contains(['\n', '\r', '\t']) && !message.contains("  "),
        "a rejection must be one line of single-spaced text: {message:?}"
    );
    message
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
fn websocket_and_grpc_require_their_sections_and_accept_tls() {
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
    ok(&wss);
    let ws_tls = format!("{ws_only}\n[crypto.websocket.tls]\nca_file = \"/etc/ca.pem\"\n");
    assert!(err(&ws_tls).contains("not readable"));

    let grpc = ws_only
        .replace("remote-websocket", "remote-grpc")
        .replace("[[crypto.websocket.endpoint]]", "[[crypto.grpc.endpoint]]")
        .replace("ws://127.0.0.1:7000", "http://localhost:7000");
    ok(&grpc);
    let grpcs = grpc.replace("http://localhost:7000", "https://crypto.internal:7000");
    ok(&grpcs);
    let missing = "config_schema_version = 1\n[volume]\nname = \"t\"\nmax_virtual_size = \"1GiB\"\n[crypto]\nprovider = \"remote-grpc\"\ncrypto_compatibility_id = \"v1\"\n[crypto.capabilities]\nsupported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4384\n[backing]\nroot = \"/x\"\n";
    assert!(err(missing).contains("crypto.grpc"));
}

#[test]
fn remote_transport_batch_must_fit_the_frame_or_message_limit() {
    // A whole crypto batch is sent as one gRPC message / one WebSocket
    // frame. Make the byte ceiling reachable with enough item slots so the
    // full serialized batch must fit. Reject a zero transport limit too
    // (consistent with HTTP's max_response_bytes check).
    let grpc = |batch: &str, grpc_extra: &str| -> String {
        format!(
            r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[crypto.batch]
max_items = 2048
max_bytes = "{batch}"
[crypto.grpc]
{grpc_extra}
[[crypto.grpc.endpoint]]
name = "a"
url = "http://localhost:7000"
[backing]
root = "/x"
[limits]
max_inflight_bytes_per_endpoint = "16MiB"
"#
        )
    };
    // 2048 units reach the 8 MiB ceiling and exceed the 4 MiB gRPC limit.
    assert!(err(&grpc("8MiB", "")).contains("max_message_bytes"));
    // Raising the message limit above the batch makes it valid again.
    ok(&grpc("8MiB", "max_message_bytes = \"16MiB\""));
    // A zero limit is refused rather than silently rejecting every request.
    assert!(err(&grpc("1MiB", "max_message_bytes = \"0\"")).contains("max_message_bytes"));

    let ws = |batch: &str, ws_extra: &str| -> String {
        format!(
            r#"
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
[crypto.batch]
max_items = 2048
max_bytes = "{batch}"
[crypto.websocket]
{ws_extra}
[[crypto.websocket.endpoint]]
name = "a"
url = "ws://127.0.0.1:7000"
[backing]
root = "/x"
[limits]
max_inflight_bytes_per_endpoint = "16MiB"
"#
        )
    };
    // 1792 units reach 7 MiB; base64 alone exceeds the 8 MiB default frame.
    assert!(err(&ws("7MiB", "")).contains("max_frame_bytes"));
    // 4 MiB raw (~5.3 MiB encoded) fits the 8 MiB frame.
    ok(&ws("4MiB", ""));
    // A zero frame limit is refused.
    assert!(err(&ws("1MiB", "max_frame_bytes = \"0\"")).contains("max_frame_bytes"));
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
fn endpoint_ports_preserve_valid_ipv4_ipv6_and_default_ports() {
    for scheme in ["http", "https", "ws", "wss"] {
        for (authority, host) in [
            ("localhost", "localhost"),
            ("127.0.0.1:", "127.0.0.1"),
            ("127.0.0.1:0", "127.0.0.1"),
            ("Host.Example:65535", "Host.Example"),
            ("[::1]", "::1"),
            ("[::1]:", "::1"),
            ("[::1]:00080", "::1"),
            ("[2001:db8::1]:443", "2001:db8::1"),
        ] {
            let url = format!("{scheme}://{authority}/v1?profile=1#fragment");
            assert_eq!(
                parse_endpoint_url(&url).unwrap(),
                (scheme.to_string(), host.to_string()),
                "{url}"
            );
        }
    }
}

#[test]
fn remote_http_rejects_invalid_hosts_at_volume_validation() {
    for host in ["[127.0.0.1]", "[localhost]", "192.168.1.999", "host name"] {
        let raw = base().replace("https://crypto.internal", &format!("https://{host}"));
        assert!(err(&raw).contains("invalid host"), "{host}");
    }
    for host in ["crypto.internal", "127.0.0.1", "[2001:db8::1]"] {
        ok(&base().replace("https://crypto.internal", &format!("https://{host}")));
    }
}

#[test]
fn endpoint_ports_reject_invalid_syntax_and_overflow() {
    for scheme in ["http", "https", "ws", "wss"] {
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            for port in [
                "65536",
                "9999999999999999999999",
                "not-a-port",
                "-1",
                "+80",
                "80:90",
            ] {
                let url = format!("{scheme}://{host}:{port}/v1?profile=1");
                let error = parse_endpoint_url(&url).expect_err(&url);
                assert!(error.to_string().contains("port"), "{url}: {error}");
            }
        }
    }
}

#[test]
fn invalid_endpoint_ports_fail_all_remote_transport_preflights() {
    for (document, old_url, scheme) in [
        (base(), "https://crypto.internal", "https"),
        (
            remote_batch("remote-websocket", "[crypto.websocket]"),
            "ws://127.0.0.1:7000",
            "ws",
        ),
        (
            remote_batch("remote-grpc", "[crypto.grpc]"),
            "http://localhost:7000",
            "http",
        ),
    ] {
        ok(&document);
        for host in ["127.0.0.1", "[::1]"] {
            for port in ["65536", "not-a-port"] {
                let url = format!("{scheme}://{host}:{port}");
                let message = err(&document.replace(old_url, &url));
                assert!(message.contains("port"), "{url}: {message}");
            }
        }
    }
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
        "[crypto.http.encrypt]\npath = \"/encrypt\"\n[crypto.http.encrypt.body]\nitems_path = \"/items\"\n[crypto.http.encrypt.body.item_fields]\n\"/unit\" = { source = \"unit_index\" }\n\"/data\" = { source = \"payload\", encoding = \"base64\" }\n[crypto.http.encrypt.response]\nitems_path = \"/items\"\ndata_path = \"/ct\"\nencoding = \"base64\"\n",
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

/// SPEC §13: the default preferred I/O size is the crypto unit, not a fixed
/// 4096. A unit below `minimum_io` is raised to it so the size ordering
/// still holds; an explicit value wins; an explicit value below the
/// minimum is refused.
#[test]
fn preferred_io_defaults_to_the_crypto_unit() {
    let with_unit = |unit: u32, nbd: &str| {
        format!(
            r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
crypto_unit_size = {unit}
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "env", name = "k" }}
[crypto.capabilities]
supported_plaintext_sizes = [{unit}]
max_ciphertext_size = {}
[backing]
root = "/x"
{nbd}
"#,
            unit + 288
        )
    };
    let cfg = parse_config(&with_unit(8192, "")).unwrap();
    assert_eq!(cfg.nbd_preferred_io(), 8192);
    let cfg = parse_config(&with_unit(4096, "")).unwrap();
    assert_eq!(cfg.nbd_preferred_io(), 4096);
    let cfg = parse_config(&with_unit(512, "")).unwrap();
    assert_eq!(cfg.nbd_preferred_io(), 4096, "raised to minimum_io");
    let cfg = parse_config(&with_unit(8192, "[nbd]\npreferred_io = 16384")).unwrap();
    assert_eq!(cfg.nbd_preferred_io(), 16384, "explicit value wins");
    let err = parse_config(&with_unit(8192, "[nbd]\npreferred_io = 2048"))
        .unwrap()
        .validate()
        .unwrap_err();
    assert!(err.to_string().contains("nbd I/O sizes"), "{err}");
}

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
        // F07: the admission budget must hold one maximal request.
        ("[limits]\nmax_plaintext_bytes = 1048575\nmax_ciphertext_bytes = \"2MiB\"", "max_plaintext_bytes"),
        // Fourth pass: the backing root is never relative to the daemon's cwd.
        ("[backing]\nroot = \"relative/vol\"", "backing.root"),
        ("[backing]\nroot = \"\"", "backing.root"),
        ("[backing]\nroot = \"/x\"\njournal_segment_size = \"1MiB\"\njournal_max_bytes = \"1MiB\"", "journal_max_bytes"),
        ("[control]\ngroup = \" \"", "control.group"),
        // Fifth pass: socket paths name one place only when absolute.
        ("[control]\nsocket = \"control.sock\"", "control.socket"),
        ("[nbd]\nsocket = \"run/nbd.sock\"", "nbd.socket"),
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

/// An escaped newline where a string continuation was meant put a line
/// break and a run of indentation into both messages.
#[test]
fn memory_hardening_rejections_are_one_line() {
    assert_eq!(
        err(&with("[security]\ndisable_core_dump = false")),
        "config invalid: security.madv_dontdump is honoured through disable_core_dump \
         (a non-dumpable process writes no core); enable disable_core_dump or set \
         madv_dontdump = false"
    );
    assert_eq!(
        err(&with("[security]\nmemory_lock_mode = \"off\"")),
        "config invalid: cache.lock_memory requires security.memory_lock_mode = \
         secure-buffers or all (cache plaintext lives in secret buffers)"
    );
    // Parse failures go through the same printers.
    assert!(err("config_schema_version = 1\n[volume\n")
        .starts_with("config parse error: invalid TOML or configuration schema at line 2"));
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
    // 4 KiB units, 1 MiB aligned requests: a request journals 256 records of
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

/// Review R04 (2026-09-07): the batch scheduler admits a request as one whole
/// group and never splits it, so a lane's pending capacity must cover the
/// largest batch. Positive-value validation alone let `max_pending_crypto_*`
/// (and the decrypt lane's `max_ciphertext_bytes`) fall below the batch
/// maxima, so a config that validated then rejected every full batch at
/// runtime. Validation now requires the cover; exact equality is allowed.
#[test]
fn audit_20260907_pending_capacity_must_cover_a_full_batch() {
    // Fewer pending item slots than a full batch.
    let msg = err(&with(
        "[limits]\nmax_pending_crypto_items = 4\n\
         [crypto.batch]\ntarget_items = 8\nmax_items = 16\n",
    ));
    assert!(msg.contains("max_pending_crypto_items"), "{msg}");
    // Smaller encrypt-lane pending budget than a full batch.
    let msg = err(&with(
        "[limits]\nmax_pending_crypto_bytes = \"512KiB\"\n\
         [crypto.batch]\nmax_bytes = \"1MiB\"\n",
    ));
    assert!(msg.contains("max_pending_crypto_bytes"), "{msg}");
    // Smaller decrypt-lane pending budget than a full batch.
    let msg = err(&with(
        "[limits]\nmax_ciphertext_bytes = \"512KiB\"\nmax_plaintext_bytes = \"256KiB\"\n\
         [crypto.batch]\nmax_bytes = \"1MiB\"\n",
    ));
    assert!(msg.contains("max_ciphertext_bytes"), "{msg}");
    // Exact cover of the item count (pending == max_items) is accepted; the
    // default byte budgets comfortably cover the default batch max_bytes.
    ok(&with(
        "[limits]\nmax_pending_crypto_items = 16\n\
         [crypto.batch]\ntarget_items = 8\nmax_items = 16\n",
    ));
}

/// FUP-013: the in-flight byte budgets (global and per-endpoint) must also
/// cover a full batch, or an over-budget RPC would be clamped and let through
/// rather than bounded.
#[test]
fn followup_inflight_byte_budgets_must_cover_a_full_batch() {
    let msg = err(&with(
        "[limits]\nmax_crypto_inflight_bytes = \"512KiB\"\n\
         [crypto.batch]\nmax_bytes = \"1MiB\"\n",
    ));
    assert!(msg.contains("max_crypto_inflight_bytes"), "{msg}");
    let msg = err(&with(
        "[limits]\nmax_inflight_bytes_per_endpoint = \"512KiB\"\n\
         [crypto.batch]\nmax_bytes = \"1MiB\"\n",
    ));
    assert!(msg.contains("max_inflight_bytes_per_endpoint"), "{msg}");
}

/// The control socket and the NBD export socket must be different files:
/// binding the control socket replaces whatever is at its path, so a shared
/// path silently takes the NBD listener's name away (or the reverse).
#[test]
fn control_and_nbd_sockets_must_differ() {
    let shared = format!(
        "{}[control]\nsocket = \"/run/maki/t/nbd.sock\"\n[nbd]\nsocket = \"/run/maki/t/nbd.sock\"\n",
        local()
    );
    let error = err(&shared);
    assert!(
        error.contains("control.socket") && error.contains("nbd.socket"),
        "{error}"
    );
    // An explicit control socket equal to the default NBD socket collides
    // too, and so does a spelling that names the same path.
    let default_nbd = format!("{}[control]\nsocket = \"/run/maki/t/nbd.sock\"\n", local());
    assert!(err(&default_nbd).contains("nbd.socket"));
    let respelled = format!(
        "{}[control]\nsocket = \"/run/maki/t//nbd.sock\"\n[nbd]\nsocket = \"/run/maki/t/./nbd.sock\"\n",
        local()
    );
    assert!(err(&respelled).contains("nbd.socket"));
    parse(&format!(
        "{}[control]\nsocket = \"/run/maki-control/t/control.sock\"\n[nbd]\nsocket = \"/run/maki/t/nbd.sock\"\n",
        local()
    ))
    .validate()
    .unwrap();
    parse(&local()).validate().unwrap();
}

#[cfg(unix)]
#[test]
fn socket_aliases_use_the_actual_parent_directory_before_binding() {
    let dir = short_dir::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("other/sub")).unwrap();
    std::os::unix::fs::symlink(root.join("other/sub"), root.join("link")).unwrap();
    let check = |control: &str, nbd: &str| {
        let raw = format!(
            "{}[control]\nsocket = {:?}\n[nbd]\nsocket = {:?}\n",
            local(),
            root.join(control),
            root.join(nbd)
        );
        parse(&raw).validate()
    };
    // systemd creates per-volume runtime directories on first start. An
    // alias of an existing ancestor already identifies the same future file.
    let check_runtime_paths = || {
        assert!(check("link/new/volume/a.sock", "other/sub/new/volume/a.sock").is_err());
        assert!(check("link/new/volume/a.sock", "other/sub/new/volume/b.sock").is_ok());
    };
    check_runtime_paths();
    std::fs::create_dir_all(root.join("other/sub/new/volume")).unwrap();
    check_runtime_paths();
    assert!(check("other/sub/../shared.sock", "other/shared.sock").is_err());
    assert!(check("link/../shared.sock", "other/shared.sock").is_err());
    assert!(check("link/../shared.sock", "shared.sock").is_ok());
    assert!(check("link/a.sock", "other/sub/b.sock").is_ok());
}

// ---------- transport limits carry ciphertext (BUG-092) ----------

/// The default 128-item batch of 4096-byte units is 512 KiB of plaintext but
/// 128 x 4384 = 561,152 bytes of ciphertext, and the ciphertext is what an
/// encrypt response and a decrypt request carry. A limit sized for the
/// plaintext validated cleanly and then refused every full batch at runtime.
fn remote_batch(provider: &str, section: &str) -> String {
    let endpoint = if provider == "remote-websocket" {
        "[[crypto.websocket.endpoint]]\nname = \"a\"\nurl = \"ws://127.0.0.1:7000\""
    } else {
        "[[crypto.grpc.endpoint]]\nname = \"a\"\nurl = \"http://localhost:7000\""
    };
    format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[crypto.batch]
max_bytes = "512KiB"
{section}
{endpoint}
[backing]
root = "/x"
"#
    )
}

#[test]
fn remote_transport_limits_carry_a_full_ciphertext_batch() {
    // 520 KiB holds the plaintext batch, not the ciphertext. Even exactly
    // 548 KiB only holds ciphertext and leaves no room for protobuf fields.
    let grpc = |limit: &str| {
        remote_batch(
            "remote-grpc",
            &format!("[crypto.grpc]\nmax_message_bytes = \"{limit}\""),
        )
    };
    assert!(err(&grpc("520KiB")).contains("max_message_bytes"));
    assert!(err(&grpc("548KiB")).contains("max_message_bytes"));
    ok(&grpc("552KiB"));

    // 731 KiB only holds the separately padded base64 ciphertext items;
    // the JSON fields and envelope need additional frame capacity.
    let ws = |limit: &str| {
        remote_batch(
            "remote-websocket",
            &format!("[crypto.websocket]\nmax_frame_bytes = \"{limit}\""),
        )
    };
    assert!(err(&ws("700KiB")).contains("max_frame_bytes"));
    assert!(err(&ws("731KiB")).contains("max_frame_bytes"));
    ok(&ws("740KiB"));
}

/// A batched HTTP mapping receives the whole batch in one response body:
/// the limit must hold both encoded ciphertext and the declared JSON shape.
#[test]
fn batched_http_response_limit_carries_a_full_ciphertext_batch() {
    let http = |limit: &str| {
        let mut ops = String::new();
        for op in ["encrypt", "decrypt"] {
            ops += &format!(
                r#"[crypto.http.{op}]
path = "/{op}"
[crypto.http.{op}.body]
items_path = "/items"
[crypto.http.{op}.body.item_fields]
"/data" = {{ source = "payload", encoding = "base64" }}
"/unit" = {{ source = "unit_index" }}
[crypto.http.{op}.response]
items_path = "/items"
item_index_path = "/unit"
data_path = "/data"
encoding = "base64"
"#
            );
        }
        format!(
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
[crypto.batch]
max_bytes = "512KiB"
[crypto.http]
max_response_bytes = "{limit}"
[[crypto.http.endpoint]]
name = "a"
url = "https://crypto.internal"
{ops}[backing]
root = "/x"
"#
        )
    };
    assert!(err(&http("700KiB")).contains("max_response_bytes"));
    assert!(err(&http("731KiB")).contains("max_response_bytes"));
    ok(&http("740KiB"));
    // The reviewed 800 KiB cap fits base64, but not hex ciphertext alone.
    let hex = http("800KiB").replace("encoding = \"base64\"", "encoding = \"hex\"");
    assert!(err(&hex).contains("max_response_bytes"));
}

/// HTTP refuses a zero timeout; WebSocket and gRPC accepted `"0s"`, which
/// makes every connect or RPC expire at once and reports each endpoint as
/// unreachable at attach.
#[test]
fn websocket_and_grpc_timeouts_must_be_positive() {
    for (provider, section) in [
        ("remote-websocket", "[crypto.websocket]"),
        ("remote-grpc", "[crypto.grpc]"),
    ] {
        let zero = remote_batch(provider, &format!("{section}\ntimeout = \"0s\""));
        let e = err(&zero);
        assert!(
            e.contains("timeout") && e.contains(section),
            "{provider}: {e}"
        );
        ok(&remote_batch(
            provider,
            &format!("{section}\ntimeout = \"1s\""),
        ));
    }
}

#[test]
fn unix_socket_paths_must_end_in_a_filename() {
    for section in ["nbd", "control"] {
        for (path, valid) in [
            ("/run/demo.sock", true),
            ("/run/./demo.sock", true),
            ("/", false),
            ("/run/demo.sock/", false),
            ("/run/demo.sock/.", false),
            ("/run/demo.sock/..", false),
        ] {
            let cfg = parse(&format!("{}[{section}]\nsocket = {path:?}\n", local()));
            assert_eq!(cfg.validate().is_ok(), valid, "{section}: {path}");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn unix_socket_path_lengths_are_checked_in_bytes() {
    for section in ["nbd", "control"] {
        for (suffix, valid) in [("", true), ("x", false)] {
            let path = format!("/{}{suffix}", "é".repeat(53));
            let cfg = parse(&format!("{}[{section}]\nsocket = {path:?}\n", local()));
            assert_eq!(cfg.validate().is_ok(), valid, "{section}: {path}");
        }
    }
}

#[test]
fn filesystem_paths_and_control_group_must_be_representable_by_the_os() {
    let mut config = parse(&local());
    config.backing.root = "/var/lib/ma\0ki".into();
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("backing.root"));
    config.backing.root = "/var/lib/maki".into();
    config.control.group = Some("maki\0group".into());
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("control.group"));
    config.control.group = Some("maki-admin".into());
    config.validate().unwrap();
}

#[test]
fn socket_filenames_cannot_be_backing_objects_or_socket_parent_directories() {
    let mut config = parse(&local());
    config.backing.root = "/runtime-checks/volume".into();
    for conflicting in [
        "/runtime-checks",
        "/runtime-checks/volume",
        "/runtime-checks/volume/superblock.a",
        "/runtime-checks/volume/volume.lock/child",
        "/runtime-checks/volume/data",
        "/runtime-checks/volume/checkpoint/state.a",
        "/runtime-checks/volume/data/shard-0000002a.alloc.b",
        "/runtime-checks/volume/journal/seg-0000000000000001/nested",
    ] {
        config.control.socket = Some(conflicting.into());
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control.socket"));
        config.control.socket = None;
        config.nbd.socket = Some(conflicting.into());
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("nbd.socket"));
        config.nbd.socket = None;
    }
    config.control.socket = Some("/runtime-checks/volume/data/custom.sock".into());
    config.nbd.socket = Some("/runtime-checks/volume-old/socket".into());
    config.validate().unwrap();
    for (parent, child) in [
        ("/run/example.sock", "/run/example.sock/nested"),
        ("/run/example.sock/nested", "/run/example.sock"),
    ] {
        config.control.socket = Some(parent.into());
        config.nbd.socket = Some(child.into());
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("nbd.socket"));
    }
}

#[test]
fn rollback_sockets_are_compared_to_the_physical_layout() {
    let source = format!("{}[backing.rollback_protection]\nwitness_root = \"/other-witness\"\ncapacity = \"64MiB\"\n", local());
    let mut config = parse(&source);
    config.backing.checkpoint_reserve_bytes.0 = 64 << 10;
    config.backing.journal_emergency_reserve_bytes.0 = 64 << 10;
    config.backing.root = "/runtime-checks/volume".into();
    config.validate().unwrap();
    for file in [
        "rollback.format",
        "rollback.arena",
        "rollback.manifest.0",
        "rollback.manifest.1",
        "rollback.lock",
    ] {
        config.control.socket = Some(format!("/runtime-checks/volume/{file}"));
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control.socket"));
    }
    config.control.socket = Some("/runtime-checks/volume/data/custom.sock".into());
    config.validate().unwrap();
}

#[test]
fn local_witness_directory_and_anchor_files_cannot_be_socket_paths() {
    let mut config = parse(&format!("{}[backing.rollback_protection]\nwitness_root = \"/witness-store/volume\"\ncapacity = \"64MiB\"\n", local()));
    config.backing.checkpoint_reserve_bytes.0 = 64 << 10;
    config.backing.journal_emergency_reserve_bytes.0 = 64 << 10;
    for path in [
        "/witness-store",
        "/witness-store/volume",
        "/witness-store/volume/anchor",
        "/witness-store/volume/anchor.next",
        "/witness-store/volume/witness.lock/child.sock",
    ] {
        config.control.socket = Some(path.into());
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control.socket"));
        config.control.socket = None;
        config.nbd.socket = Some(path.into());
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("nbd.socket"));
        config.nbd.socket = None;
    }
    config.control.socket = Some("/witness-store/volume/anchor.sock".into());
    config.nbd.socket = Some("/witness-store/volume-old/anchor".into());
    config.validate().unwrap();
}

#[test]
fn local_file_keys_require_a_filename_independent_of_the_runtime_layout() {
    for provider in ["local-aes-gcm-siv", "local-aes-xts"] {
        let raw = local().replace("local-aes-gcm-siv", provider);
        let mut config = parse(&raw);
        config.backing.root = "/runtime-checks/volume".into();
        config.control.socket = Some("/runtime-checks/control.sock".into());
        config.nbd.socket = Some("/runtime-checks/nbd.sock".into());
        config.crypto.key.as_mut().unwrap().source = "file".into();
        for path in [
            "/runtime-checks",
            "/runtime-checks/volume",
            "/runtime-checks/volume/superblock.a",
            "/runtime-checks/volume/superblock.a/key",
            "/runtime-checks/volume/checkpoint/state.a",
            "/runtime-checks/volume/data/shard-0000002a.alloc.b",
            "/runtime-checks/control.sock/key",
            "/runtime-checks/nbd.sock",
        ] {
            config.crypto.key.as_mut().unwrap().name = path.into();
            let error = config.validate().expect_err(path).to_string();
            assert!(
                error.contains("crypto.key") && !error.contains(path),
                "{error}"
            );
        }
        for path in [
            "/runtime-checks/volume/data/custom.key",
            "/runtime-checks/volume-old/key",
        ] {
            config.crypto.key.as_mut().unwrap().name = path.into();
            config.validate().unwrap();
        }
    }
}

#[test]
fn rollback_file_keys_use_the_physical_backing_and_witness_layouts() {
    let mut config = parse(&format!("{}[backing.rollback_protection]\nwitness_root = \"/runtime-witness/volume\"\ncapacity = \"64MiB\"\n", local()));
    config.backing.checkpoint_reserve_bytes.0 = 64 << 10;
    config.backing.journal_emergency_reserve_bytes.0 = 64 << 10;
    config.crypto.key.as_mut().unwrap().source = "file".into();
    for path in [
        "/x/rollback.arena",
        "/runtime-witness",
        "/runtime-witness/volume/anchor.next/key",
    ] {
        config.crypto.key.as_mut().unwrap().name = path.into();
        assert!(config
            .validate()
            .expect_err(path)
            .to_string()
            .contains("crypto.key"));
    }
    for path in ["/x/superblock.a", "/runtime-witness/volume/anchor.key"] {
        config.crypto.key.as_mut().unwrap().name = path.into();
        config.validate().unwrap();
    }
}
