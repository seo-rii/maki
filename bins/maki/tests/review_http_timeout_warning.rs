//! `maki volume create` and `maki check` warn about an HTTP provider
//! `timeout` under 600 ms.
//!
//! The HTTP transport starts the other address family of an endpoint's host
//! 300 ms after the first, or at once when the first family has failed,
//! which reqwest does not let the provider change (docs/configuration.md,
//! remote HTTP mapping): while the first family does not answer, the other
//! gets less than half of a `timeout` under 600 ms and is never tried at
//! 300 ms or less. Such a configuration is still valid: creation succeeds and both
//! checks pass, with a `warning:` line that names the value. A `timeout` of
//! 600 ms or more, or none (10 s), gets no warning.

#[path = "support/volume_config.rs"]
mod volume_config;

use std::path::Path;
use std::process::{Command, Output};

fn config(root: &Path, timeout: &str) -> String {
    let timeout = match timeout {
        "" => String::new(),
        value => format!("timeout = \"{value}\"\n"),
    };
    format!(
        "config_schema_version = 1\n\
         [volume]\n\
         name = \"http-timeout\"\n\
         max_virtual_size = \"1MiB\"\n\
         device_block_size = 512\n\
         crypto_unit_size = 4096\n\
         shard_logical_size = \"64KiB\"\n\
         [crypto]\n\
         provider = \"remote-http\"\n\
         crypto_compatibility_id = \"remote-v1\"\n\
         [crypto.capabilities]\n\
         supported_plaintext_sizes = [4096]\n\
         max_ciphertext_size = 4384\n\
         [crypto.http]\n\
         {timeout}\
         [[crypto.http.endpoint]]\n\
         name = \"only\"\n\
         url = \"http://127.0.0.1:9\"\n\
         [crypto.http.encrypt]\n\
         path = \"/encrypt\"\n\
         [crypto.http.decrypt]\n\
         path = \"/decrypt\"\n\
         [backing]\n\
         root = {}\n",
        serde_json::to_string(root.to_str().unwrap()).unwrap()
    )
}

fn maki(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .output()
        .expect("spawn maki")
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The warning line for an HTTP `timeout` printed as `value`.
fn warning(value: &str) -> String {
    format!(
        "warning: [crypto.http] timeout is {value}: while the first address family of an \
         endpoint's host does not answer, the other family gets less than half of a timeout \
         under 600 ms and is never tried at 300 ms or less, so such a host can fail every \
         connect"
    )
}

/// The lines of `bytes` that warn about the HTTP `timeout`.
fn timeout_warnings(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|line| line.contains("[crypto.http] timeout"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn create_and_check_warn_about_an_http_timeout_under_600_ms() {
    for (timeout, expected) in [
        ("300ms", vec![warning("300ms")]),
        ("450ms", vec![warning("450ms")]),
        ("600ms", vec![]),
        ("", vec![]),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("volume.toml");
        volume_config::write(&path, config(&directory.path().join("volume"), timeout)).unwrap();
        let path = path.to_str().unwrap();

        let created = maki(&["volume", "create", path]);
        assert!(
            created.status.success(),
            "{timeout:?}: create: {}",
            text(&created)
        );
        assert_eq!(
            timeout_warnings(&created.stderr),
            expected,
            "{timeout:?}: create: {}",
            text(&created)
        );
        for check in [maki(&["check", path]), maki(&["check", path, "--deep"])] {
            let report = text(&check);
            assert_eq!(check.status.code(), Some(0), "{timeout:?}: {report}");
            assert!(report.contains("check passed"), "{timeout:?}: {report}");
            assert_eq!(
                timeout_warnings(&check.stdout),
                expected,
                "{timeout:?}: {report}"
            );
        }
    }
}
