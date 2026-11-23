//! `MAKI_LOG` set to a word that is not a level (`warning`, `err`, a typo)
//! silenced every log event of the CLI, WARN and ERROR included, although
//! unset or invalid values are documented to mean `info`: EnvFilter read the
//! word as a target enabled at trace and turned every other target off. An
//! empty value enabled nothing at all.

#[path = "support/volume_config.rs"]
mod volume_config;

use std::process::{Command, Output};

const VOLUME: &str = r#"
config_schema_version = 1
[volume]
name = "logvol"
max_virtual_size = "8MiB"
shard_logical_size = "1MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = { source = "env", name = "log-filter-key" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
"#;

const REFUSED: &str = "MAKI_LOG is not a valid filter";

fn check(config: &str, filter: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki"));
    command.args(["check", config, "--deep"]);
    match filter {
        Some(value) => command.env("MAKI_LOG", value),
        None => command.env_remove("MAKI_LOG"),
    };
    command.output().unwrap()
}

/// The store's WARN about the orphan shard data file it adopts at open.
fn adoption_warnings(out: &Output) -> usize {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|line| line.contains("WARN") && line.contains("adopting"))
        .count()
}

#[test]
fn a_maki_log_value_that_is_not_a_level_keeps_warnings_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol");
    let config_path = dir.path().join("volume.toml");
    volume_config::write(
        &config_path,
        format!("{VOLUME}[backing]\nroot = {:?}\n", root.to_string_lossy()),
    )
    .unwrap();
    let config = config_path.to_str().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(["volume", "create", config])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    // An orphan shard data file makes the store log a WARN at open.
    std::fs::write(root.join("data/shard-00000000.dat"), b"").unwrap();

    for filter in [None, Some("warn"), Some("WARN"), Some("2")] {
        let out = check(config, filter);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(adoption_warnings(&out), 1, "MAKI_LOG={filter:?}:\n{stderr}");
        assert!(!stderr.contains(REFUSED), "MAKI_LOG={filter:?}:\n{stderr}");
    }
    let out = check(config, Some("error"));
    assert_eq!(
        adoption_warnings(&out),
        0,
        "a valid threshold still applies"
    );

    for filter in ["warning", "err", "notice", "wran", "warn ", "maki_core"] {
        let out = check(config, Some(filter));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            adoption_warnings(&out),
            1,
            "MAKI_LOG={filter:?} must fall back to info:\n{stderr}"
        );
        assert_eq!(
            stderr.matches(REFUSED).count(),
            1,
            "MAKI_LOG={filter:?} must be reported once:\n{stderr}"
        );
    }
    for filter in ["", ","] {
        let out = check(config, Some(filter));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            adoption_warnings(&out),
            1,
            "MAKI_LOG={filter:?} must mean info:\n{stderr}"
        );
        assert!(!stderr.contains(REFUSED), "MAKI_LOG={filter:?}:\n{stderr}");
    }
}
