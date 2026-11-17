//! Audit round 3 (cli-ops): docs/operations.md "Logging" says `MAKI_LOG`
//! "unset or invalid values mean `info`". A misspelt level such as
//! `warning` or `err` is not rejected by `EnvFilter`: it parses as a bare
//! *target* directive, so every other target (all of Maki) is filtered out,
//! WARN and ERROR included.

use std::process::Command;

fn config(root: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "logvol"
max_virtual_size = "8MiB"
shard_logical_size = "1MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "audit3-log-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{root}"
"#
    )
}

fn warnings(cfg: &str, filter: Option<&str>) -> usize {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki"));
    command.args(["check", cfg, "--deep"]);
    match filter {
        Some(value) => command.env("MAKI_LOG", value),
        None => command.env_remove("MAKI_LOG"),
    };
    let out = command.output().unwrap();
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|line| line.contains("WARN") && line.contains("adopting"))
        .count()
}

#[test]
fn misspelt_level_must_not_silence_warnings() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let cfg_path = dir.path().join("v.toml");
    std::fs::write(&cfg_path, config(&root)).unwrap();
    let cfg = cfg_path.to_str().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(["volume", "create", cfg])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    // An orphan shard data file makes the store log a WARN at open.
    std::fs::write(dir.path().join("vol/data/shard-00000000.dat"), b"").unwrap();

    assert_eq!(
        warnings(cfg, None),
        1,
        "control: default threshold shows the WARN"
    );
    assert_eq!(warnings(cfg, Some("warn")), 1, "control: a valid level");
    let mut silenced = Vec::new();
    for value in ["warning", "err", "notice", "wran"] {
        if warnings(cfg, Some(value)) == 0 {
            silenced.push(value);
        }
    }
    assert!(
        silenced.is_empty(),
        "MAKI_LOG values that are not valid levels silenced every WARN/ERROR \
         instead of falling back to info: {silenced:?}"
    );
}
