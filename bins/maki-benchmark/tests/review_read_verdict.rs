//! BUG-052: successful write-only runs must not claim successful read checks.
use std::process::Command;

fn run(ops: &str, percent: Option<&str>, json: bool) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("volume.toml");
    std::fs::write(
        &config,
        format!(
            r#"
config_schema_version = 1
[volume]
name = "read-verdict"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "benchmark-v1"
key = {{ source = "env", name = "read-verdict-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = {:?}
journal_emergency_reserve_bytes = "0B"
"#,
            dir.path().join("volume").to_string_lossy()
        ),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki-benchmark"));
    if json {
        command.arg("--json");
    }
    if let Some(percent) = percent {
        command.args(["--read-percent", percent]);
    }
    let output = command
        .arg(config)
        .args([ops, "4096"])
        .env("MAKI_CREDENTIAL_READ_VERDICT_KEY", "25".repeat(32))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn zero_percent_and_short_mixed_runs_report_skipped_verification() {
    for (ops, percent) in [("10", "0"), ("3", "20")] {
        let output = run(ops, Some(percent), true);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["read"]["latency"]["samples"], 0);
        assert_eq!(report["read_verified"], false, "{report}");
        assert_eq!(report["read_verification"], "skipped");
        assert_eq!(report["verified_read_operations"], 0);
    }
}

#[test]
fn actual_reads_report_passed_and_the_verified_sample_count() {
    for percent in [None, Some("20"), Some("100")] {
        let output = run("10", percent, true);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let expected = if percent == Some("20") { 2 } else { 10 };
        assert_eq!(report["read"]["latency"]["samples"], expected);
        assert_eq!(report["read_verified"], true);
        assert_eq!(report["read_verification"], "passed");
        assert_eq!(report["verified_read_operations"], expected);
    }
}

#[test]
fn text_report_does_not_claim_passed_when_there_were_no_reads() {
    let output = run("3", Some("20"), false);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("read verification: skipped: no read operations"),
        "{text}"
    );
    assert!(!text.contains("read verification: passed"), "{text}");
}
