//! A machine-readable performance run must describe its workload, verify reads,
//! and reject invalid requests before creating or touching a volume.

use std::process::{Command, Output};

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    let config = dir.path().join("volume.toml");
    std::fs::write(
        &config,
        format!(
            r#"
config_schema_version = 1
[volume]
name = "benchreport"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "benchmark-report-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
"#
        ),
    )
    .unwrap();
    (dir, config)
}

fn run(config: &std::path::Path, options: &[&str], workload: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
        .args(options)
        .arg(config)
        .args(workload)
        .env("MAKI_CREDENTIAL_BENCHMARK_REPORT_KEY", "17".repeat(32))
        .output()
        .unwrap()
}

#[test]
fn json_report_records_latency_durability_and_verified_workload() {
    let (_dir, config) = fixture();
    // More operations than slots also exercises the wrapped working set.
    let output = run(&config, &["--json", "--fua"], &["260", "4096"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["operations"], 260);
    assert_eq!(report["io_size_bytes"], 4096);
    assert_eq!(report["concurrency"], 1);
    assert_eq!(report["fua"], true);
    assert_eq!(report["read_verified"], true);
    assert_eq!(report["provider"], "local-aes-gcm-siv");
    assert!(report["flush_us"].as_f64().unwrap() >= 0.0);
    for operation in ["write", "read"] {
        let stats = &report[operation];
        assert_eq!(stats["latency"]["samples"], 260);
        assert!(stats["mib_per_second"].as_f64().unwrap() > 0.0);
        assert!(stats["iops"].as_f64().unwrap() > 0.0);
        let latency = &stats["latency"];
        let p50 = latency["p50_upper_us"].as_f64().unwrap();
        let p95 = latency["p95_upper_us"].as_f64().unwrap();
        let p99 = latency["p99_upper_us"].as_f64().unwrap();
        let maximum = latency["max_us"].as_f64().unwrap();
        assert!(0.0 <= p50 && p50 <= p95 && p95 <= p99 && p99 <= maximum);
    }
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("benchmark-report-key"));
    assert!(!text.contains(config.to_str().unwrap()));
}

#[test]
fn invalid_workloads_never_create_a_volume() {
    let (dir, config) = fixture();
    for workload in [
        vec!["0", "4096"],
        vec!["nope", "4096"],
        vec!["18446744073709551616", "4096"],
        vec!["1", "0"],
        vec!["1", "513"],
        vec!["1", "2097152"],
        vec!["1", "4096", "extra"],
    ] {
        let output = run(&config, &[], &workload);
        assert_eq!(output.status.code(), Some(2), "{workload:?}");
        assert!(output.stdout.is_empty(), "invalid run reported success");
        assert!(!dir.path().join("vol").exists(), "{workload:?}");
    }
    let output = run(&config, &["--unknown"], &["1", "4096"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!dir.path().join("vol").exists());
}

#[test]
fn existing_volume_geometry_still_bounds_a_changed_config() {
    let (dir, config) = fixture();
    let output = run(&config, &[], &["1", "4096"]);
    assert!(output.status.success());
    let superblock = dir.path().join("vol/superblock.a");
    let original = std::fs::read(&superblock).unwrap();
    let raw = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        raw.replace("max_virtual_size = \"1MiB\"", "max_virtual_size = \"4MiB\"")
            + "\n[nbd]\nmaximum_io = \"2MiB\"\n",
    )
    .unwrap();
    let output = run(&config, &["--destroy-data"], &["1", "2097152"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read(&superblock).unwrap(), original);
}
