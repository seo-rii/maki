use std::process::{Command, Output};
fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("volume.toml");
    std::fs::write(
        &config,
        format!(
            r#"
config_schema_version = 1
[volume]
name = "concurrent-benchmark"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "benchmark-v1"
key = {{ source = "env", name = "concurrent-benchmark-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "read"
max_bytes = "16KiB"
ttl = "30s"
"#,
            directory
                .path()
                .join("volume")
                .to_string_lossy()
                .replace('\\', "/")
        ),
    )
    .unwrap();
    (directory, config)
}
fn run(config: &std::path::Path, flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
        .args(flags)
        .arg(config)
        .args(["32", "4096"])
        .env("MAKI_CREDENTIAL_CONCURRENT_BENCHMARK_KEY", "25".repeat(32))
        .output()
        .unwrap()
}

#[test]
fn real_concurrency_random_mixed_fua_and_periodic_flush_are_verified_and_reported() {
    for concurrency in [1, 2, 8, 32] {
        let (_directory, config) = fixture();
        let value = concurrency.to_string();
        let output = run(
            &config,
            &[
                "--json",
                "--fua",
                "--concurrency",
                &value,
                "--access",
                "random",
                "--read-percent",
                "25",
                "--working-set",
                "64KiB",
                "--flush-every",
                "9",
                "--seed",
                "12",
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["concurrency"], concurrency);
        assert_eq!(report["operations"], 32);
        assert_eq!(report["read_verified"], true);
        assert_eq!(report["write"]["latency"]["samples"], 24);
        assert_eq!(report["read"]["latency"]["samples"], 8);
        assert_eq!(report["flush"]["latency"]["samples"], 4);
        assert_eq!(report["workload"]["access"], "random");
        assert_eq!(report["workload"]["mode"], "mixed");
        assert_eq!(report["workload"]["working_set_bytes"], 65536);
        assert_eq!(report["setup"]["writes"], 16);
        assert_eq!(report["setup"]["flushes"], 1);
        let pending = report["resources"]["peak_pending_operations"]
            .as_u64()
            .unwrap();
        assert!(pending > 0 && pending <= concurrency);
        assert_eq!(report["resources"]["pending_operations_at_exit"], 0);
        assert_eq!(report["resources"]["oracle_generation_bytes"], 16 * 8);
        #[cfg(target_os = "linux")]
        assert!(
            report["resources"]["process_peak_rss_bytes"]
                .as_u64()
                .unwrap()
                > 0
        );
        #[cfg(not(target_os = "linux"))]
        assert!(report["resources"]["process_peak_rss_bytes"].is_null());
        for operation in ["read", "write", "flush"] {
            let latency = &report[operation]["latency"];
            assert!(
                latency["p95_upper_us"].as_f64().unwrap()
                    <= latency["p99_upper_us"].as_f64().unwrap()
            );
        }
    }
}

#[test]
fn oracle_budget_is_rejected_before_backing_creation() {
    let (directory, config) = fixture();
    let raw = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        raw.replace(
            "max_virtual_size = \"1MiB\"",
            "max_virtual_size = \"64GiB\"",
        ),
    )
    .unwrap();
    let output = run(&config, &["--working-set", "34359742464"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("generation-oracle budget"));
    assert!(!directory.path().join("volume").exists());
}

#[test]
fn sequential_concurrent_phases_keep_default_counts_and_verify_wrapped_addresses() {
    let (_directory, config) = fixture();
    let output = run(
        &config,
        &[
            "--json",
            "--concurrency",
            "8",
            "--working-set",
            "16KiB",
            "--flush-every",
            "10",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["write"]["latency"]["samples"], 32);
    assert_eq!(report["read"]["latency"]["samples"], 32);
    assert_eq!(report["flush"]["latency"]["samples"], 4);
    assert_eq!(report["setup"]["writes"], 0);
    assert_eq!(report["workload"]["mode"], "phased");
}

#[test]
fn invalid_workload_controls_are_rejected_before_backing_changes() {
    let (directory, config) = fixture();
    for flags in [
        vec!["--concurrency", "0"],
        vec!["--concurrency", "257"],
        vec!["--concurrency"],
        vec!["--read-percent", "101"],
        vec!["--read-percent", "-1"],
        vec!["--access", "typo"],
        vec!["--working-set", "2MiB"],
        vec!["--working-set", "0B"],
        vec!["--working-set", "513B"],
        vec!["--flush-every", "0"],
        vec!["--seed", "nope"],
        vec!["--concurrency", "2", "--concurrency", "4"],
    ] {
        let output = run(&config, &flags);
        assert_eq!(output.status.code(), Some(2), "{flags:?}");
        assert!(output.stdout.is_empty());
        assert!(!directory.path().join("volume").exists());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
        .arg(&config)
        .args(["1000000001", "4096"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!directory.path().join("volume").exists());
}

#[test]
fn entirely_read_or_write_mixed_workloads_have_finite_empty_operation_reports() {
    for percent in ["0", "100"] {
        let (_directory, config) = fixture();
        let output = run(
            &config,
            &["--json", "--concurrency", "8", "--read-percent", percent],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let empty = if percent == "0" { "read" } else { "write" };
        assert_eq!(report[empty]["latency"]["samples"], 0);
        assert_eq!(report[empty]["latency"]["p99_upper_us"], 0.0);
        assert_eq!(report[empty]["iops"], 0.0);
        assert_eq!(report["read_verified"], percent != "0");
    }
}
