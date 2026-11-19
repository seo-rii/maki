//! End-to-end test of `maki-benchmark` as a real process: full daemon
//! assembly (config → FileBacking → AES-GCM-SIV keyed from the environment →
//! engine), real I/O, and — on the second run — attach over the state the
//! first process left behind (journal replay through the shipped binary).

use std::process::{Command, Output};

const KEY_HEX: &str = "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677";

fn run_with(config_path: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
        .args(extra)
        .args([config_path, "64", "4096"])
        .env("MAKI_CREDENTIAL_E2E_BENCH_KEY", KEY_HEX)
        .output()
        .expect("spawn maki-benchmark")
}

fn run(config_path: &str) -> Output {
    run_with(config_path, &[])
}

#[test]
fn benchmark_creates_volume_runs_io_and_reattaches() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    let config_path = dir
        .path()
        .join("volume.toml")
        .to_string_lossy()
        .into_owned();
    std::fs::write(
        &config_path,
        format!(
            r#"
config_schema_version = 1
[volume]
name = "benchvol"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "e2e-bench-key" }}
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

    // Refusing unavailable local credentials must leave a first run retryable.
    let failed = Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
        .args([&config_path, "1", "4096"])
        .env_remove("MAKI_CREDENTIAL_E2E_BENCH_KEY")
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1));
    assert!(!std::path::Path::new(&root).exists());

    // First run creates the volume and pushes 64 writes + flush + 64 reads.
    let out = run(&config_path);
    assert!(
        out.status.success(),
        "first run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(text.contains("write:"), "{text}");
    assert!(text.contains("read:"), "{text}");

    // R5-017: the benchmark overwrites the start of the volume, so a volume
    // it did not create in this run is refused without `--destroy-data`.
    let shards = || {
        let mut shards: Vec<(String, Vec<u8>)> = std::fs::read_dir(format!("{root}/data"))
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
            .collect();
        shards.sort();
        shards
    };
    let journal_before = std::fs::read_dir(format!("{root}/journal"))
        .unwrap()
        .count();
    let data_before = shards();
    let out = run(&config_path);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--destroy-data"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(shards(), data_before, "a refused run changed the volume");
    assert_eq!(
        std::fs::read_dir(format!("{root}/journal"))
            .unwrap()
            .count(),
        journal_before
    );

    // The process exited without a checkpoint, so the second run must
    // recover the journal it left behind and serve I/O again.
    let out = run_with(&config_path, &["--destroy-data"]);
    assert!(
        out.status.success(),
        "re-attach over existing state failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn invalid_remote_tls_leaves_new_volume_retryable() {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, "no certificate here\n").unwrap();
    let ca = ca.to_string_lossy().replace('\\', "/");
    let file = dir.path().join("volume.toml");
    for (transport, url, fields) in [
        (
            "http",
            "https://127.0.0.1:9",
            "[crypto.http.encrypt]\npath = \"/encrypt\"\n[crypto.http.decrypt]\npath = \"/decrypt\"",
        ),
        ("websocket", "wss://127.0.0.1:9", ""),
        ("grpc", "https://127.0.0.1:9", ""),
    ] {
        let root = dir.path().join(transport);
        let path = root.to_string_lossy().replace('\\', "/");
        let config = format!(r#"
config_schema_version = 1
[volume]
name = "benchvol"
max_virtual_size = "1MiB"
[crypto]
provider = "remote-{transport}"
crypto_compatibility_id = "bench-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[[crypto.{transport}.endpoint]]
name = "test"
url = "{url}"
[crypto.{transport}.tls]
ca_file = "{ca}"
{fields}
[backing]
root = "{path}"
"#);
        std::fs::write(&file, config).unwrap();
        for _ in 0..2 {
            let out = run(file.to_str().unwrap());
            let message = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(1), "{transport}: {message}");
            assert!(message.to_lowercase().contains("certificate"), "{transport}: {message}");
            assert!(!root.exists(), "{transport} published a volume before loading its CA");
        }
    }
}
