//! End-to-end test of `maki-benchmark` as a real process: full daemon
//! assembly (config → FileBacking → AES-GCM-SIV keyed from the environment →
//! engine), real I/O, and — on the second run — attach over the state the
//! first process left behind (journal replay through the shipped binary).

use std::process::{Command, Output};

const KEY_HEX: &str = "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677";

fn run(config_path: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
        .args([config_path, "64", "4096"])
        .env("MAKI_CREDENTIAL_E2E_BENCH_KEY", KEY_HEX)
        .output()
        .expect("spawn maki-benchmark")
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
"#
        ),
    )
    .unwrap();

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

    // The process exited without a checkpoint, so the second run must
    // recover the journal it left behind and serve I/O again.
    let out = run(&config_path);
    assert!(
        out.status.success(),
        "re-attach over existing state failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
