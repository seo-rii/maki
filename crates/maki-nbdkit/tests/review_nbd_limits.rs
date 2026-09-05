//! BUG-011 / O-03: enforce the sizes promised to clients before touching
//! engine state, and exercise the actual sizing callback through nbdkit.

use maki_format::config::{parse_config, ByteSize};
use maki_nbdkit::adapter::{NbdAdapter, EINVAL};

fn config(root: &str, socket: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "nbdlimits"
max_virtual_size = "2MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = "{root}"
[nbd]
minimum_io = 4096
preferred_io = 4096
maximum_io = "8KiB"
threads = 2
[control]
socket = "{socket}"
"#
    )
}

struct Fixture {
    directory: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("volume");
        let socket = directory.path().join("control.sock");
        let raw = config(
            &root.to_string_lossy().replace('\\', "/"),
            &socket.to_string_lossy().replace('\\', "/"),
        );
        let path = directory.path().join("volume.toml");
        std::fs::write(&path, &raw).unwrap();
        maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        Self { directory, path }
    }

    fn open(&self) -> NbdAdapter {
        assert!(self.directory.path().exists());
        NbdAdapter::open_config(self.path.to_str().unwrap()).unwrap()
    }
}

#[test]
fn oversized_reads_are_refused_without_changing_the_callers_buffer() {
    let fixture = Fixture::new();
    let adapter = fixture.open();
    let mut data = vec![0xAB; 12 * 1024];
    let error = adapter.pread(&mut data, 0).expect_err("over maximum_io");
    assert_eq!(error.errno, EINVAL);
    assert!(data.iter().all(|byte| *byte == 0xAB));
    adapter.shutdown().unwrap();
}

#[test]
fn oversized_writes_are_refused_without_changing_volume_data() {
    let fixture = Fixture::new();
    let adapter = fixture.open();
    let error = adapter
        .pwrite(&vec![0xCD; 12 * 1024], 0, true)
        .expect_err("over maximum_io");
    assert_eq!(error.errno, EINVAL);
    let mut data = vec![0xFF; 8192];
    adapter.pread(&mut data, 0).unwrap();
    assert!(data.iter().all(|byte| *byte == 0));
    adapter.shutdown().unwrap();
}

#[test]
fn advertised_minimum_applies_to_both_request_offset_and_length() {
    let fixture = Fixture::new();
    let adapter = fixture.open();
    for (offset, length) in [(512, 4096), (0, 512)] {
        let error = adapter
            .pwrite(&vec![0xCE; length], offset, false)
            .expect_err("device-block aligned but below the advertised minimum");
        assert_eq!(error.errno, EINVAL);
        let mut data = vec![0xAF; length];
        let error = adapter.pread(&mut data, offset).unwrap_err();
        assert_eq!(error.errno, EINVAL);
        assert!(data.iter().all(|byte| *byte == 0xAF));
    }
    adapter.shutdown().unwrap();
}

#[test]
fn aligned_maximum_request_roundtrips_and_survives_reopen() {
    let fixture = Fixture::new();
    let adapter = fixture.open();
    assert_eq!(adapter.block_sizes(), (4096, 4096, 8192));
    let expected = vec![0xD1; 8192];
    adapter.pwrite(&expected, 4096, true).unwrap();
    adapter.shutdown().unwrap();
    drop(adapter);
    let reopened = fixture.open();
    let mut data = vec![0; 8192];
    reopened.pread(&mut data, 4096).unwrap();
    assert_eq!(data, expected);
    reopened.shutdown().unwrap();
}

#[test]
fn configuration_rejects_sizes_that_cannot_be_advertised_over_nbd() {
    let mut config = parse_config(&config("/tmp/unused-volume", "/tmp/unused.sock")).unwrap();
    config.backing.journal_max_bytes = ByteSize(16 << 30);
    config.nbd.maximum_io = ByteSize(1 << 32);
    let error = config.validate().expect_err("maximum must fit in u32");
    assert!(error.to_string().contains("nbd.maximum_io"), "{error}");

    config.nbd.maximum_io = ByteSize(1 << 20);
    config.nbd.minimum_io = 1 << 17;
    config.nbd.preferred_io = 1 << 17;
    let error = config.validate().expect_err("minimum is at most 64 KiB");
    assert!(error.to_string().contains("nbd.minimum_io"), "{error}");
}

#[cfg(target_os = "linux")]
#[test]
fn real_nbdkit_negotiates_configured_block_sizes() {
    use std::process::Command;

    // Adapter startup applies process-wide hardening. Keep the native
    // server/client qualification independent of sibling adapter tests.
    if std::env::var_os("MAKI_NBD_LIMITS_CHILD").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "real_nbdkit_negotiates_configured_block_sizes",
                "--nocapture",
            ])
            .env("MAKI_NBD_LIMITS_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "native NBD child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // Optional Linux qualification dependencies, also used by the documented
    // rootless NBD checks. No kernel device, root, or external service is used.
    for program in ["nbdkit", "nbdinfo"] {
        if Command::new(program).arg("--version").output().is_err() {
            eprintln!("{program} unavailable; skipping real NBD negotiation");
            return;
        }
    }
    let fixture = Fixture::new();
    let plugin = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("libmaki_nbdkit.so");
    assert!(plugin.is_file(), "missing cargo-built plugin: {plugin:?}");
    let output = Command::new("nbdkit")
        .args(["--foreground", "--exit-with-parent", "-U", "-"])
        .arg(plugin)
        .arg(format!("config={}", fixture.path.display()))
        .args(["--run", "nbdinfo --json --list \"$uri\""])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "nbdkit negotiation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let export = &report["exports"][0];
    assert_eq!(export["block_size_minimum"], 4096, "{report}");
    assert_eq!(export["block_size_preferred"], 4096, "{report}");
    assert_eq!(export["block_size_maximum"], 8192, "{report}");
}
