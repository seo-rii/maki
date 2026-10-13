//! BUG-070: existing protected volumes need ordinary attach, not enrollment.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use maki_format::superblock::load_volume_superblock;
use maki_nbdkit::daemon::{build_backing, parse_and_validate};

struct Fixture {
    directory: tempfile::TempDir,
    witness: tempfile::TempDir,
    config: PathBuf,
    raw: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        // The independent witness must be on another filesystem.
        let witness = tempfile::tempdir_in("/dev/shm").unwrap();
        let key = directory.path().join("key");
        std::fs::write(&key, "17".repeat(32)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let raw = format!(
            r#"
config_schema_version = 1
[volume]
name = "benchmark-rollback-reuse"
max_virtual_size = "1MiB"
shard_logical_size = "128KiB"
device_block_size = 4096
crypto_unit_size = 4096
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "benchmark-rollback-reuse-v1"
key = {{ source = "file", name = {:?} }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = {:?}
slot_alignment = 4096
journal_segment_size = "64KiB"
journal_max_bytes = "1MiB"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "64KiB"
[backing.rollback_protection]
witness_root = {:?}
capacity = "8MiB"
[nbd]
minimum_io = 4096
preferred_io = 4096
maximum_io = "64KiB"
threads = 2
"#,
            key.display().to_string(),
            directory.path().join("volume").display().to_string(),
            witness.path().display().to_string()
        );
        let config = directory.path().join("volume.toml");
        std::fs::write(&config, &raw).unwrap();
        Self {
            directory,
            witness,
            config,
            raw,
        }
    }

    fn root(&self) -> PathBuf {
        self.directory.path().join("volume")
    }

    fn run(&self, destroy: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_maki-benchmark"));
        if destroy {
            command.arg("--destroy-data");
        }
        command
            .arg("--json")
            .arg(&self.config)
            .args(["2", "4096"])
            .output()
            .unwrap()
    }

    fn create(&self) {
        let output = self.run(false);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn uuid(&self) -> String {
        let config = parse_and_validate(&self.raw).unwrap();
        let backing = build_backing(&config).unwrap();
        load_volume_superblock(backing.as_ref())
            .unwrap()
            .superblock
            .volume_uuid
            .to_string()
    }
}

fn snapshot(directory: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

fn assert_failed_without_report(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn fresh_protected_volume_still_initializes_and_verifies_reads() {
    let fixture = Fixture::new();
    let output = fixture.run(false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["read_verified"], true);
    assert_eq!(report["verified_read_operations"], 2);
    assert!(fixture.root().join("rollback.format").is_file());
    assert!(!snapshot(fixture.witness.path()).is_empty());
}

#[test]
fn existing_protected_volume_requires_explicit_destruction_authorization() {
    let fixture = Fixture::new();
    fixture.create();
    let witness_before = snapshot(fixture.witness.path());
    let uuid_before = fixture.uuid();
    let output = fixture.run(false);
    assert_failed_without_report(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("--destroy-data"));
    assert_eq!(snapshot(fixture.witness.path()), witness_before);
    assert_eq!(fixture.uuid(), uuid_before);
}

#[test]
fn authorized_protected_reuse_verifies_reads_and_preserves_volume_uuid() {
    let fixture = Fixture::new();
    fixture.create();
    let uuid_before = fixture.uuid();
    let marker_before = std::fs::read(fixture.root().join("rollback.format")).unwrap();
    let output = fixture.run(true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["read_verified"], true);
    assert_eq!(report["verified_read_operations"], 2);
    assert_eq!(fixture.uuid(), uuid_before);
    assert_eq!(
        std::fs::read(fixture.root().join("rollback.format")).unwrap(),
        marker_before
    );
}

#[test]
fn authorized_reuse_still_rejects_changed_protected_capacity() {
    let fixture = Fixture::new();
    fixture.create();
    let before = snapshot(fixture.witness.path());
    std::fs::write(
        &fixture.config,
        fixture
            .raw
            .replace("capacity = \"8MiB\"", "capacity = \"16MiB\""),
    )
    .unwrap();
    let output = fixture.run(true);
    assert_failed_without_report(&output, 1);
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("capacity mismatch"), "{message}");
    assert_eq!(snapshot(fixture.witness.path()), before);
}

#[test]
fn authorized_reuse_still_rejects_changed_key_identity() {
    let fixture = Fixture::new();
    fixture.create();
    let key = fixture.directory.path().join("key");
    let other_key = fixture.directory.path().join("other-key");
    std::fs::copy(&key, &other_key).unwrap();
    let uuid_before = fixture.uuid();
    std::fs::write(
        &fixture.config,
        fixture
            .raw
            .replace(&format!("{key:?}"), &format!("{other_key:?}")),
    )
    .unwrap();
    let output = fixture.run(true);
    assert_failed_without_report(&output, 1);
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("key identity"), "{message}");
    assert_eq!(fixture.uuid(), uuid_before);
}

#[test]
fn corrupted_protected_marker_is_never_treated_as_reusable() {
    let fixture = Fixture::new();
    fixture.create();
    let before = snapshot(fixture.witness.path());
    std::fs::write(fixture.root().join("rollback.format"), b"invalid").unwrap();
    let output = fixture.run(true);
    assert_failed_without_report(&output, 1);
    assert_eq!(snapshot(fixture.witness.path()), before);
    assert_eq!(
        std::fs::read(fixture.root().join("rollback.format")).unwrap(),
        b"invalid"
    );
}

#[test]
fn partial_protected_layout_cannot_be_reinitialized_with_destroy_data() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.root()).unwrap();
    std::fs::write(fixture.root().join("unrelated"), b"leave this file").unwrap();
    let output = fixture.run(true);
    assert_failed_without_report(&output, 1);
    assert!(snapshot(fixture.witness.path()).is_empty());
    assert!(!fixture.root().join("rollback.format").exists());
    assert_eq!(
        std::fs::read(fixture.root().join("unrelated")).unwrap(),
        b"leave this file"
    );
}

#[test]
fn protected_backing_without_volume_metadata_is_never_reinitialized() {
    let fixture = Fixture::new();
    fixture.create();
    let config = parse_and_validate(&fixture.raw).unwrap();
    let backing = build_backing(&config).unwrap();
    backing.remove(maki_format::layout::SUPERBLOCK_A).unwrap();
    backing.remove(maki_format::layout::SUPERBLOCK_B).unwrap();
    backing.sync_dir("").unwrap();
    drop(backing);
    let before = snapshot(fixture.witness.path());
    let output = fixture.run(true);
    assert_failed_without_report(&output, 1);
    assert_eq!(snapshot(fixture.witness.path()), before);
    let backing = build_backing(&config).unwrap();
    assert!(load_volume_superblock(backing.as_ref()).is_err());
}

#[test]
fn protected_root_without_configuration_still_refuses_plain_backing() {
    let fixture = Fixture::new();
    fixture.create();
    let before = snapshot(fixture.witness.path());
    let rollback_start = fixture.raw.find("[backing.rollback_protection]").unwrap();
    let nbd_start = fixture.raw.find("[nbd]").unwrap();
    let raw = format!(
        "{}{}",
        &fixture.raw[..rollback_start],
        &fixture.raw[nbd_start..]
    );
    std::fs::write(&fixture.config, raw).unwrap();
    let output = fixture.run(true);
    assert_failed_without_report(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("protected backing requires"));
    assert_eq!(snapshot(fixture.witness.path()), before);
}
