//! `maki check` compares the configuration with the volume it checks.
//!
//! Attach refuses a configuration whose provider, key identity,
//! compatibility id (with the random prefix it derives from) or geometry
//! differs from what the volume's superblock stores (SPEC §20). `maki check`
//! and `maki check --deep` passed such a configuration, so an operator who
//! checked before attaching was told the volume was fine and the attach then
//! failed. Each mismatch is an `ERROR:` line naming the setting, the
//! configured value and the volume's, and the check fails with status 1;
//! settings that may change after creation still pass.

#[path = "support/volume_config.rs"]
mod volume_config;

use std::path::Path;
use std::process::{Command, Output};

const KEY_ENV: &str = "MAKI_CREDENTIAL_IDENTITY_KEY";
const KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// The fixture's settings, one per line, so a variant replaces whole lines.
const SETTINGS: &[(&str, &str)] = &[
    ("name", "\"identity\""),
    ("max_virtual_size", "\"1MiB\""),
    ("device_block_size", "512"),
    ("crypto_unit_size", "4096"),
    ("shard_logical_size", "\"64KiB\""),
    ("provider", "\"local-aes-gcm-siv\""),
    ("crypto_compatibility_id", "\"local-profile-v1\""),
    ("random_prefix_bytes", "0"),
    ("key", "{ source = \"env\", name = \"identity-key\" }"),
    ("supported_plaintext_sizes", "[4096]"),
    ("max_ciphertext_size", "4384"),
    ("slot_alignment", "512"),
    ("journal_segment_size", "\"64KiB\""),
    ("minimum_io", "4096"),
];

/// The fixture with `changes` applied, each a `(setting, value)` pair.
fn config(root: &Path, changes: &[(&str, &str)]) -> String {
    let value = |name: &str| {
        changes
            .iter()
            .chain(SETTINGS)
            .find(|(setting, _)| *setting == name)
            .map(|(_, value)| *value)
            .unwrap()
    };
    let line = |name: &str| format!("{name} = {}\n", value(name));
    let mut text = String::from("config_schema_version = 1\n[volume]\n");
    for name in [
        "name",
        "max_virtual_size",
        "device_block_size",
        "crypto_unit_size",
        "shard_logical_size",
    ] {
        text += &line(name);
    }
    text += "[crypto]\n";
    for name in [
        "provider",
        "crypto_compatibility_id",
        "random_prefix_bytes",
        "key",
    ] {
        text += &line(name);
    }
    text += "[crypto.capabilities]\n";
    text += &line("supported_plaintext_sizes");
    text += &line("max_ciphertext_size");
    text += "[backing]\n";
    text += &format!(
        "root = {}\n",
        serde_json::to_string(root.to_str().unwrap()).unwrap()
    );
    text += &line("slot_alignment");
    text += &line("journal_segment_size");
    text += "[nbd]\n";
    text += &line("minimum_io");
    text
}

fn maki(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .env(KEY_ENV, KEY_HEX)
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

struct Volume {
    directory: tempfile::TempDir,
    root: std::path::PathBuf,
    created: Vec<(&'static str, &'static str)>,
}

impl Volume {
    /// A volume created by `maki volume create` with `created` applied.
    fn create(created: &[(&'static str, &'static str)]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("volume");
        let volume = Self {
            directory,
            root,
            created: created.to_vec(),
        };
        let path = volume.write("create.toml", &[]);
        let output = maki(&["volume", "create", &path]);
        assert!(output.status.success(), "create: {}", text(&output));
        volume
    }

    /// Write the creation configuration with `changes` applied on top.
    fn write(&self, name: &str, changes: &[(&str, &str)]) -> String {
        let all: Vec<_> = changes.iter().chain(&self.created).copied().collect();
        let path = self.directory.path().join(name);
        volume_config::write(&path, config(&self.root, &all)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    /// `maki check` and `maki check --deep` of the configuration with
    /// `changes` applied.
    fn check(&self, changes: &[(&str, &str)]) -> [Output; 2] {
        let path = self.write("changed.toml", changes);
        [maki(&["check", &path]), maki(&["check", &path, "--deep"])]
    }
}

/// Every line of `output` that names a configuration mismatch.
fn mismatches(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.starts_with("ERROR: configuration mismatch: "))
        .map(str::to_owned)
        .collect()
}

/// Check that the configuration with `changes` fails both checks with
/// exactly the `expected` settings, each naming the configured value first
/// and then the volume's.
fn refused(volume: &Volume, changes: &[(&str, &str)], expected: &[(&str, &str, &str)]) {
    for output in volume.check(changes) {
        let report = text(&output);
        assert_eq!(output.status.code(), Some(1), "{changes:?}: {report}");
        assert!(report.contains("check FAILED"), "{changes:?}: {report}");
        assert!(!report.contains(KEY_HEX), "{changes:?}: {report}");
        let lines = mismatches(&output);
        assert_eq!(lines.len(), expected.len(), "{changes:?}: {report}");
        for ((setting, configured, stored), line) in expected.iter().zip(&lines) {
            assert_eq!(
                *line,
                format!(
                    "ERROR: configuration mismatch: {setting} is {configured} in the \
                     configuration, the volume has {stored}; attach refuses this configuration"
                ),
                "{changes:?}: {report}"
            );
        }
    }
}

/// Check that the configuration with `changes` passes both checks.
fn accepted(volume: &Volume, changes: &[(&str, &str)]) {
    for output in volume.check(changes) {
        let report = text(&output);
        assert_eq!(output.status.code(), Some(0), "{changes:?}: {report}");
        assert!(report.contains("check passed"), "{changes:?}: {report}");
        assert!(mismatches(&output).is_empty(), "{changes:?}: {report}");
        assert!(
            report.contains(
                "info: configuration matches the volume's provider, key identity, \
                 compatibility id and geometry"
            ),
            "{changes:?}: {report}"
        );
    }
}

#[test]
fn every_setting_fixed_at_creation_is_compared_with_the_volume() {
    let volume = Volume::create(&[]);
    for (changes, expected) in [
        (
            &[("max_virtual_size", "\"2MiB\"")][..],
            &[("volume.max_virtual_size", "2097152", "1048576")][..],
        ),
        (
            &[("device_block_size", "4096")],
            &[("volume.device_block_size", "4096", "512")],
        ),
        (
            &[
                ("crypto_unit_size", "8192"),
                ("supported_plaintext_sizes", "[8192]"),
                ("max_ciphertext_size", "8480"),
            ],
            &[
                ("volume.crypto_unit_size", "8192", "4096"),
                ("crypto.capabilities.max_ciphertext_size", "8480", "4384"),
            ],
        ),
        (
            &[("shard_logical_size", "\"128KiB\"")],
            &[("volume.shard_logical_size", "131072", "65536")],
        ),
        (
            &[("slot_alignment", "4096")],
            &[("backing.slot_alignment", "4096", "512")],
        ),
        (
            &[("max_ciphertext_size", "4400")],
            &[("crypto.capabilities.max_ciphertext_size", "4400", "4384")],
        ),
        (
            &[("provider", "\"local-aes-xts\"")],
            &[(
                "crypto.provider",
                "\"local-aes-xts\"",
                "\"local-aes-gcm-siv\"",
            )],
        ),
        (
            &[("key", "{ source = \"env\", name = \"renamed-key\" }")],
            &[("crypto.key.name", "\"renamed-key\"", "\"identity-key\"")],
        ),
        (
            &[("crypto_compatibility_id", "\"local-profile-v2\"")],
            &[(
                "crypto.crypto_compatibility_id",
                "\"local-profile-v2\"",
                "\"local-profile-v1\"",
            )],
        ),
        (
            &[
                ("random_prefix_bytes", "16"),
                ("supported_plaintext_sizes", "[4112]"),
            ],
            &[("crypto.random_prefix_bytes", "16", "0")],
        ),
        // Several at once: every one is reported, not only the first.
        (
            &[
                ("max_virtual_size", "\"2MiB\""),
                ("provider", "\"local-aes-xts\""),
                ("crypto_compatibility_id", "\"local-profile-v2\""),
            ],
            &[
                ("volume.max_virtual_size", "2097152", "1048576"),
                (
                    "crypto.provider",
                    "\"local-aes-xts\"",
                    "\"local-aes-gcm-siv\"",
                ),
                (
                    "crypto.crypto_compatibility_id",
                    "\"local-profile-v2\"",
                    "\"local-profile-v1\"",
                ),
            ],
        ),
    ] {
        refused(&volume, changes, expected);
    }
    // What may change after creation (configuration guide) still passes.
    for changes in [
        &[][..],
        &[("name", "\"renamed\"")],
        &[("journal_segment_size", "\"128KiB\"")],
        &[("minimum_io", "8192")],
    ] {
        accepted(&volume, changes);
    }
}

#[test]
fn a_prefixed_volume_is_compared_by_prefix_length_and_base_id() {
    let volume = Volume::create(&[
        ("random_prefix_bytes", "32"),
        ("supported_plaintext_sizes", "[4128]"),
    ]);
    refused(
        &volume,
        &[
            ("random_prefix_bytes", "0"),
            ("supported_plaintext_sizes", "[4096]"),
        ],
        &[("crypto.random_prefix_bytes", "0", "32")],
    );
    refused(
        &volume,
        &[
            ("random_prefix_bytes", "16"),
            ("supported_plaintext_sizes", "[4112]"),
        ],
        &[("crypto.random_prefix_bytes", "16", "32")],
    );
    refused(
        &volume,
        &[("crypto_compatibility_id", "\"local-profile-v2\"")],
        &[(
            "crypto.crypto_compatibility_id",
            "\"local-profile-v2\"",
            "\"local-profile-v1\"",
        )],
    );
    accepted(&volume, &[]);
}

/// Older builds stored a file key's path with a trailing directory suffix
/// (`key/.`) and opened it as `key`; attach accepts the corrected path for
/// such a volume, so the check must accept it too, and nothing else.
#[test]
fn a_legacy_key_path_suffix_matches_the_corrected_path() {
    use maki_backing::FileBacking;
    use maki_format::superblock::{Superblock, CRYPTO_FORMAT_VERSION};

    let directory = tempfile::tempdir().unwrap();
    let key = directory
        .path()
        .join("key")
        .to_str()
        .unwrap()
        .replace('\\', "/");
    let root = directory.path().join("volume");
    let file_key = format!(
        "{{ source = \"file\", name = {} }}",
        serde_json::to_string(&key).unwrap()
    );
    let path = directory.path().join("volume.toml");
    volume_config::write(&path, config(&root, &[("key", &file_key)])).unwrap();
    let cfg = maki_format::config::parse_config(&config(&root, &[("key", &file_key)])).unwrap();
    cfg.validate().unwrap();
    let stored = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::new_v4(),
        provider_type: cfg.crypto.provider.clone(),
        crypto_compatibility_id: cfg.crypto.effective_compatibility_id(),
        key_identity: format!("{key}/."),
        geometry: cfg.geometry().unwrap(),
        format_version: CRYPTO_FORMAT_VERSION,
        created_unix: 0,
    };
    maki_format::init::create_volume(&FileBacking::new(&root).unwrap(), stored).unwrap();
    let path = path.to_str().unwrap();
    for output in [maki(&["check", path]), maki(&["check", path, "--deep"])] {
        assert_eq!(output.status.code(), Some(0), "{}", text(&output));
        assert!(mismatches(&output).is_empty(), "{}", text(&output));
    }
    let other = format!("{key}x");
    let other_key = format!(
        "{{ source = \"file\", name = {} }}",
        serde_json::to_string(&other).unwrap()
    );
    volume_config::write(path, config(&root, &[("key", &other_key)])).unwrap();
    for output in [maki(&["check", path]), maki(&["check", path, "--deep"])] {
        assert_eq!(output.status.code(), Some(1), "{}", text(&output));
        assert_eq!(
            mismatches(&output),
            [format!(
                "ERROR: configuration mismatch: crypto.key.name is {other:?} in the \
                 configuration, the volume has {:?}; attach refuses this configuration",
                format!("{key}/.")
            )],
            "{}",
            text(&output)
        );
    }
}
