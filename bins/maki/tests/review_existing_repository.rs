//! Inspect/check must open an existing repository without creating a missing root.
#[path = "support/volume_config.rs"]
mod volume_config;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn config(root: &Path) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "existing-repository"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "MAKI_CREDENTIAL_INSPECT_EXISTING_KEY" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = {root:?}
"#
    )
}

fn run(config: &Path, command: &str, deep: bool) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_maki"));
    if command == "check" {
        process.arg("check");
    } else {
        process.args(["volume", command]);
    }
    process.arg(config);
    if deep {
        process.arg("--deep");
    }
    process
        .env(
            "MAKI_CREDENTIAL_INSPECT_EXISTING_KEY",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .output()
        .unwrap()
}

fn missing_root(command: &str, deep: bool) {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("missing-parent");
    let root = parent.join("volume");
    let path = directory.path().join("config.toml");
    volume_config::write(&path, config(&root)).unwrap();
    let result = run(&path, command, deep);
    assert_eq!(result.status.code(), Some(1));
    assert!(!root.exists(), "{command} created a missing repository");
    assert!(
        !parent.exists(),
        "{command} created missing parent directories"
    );
}

#[test]
fn inspect_does_not_create_a_missing_repository() {
    missing_root("inspect", false);
}
#[test]
fn check_does_not_create_a_missing_repository() {
    missing_root("check", false);
}
#[test]
fn deep_check_does_not_create_a_missing_repository_or_lock() {
    missing_root("check", true);
}

#[test]
fn new_volume_creation_and_existing_volume_inspection_still_work() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("new-parent/volume");
    let path = directory.path().join("config.toml");
    volume_config::write(&path, config(&root)).unwrap();
    for (command, deep) in [
        ("create", false),
        ("inspect", false),
        ("check", false),
        ("check", true),
    ] {
        let result = run(&path, command, deep);
        assert!(
            result.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert!(root.join("superblock.a").is_file());
}

#[test]
fn a_regular_file_is_refused_without_modifying_it() {
    let directory = tempfile::tempdir().unwrap();
    let root: PathBuf = directory.path().join("volume-file");
    std::fs::write(&root, b"not a directory").unwrap();
    let path = directory.path().join("config.toml");
    volume_config::write(&path, config(&root)).unwrap();
    for (command, deep) in [("inspect", false), ("check", false), ("check", true)] {
        assert_eq!(run(&path, command, deep).status.code(), Some(1));
        assert_eq!(std::fs::read(&root).unwrap(), b"not a directory");
    }
}

/// A backing root these commands cannot open is named with its path, the
/// setting that names it and what to check, not with the bare system error.
#[test]
fn a_root_that_cannot_be_opened_is_named_with_its_setting() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing-parent/volume");
    let file = directory.path().join("volume-file");
    std::fs::write(&file, b"not a directory").unwrap();
    for (index, (root, says)) in [
        (
            &missing,
            "does not exist: check the configured path for a typo",
        ),
        (&file, "is not a directory"),
    ]
    .into_iter()
    .enumerate()
    {
        let path = directory.path().join(format!("config-{index}.toml"));
        volume_config::write(&path, config(root)).unwrap();
        for (command, deep) in [("inspect", false), ("check", false), ("check", true)] {
            let result = run(&path, command, deep);
            assert_eq!(result.status.code(), Some(1));
            let stderr = String::from_utf8_lossy(&result.stderr);
            let named = format!("the backing root {} (`backing.root`)", root.display());
            assert!(stderr.contains(&named), "{command}: {stderr}");
            assert!(stderr.contains(says), "{command}: {stderr}");
        }
    }
}

/// Restores a directory's mode before it is removed.
#[cfg(unix)]
struct Mode<'a>(&'a Path);

#[cfg(unix)]
impl Drop for Mode<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700));
    }
}

#[cfg(unix)]
#[test]
fn a_root_this_user_may_not_open_is_named_with_its_setting() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("parent");
    let root = parent.join("volume");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mode = Mode(&parent);
    // Root may open a mode-000 directory (CAP_DAC_OVERRIDE): only another
    // user is refused one.
    if std::fs::read_dir(&parent).is_ok() {
        drop(mode);
        eprintln!("needs a user that a mode-000 directory refuses (not root); skipping");
        return;
    }
    let path = directory.path().join("config.toml");
    volume_config::write(&path, config(&root)).unwrap();
    for (closed, command) in [(&parent, "check"), (&root, "inspect")] {
        if closed == &root {
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let result = run(&path, command, false);
        assert_eq!(result.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&result.stderr);
        let named = format!(
            "may not open the backing root {} (`backing.root`)",
            root.display()
        );
        assert!(stderr.contains(&named), "{command}: {stderr}");
        assert!(stderr.contains("Permission denied"), "{command}: {stderr}");
    }
    let _root_mode = Mode(&root);
    drop(mode);
}
