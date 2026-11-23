#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

use std::path::Path;

use maki_nbdkit::daemon::{build_backing, create_volume_from_config_str, parse_and_validate};

/// The backing root and a witness on another filesystem, or `None` when
/// there is none and the test is skipped.
fn fixture() -> Option<(tempfile::TempDir, tempfile::TempDir)> {
    let backing = tempfile::tempdir().expect("backing fixture");
    let witness = other_filesystem::tempdir(backing.path())?;
    Some((backing, witness))
}

fn config(root: &Path, witness: Option<&Path>) -> String {
    let rollback = witness.map_or_else(String::new, |path| {
        format!(
            "[backing.rollback_protection]\nwitness_root = {:?}\ncapacity = \"8MiB\"",
            path.display().to_string()
        )
    });
    format!(
        r#"
config_schema_version = 1
[volume]
name = "rollback"
max_virtual_size = "16MiB"
shard_logical_size = "8MiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = {:?}
journal_segment_size = "64KiB"
journal_max_bytes = "1MiB"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "64KiB"
{}
[nbd]
maximum_io = "64KiB"
"#,
        root.display().to_string(),
        rollback
    )
}

#[test]
fn protected_volume_is_created_then_opened_only_with_its_witness() {
    let Some((backing, witness)) = fixture() else {
        return;
    };
    let raw = config(backing.path(), Some(witness.path()));
    create_volume_from_config_str(&raw).unwrap();
    let parsed = parse_and_validate(&raw).unwrap();
    build_backing(&parsed).unwrap();

    let unprotected = parse_and_validate(&config(backing.path(), None)).unwrap();
    assert!(build_backing(&unprotected).is_err());

    let displaced_root = backing.path().with_extension("temporarily-absent");
    std::fs::rename(backing.path(), &displaced_root).unwrap();
    assert!(build_backing(&parsed).is_err());
    std::fs::rename(&displaced_root, backing.path()).unwrap();

    std::fs::remove_dir_all(witness.path()).unwrap();
    assert!(build_backing(&parsed).is_err());
}

#[test]
fn protected_create_refuses_in_place_migration_of_a_raw_volume() {
    let Some((backing, witness)) = fixture() else {
        return;
    };
    create_volume_from_config_str(&config(backing.path(), None)).unwrap();

    let error = create_volume_from_config_str(&config(backing.path(), Some(witness.path())))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("empty") || error.contains("existing"),
        "unexpected error: {error}"
    );
}
