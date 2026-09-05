//! SPEC §9: a file credential is a root-only secret file. A key file that
//! the group or others can read, or that is not a regular file, is refused
//! at load rather than used (fourth audit pass).

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use maki_crypto_local::keysource::{FileKeySource, KeySource};

#[test]
fn group_or_world_readable_key_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("volume-key");
    std::fs::write(&path, "00112233445566778899aabbccddeeff\n").unwrap();
    let source = FileKeySource::new(dir.path());

    for mode in [0o644u32, 0o640, 0o604, 0o660, 0o666] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let err = source
            .load("volume-key")
            .expect_err(&format!("mode {mode:04o} must be refused"));
        assert!(err.to_string().contains("readable"), "{mode:04o}: {err}");
    }
    for mode in [0o600u32, 0o400] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let key = source.load("volume-key").unwrap();
        assert_eq!(key.len(), 16, "hex content decodes");
    }
}

#[test]
fn a_symlink_or_special_file_is_not_a_credential() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("elsewhere");
    std::fs::write(&target, "secret").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, dir.path().join("linked")).unwrap();
    let source = FileKeySource::new(dir.path());
    let err = source.load("linked").unwrap_err();
    assert!(err.to_string().contains("regular file"), "{err}");
    assert!(source.load("absent").is_err());
}
