//! R5-037: systemd 257 (Debian 13) writes `LoadCredential=` files with mode
//! 0440, readable by the service's group. The loader required 0600 or 0400
//! for every credential, so `maki@.service` could not start on Debian 13
//! with any provider. Found by the 2026-10-04 Debian 13 campaign.
//!
//! The credentials directory is created and populated by systemd for the
//! one unit; group read is accepted there when the group is the process's
//! own or root. Plain `file` credentials keep the root-only rule.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use maki_crypto_local::keysource::{FileKeySource, KeySource};

fn credential(mode: u32) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crypto-token");
    std::fs::write(&path, "00112233445566778899aabbccddeeff\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    dir
}

#[test]
fn the_credentials_directory_accepts_the_mode_systemd_257_uses() {
    for mode in [0o440u32, 0o400, 0o600, 0o640] {
        let dir = credential(mode);
        let source = FileKeySource::credentials_directory(dir.path());
        assert_eq!(
            source.load("crypto-token").unwrap().len(),
            16,
            "mode {mode:04o}"
        );
    }
}

#[test]
fn the_credentials_directory_still_refuses_other_and_group_write() {
    for mode in [0o444u32, 0o404, 0o460, 0o470, 0o644] {
        let dir = credential(mode);
        let source = FileKeySource::credentials_directory(dir.path());
        let error = source
            .load("crypto-token")
            .expect_err(&format!("mode {mode:04o} must be refused"));
        assert!(error.to_string().contains("mode"), "{mode:04o}: {error}");
    }
}

#[test]
fn plain_file_credentials_stay_root_only() {
    let dir = credential(0o440);
    assert!(FileKeySource::new(dir.path()).load("crypto-token").is_err());
}
