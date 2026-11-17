//! SPEC §9 names a *root-only secret file* as a credential source, but the
//! loader checked the mode bits alone. The owner of a file can read and
//! rewrite it whatever its mode, so a `0600` key owned by an unprivileged
//! user was accepted by any root process that loaded it (`maki-benchmark`,
//! a daemon run by hand as root): that user could read or replace the
//! volume key. A credential file must belong to root or to the user the
//! process runs as, in a `file` directory and in systemd's credentials
//! directory alike.
//!
//! Changing a file's owner needs root, so these cases skip otherwise.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use maki_crypto_local::keysource::{FileKeySource, KeySource};

/// An unprivileged uid and gid that is neither root nor this process.
const NOBODY: u32 = 65534;
const KEY_HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn credential(dir: &Path, name: &str, mode: u32, owner: Option<(u32, u32)>) {
    let path = dir.join(name);
    std::fs::write(&path, format!("{KEY_HEX}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(&path, Some(uid), Some(gid)).unwrap();
    }
}

fn assert_refused_for_its_owner(source: &FileKeySource, name: &str) {
    for (what, loaded) in [
        ("load", source.load(name)),
        ("load_text", source.load_text(name)),
    ] {
        let Err(error) = loaded else {
            panic!("{what}: a credential owned by uid {NOBODY} was accepted");
        };
        let message = error.to_string();
        assert!(message.contains(name), "{what}: {message}");
        assert!(message.contains("owned by uid 65534"), "{what}: {message}");
        assert!(
            !message.contains(KEY_HEX),
            "{what}: the key leaked: {message}"
        );
    }
}

#[test]
fn a_key_file_owned_by_another_user_is_refused() {
    if !is_root() {
        eprintln!("needs root to chown the fixture to uid {NOBODY}; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o600u32, 0o400] {
        credential(dir.path(), "volume-key", mode, Some((NOBODY, NOBODY)));
        assert_refused_for_its_owner(&FileKeySource::new(dir.path()), "volume-key");
    }
}

/// systemd writes `$CREDENTIALS_DIRECTORY` files as the service manager:
/// root-owned with an ACL for the service user, or, where ACLs are not
/// supported, owned by the service user. Either is root or this process;
/// any other owner is not a credential systemd put there. Group `root`
/// keeps the R5-037 group rule out of the way: only the owner is wrong.
#[test]
fn a_systemd_credential_owned_by_another_user_is_refused() {
    if !is_root() {
        eprintln!("needs root to chown the fixture to uid {NOBODY}; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o400u32, 0o440] {
        credential(dir.path(), "crypto-token", mode, Some((NOBODY, 0)));
        assert_refused_for_its_owner(
            &FileKeySource::credentials_directory(dir.path()),
            "crypto-token",
        );
    }
}

#[test]
fn root_or_process_owned_credentials_are_still_accepted() {
    let dir = tempfile::tempdir().unwrap();
    // Root can hand the file to root explicitly; anyone else owns what they
    // create, which is the process's own user.
    let owner = is_root().then_some((0, 0));
    credential(dir.path(), "volume-key", 0o600, owner);
    credential(dir.path(), "crypto-token", 0o440, owner);
    assert_eq!(
        FileKeySource::new(dir.path())
            .load("volume-key")
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        FileKeySource::credentials_directory(dir.path())
            .load("crypto-token")
            .unwrap()
            .len(),
        32
    );
}
