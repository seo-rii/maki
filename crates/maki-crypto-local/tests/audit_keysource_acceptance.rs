//! Audit (crypto-core): what `FileKeySource` accepts as a "root-only secret
//! file" (SPEC §9) and as a present credential (SPEC §44 "missing or invalid
//! credentials fail closed").
//!
//! * The check looks at mode bits only, never at the owner: a `0600` file
//!   owned by an unrelated, unprivileged user is loaded by a root process
//!   (`maki-check`, `maki-benchmark`, a daemon run as root). That user can
//!   read and replace the key at will, so the file is not root-only.
//! * An empty (or whitespace-only) credential file is returned as a valid,
//!   empty text credential instead of failing closed; HTTP then sends
//!   `Authorization: Bearer ` with no token.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use maki_crypto_local::keysource::{FileKeySource, KeySource};

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn a_0600_key_owned_by_another_unprivileged_user_is_accepted() {
    if !is_root() {
        eprintln!("needs root to chown the fixture; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("volume-key");
    std::fs::write(&path, [0x5au8; 32]).unwrap(); // raw, not hex text
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    // nobody:nogroup — neither root nor this process's user/group.
    std::os::unix::fs::chown(&path, Some(65534), Some(65534)).unwrap();
    let loaded = FileKeySource::new(dir.path()).load("volume-key");
    assert!(
        loaded.is_err(),
        "a key file owned by uid 65534 (who can read and rewrite it) was accepted as a \
         root-only secret file ({} bytes loaded)",
        loaded.map(|k| k.len()).unwrap_or(0)
    );
}

#[test]
fn an_empty_text_credential_does_not_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in [("empty-token", &b""[..]), ("blank-token", &b"\n"[..])] {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let source = FileKeySource::new(dir.path());
    for name in ["empty-token", "blank-token"] {
        let loaded = source.load_text(name);
        assert!(
            loaded.is_err(),
            "{name}: an empty credential loaded as a present credential of {} byte(s)",
            loaded.map(|t| t.len()).unwrap_or(0)
        );
    }
}
