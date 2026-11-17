//! SPEC §44: missing or invalid credentials fail closed. An empty or
//! whitespace-only credential (a token file truncated by a failed rotation,
//! an empty `LoadCredential=` source, an empty environment variable) was
//! returned as a present credential, and the header and metadata builders,
//! which trim surrounding whitespace, then sent `Authorization: Bearer `
//! with no token. Every source refuses it, for keys and text credentials
//! alike, after the same trimming those builders apply.

use maki_crypto_local::keysource::{EnvKeySource, FileKeySource, KeySource, MapKeySource};

/// Empty, ASCII whitespace, and Unicode whitespace that `str::trim` removes.
const BLANK: [&[u8]; 4] = [b"", b"\n", b" \t\r\n", "\u{3000}\u{a0}\n".as_bytes()];

fn assert_refused(
    what: &str,
    name: &str,
    loaded: Result<maki_crypto::SecretBuffer, maki_crypto::CryptoError>,
) {
    let Err(error) = loaded else {
        panic!("{what}: a blank credential {name:?} loaded as a present credential");
    };
    assert!(
        matches!(error, maki_crypto::CryptoError::ProviderFatal(_)),
        "{what}: {error}"
    );
    let message = error.to_string();
    assert!(message.contains(name), "{what}: {message}");
    assert!(message.contains("empty"), "{what}: {message}");
}

fn write_secret(path: &std::path::Path, content: &[u8], mode: u32) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = mode;
}

#[test]
fn a_blank_credential_file_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    for (index, content) in BLANK.iter().enumerate() {
        let name = format!("blank-{index}");
        write_secret(&dir.path().join(&name), content, 0o600);
        for source in [
            FileKeySource::new(dir.path()),
            FileKeySource::credentials_directory(dir.path()),
        ] {
            assert_refused("load_text", &name, source.load_text(&name));
            assert_refused("load", &name, source.load(&name));
        }
    }
}

#[test]
fn a_blank_environment_credential_fails_closed() {
    for (index, content) in BLANK.iter().enumerate() {
        let name = format!("review-blank-env-{index}");
        let var = format!("MAKI_CREDENTIAL_REVIEW_BLANK_ENV_{index}");
        std::env::set_var(&var, std::str::from_utf8(content).unwrap());
        assert_refused("load_text", &name, EnvKeySource.load_text(&name));
        assert_refused("load", &name, EnvKeySource.load(&name));
        std::env::remove_var(&var);
    }
}

#[test]
fn a_blank_in_memory_credential_fails_closed() {
    let mut keys = MapKeySource::new();
    for (index, content) in BLANK.iter().enumerate() {
        keys.insert(&format!("blank-{index}"), content.to_vec());
    }
    for index in 0..BLANK.len() {
        let name = format!("blank-{index}");
        assert_refused("load_text", &name, keys.load_text(&name));
        assert_refused("load", &name, keys.load(&name));
    }
}

/// Only blank content is refused: a text credential with surrounding
/// whitespace still loads exactly as stored (R5-035), and the builders trim it.
#[test]
fn a_padded_text_credential_still_loads_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    write_secret(&dir.path().join("token"), b" \ttok\r\n", 0o600);
    assert_eq!(
        FileKeySource::new(dir.path())
            .load_text("token")
            .unwrap()
            .expose(),
        b" \ttok\r\n"
    );
    let mut keys = MapKeySource::new();
    keys.insert("token", b"\ntok ".to_vec());
    assert_eq!(keys.load_text("token").unwrap().expose(), b"\ntok ");
}
