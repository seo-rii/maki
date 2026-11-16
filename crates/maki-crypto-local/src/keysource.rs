//! Key-source abstraction (SPEC §9, §44).
//!
//! Missing, blank or malformed credentials fail closed (`ProviderFatal`);
//! key bytes travel in `SecretBuffer` and are never logged.

use std::collections::HashMap;
use std::path::PathBuf;

use maki_crypto::{CryptoError, SecretBuffer};

/// Every source here refuses a credential that is empty or holds only
/// whitespace, for `load` and `load_text` alike (SPEC §44).
pub trait KeySource: Send + Sync {
    /// Key material: a stored pure hex string is decoded (sources may keep
    /// binary keys as hex).
    fn load(&self, name: &str) -> Result<SecretBuffer, CryptoError>;

    /// A credential used as text (a header or metadata value, a PEM private
    /// key): exactly the stored bytes, never hex-decoded. A token generated
    /// as hex is still the hex text (R5-035).
    fn load_text(&self, name: &str) -> Result<SecretBuffer, CryptoError>;
}

/// In-memory source for tests.
#[derive(Default)]
pub struct MapKeySource {
    map: HashMap<String, Vec<u8>>,
}

impl MapKeySource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: &str, bytes: Vec<u8>) {
        self.map.insert(name.to_string(), bytes);
    }
}

impl KeySource for MapKeySource {
    fn load(&self, name: &str) -> Result<SecretBuffer, CryptoError> {
        let stored = self.map.get(name).ok_or_else(|| missing(name))?;
        ensure_present(name, stored)?;
        Ok(SecretBuffer::from_slice(stored))
    }

    fn load_text(&self, name: &str) -> Result<SecretBuffer, CryptoError> {
        self.load(name)
    }
}

fn missing(name: &str) -> CryptoError {
    CryptoError::ProviderFatal(format!("credential {name:?} unavailable — failing closed"))
}

/// A blank credential is a missing one (SPEC §44): an empty file or
/// variable, or one holding only whitespace (a token file truncated by a
/// failed rotation), would otherwise be sent as `Authorization: Bearer `
/// with no token. Whitespace is what `str::trim` removes, the trimming the
/// header and metadata builders apply, so no value they would reduce to
/// nothing is ever returned. `stored` is the credential as stored, before
/// any hex decoding; the check borrows it and never copies it.
fn ensure_present(name: &str, stored: &[u8]) -> Result<(), CryptoError> {
    if std::str::from_utf8(stored).is_ok_and(|text| text.trim().is_empty()) {
        return Err(CryptoError::ProviderFatal(format!(
            "credential {name:?} is empty or only whitespace — failing closed"
        )));
    }
    Ok(())
}

/// Reads credentials from a directory of files: systemd `LoadCredential`
/// (`$CREDENTIALS_DIRECTORY`) or a root-only secret directory. On Unix every
/// file must be a regular file owned by root or by the user this process
/// runs as, and not accessible to others (see `new` and
/// `credentials_directory` for the group rule).
///
/// `load` uses file content raw, except when it is a pure even-length hex
/// string (optionally newline-terminated), which is decoded; `load_text`
/// always returns the content raw.
pub struct FileKeySource {
    dir: PathBuf,
    /// Accept group read when the group is the process's own or root.
    /// Modes exist on Unix only.
    #[cfg_attr(not(unix), allow(dead_code))]
    group_readable: bool,
}

impl FileKeySource {
    /// A root-only secret directory: files must be 0600 or 0400 and owned
    /// by root or by the process's effective user.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            group_readable: false,
        }
    }

    /// systemd's per-unit credentials directory (`$CREDENTIALS_DIRECTORY`).
    /// systemd creates it for the one unit and, from version 257, writes
    /// `LoadCredential=` files with mode 0440 for the service's group. Group
    /// read is accepted when the file's group is the process's effective
    /// group or root; group write and any access by others are still
    /// refused (R5-037). The owner rule is the same as for `new`: the
    /// service manager writes these files owned by root or by the service
    /// user, so a file owned by anyone else is not one systemd put there.
    pub fn credentials_directory(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            group_readable: true,
        }
    }
}

fn valid_credential_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !name.starts_with('.')
}

/// Decode a pure even-length hex string (surrounding whitespace allowed)
/// into a guarded buffer; `None` when the bytes are not such a string.
fn try_hex_decode(bytes: &[u8]) -> Option<SecretBuffer> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Guarded before the first key byte is produced (R4-002).
    let mut out = SecretBuffer::zeroed(s.len() / 2);
    for (index, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.expose_mut()[index] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// The raw or hex-decoded key from `bytes`, born in guarded memory.
fn key_from_bytes(bytes: &[u8]) -> SecretBuffer {
    try_hex_decode(bytes).unwrap_or_else(|| SecretBuffer::from_slice(bytes))
}

/// Read a whole credential file into a guarded buffer without an
/// intermediate ordinary allocation. Files are small; a bound keeps a
/// misconfigured path from pinning arbitrary memory.
fn read_guarded(mut file: std::fs::File, expected_len: u64) -> std::io::Result<SecretBuffer> {
    use std::io::Read;
    const MAX_CREDENTIAL_BYTES: u64 = 1 << 20;
    if expected_len > MAX_CREDENTIAL_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "credential file exceeds 1 MiB",
        ));
    }
    let mut raw = SecretBuffer::zeroed(expected_len as usize);
    file.read_exact(raw.expose_mut())?;
    // A file that grew after stat is refused rather than partially read.
    let mut probe = [0u8; 1];
    if file.read(&mut probe)? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "credential file changed while being read",
        ));
    }
    Ok(raw)
}

/// Why a secret file's owner cannot be trusted, or `None` when it is root
/// or the effective user of this process. SPEC §9 asks for a *root-only*
/// secret file, and a file's owner can read and rewrite it whatever its
/// mode: a `0600` key owned by an unprivileged user is that user's to read
/// or replace, so a root process must not load it. A process running as
/// the service user may still load its own files.
#[cfg(unix)]
pub fn untrusted_secret_owner(meta: &std::fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let owner = meta.uid();
    (owner != 0 && owner != euid).then(|| {
        format!("is owned by uid {owner}, not by root or this process's user (uid {euid})")
    })
}

/// Open a credential file once and describe the opened descriptor, so the
/// checks and the read concern the same file. On Unix the open neither
/// follows a symlink (`O_NOFOLLOW`) nor blocks on a FIFO without a writer
/// (`O_NONBLOCK`); validating a path and then opening it again let a swap
/// in between be loaded as the key.
pub fn open_credential(
    path: &std::path::Path,
) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    Ok((file, meta))
}

impl KeySource for FileKeySource {
    fn load(&self, name: &str) -> Result<SecretBuffer, CryptoError> {
        let raw = self.read(name)?;
        Ok(key_from_bytes(raw.expose()))
    }

    fn load_text(&self, name: &str) -> Result<SecretBuffer, CryptoError> {
        self.read(name)
    }
}

impl FileKeySource {
    /// The checked file's bytes, in a guarded buffer.
    fn read(&self, name: &str) -> Result<SecretBuffer, CryptoError> {
        if !valid_credential_name(name) {
            return Err(CryptoError::ProviderFatal(format!(
                "invalid credential name {name:?}"
            )));
        }
        let path = self.dir.join(name);
        // SPEC §9: a file credential is a *root-only secret file*. A file
        // owned by anyone but root or this process's user, any group or
        // other access, or anything but a regular file (a symlink to
        // somewhere else, a FIFO), is refused rather than loaded. The one
        // exception to the mode rule is systemd's credentials directory:
        // from systemd 257, LoadCredential files are 0440 for the service's
        // group, so group read (never write) is accepted there when the
        // file's group is the process's effective group or root (R5-037).
        // The checks run on the opened descriptor (see `open_credential`).
        let (file, meta) = match open_credential(&path) {
            Ok(opened) => opened,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(missing(name))
            }
            Err(error) => return Err(open_error(name, &error)),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !meta.file_type().is_file() {
                return Err(CryptoError::ProviderFatal(format!(
                    "credential {name:?} is not a regular file"
                )));
            }
            if let Some(owner) = untrusted_secret_owner(&meta) {
                return Err(CryptoError::ProviderFatal(format!(
                    "credential file {name:?} {owner}: its owner can read or replace it \
                     whatever its mode; a secret file must belong to root or to the service \
                     user (SPEC 9)"
                )));
            }
            use std::os::unix::fs::MetadataExt;
            let mode = meta.permissions().mode() & 0o777;
            // SAFETY: getegid has no preconditions and cannot fail.
            let own_group = meta.gid() == 0 || meta.gid() == unsafe { libc::getegid() };
            let forbidden = if self.group_readable && own_group {
                0o037
            } else {
                0o077
            };
            if mode & forbidden != 0 {
                let rule = if self.group_readable {
                    "a systemd credential may add read for the service's own group (0440)"
                } else {
                    "a secret file must be 0600 or 0400"
                };
                return Err(CryptoError::ProviderFatal(format!(
                    "credential file {name:?} has mode {mode:04o}: it is readable or writable by \
                     the group or by others; {rule} (SPEC 9)"
                )));
            }
        }
        // The file bytes live only in a guarded buffer (R4-002); `load`
        // decodes a hex key into another one and drops this one zeroized.
        #[cfg(not(unix))]
        if !meta.file_type().is_file() {
            return Err(CryptoError::ProviderFatal(format!(
                "credential {name:?} is not a regular file"
            )));
        }
        let raw = read_guarded(file, meta.len()).map_err(|_| missing(name))?;
        ensure_present(name, raw.expose())?;
        Ok(raw)
    }
}

/// Say why a credential file could not be opened (BUG-119): a key the
/// daemon user cannot read is the common deployment mistake, and reporting
/// every failure as "not a regular file" pointed at symlinks and FIFOs.
fn open_error(name: &str, error: &std::io::Error) -> CryptoError {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return CryptoError::ProviderFatal(format!(
            "credential {name:?} is a symlink, not a regular file (SPEC 9)"
        ));
    }
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        return CryptoError::ProviderFatal(format!(
            "credential {name:?} is not readable by the daemon user; give it the service's \
             owner (0600/0400) or deliver it as a systemd credential"
        ));
    }
    CryptoError::ProviderFatal(format!(
        "credential {name:?} is not a regular file or cannot be opened"
    ))
}

/// Development-only source: `MAKI_CREDENTIAL_<NAME>` environment variables
/// (SPEC §9: not for production).
pub struct EnvKeySource;

fn env_var_name(name: &str) -> String {
    format!(
        "MAKI_CREDENTIAL_{}",
        name.to_uppercase().replace(['-', '.'], "_")
    )
}

impl KeySource for EnvKeySource {
    fn load(&self, name: &str) -> Result<SecretBuffer, CryptoError> {
        let var = env_var_name(name);
        // The environment copy itself is outside our control (development
        // only, SPEC §9); the key is copied into guarded memory and the
        // intermediate string is erased.
        let mut value = std::env::var(&var).map_err(|_| missing(name))?;
        let key = ensure_present(name, value.as_bytes()).map(|()| key_from_bytes(value.as_bytes()));
        zeroize::Zeroize::zeroize(&mut value);
        key
    }

    fn load_text(&self, name: &str) -> Result<SecretBuffer, CryptoError> {
        let var = env_var_name(name);
        let mut value = std::env::var(&var).map_err(|_| missing(name))?;
        let text = ensure_present(name, value.as_bytes())
            .map(|()| SecretBuffer::from_slice(value.as_bytes()));
        zeroize::Zeroize::zeroize(&mut value);
        text
    }
}

/// systemd credentials directory, when running under `LoadCredential`.
pub fn systemd_credential_source() -> Option<FileKeySource> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(FileKeySource::credentials_directory)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn secret_file(dir: &std::path::Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, [7u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// The checks and the read must describe the same file: validating a
    /// path and then opening it again lets a swap in between (a symlink to
    /// another file of the same length) be loaded as the key. The opened
    /// descriptor is refused if it is not the regular file it claims to be.
    #[test]
    fn the_opened_credential_is_the_file_that_was_checked() {
        let dir = tempfile::tempdir().unwrap();
        let target = secret_file(dir.path(), "target");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            open_credential(&link).is_err(),
            "opening must not follow a symlink planted after the check"
        );
        let (_, meta) = open_credential(&target).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.len(), 32);
    }

    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        // No writer: a blocking open would hang here forever. The
        // non-blocking open returns, and the descriptor is no regular file.
        let (_, meta) = open_credential(&fifo).unwrap();
        assert!(!meta.file_type().is_file());
        assert!(matches!(
            FileKeySource::new(dir.path()).load("fifo"),
            Err(CryptoError::ProviderFatal(_))
        ));
    }

    #[test]
    fn a_readable_by_others_mode_is_refused_on_the_open_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), "loose");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FileKeySource::new(dir.path()).load("loose").is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            FileKeySource::new(dir.path()).load("loose").unwrap().len(),
            32
        );
    }

    /// R5-035: keys may be stored as hex, text credentials never are: a
    /// hex-looking bearer token must load as exactly the bytes on disk.
    #[test]
    fn text_credentials_are_loaded_verbatim_while_keys_stay_hex_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, b"00ff10ab\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let source = FileKeySource::new(dir.path());
        assert_eq!(
            source.load("token").unwrap().expose(),
            &[0x00, 0xff, 0x10, 0xab]
        );
        assert_eq!(source.load_text("token").unwrap().expose(), b"00ff10ab\n");
        let mut map = MapKeySource::new();
        map.insert("token", b"00ff".to_vec());
        assert_eq!(map.load_text("token").unwrap().expose(), b"00ff");
    }
}
