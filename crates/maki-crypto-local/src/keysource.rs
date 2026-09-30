//! Key-source abstraction (SPEC §9, §44).
//!
//! Missing or malformed credentials fail closed (`ProviderFatal`); key bytes
//! travel in `SecretBuffer` and are never logged.

use std::collections::HashMap;
use std::path::PathBuf;

use maki_crypto::{CryptoError, SecretBuffer};

pub trait KeySource: Send + Sync {
    fn load(&self, name: &str) -> Result<SecretBuffer, CryptoError>;
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
        self.map
            .get(name)
            .map(|b| SecretBuffer::from_slice(b))
            .ok_or_else(|| missing(name))
    }
}

fn missing(name: &str) -> CryptoError {
    CryptoError::ProviderFatal(format!("credential {name:?} unavailable — failing closed"))
}

/// Reads credentials from a directory of files: systemd `LoadCredential`
/// (`$CREDENTIALS_DIRECTORY`) or a root-only secret directory.
///
/// File content is used raw, except when it is a pure even-length hex string
/// (optionally newline-terminated), which is decoded.
pub struct FileKeySource {
    dir: PathBuf,
}

impl FileKeySource {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
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
        if !valid_credential_name(name) {
            return Err(CryptoError::ProviderFatal(format!(
                "invalid credential name {name:?}"
            )));
        }
        let path = self.dir.join(name);
        // SPEC §9: a file credential is a *root-only secret file*. A key
        // readable by the group or by others, or anything but a regular
        // file (a symlink to somewhere else, a FIFO), is refused rather
        // than loaded. systemd's LoadCredential files are 0400. The checks
        // run on the opened descriptor (see `open_credential`).
        let (file, meta) = match open_credential(&path) {
            Ok(opened) => opened,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(missing(name))
            }
            Err(_) => {
                return Err(CryptoError::ProviderFatal(format!(
                    "credential {name:?} is not a regular file"
                )))
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !meta.file_type().is_file() {
                return Err(CryptoError::ProviderFatal(format!(
                    "credential {name:?} is not a regular file"
                )));
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(CryptoError::ProviderFatal(format!(
                    "credential file {name:?} has mode {mode:04o}: it is readable by the group \
                     or by others; a secret file must be 0600 or 0400 (SPEC 9)"
                )));
            }
        }
        // The file bytes and the decoded key both live only in guarded
        // buffers (R4-002); `raw` zeroizes when it goes out of scope.
        #[cfg(not(unix))]
        if !meta.file_type().is_file() {
            return Err(CryptoError::ProviderFatal(format!(
                "credential {name:?} is not a regular file"
            )));
        }
        let raw = read_guarded(file, meta.len()).map_err(|_| missing(name))?;
        Ok(key_from_bytes(raw.expose()))
    }
}

/// Development-only source: `MAKI_CREDENTIAL_<NAME>` environment variables
/// (SPEC §9: not for production).
pub struct EnvKeySource;

impl KeySource for EnvKeySource {
    fn load(&self, name: &str) -> Result<SecretBuffer, CryptoError> {
        let var = format!(
            "MAKI_CREDENTIAL_{}",
            name.to_uppercase().replace(['-', '.'], "_")
        );
        // The environment copy itself is outside our control (development
        // only, SPEC §9); the key is copied into guarded memory and the
        // intermediate string is erased.
        let mut value = std::env::var(&var).map_err(|_| missing(name))?;
        let key = key_from_bytes(value.as_bytes());
        zeroize::Zeroize::zeroize(&mut value);
        Ok(key)
    }
}

/// systemd credentials directory, when running under `LoadCredential`.
pub fn systemd_credential_source() -> Option<FileKeySource> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(FileKeySource::new)
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
}
