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
    CryptoError::ProviderFatal(format!(
        "credential {name:?} unavailable — failing closed"
    ))
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

fn try_hex_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

impl KeySource for FileKeySource {
    fn load(&self, name: &str) -> Result<SecretBuffer, CryptoError> {
        if !valid_credential_name(name) {
            return Err(CryptoError::ProviderFatal(format!(
                "invalid credential name {name:?}"
            )));
        }
        let path = self.dir.join(name);
        let mut raw = std::fs::read(&path).map_err(|_| missing(name))?;
        let result = match try_hex_decode(&raw) {
            Some(decoded) => SecretBuffer::from_vec(decoded),
            None => SecretBuffer::from_slice(&raw),
        };
        zeroize::Zeroize::zeroize(&mut raw);
        Ok(result)
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
        let value = std::env::var(&var).map_err(|_| missing(name))?;
        let bytes = value.into_bytes();
        Ok(match try_hex_decode(&bytes) {
            Some(decoded) => SecretBuffer::from_vec(decoded),
            None => SecretBuffer::from_vec(bytes),
        })
    }
}

/// systemd credentials directory, when running under `LoadCredential`.
pub fn systemd_credential_source() -> Option<FileKeySource> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(FileKeySource::new)
}
