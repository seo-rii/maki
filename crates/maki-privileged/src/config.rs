//! Root-owned attach configuration (`/etc/maki/attach/<volume>.toml`,
//! review M-016) and argument hygiene for everything the helper hands to
//! system utilities.
//!
//! The helper runs as root and execs `nbd-client`, `mount`, `vgchange` and
//! friends with values that come from configuration or the command line.
//! Every such value is checked here: no leading dash (option injection), no
//! control characters, absolute canonical paths, a well-formed UUID.

use serde::Deserialize;

use crate::plan::{AttachRequest, AUTO_NBD_DEVICE};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("attach config {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("attach config parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("attach config invalid: {0}")]
    Invalid(String),
}

/// Per-volume attach parameters. Every path is absolute; `nbd_device`
/// absent means "allocate a free device".
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AttachConfig {
    pub volume_uuid: Option<String>,
    #[serde(default)]
    pub nbd_device: Option<String>,
    #[serde(default)]
    pub nbd_socket: Option<String>,
    #[serde(default)]
    pub device_block_size: Option<u32>,
    #[serde(default)]
    pub vg_name: Option<String>,
    #[serde(default)]
    pub lv_name: Option<String>,
    #[serde(default)]
    pub mountpoint: Option<String>,
    #[serde(default)]
    pub fs_uuid: Option<String>,
    #[serde(default)]
    pub init_sentinel: bool,
}

/// `/etc/maki/attach/<volume>.toml`.
pub fn default_path(volume: &str) -> String {
    format!("/etc/maki/attach/{volume}.toml")
}

pub fn parse(text: &str) -> Result<AttachConfig, ConfigError> {
    Ok(toml::from_str(text)?)
}

pub fn load(path: &str) -> Result<AttachConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_string(),
        source,
    })?;
    parse(&text)
}

/// Command-line overrides applied on top of the configuration.
#[derive(Debug, Clone, Default)]
pub struct AttachOverrides {
    pub nbd_device: Option<String>,
    pub nbd_socket: Option<String>,
    pub vg_name: Option<String>,
    pub lv_name: Option<String>,
    pub mountpoint: Option<String>,
    pub volume_uuid: Option<String>,
    pub fs_uuid: Option<String>,
    pub init_sentinel: bool,
}

impl AttachConfig {
    /// Resolve configuration + overrides into a validated request. The
    /// volume UUID may be absent only when `require_uuid` is false (plan
    /// rendering); execution always requires it.
    pub fn into_request(
        self,
        volume: &str,
        overrides: AttachOverrides,
        require_uuid: bool,
    ) -> Result<AttachRequest, ConfigError> {
        check_volume_name(volume)?;
        let nbd_device = overrides
            .nbd_device
            .or(self.nbd_device)
            .unwrap_or_else(|| AUTO_NBD_DEVICE.to_string());
        if nbd_device != AUTO_NBD_DEVICE {
            check_abs_path("nbd_device", &nbd_device)?;
            if !nbd_device.starts_with("/dev/nbd") {
                return Err(ConfigError::Invalid(format!(
                    "nbd_device {nbd_device:?} must be a /dev/nbdN device"
                )));
            }
        }
        let nbd_socket = overrides
            .nbd_socket
            .or(self.nbd_socket)
            .unwrap_or_else(|| format!("/run/maki/{volume}/nbd.sock"));
        check_abs_path("nbd_socket", &nbd_socket)?;
        let vg_name = overrides
            .vg_name
            .or(self.vg_name)
            .unwrap_or_else(|| format!("vg_maki_{volume}"));
        check_lvm_name("vg_name", &vg_name)?;
        let lv_name = overrides
            .lv_name
            .or(self.lv_name)
            .unwrap_or_else(|| "data".to_string());
        check_lvm_name("lv_name", &lv_name)?;
        let mountpoint = overrides
            .mountpoint
            .or(self.mountpoint)
            .unwrap_or_else(|| format!("/srv/{volume}"));
        check_abs_path("mountpoint", &mountpoint)?;
        let device_block_size = self.device_block_size.unwrap_or(4096);
        if device_block_size == 0 || !device_block_size.is_power_of_two() {
            return Err(ConfigError::Invalid(format!(
                "device_block_size {device_block_size} must be a power of two"
            )));
        }
        let volume_uuid = match overrides.volume_uuid.or(self.volume_uuid) {
            Some(uuid) => {
                check_uuid("volume_uuid", &uuid)?;
                uuid
            }
            None if require_uuid => {
                return Err(ConfigError::Invalid(
                    "volume_uuid is required (attach config or --uuid): the mount identity \
                     check cannot run without it"
                        .to_string(),
                ))
            }
            None => "<unset>".to_string(),
        };
        let fs_uuid = overrides.fs_uuid.or(self.fs_uuid);
        if let Some(fs_uuid) = &fs_uuid {
            check_uuid("fs_uuid", fs_uuid)?;
        }
        Ok(AttachRequest {
            volume: volume.to_string(),
            nbd_socket,
            nbd_device,
            device_block_size,
            vg_name,
            lv_name,
            mountpoint,
            volume_uuid,
            fs_uuid,
            init_sentinel: overrides.init_sentinel || self.init_sentinel,
        })
    }
}

/// A value passed to a system utility: never empty, never option-like,
/// never containing control characters.
pub fn check_argument(name: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::Invalid(format!("{name} is empty")));
    }
    if value.starts_with('-') {
        return Err(ConfigError::Invalid(format!(
            "{name} {value:?} starts with '-' and could be parsed as an option"
        )));
    }
    if value.chars().any(|c| c.is_control() || c == '\0') {
        return Err(ConfigError::Invalid(format!(
            "{name} contains control characters"
        )));
    }
    Ok(())
}

/// An absolute, canonical path: no relative segments, no repeated slashes.
pub fn check_abs_path(name: &str, value: &str) -> Result<(), ConfigError> {
    check_argument(name, value)?;
    if !value.starts_with('/') {
        return Err(ConfigError::Invalid(format!(
            "{name} {value:?} must be an absolute path"
        )));
    }
    if value == "/" {
        return Ok(());
    }
    if value.ends_with('/') {
        return Err(ConfigError::Invalid(format!(
            "{name} {value:?} must not end with '/'"
        )));
    }
    for component in value.split('/').skip(1) {
        if component.is_empty() || component == "." || component == ".." {
            return Err(ConfigError::Invalid(format!(
                "{name} {value:?} is not canonical (empty, '.' or '..' component)"
            )));
        }
    }
    Ok(())
}

pub fn check_volume_name(value: &str) -> Result<(), ConfigError> {
    check_argument("volume", value)?;
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ConfigError::Invalid(format!(
            "volume name {value:?} must be [A-Za-z0-9_-]"
        )));
    }
    Ok(())
}

/// LVM VG/LV names: letters, digits, `.`, `_`, `-`, `+`; never starting
/// with `-`; no path separators.
pub fn check_lvm_name(name: &str, value: &str) -> Result<(), ConfigError> {
    check_argument(name, value)?;
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
        || value == "."
        || value == ".."
    {
        return Err(ConfigError::Invalid(format!(
            "{name} {value:?} is not a valid LVM name"
        )));
    }
    Ok(())
}

/// Hyphenated lowercase-or-uppercase hex UUID (8-4-4-4-12).
pub fn check_uuid(name: &str, value: &str) -> Result<(), ConfigError> {
    check_argument(name, value)?;
    let parts: Vec<&str> = value.split('-').collect();
    let shape = [8usize, 4, 4, 4, 12];
    let ok = parts.len() == 5
        && parts
            .iter()
            .zip(shape.iter())
            .all(|(p, len)| p.len() == *len && p.chars().all(|c| c.is_ascii_hexdigit()));
    if !ok {
        return Err(ConfigError::Invalid(format!(
            "{name} {value:?} is not a hyphenated UUID"
        )));
    }
    Ok(())
}
