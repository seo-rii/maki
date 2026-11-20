//! Root-owned attach configuration (`/etc/maki/attach/<volume>.toml`,
//! review M-016) and argument hygiene for everything the helper hands to
//! system utilities.
//!
//! The helper runs as root and execs `nbd-client`, `mount`, `vgchange` and
//! friends with values that come from configuration or the command line.
//! Every such value is checked here: no leading dash (option injection), no
//! control characters, absolute canonical paths, a well-formed UUID.

use serde::Deserialize;

use crate::plan::{AttachRequest, LvmIdentityPins, AUTO_NBD_DEVICE};

const MAX_LVM_PVS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("attach config {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Fixed classification and location only; never retain the TOML error.
    #[error("attach config parse error: {0}")]
    Parse(String),
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
    pub lvm_identity: Option<LvmIdentityPins>,
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

/// Parse attach configuration without retaining its contents in diagnostics.
/// Values and unknown field names can contain accidentally pasted secrets;
/// the TOML error, message, and source text must not escape through any of
/// `Display`, `Debug`, or the error source chain.
pub fn parse(text: &str) -> Result<AttachConfig, ConfigError> {
    toml::from_str(text).map_err(|error| {
        let location = error
            .span()
            .and_then(|span| text.get(..span.start))
            .map(|before| {
                let line = before.matches('\n').count() + 1;
                let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
                format!(" at line {line}, column {column}")
            })
            .unwrap_or_default();
        ConfigError::Parse(format!("invalid TOML or configuration schema{location}"))
    })
}

pub fn load(path: impl AsRef<std::path::Path>) -> Result<AttachConfig, ConfigError> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.display().to_string(),
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
        let request = self.into_existing_request(volume, overrides, require_uuid)?;
        // The canonical absolute path check also accepts the filesystem root.
        if request.nbd_socket == "/" {
            return Err(ConfigError::Invalid(
                "nbd_socket must end with a socket filename".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        check_mountpoint_path(&request.mountpoint)?;
        // Device mapper reserves one of its 128 name bytes for NUL. LVM joins
        // the VG and LV with a hyphen and doubles every hyphen in either name.
        let vg = &request.vg_name;
        #[cfg(target_os = "linux")]
        if std::fs::metadata(std::path::Path::new("/dev").join(vg))
            .is_ok_and(|entry| !entry.is_dir())
        {
            return Err(ConfigError::Invalid(
                "vg_name conflicts with a non-directory entry under /dev".into(),
            ));
        }
        let lv = &request.lv_name;
        let hyphens = vg.bytes().chain(lv.bytes()).filter(|&b| b == b'-').count();
        if vg.len() + lv.len() + 1 + hyphens > 127 {
            return Err(ConfigError::Invalid(
                "vg_name and lv_name exceed the 127-byte device-mapper name limit".into(),
            ));
        }
        // LVM reserves these names and fragments for its internal LVs.
        if lv.starts_with("snapshot")
            || lv.starts_with("pvmove")
            || [
                "_cdata", "_cmeta", "_corig", "_cpool", "_cvol", "_imeta", "_iorig", "_mimage",
                "_mlog", "_pmspare", "_rimage", "_rmeta", "_tdata", "_tmeta", "_vdata", "_vorigin",
                "_wcorig",
            ]
            .iter()
            .any(|reserved| lv.contains(reserved))
        {
            return Err(ConfigError::Invalid("lv_name is reserved by LVM".into()));
        }
        Ok(request)
    }

    /// Resolve a lifecycle operation for an existing attachment. Keep older
    /// instance aliases reachable until their trusted devices are detached.
    pub fn into_existing_request(
        self,
        volume: &str,
        overrides: AttachOverrides,
        require_uuid: bool,
    ) -> Result<AttachRequest, ConfigError> {
        check_instance_name(volume)?;
        let nbd_device = overrides
            .nbd_device
            .or(self.nbd_device)
            .unwrap_or_else(|| AUTO_NBD_DEVICE.to_string());
        if nbd_device != AUTO_NBD_DEVICE {
            check_abs_path("nbd_device", &nbd_device)?;
            if crate::probe::nbd_index(&nbd_device).is_none() {
                return Err(ConfigError::Invalid(
                    "nbd_device must be a /dev/nbdN device".into(),
                ));
            }
        }
        let nbd_socket = overrides
            .nbd_socket
            .or(self.nbd_socket)
            .unwrap_or_else(|| format!("/run/maki/{volume}/nbd.sock"));
        check_abs_path("nbd_socket", &nbd_socket)?;
        #[cfg(unix)]
        if std::os::unix::net::SocketAddr::from_pathname(&nbd_socket).is_err() {
            return Err(ConfigError::Invalid(
                "nbd_socket is not a usable Unix socket pathname".into(),
            ));
        }
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
        let lvm_identity = self.lvm_identity.map(normalize_lvm_identity).transpose()?;
        let mountpoint = overrides
            .mountpoint
            .or(self.mountpoint)
            .unwrap_or_else(|| format!("/srv/{volume}"));
        check_abs_path("mountpoint", &mountpoint)?;
        if mountpoint == "/" {
            // Mounting over the host root hides the running system, and
            // detach would unmount `/` (R5-019).
            return Err(ConfigError::Invalid(
                "mountpoint \"/\" would hide the host root; use a directory such as /srv/<volume>"
                    .to_string(),
            ));
        }
        let device_block_size = self.device_block_size.unwrap_or(4096);
        // Linux BLKBSZSET accepts powers of two from 512 through PAGE_SIZE.
        #[cfg(target_os = "linux")]
        let maximum_block_size = u32::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| ConfigError::Invalid("cannot determine the kernel page size".into()))?;
        #[cfg(not(target_os = "linux"))]
        let maximum_block_size = 65536;
        if !(512..=maximum_block_size).contains(&device_block_size)
            || !device_block_size.is_power_of_two()
        {
            return Err(ConfigError::Invalid(format!(
                "device_block_size must be a power of two between 512 and {maximum_block_size}"
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
            lvm_identity,
            mountpoint,
            volume_uuid,
            fs_uuid,
            init_sentinel: overrides.init_sentinel || self.init_sentinel,
        })
    }
}

fn normalize_lvm_identity(mut pins: LvmIdentityPins) -> Result<LvmIdentityPins, ConfigError> {
    check_lvm_identity(&pins)?;
    pins.pv_uuids.sort();
    Ok(pins)
}

pub(crate) fn check_lvm_identity(pins: &LvmIdentityPins) -> Result<(), ConfigError> {
    if pins.pv_uuids.is_empty() || pins.pv_uuids.len() > MAX_LVM_PVS {
        return Err(ConfigError::Invalid(format!(
            "lvm_identity.pv_uuids must contain 1..={MAX_LVM_PVS} values"
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in &pins.pv_uuids {
        check_lvm_uuid("lvm_identity.pv_uuids", value)?;
        if !seen.insert(value) {
            return Err(ConfigError::Invalid(
                "lvm_identity.pv_uuids contains a duplicate".into(),
            ));
        }
    }
    check_lvm_uuid("lvm_identity.vg_uuid", &pins.vg_uuid)?;
    check_lvm_uuid("lvm_identity.lv_uuid", &pins.lv_uuid)?;
    Ok(())
}

/// A value passed to a system utility: never empty, never option-like,
/// never containing control characters. Diagnostics name the field, never
/// its rejected value: a valid TOML string can still contain a pasted secret.
pub fn check_argument(name: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::Invalid(format!("{name} is empty")));
    }
    if value.starts_with('-') {
        return Err(ConfigError::Invalid(format!(
            "{name} starts with '-' and could be parsed as an option"
        )));
    }
    if value.chars().any(|c| c.is_control() || c == '\0') {
        return Err(ConfigError::Invalid(format!(
            "{name} contains control characters"
        )));
    }
    Ok(())
}

/// Existing components must be directories, as required by the mount step.
/// Missing components inherit the nearest existing parent's name limit.
#[cfg(target_os = "linux")]
fn check_mountpoint_path(mountpoint: &str) -> Result<(), ConfigError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    let mut parent = PathBuf::from("/");
    let mut limit = None;
    for name in Path::new(mountpoint).components().skip(1) {
        let directory = CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| ConfigError::Invalid("invalid mountpoint".into()))?;
        // SAFETY: directory is a valid, NUL-terminated path for this call.
        let result = unsafe {
            // A -1 result with errno unchanged means an indeterminate limit.
            *libc::__errno_location() = 0;
            libc::pathconf(directory.as_ptr(), libc::_PC_NAME_MAX)
        };
        if let Ok(current) = usize::try_from(result) {
            limit = Some(current);
        } else if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
            // Some filesystems do not specify a fixed maximum.
            limit = None;
        }
        if limit.is_some_and(|max| name.as_os_str().as_bytes().len() > max) {
            return Err(ConfigError::Invalid(
                "mountpoint component exceeds the filesystem name length limit".into(),
            ));
        }
        parent.push(name);
        match std::fs::symlink_metadata(&parent) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(ConfigError::Invalid(
                    "mountpoint path must not contain a symlink".into(),
                ));
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(ConfigError::Invalid(
                    "mountpoint path must contain only directories".into(),
                ));
            }
            Ok(_) => {}
            // The directory may be provisioned later, or the plan rendered by
            // a user who cannot search this part of the path.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) => {}
            Err(e) => {
                return Err(ConfigError::Invalid(format!(
                    "cannot resolve mountpoint: {e}"
                )));
            }
        }
    }
    Ok(())
}

/// An absolute, canonical path: no relative segments, no repeated slashes.
pub fn check_abs_path(name: &str, value: &str) -> Result<(), ConfigError> {
    check_argument(name, value)?;
    if !value.starts_with('/') {
        return Err(ConfigError::Invalid(format!(
            "{name} must be an absolute path"
        )));
    }
    if value == "/" {
        return Ok(());
    }
    if value.ends_with('/') {
        return Err(ConfigError::Invalid(format!(
            "{name} must not end with '/'"
        )));
    }
    for component in value.split('/').skip(1) {
        if component.is_empty() || component == "." || component == ".." {
            return Err(ConfigError::Invalid(format!(
                "{name} is not canonical (empty, '.' or '..' component)"
            )));
        }
    }
    Ok(())
}

pub fn check_volume_name(value: &str) -> Result<(), ConfigError> {
    // Match the format's MAX_VOLUME_NAME_BYTES without coupling the privileged helper to it.
    if value.len() > 64 {
        return Err(ConfigError::Invalid(
            "volume name must be at most 64 ASCII bytes".into(),
        ));
    }
    check_instance_name(value)
}

/// Validate the syntax used for stored instance aliases and cleanup paths.
pub fn check_instance_name(value: &str) -> Result<(), ConfigError> {
    check_argument("volume", value)?;
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ConfigError::Invalid(
            "volume name must be [A-Za-z0-9_-]".into(),
        ));
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
            "{name} is not a valid LVM name"
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
            "{name} is not a hyphenated UUID"
        )));
    }
    Ok(())
}

/// LVM's 6-4-4-4-4-4-6 alphanumeric identifier format.
pub fn check_lvm_uuid(name: &str, value: &str) -> Result<(), ConfigError> {
    check_argument(name, value)?;
    let parts: Vec<&str> = value.split('-').collect();
    let shape = [6usize, 4, 4, 4, 4, 4, 6];
    let ok = parts.len() == shape.len()
        && parts.iter().zip(shape).all(|(part, len)| {
            part.len() == len && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
        });
    if !ok {
        return Err(ConfigError::Invalid(format!("{name} is not an LVM UUID")));
    }
    Ok(())
}
