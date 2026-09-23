//! Process hardening from the `[security]` section (SPEC §36–§37; review
//! M-013): applied before the volume is attached, fail-closed on Linux,
//! and reported in `status` so nothing is a placebo.
//!
//! | Setting | Effect on Linux |
//! |---|---|
//! | `disable_core_dump` | `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE = 0`, verified |
//! | `madv_dontdump` | Honoured through `disable_core_dump` (a non-dumpable process writes no core); validation refuses it without that flag |
//! | `memory_lock_mode = "all"` | `mlockall(MCL_CURRENT \| MCL_FUTURE)`; failure refuses attach |
//! | `memory_lock_mode = "secure-buffers"` | Every `SecretBuffer` is `mlock`ed for its lifetime (best effort, failures counted) |
//! | `require_secure_swap_policy` | `/proc/swaps` must be readable and list only RAM-only zram devices (`/dev/zramN` with no `backing_dev`) or dm-crypt devices with independent physical backing (the same rule applies to zram writeback); anything else, an unreadable file, or an unparseable one refuses attach |
//! | `cache.lock_memory` | Cache plaintext lives in `SecretBuffer`s, so it follows `memory_lock_mode` (validation refuses it with `off`) |
//!
//! On non-Linux hosts nothing is enforced; the posture says so and a
//! warning is logged. Production runs on Linux. The swap topology is checked
//! at attach; operators must keep it fixed for the lifetime of the attachment.

use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use maki_format::config::VolumeConfig;

use crate::daemon::DaemonError;

/// What was actually applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPosture {
    /// "linux" or "unsupported-platform".
    pub platform: &'static str,
    pub core_dump_disabled: bool,
    pub memory_lock_mode: String,
    pub secret_buffers_locked: bool,
    pub process_locked: bool,
    /// Human-readable swap policy result.
    pub swap_policy: String,
}

fn posture_slot() -> &'static Mutex<Option<SecurityPosture>> {
    static SLOT: OnceLock<Mutex<Option<SecurityPosture>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// The posture applied by the last [`apply`] in this process.
pub fn posture() -> Option<SecurityPosture> {
    posture_slot().lock().unwrap().clone()
}

/// JSON for the control socket `status` document.
pub fn posture_json() -> Value {
    match posture() {
        None => json!({ "applied": false }),
        Some(p) => json!({
            "applied": true,
            "platform": p.platform,
            "core_dump_disabled": p.core_dump_disabled,
            "memory_lock_mode": p.memory_lock_mode,
            "secret_buffers_locked": p.secret_buffers_locked,
            "secret_buffer_lock_failures": maki_crypto::secret::page_lock_failures(),
            "process_locked": p.process_locked,
            "swap_policy": p.swap_policy,
        }),
    }
}

/// How one swap device was classified for the secure-swap policy (F05:
/// the classification is by device identity, never by its name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapSafety {
    /// A zram device with no writeback backing device: RAM only.
    RamOnly,
    /// A dm-crypt mapping with independent backing, or zram writing to one.
    Encrypted,
    /// Everything else, including devices that could not be classified.
    Unsafe,
}

/// One line of `/proc/swaps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapEntry {
    pub name: String,
    pub kind: String,
}

/// Parse `/proc/swaps`. The file always starts with a `Filename` header
/// line, even with no swap; anything else is not the file's format and is
/// an error, never "no swap" (a read failure must not pass the policy).
pub fn parse_proc_swaps(text: &str) -> Result<Vec<SwapEntry>, String> {
    let mut lines = text.lines();
    match lines.next() {
        Some(header) if header.trim_start().starts_with("Filename") => {}
        other => {
            return Err(format!(
                "/proc/swaps does not start with the Filename header (got {:?})",
                other.unwrap_or("")
            ))
        }
    }
    let mut entries = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(name), Some(kind)) = (fields.next(), fields.next()) else {
            return Err(format!("unparseable /proc/swaps line {line:?}"));
        };
        entries.push(SwapEntry {
            name: name.to_string(),
            kind: kind.to_string(),
        });
    }
    Ok(entries)
}

/// Swap entries `classify` does not prove RAM-only or encrypted. An
/// unparseable file is an error.
pub fn unsafe_swaps(
    proc_swaps: &str,
    classify: impl Fn(&str) -> SwapSafety,
) -> Result<Vec<String>, String> {
    Ok(parse_proc_swaps(proc_swaps)?
        .into_iter()
        .filter(|entry| classify(&entry.name) == SwapSafety::Unsafe)
        .map(|entry| entry.name)
        .collect())
}

/// The index of a `/dev/zramN` device — exactly that path, so a swap file
/// or partition merely *named* like zram never matches.
pub fn zram_index(device: &str) -> Option<u32> {
    let rest = device.strip_prefix("/dev/zram")?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

/// The writeback target a zram device would page to, from its
/// `/sys/block/zramN/backing_dev` attribute. `None` means RAM only: the
/// attribute says `none`, or the kernel has no zram writeback support and
/// the attribute is absent.
pub fn zram_writeback_target(backing_dev: Option<&str>) -> Option<String> {
    let value = backing_dev?.trim();
    if value.is_empty() || value == "none" {
        None
    } else {
        Some(value.to_string())
    }
}

/// Classify a zram device from the *result* of reading its `backing_dev`
/// attribute plus a check for whether a writeback target is itself encrypted.
///
/// A missing attribute (`NotFound`) means the kernel lacks zram writeback
/// support, so the device is genuinely RAM-only. Any *other* read failure
/// (`PermissionDenied`, an I/O error, …) is ambiguous: the device may have a
/// plaintext writeback target we simply could not read, so it fails closed as
/// `Unsafe` rather than being trusted as RAM-only (MAKI-017).
pub fn classify_zram_backing(
    backing_dev: Result<String, std::io::ErrorKind>,
    is_encrypted: impl Fn(&str) -> bool,
) -> SwapSafety {
    match backing_dev {
        Ok(value) if value.trim().is_empty() => SwapSafety::Unsafe,
        Ok(value) => match zram_writeback_target(Some(&value)) {
            None => SwapSafety::RamOnly,
            Some(target) if is_encrypted(&target) => SwapSafety::Encrypted,
            Some(_) => SwapSafety::Unsafe,
        },
        Err(std::io::ErrorKind::NotFound) => SwapSafety::RamOnly,
        Err(_) => SwapSafety::Unsafe,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    type Device = (u32, u32);

    fn device_number(path: &Path) -> Option<Device> {
        let value = std::fs::read_to_string(path.join("dev")).ok()?;
        let (major, minor) = value.trim().split_once(':')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    }

    /// Resolve through the kernel's major:minor index, then cross-check the
    /// target. A device pathname or a stale/inconsistent dependency is not proof.
    fn block_node(sysfs: &Path, device: Device) -> Option<PathBuf> {
        let path = sysfs
            .join(format!("dev/block/{}:{}", device.0, device.1))
            .canonicalize()
            .ok()?;
        (path.starts_with(sysfs.join("devices")) && device_number(&path) == Some(device))
            .then_some(path)
    }

    /// A bounded proof that every dependency terminates at a physical device.
    /// In particular, dm-crypt above Maki (or any other NBD server) can recurse
    /// into the process being paged out and is never safe swap for that process.
    struct IndependentBacking<'a> {
        sysfs: &'a Path,
        visiting: HashSet<Device>,
        proven: HashSet<Device>,
        remaining: usize,
    }

    impl IndependentBacking<'_> {
        fn prove(&mut self, device: Device, depth: usize) -> Option<()> {
            if depth >= 64 || self.remaining == 0 {
                return None;
            }
            self.remaining -= 1;
            let path = block_node(self.sysfs, device)?;
            let name = path.file_name()?.to_str()?;
            // NBD has the reserved block major 43; the name check also refuses
            // an unexpected sysfs identity instead of weakening the policy.
            if device.0 == 43 || name.starts_with("nbd") {
                return None;
            }
            if self.proven.contains(&device) {
                return Some(());
            }
            if !self.visiting.insert(device) {
                return None;
            }

            match std::fs::read_to_string(path.join("partition")) {
                Ok(index) => {
                    if index.trim().parse::<u32>().ok()? == 0 {
                        return None;
                    }
                    // A partition inherits the whole disk's dependencies.
                    let parent = path.parent()?;
                    let parent_device = device_number(parent)?;
                    if block_node(self.sysfs, parent_device)? != parent {
                        return None;
                    }
                    self.prove(parent_device, depth + 1)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut has_dependencies = false;
                    for entry in std::fs::read_dir(path.join("slaves")).ok()? {
                        let dependency = entry.ok()?.path().canonicalize().ok()?;
                        let child = device_number(&dependency)?;
                        if block_node(self.sysfs, child)? != dependency {
                            return None;
                        }
                        has_dependencies = true;
                        self.prove(child, depth + 1)?;
                    }
                    if !has_dependencies {
                        // Loop, NBD, ublk, and other unknown virtual leaves do
                        // not establish independent backing. Physical leaves
                        // must expose a kernel device link outside virtual/.
                        let virtual_devices = self.sysfs.join("devices/virtual");
                        std::fs::read_link(path.join("device")).ok()?;
                        let physical = path.join("device").canonicalize().ok()?;
                        if path.starts_with(&virtual_devices)
                            || !physical.starts_with(self.sysfs.join("devices"))
                            || physical.starts_with(&virtual_devices)
                        {
                            return None;
                        }
                    }
                }
                Err(_) => return None,
            }
            // Fail closed if the indexed node disappeared or changed during
            // the walk. Operators must keep swap topology fixed while attached.
            if block_node(self.sysfs, device)? != path {
                return None;
            }
            self.visiting.remove(&device);
            self.proven.insert(device);
            Some(())
        }
    }

    fn is_encrypted_swap(device: Device, sysfs: &Path) -> bool {
        let Some(path) = block_node(sysfs, device) else {
            return false;
        };
        if !std::fs::read_to_string(path.join("dm/uuid"))
            .is_ok_and(|uuid| uuid.trim().starts_with("CRYPT-"))
        {
            return false;
        }
        IndependentBacking {
            sysfs,
            visiting: HashSet::new(),
            proven: HashSet::new(),
            remaining: 256,
        }
        .prove(device, 0)
        .is_some()
    }

    /// Resolve aliases to their block-device identity before inspecting sysfs.
    /// Only RAM-only zram or dm-crypt with proven independent backing passes.
    pub(super) fn classify_swap(device: &str) -> SwapSafety {
        classify_swap_with(device, Path::new("/sys"), &|path| {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let metadata = std::fs::metadata(path).ok()?;
            if !metadata.file_type().is_block_device() {
                return None;
            }
            Some((libc::major(metadata.rdev()), libc::minor(metadata.rdev())))
        })
    }

    pub(super) fn classify_swap_with(
        device: &str,
        sysfs_root: &Path,
        resolve: &impl Fn(&str) -> Option<Device>,
    ) -> SwapSafety {
        let Some(device) = resolve(device) else {
            return SwapSafety::Unsafe;
        };
        let Ok(sysfs) = sysfs_root.canonicalize() else {
            return SwapSafety::Unsafe;
        };
        let Some(path) = block_node(&sysfs, device) else {
            return SwapSafety::Unsafe;
        };
        let is_zram = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| zram_index(&format!("/dev/{name}")))
            .is_some()
            && path.parent() == Some(sysfs.join("devices/virtual/block").as_path());
        if is_zram {
            let read = std::fs::read_to_string(path.join("backing_dev")).map_err(|e| e.kind());
            let result = classify_zram_backing(read, |target| {
                resolve(target).is_some_and(|target| is_encrypted_swap(target, &sysfs))
            });
            // A disappearing zram is not a device without writeback support.
            return if block_node(&sysfs, device).as_ref() == Some(&path) {
                result
            } else {
                SwapSafety::Unsafe
            };
        }
        if is_encrypted_swap(device, &sysfs) {
            SwapSafety::Encrypted
        } else {
            SwapSafety::Unsafe
        }
    }

    pub fn apply(config: &VolumeConfig) -> Result<SecurityPosture, DaemonError> {
        let security = &config.security;
        let mut core_dump_disabled = false;
        if security.disable_core_dump {
            // SAFETY: plain prctl/setrlimit calls with constant arguments.
            unsafe {
                if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                    return Err(DaemonError::Unsupported(format!(
                        "security.disable_core_dump: PR_SET_DUMPABLE failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                    return Err(DaemonError::Unsupported(format!(
                        "security.disable_core_dump: RLIMIT_CORE=0 failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                if libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 {
                    return Err(DaemonError::Unsupported(
                        "security.disable_core_dump: process is still dumpable".to_string(),
                    ));
                }
            }
            core_dump_disabled = true;
        }

        let mut process_locked = false;
        let mut secret_buffers_locked = false;
        match security.memory_lock_mode.as_str() {
            "all" => {
                // SAFETY: mlockall with constant flags.
                if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
                    return Err(DaemonError::Unsupported(format!(
                        "security.memory_lock_mode = \"all\": mlockall failed: {} \
                         (raise LimitMEMLOCK / RLIMIT_MEMLOCK or use secure-buffers)",
                        std::io::Error::last_os_error()
                    )));
                }
                process_locked = true;
                // Everything is locked already; no per-buffer syscalls needed.
                maki_crypto::secret::set_page_locking(false);
            }
            "secure-buffers" => {
                maki_crypto::secret::set_page_locking(true);
                secret_buffers_locked = true;
            }
            _ => maki_crypto::secret::set_page_locking(false),
        }

        let swap_policy = if security.require_secure_swap_policy {
            // A check that cannot run has not passed: an unreadable or
            // garbled /proc/swaps refuses attach instead of reading as
            // "no swap" (F05).
            let text = std::fs::read_to_string("/proc/swaps").map_err(|e| {
                DaemonError::Unsupported(format!(
                    "security.require_secure_swap_policy: cannot read /proc/swaps ({e}); \
                     the swap layout is unknown, refusing to assume it is safe"
                ))
            })?;
            let entries = parse_proc_swaps(&text).map_err(|e| {
                DaemonError::Unsupported(format!(
                    "security.require_secure_swap_policy: {e}; refusing to assume it is safe"
                ))
            })?;
            let unsafe_entries: Vec<String> = entries
                .iter()
                .filter(|entry| classify_swap(&entry.name) == SwapSafety::Unsafe)
                .map(|entry| entry.name.clone())
                .collect();
            if !unsafe_entries.is_empty() {
                return Err(DaemonError::Unsupported(format!(
                    "security.require_secure_swap_policy: swap {:?} is neither RAM-only zram \
                     nor dm-crypt with proven independent backing; disable it or use encrypted \
                     swap on an independent physical device (SPEC 37)",
                    unsafe_entries
                )));
            }
            if entries.is_empty() {
                "enforced: no swap".to_string()
            } else {
                "enforced: RAM-only zram or independently backed encrypted swap only".to_string()
            }
        } else {
            "not required".to_string()
        };

        Ok(SecurityPosture {
            platform: "linux",
            core_dump_disabled,
            memory_lock_mode: security.memory_lock_mode.clone(),
            secret_buffers_locked,
            process_locked,
            swap_policy,
        })
    }
}

/// Apply the configured hardening and record the posture. Linux enforces
/// every setting (fail closed); other hosts record that nothing was
/// enforced.
pub fn apply(config: &VolumeConfig) -> Result<SecurityPosture, DaemonError> {
    #[cfg(target_os = "linux")]
    let posture = linux::apply(config)?;
    #[cfg(not(target_os = "linux"))]
    let posture = {
        tracing::warn!(
            "[security] settings are not enforced on this platform (development host); \
             production runs on Linux"
        );
        maki_crypto::secret::set_page_locking(false);
        SecurityPosture {
            platform: "unsupported-platform",
            core_dump_disabled: false,
            memory_lock_mode: config.security.memory_lock_mode.clone(),
            secret_buffers_locked: false,
            process_locked: false,
            swap_policy: "not enforced (platform)".to_string(),
        }
    };
    *posture_slot().lock().unwrap() = Some(posture.clone());
    Ok(posture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_parser_flags_only_unencrypted_non_zram_entries() {
        let swaps = "Filename\t\t\t\tType\t\tSize\tUsed\tPriority
/dev/zram0                              partition\t8388604\t0\t100
/dev/dm-3                               partition\t4194300\t0\t-2
/swapfile                               file\t\t1048572\t0\t-3
";
        let classify = |name: &str| match name {
            "/dev/dm-3" => SwapSafety::Encrypted,
            "/dev/zram0" => SwapSafety::RamOnly,
            _ => SwapSafety::Unsafe,
        };
        let flagged = unsafe_swaps(swaps, classify).unwrap();
        assert_eq!(flagged, vec!["/swapfile".to_string()]);
        assert!(
            unsafe_swaps("Filename Type Size Used Priority\n", |_| SwapSafety::Unsafe)
                .unwrap()
                .is_empty()
        );
        assert!(
            unsafe_swaps("", |_| SwapSafety::Unsafe).is_err(),
            "an empty file is not the /proc/swaps format"
        );
    }

    /// MAKI-017: an unreadable `backing_dev` (EACCES/EIO) is ambiguous and must
    /// fail closed as Unsafe, not be trusted as RAM-only; only a genuinely
    /// absent attribute (NotFound) or an explicit `none` is RAM-only.
    #[test]
    fn zram_backing_read_failure_is_unsafe_not_ram_only() {
        use std::io::ErrorKind;
        let enc = |t: &str| t == "/dev/mapper/cryptswap";
        // Genuinely RAM-only: no writeback support, or writeback disabled.
        assert_eq!(
            classify_zram_backing(Err(ErrorKind::NotFound), enc),
            SwapSafety::RamOnly
        );
        assert_eq!(
            classify_zram_backing(Ok("none\n".to_string()), enc),
            SwapSafety::RamOnly
        );
        // Ambiguous read failures must not be trusted as RAM-only.
        for kind in [ErrorKind::PermissionDenied, ErrorKind::Other] {
            assert_eq!(
                classify_zram_backing(Err(kind), enc),
                SwapSafety::Unsafe,
                "{kind:?}"
            );
        }
        // A readable writeback target is classified by whether it is encrypted.
        assert_eq!(
            classify_zram_backing(Ok("/dev/sda2\n".to_string()), enc),
            SwapSafety::Unsafe
        );
        assert_eq!(
            classify_zram_backing(Ok("/dev/mapper/cryptswap\n".to_string()), enc),
            SwapSafety::Encrypted
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "security_swap_tests.rs"]
mod swap_topology_tests;
