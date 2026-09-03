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
//! | `require_secure_swap_policy` | `/proc/swaps` must be empty or list only zram / dm-crypt devices; otherwise attach is refused |
//! | `cache.lock_memory` | Cache plaintext lives in `SecretBuffer`s, so it follows `memory_lock_mode` (validation refuses it with `off`) |
//!
//! On non-Linux hosts nothing is enforced; the posture says so and a
//! warning is logged. Production runs on Linux.

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

/// Swap entries from `/proc/swaps` that are neither zram nor proven
/// encrypted by `is_encrypted`.
pub fn unsafe_swaps(proc_swaps: &str, is_encrypted: impl Fn(&str) -> bool) -> Vec<String> {
    proc_swaps
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| !name.contains("zram") && !is_encrypted(name))
        .map(|s| s.to_string())
        .collect()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    fn dm_uuid_for(device: &str) -> Option<String> {
        // /dev/dm-N -> /sys/block/dm-N/dm/uuid; /dev/mapper/<name> -> find by dm/name.
        if let Some(dm) = device.strip_prefix("/dev/") {
            if dm.starts_with("dm-") {
                return std::fs::read_to_string(format!("/sys/block/{dm}/dm/uuid")).ok();
            }
            if let Some(name) = dm.strip_prefix("mapper/") {
                for entry in std::fs::read_dir("/sys/block").ok()?.flatten() {
                    let path = entry.path();
                    let dm_name = std::fs::read_to_string(path.join("dm/name")).ok();
                    if dm_name.map(|n| n.trim() == name).unwrap_or(false) {
                        return std::fs::read_to_string(path.join("dm/uuid")).ok();
                    }
                }
            }
        }
        None
    }

    fn is_encrypted_swap(device: &str) -> bool {
        dm_uuid_for(device)
            .map(|uuid| uuid.trim().starts_with("CRYPT-"))
            .unwrap_or(false)
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
            let text = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
            let unsafe_entries = unsafe_swaps(&text, is_encrypted_swap);
            if !unsafe_entries.is_empty() {
                return Err(DaemonError::Unsupported(format!(
                    "security.require_secure_swap_policy: swap {:?} is neither zram nor \
                     dm-crypt; disable it or encrypt it (SPEC 37)",
                    unsafe_entries
                )));
            }
            if text.lines().count() <= 1 {
                "enforced: no swap".to_string()
            } else {
                "enforced: zram or encrypted swap only".to_string()
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
        let flagged = unsafe_swaps(swaps, |name| name == "/dev/dm-3");
        assert_eq!(flagged, vec!["/swapfile".to_string()]);
        assert!(unsafe_swaps("Filename Type Size Used Priority\n", |_| false).is_empty());
        assert!(unsafe_swaps("", |_| false).is_empty());
    }
}
