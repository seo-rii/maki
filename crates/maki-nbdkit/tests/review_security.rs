//! Review M-013 (security settings): what `[security]` asks for is either
//! enforced or reported as not enforced, never silently accepted. Linux
//! enforces; the posture document says what happened.

use std::sync::{Mutex, MutexGuard, OnceLock};

use maki_nbdkit::daemon::parse_and_validate;
use maki_nbdkit::security::{
    apply, parse_proc_swaps, posture, posture_json, unsafe_swaps, zram_index,
    zram_writeback_target, SwapSafety,
};

/// `apply` records a process-global posture: tests that call it must not
/// interleave.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn config(security: &str, cache: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "sec"
max_virtual_size = "1MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "env", name = "k" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/x"
[cache]
{cache}
[security]
{security}
"#
    )
}

#[test]
fn inconsistent_security_settings_are_rejected_at_validation() {
    let err = parse_and_validate(&config(
        "disable_core_dump = false\nmadv_dontdump = true",
        "",
    ))
    .unwrap_err();
    assert!(err.to_string().contains("madv_dontdump"), "{err}");

    let err = parse_and_validate(&config("memory_lock_mode = \"off\"", "lock_memory = true"))
        .unwrap_err();
    assert!(err.to_string().contains("lock_memory"), "{err}");

    parse_and_validate(&config(
        "memory_lock_mode = \"off\"\nmadv_dontdump = false",
        "lock_memory = false",
    ))
    .unwrap();
}

#[test]
fn swap_parser_is_strict() {
    let swaps = "Filename Type Size Used Priority\n/dev/sda2 partition 1 0 -2\n/dev/zram0 partition 1 0 100\n";
    let ram_only_zram = |n: &str| {
        if zram_index(n).is_some() {
            SwapSafety::RamOnly
        } else {
            SwapSafety::Unsafe
        }
    };
    assert_eq!(
        unsafe_swaps(swaps, ram_only_zram).unwrap(),
        vec!["/dev/sda2".to_string()]
    );
    assert!(unsafe_swaps(swaps, |n| if n == "/dev/sda2" {
        SwapSafety::Encrypted
    } else {
        ram_only_zram(n)
    })
    .unwrap()
    .is_empty());
}

// ---------- F05 (third review): swap safety is decided by device identity ----------

/// A swap file whose *name* contains "zram" is a plain swap file; a zram
/// device is only RAM-only while it has no writeback target; and a
/// classifier that cannot prove either flags the entry.
#[test]
fn swap_classification_never_trusts_a_name() {
    let swaps = "Filename Type Size Used Priority\n\
                 /var/swap/zram-backup file 1 0 -2\n\
                 /dev/zram0 partition 1 0 100\n\
                 /dev/zram1 partition 1 0 90\n";
    // /dev/zram1 pages out to an unencrypted disk; /dev/zram0 is RAM only.
    let classify = |n: &str| match n {
        "/dev/zram0" => SwapSafety::RamOnly,
        _ => SwapSafety::Unsafe,
    };
    assert_eq!(
        unsafe_swaps(swaps, classify).unwrap(),
        vec![
            "/var/swap/zram-backup".to_string(),
            "/dev/zram1".to_string()
        ]
    );
    assert_eq!(zram_index("/dev/zram0"), Some(0));
    assert_eq!(zram_index("/dev/zram12"), Some(12));
    assert_eq!(zram_index("/dev/zram"), None);
    assert_eq!(zram_index("/dev/zram0p1"), None);
    assert_eq!(zram_index("/var/swap/zram-backup"), None);
    assert_eq!(zram_index("/dev/mapper/zram0"), None);
}

/// `/sys/block/zramN/backing_dev`: `none` or absent means RAM only;
/// anything else names the device zram writes back to.
#[test]
fn zram_writeback_target_is_read_from_sysfs_not_assumed() {
    assert_eq!(zram_writeback_target(Some("none\n")), None);
    assert_eq!(zram_writeback_target(Some("")), None);
    assert_eq!(zram_writeback_target(None), None);
    assert_eq!(
        zram_writeback_target(Some("/dev/sda3\n")),
        Some("/dev/sda3".to_string())
    );
    assert_eq!(
        zram_writeback_target(Some("/dev/mapper/cryptswap\n")),
        Some("/dev/mapper/cryptswap".to_string())
    );
}

/// An unreadable or garbled `/proc/swaps` used to read as "no swap" and
/// pass the policy. Not the format = an error, never a pass.
#[test]
fn unparseable_proc_swaps_is_an_error_not_no_swap() {
    assert!(parse_proc_swaps("").is_err());
    assert!(parse_proc_swaps("garbage\n/dev/sda2 partition 1 0 -2\n").is_err());
    assert!(
        parse_proc_swaps("Filename Type\n/dev/sda2\n").is_err(),
        "short line"
    );
    assert!(parse_proc_swaps("Filename Type Size Used Priority\n")
        .unwrap()
        .is_empty());
    let entries =
        parse_proc_swaps("Filename Type Size Used Priority\n/dev/sda2 partition 1 0 -2\n").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "/dev/sda2");
    assert_eq!(entries[0].kind, "partition");
    assert!(unsafe_swaps("", |_| SwapSafety::RamOnly).is_err());
}

#[test]
fn posture_is_recorded_and_reported() {
    let _serial = serial();
    let cfg = parse_and_validate(&config(
        "disable_core_dump = true\nmemory_lock_mode = \"secure-buffers\"\nrequire_secure_swap_policy = false",
        "",
    ))
    .unwrap();
    let applied = apply(&cfg).unwrap();
    assert_eq!(posture().unwrap(), applied);
    let json = posture_json();
    assert_eq!(json["applied"], serde_json::json!(true));
    assert_eq!(
        json["memory_lock_mode"],
        serde_json::json!("secure-buffers")
    );
    if cfg!(target_os = "linux") {
        assert_eq!(json["platform"], serde_json::json!("linux"));
        assert_eq!(json["core_dump_disabled"], serde_json::json!(true));
        assert_eq!(json["secret_buffers_locked"], serde_json::json!(true));
        assert!(maki_crypto::secret::page_locking_enabled());
        // Undo the process-wide toggle for the other tests in this binary.
        maki_crypto::secret::set_page_locking(false);
    } else {
        assert_eq!(json["platform"], serde_json::json!("unsupported-platform"));
        assert_eq!(json["core_dump_disabled"], serde_json::json!(false));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_disables_core_dumps_for_real() {
    let _serial = serial();
    let cfg = parse_and_validate(&config(
        "disable_core_dump = true\nmemory_lock_mode = \"off\"\nmadv_dontdump = false\nrequire_secure_swap_policy = false",
        "lock_memory = false",
    ))
    .unwrap();
    apply(&cfg).unwrap();
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    // Either the kernel reports the flag, or prctl agrees.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(dumpable, 0, "{status}");
}
