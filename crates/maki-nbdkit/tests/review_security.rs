//! Review M-013 (security settings): what `[security]` asks for is either
//! enforced or reported as not enforced, never silently accepted. Linux
//! enforces; the posture document says what happened.

use maki_nbdkit::daemon::parse_and_validate;
use maki_nbdkit::security::{apply, posture, posture_json, unsafe_swaps};

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
    assert_eq!(
        unsafe_swaps(swaps, |_| false),
        vec!["/dev/sda2".to_string()]
    );
    assert!(unsafe_swaps(swaps, |n| n == "/dev/sda2").is_empty());
}

#[test]
fn posture_is_recorded_and_reported() {
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
