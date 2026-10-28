//! `/proc/swaps` filenames must reach the device classifier unchanged.
//! Synthetic inventories only: no host swap or device configuration changes.

use maki_nbdkit::security::{parse_proc_swaps, unsafe_swaps, SwapSafety};
use std::sync::Mutex;

const HEADER: &str = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";

fn inventory(name: &str) -> String {
    format!("{HEADER}{name} partition\t1048572\t0\t-2\n")
}

#[test]
fn ordinary_paths_and_empty_inventory_keep_the_existing_policy() {
    assert!(parse_proc_swaps(HEADER).unwrap().is_empty());
    let text = format!(
        "{HEADER}/dev/mapper/cryptswap partition 1024 0 -2\n/dev/plain-swap partition 1024 0 -3\n"
    );
    let unsafe_paths = unsafe_swaps(&text, |path| {
        if path == "/dev/mapper/cryptswap" {
            SwapSafety::Encrypted
        } else {
            SwapSafety::Unsafe
        }
    })
    .unwrap();
    assert_eq!(unsafe_paths, vec!["/dev/plain-swap"]);
}

#[test]
fn unicode_nonwhitespace_filename_is_preserved() {
    let path = "/dev/스왑장치";
    let entries = parse_proc_swaps(&inventory(path)).unwrap();
    assert_eq!(entries[0].name, path);
    assert_eq!(entries[0].kind, "partition");
}

#[test]
fn unicode_whitespace_stays_inside_the_kernel_filename() {
    for whitespace in [
        '\u{a0}', '\u{2003}', '\u{3000}', '\u{85}', '\u{2028}', '\u{2029}',
    ] {
        let path = format!("/dev/mapper/cryptswap{whitespace}plain");
        let entries = parse_proc_swaps(&inventory(&path)).unwrap();
        assert_eq!(entries[0].name, path);
        assert_eq!(entries[0].kind, "partition");
    }
}

#[test]
fn ascii_controls_the_kernel_does_not_escape_stay_in_the_filename() {
    for control in ['\u{b}', '\u{c}', '\r'] {
        let path = format!("/dev/swap{control}device");
        let entries = parse_proc_swaps(&inventory(&path)).unwrap();
        assert_eq!(entries[0].name, path);
        assert_eq!(entries[0].kind, "partition");
    }
}

#[test]
fn a_different_encrypted_prefix_cannot_approve_the_swap_device() {
    for whitespace in ['\u{a0}', '\u{2003}', '\u{3000}'] {
        let unsafe_path = format!("/dev/mapper/cryptswap{whitespace}plain");
        let classified = Mutex::new(Vec::new());
        let unsafe_paths = unsafe_swaps(&inventory(&unsafe_path), |path| {
            classified.lock().unwrap().push(path.to_owned());
            if path == "/dev/mapper/cryptswap" {
                SwapSafety::Encrypted
            } else {
                SwapSafety::Unsafe
            }
        })
        .unwrap();
        assert_eq!(classified.into_inner().unwrap(), vec![unsafe_path.clone()]);
        assert_eq!(unsafe_paths, vec![unsafe_path]);
    }
}

#[test]
fn escaped_safe_device_is_classified_by_its_original_name() {
    let original = "/dev/mapper/crypt swap";
    let encoded = r"/dev/mapper/crypt\040swap";
    let classified = Mutex::new(Vec::new());
    let unsafe_paths = unsafe_swaps(&inventory(encoded), |path| {
        classified.lock().unwrap().push(path.to_owned());
        if path == original {
            SwapSafety::Encrypted
        } else {
            SwapSafety::Unsafe
        }
    })
    .unwrap();
    assert_eq!(classified.into_inner().unwrap(), vec![original]);
    assert!(unsafe_paths.is_empty());
}

#[test]
fn all_four_kernel_filename_escapes_are_decoded() {
    for (encoded, decoded) in [
        (r"/dev/swap\040device", "/dev/swap device"),
        (r"/dev/swap\011device", "/dev/swap\tdevice"),
        (r"/dev/swap\012device", "/dev/swap\ndevice"),
        (r"/dev/swap\134device", r"/dev/swap\device"),
    ] {
        let entries = parse_proc_swaps(&inventory(encoded)).unwrap();
        assert_eq!(entries[0].name, decoded);
        assert_eq!(entries[0].kind, "partition");
    }
}

#[test]
fn escaped_backslash_is_decoded_once() {
    let entries = parse_proc_swaps(&inventory(r"/dev/swap\134040device")).unwrap();
    assert_eq!(entries[0].name, r"/dev/swap\040device");
}

#[test]
fn malformed_or_unsupported_filename_escapes_are_refused() {
    for encoded in [
        "/dev/swap\\",
        r"/dev/swap\0",
        r"/dev/swap\04",
        r"/dev/swap\777device",
        r"/dev/swap\000device",
        r"/dev/swap\057device",
        r"/dev/swap\x20device",
        "/dev/swap\0device",
        "relative-device",
    ] {
        assert!(
            parse_proc_swaps(&inventory(encoded)).is_err(),
            "{encoded:?}"
        );
    }
}

#[test]
fn header_must_name_all_kernel_columns_in_order() {
    for header in [
        "",
        "Filename",
        "Filename Type",
        "FilenameBogus Type Size Used Priority",
        "Filename Type Used Size Priority",
        "Filename Type Size Used Priority Extra",
        "Filename\u{a0}Type Size Used Priority",
    ] {
        let text = format!("{header}\n/dev/swap partition 1 0 -2\n");
        assert!(parse_proc_swaps(&text).is_err(), "{header:?}");
    }
}

#[test]
fn malformed_full_rows_fail_before_any_classification() {
    for row in [
        "/dev/swap partition",
        "/dev/swap partition 1 0",
        "/dev/swap partition 1 0 -2 extra",
        "/dev/swap unknown 1 0 -2",
        "/dev/swap partition bad 0 -2",
        "/dev/swap partition -1 0 -2",
        "/dev/swap partition +1 0 -2",
        "/dev/swap partition 18446744073709551616 0 -2",
        "/dev/swap partition 1 bad -2",
        "/dev/swap partition 1 18446744073709551616 -2",
        "/dev/swap partition 1 0 bad",
        "/dev/swap partition 1 0 +2",
        "/dev/swap partition 1 0 2147483648",
        "/dev/swap partition 1 0 -2147483649",
    ] {
        let text = format!("{HEADER}{row}\n");
        let result = unsafe_swaps(&text, |_| panic!("malformed inventory reached classifier"));
        assert!(result.is_err(), "{row:?}");
    }
}

#[test]
fn numeric_columns_accept_their_types_without_extra_policy_assumptions() {
    let text = format!(
        "{HEADER}/dev/swap-a partition 0 18446744073709551615 -2147483648\n/dev/swap-b file 18446744073709551615 0 2147483647\n"
    );
    let entries = parse_proc_swaps(&text).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].kind, "file");
}

#[test]
fn malformed_inventory_diagnostics_do_not_repeat_filename_contents() {
    let marker = "synthetic-private-filename-marker";
    let text = format!("{HEADER}/dev/{marker} partition bad 0 -2\n");
    let error = parse_proc_swaps(&text).unwrap_err();
    assert!(!error.contains(marker));
    assert!(error.contains("/proc/swaps"));
}
