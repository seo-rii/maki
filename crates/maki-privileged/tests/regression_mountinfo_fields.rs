//! BUG-164: Linux separates mountinfo fields with ASCII spaces, preserving
//! other Unicode whitespace and unescaped control characters inside paths.

use maki_privileged::config::{AttachConfig, AttachOverrides};
use maki_privileged::probe::parse_mountinfo;

fn configured_mountpoint(path: &str) -> String {
    AttachConfig {
        volume_uuid: Some("01234567-89ab-cdef-0123-456789abcdef".into()),
        mountpoint: Some(path.into()),
        ..AttachConfig::default()
    }
    .into_request("audit", AttachOverrides::default(), true)
    .expect("the real attach config accepts this absolute UTF-8 path")
    .mountpoint
}

fn escape_path(path: &str) -> String {
    // The four path bytes escaped by Linux's mountinfo output.
    path.replace('\\', "\\134")
        .replace(' ', "\\040")
        .replace('\t', "\\011")
        .replace('\n', "\\012")
}

fn mountinfo(path: &str, source: &str) -> String {
    format!(
        "35 27 253:0 / {} rw,noatime - xfs {} rw\n",
        escape_path(path),
        escape_path(source)
    )
}

#[test]
fn mountinfo_escaped_ascii_paths_and_ordinary_unicode_remain_supported() {
    for path in [
        "/srv/audit data",
        "/srv/audit\tdata",
        "/srv/audit\ndata",
        "/srv/audit\\data",
        "/srv/마키",
    ] {
        let source = "/dev/audit device";
        let observed = parse_mountinfo(&mountinfo(path, source), path).unwrap();
        assert_eq!(observed.fstype, "xfs");
        assert_eq!(observed.major_minor, "253:0");
        assert_eq!(observed.source, source);
        assert_eq!(observed.mount_options, ["rw", "noatime"]);
    }
}

#[test]
fn mountinfo_preserves_configured_unicode_whitespace_paths() {
    for space in ['\u{00a0}', '\u{2003}', '\u{3000}'] {
        let path = configured_mountpoint(&format!("/srv/audit{space}data"));
        let observed = parse_mountinfo(&mountinfo(&path, "/dev/dm-0"), &path);
        assert!(
            observed.is_some(),
            "valid mounted path reported absent: {path:?}"
        );
    }
}

#[test]
fn mountinfo_preserves_unescaped_whitespace_in_path_and_source_fields() {
    // These ASCII controls cannot occur in Maki's configured mountpoint, but
    // can occur in the kernel inventory's other paths. split_ascii_whitespace
    // would still corrupt CR and form-feed, so only ASCII SPACE separates fields.
    for space in [
        '\r', '\u{000b}', '\u{000c}', '\u{00a0}', '\u{2003}', '\u{3000}',
    ] {
        let path = format!("/srv/audit{space}data");
        let source = format!("/dev/audit{space}device");
        let observed = parse_mountinfo(&mountinfo(&path, &source), &path)
            .unwrap_or_else(|| panic!("valid mounted path reported absent: {path:?}"));
        assert_eq!(observed.source, source);
        assert_eq!(observed.mount_options, ["rw", "noatime"]);
    }
}

/// Linux emits path, source and type bytes other than space, tab, newline
/// and backslash unescaped, so a foreign mount's fields need not be UTF-8.
#[test]
fn non_utf8_records_neither_fail_nor_hide_the_configured_mount() {
    let path = configured_mountpoint("/srv/audit");
    let foreign = b"36 27 0:61 / /home/user/fuse-\xff rw,nosuid - fuse.\xfe \xfd rw\n";
    let table = [
        foreign.as_slice(),
        mountinfo(&path, "/dev/dm-0").as_bytes(),
        foreign,
    ]
    .concat();
    let observed = parse_mountinfo(&table, &path).expect("the volume stays visible");
    assert_eq!(observed.fstype, "xfs");
    assert_eq!(observed.major_minor, "253:0");
    assert_eq!(observed.source, "/dev/dm-0");

    // The mount at the path is still found when only its source is not
    // UTF-8; the source is a probe hint, decoded lossily.
    let table = [
        format!("35 27 253:0 / {path} rw,noatime - xfs ").as_bytes(),
        b"/dev/\xff rw\n",
    ]
    .concat();
    let observed = parse_mountinfo(&table, &path).unwrap();
    assert_eq!(observed.source, "/dev/\u{fffd}");
    assert_eq!(observed.mount_options, ["rw", "noatime"]);
}

#[test]
fn non_utf8_paths_match_only_their_exact_bytes() {
    // A replacement character in a configured path is not the byte it
    // would replace, raw or escaped: nothing decodes a path lossily.
    let replacement = "/srv/audit\u{fffd}";
    for raw in [b"/srv/audit\xff".as_slice(), b"/srv/audit\\377"] {
        let table = [b"35 27 253:0 / ", raw, b" rw - xfs /dev/dm-0 rw\n"].concat();
        assert!(parse_mountinfo(&table, replacement).is_none(), "{raw:?}");
        assert!(parse_mountinfo(&table, "/srv/audit").is_none(), "{raw:?}");
    }
    assert!(parse_mountinfo(&mountinfo(replacement, "/dev/dm-0"), replacement).is_some());
}
