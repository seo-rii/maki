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
