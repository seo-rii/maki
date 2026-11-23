//! Linux prints a mount whose source string is empty as an empty field:
//! `76 75 0:41 / /run/x rw,relatime - tmpfs  rw,mode=755`, with two spaces
//! before the super options (`mount -t tmpfs '' /dir`, or a FUSE mount with
//! an empty `fsname`). One such mount anywhere in the helper's mount
//! namespace must not make the privileged observations fail. Dropping the
//! empty field left the record with two filesystem fields, so NBD
//! allocation (every attach) and cleanup (planned stop, `maki-recover@`)
//! refused for every volume, and the post-mount verifier read the super
//! options as the mount's source.
//!
//! The kernel scenario needs root and `unshare`. It runs in a child process
//! inside a private mount namespace (`unshare --mount --propagation
//! private`) that mounts a tmpfs over `/run` and further tmpfs mounts below
//! it. Nothing is mounted in the test's own namespace: the child refuses to
//! run unless its namespace differs from the parent's. Without root or a
//! usable `unshare` the test is skipped.

use maki_privileged::probe::parse_mountinfo;

#[test]
fn an_empty_mount_source_is_an_empty_field() {
    let path = "/srv/audit";
    let table = format!("35 27 253:0 / {path} rw,noatime - xfs  rw,attr2\n");
    let observed = parse_mountinfo(&table, path).expect("the mount is visible");
    assert_eq!(observed.fstype, "xfs");
    assert_eq!(observed.source, "", "the super options are not the source");
    assert_eq!(observed.major_minor, "253:0");
    assert_eq!(observed.mount_options, ["rw", "noatime"]);

    // An unrelated empty-source mount neither hides nor replaces the one
    // at the path.
    let unrelated = "36 27 0:41 / /run/empty rw,relatime - tmpfs  rw,mode=755\n";
    let table = format!("{unrelated}35 27 253:0 / {path} rw - xfs /dev/dm-0 rw\n{unrelated}");
    let observed = parse_mountinfo(&table, path).expect("the mount is visible");
    assert_eq!(observed.source, "/dev/dm-0");
}

/// Kernel records keep one space between fields, and only the source can
/// be empty. A record with any other empty field, or without all three
/// filesystem fields, was not written by the kernel and identifies nothing.
#[test]
fn records_with_another_empty_field_are_not_mounts() {
    let path = "/srv/audit";
    for table in [
        format!("35 27 253:0 /  {path} rw - xfs /dev/dm-0 rw\n"),
        format!("35 27 253:0 / {path}  rw - xfs /dev/dm-0 rw\n"),
        format!("35 27 253:0 / {path} rw  - xfs /dev/dm-0 rw\n"),
        format!(" 35 27 253:0 / {path} rw - xfs /dev/dm-0 rw\n"),
        format!("35 27 253:0 / {path} rw -  /dev/dm-0 rw\n"),
        format!("35 27 253:0 / {path} rw - xfs /dev/dm-0 \n"),
        format!("35 27 253:0 / {path} rw - xfs /dev/dm-0\n"),
        format!("35 27 253:0 / {path} rw - xfs  \n"),
        format!("35 27 253:0 / {path} rw - xfs\n"),
    ] {
        assert!(parse_mountinfo(&table, path).is_none(), "{table:?}");
    }
    // The super options are the rest of the record.
    let table = format!("35 27 253:0 / {path} rw - xfs  rw,opt=a b\n");
    assert_eq!(parse_mountinfo(&table, path).unwrap().source, "");
}

#[cfg(target_os = "linux")]
mod namespace {
    use std::ffi::{CString, OsString};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use maki_privileged::exec::{allocate_nbd_device, cleanup, ExecError};
    use maki_privileged::probe::parse_mountinfo;

    const CHILD_ENV: &str = "MAKI_REVIEW_MOUNTINFO_EMPTY_SOURCE_PARENT_NAMESPACE";
    const TEST_NAME: &str =
        "namespace::review_empty_source_mounts_do_not_block_privileged_observation";
    const VOLUME: &str = "reviewempty";
    const VOLUME_UUID: &str = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

    fn mount_tmpfs(source: &str, target: &Path) {
        let source = CString::new(source).unwrap();
        let target_c = CString::new(target.as_os_str().as_bytes()).unwrap();
        // SAFETY: every pointer is a valid NUL-terminated string for the call.
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c"mode=0755".as_ptr().cast(),
            )
        };
        assert_eq!(
            rc,
            0,
            "mount {target:?}: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A trusted record for a disconnected device with no live resources:
    /// cleanup must retire it.
    fn write_record() -> PathBuf {
        let state = Path::new("/run/maki-attach");
        std::fs::create_dir_all(state).unwrap();
        std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let record = format!(
            r#"{{"version":1,"volume":"{VOLUME}","attachment":{{"volume_uuid":"{VOLUME_UUID}","nbd_socket":"/run/maki/{VOLUME}/nbd.sock","mountpoint":"/srv/{VOLUME}","vg_name":"vg_maki_{VOLUME}","lv_name":"data"}},"device":"/dev/nbd250","connection_id":"maki-11111111-2222-3333-4444-555555555555"}}"#
        );
        let path = state.join(format!("{VOLUME}.nbd"));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, record.as_bytes()).unwrap();
        path
    }

    fn detach_plan() -> maki_privileged::plan::Plan {
        let config =
            maki_privileged::config::parse(&format!("volume_uuid = \"{VOLUME_UUID}\"\n")).unwrap();
        let request = config
            .into_request(VOLUME, Default::default(), false)
            .unwrap();
        maki_privileged::plan::plan_detach(&request)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn namespace() -> OsString {
        std::fs::read_link("/proc/self/ns/mnt")
            .expect("mount namespace link")
            .into_os_string()
    }

    fn child(parent_namespace: OsString) {
        // Never mount anything in the namespace the test was started in.
        assert_ne!(
            namespace(),
            parent_namespace,
            "refusing to mount outside a private mount namespace"
        );
        let mounts = std::fs::read("/proc/self/mountinfo").unwrap();
        assert!(
            !contains(&mounts, b" shared:"),
            "the child's mounts must not propagate to another namespace"
        );

        mount_tmpfs("review-run", Path::new("/run"));
        let record = write_record();
        let empty = Path::new("/run/review-empty");
        std::fs::create_dir(empty).unwrap();
        mount_tmpfs("", empty);
        let table = std::fs::read("/proc/self/mountinfo").unwrap();
        let line = table
            .split(|&byte| byte == b'\n')
            .find(|line| contains(line, b" /run/review-empty "))
            .expect("the kernel lists the empty-source mount");
        assert!(
            contains(line, b" - tmpfs  rw"),
            "the kernel prints the empty source as an empty field: {}",
            String::from_utf8_lossy(line)
        );

        let mut failures = Vec::new();
        let observed = parse_mountinfo(&table, "/run/review-empty").expect("the mount is visible");
        if (observed.fstype.as_str(), observed.source.as_str()) != ("tmpfs", "") {
            failures.push(format!(
                "the post-mount verifier misread the empty-source record: {observed:?}"
            ));
        }
        let allocation = allocate_nbd_device();
        if !matches!(allocation, Ok(_) | Err(ExecError::NoFreeDevice)) {
            failures.push(format!(
                "an unrelated empty-source mount made NBD allocation fail: {allocation:?}"
            ));
        }
        let cleaned = cleanup(&detach_plan());
        if cleaned.is_err() || record.exists() {
            failures.push(format!(
                "an unrelated empty-source mount made cleanup fail: {cleaned:?}"
            ));
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn review_empty_source_mounts_do_not_block_privileged_observation() {
        if let Some(parent_namespace) = std::env::var_os(CHILD_ENV) {
            child(parent_namespace);
            return;
        }
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: a private mount namespace needs root");
            return;
        }
        let usable = Command::new("unshare")
            .args(["--mount", "--propagation", "private", "true"])
            .output()
            .is_ok_and(|output| output.status.success());
        if !usable {
            eprintln!("skipping: unshare cannot create a private mount namespace here");
            return;
        }
        let output = Command::new("unshare")
            .args(["--mount", "--propagation", "private"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, namespace())
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "child failed:\n{text}");
        assert!(
            text.contains("test result: ok. 1 passed"),
            "the child did not run the scenario:\n{text}"
        );
    }
}
