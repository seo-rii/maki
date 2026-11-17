//! Audit probe (round 2, #158): systemd grants a non-root service read on a
//! root-owned 0400 LoadCredential file with a POSIX ACL (`user:<uid>:r`),
//! where the filesystem supports one. The ACL mask then appears as the group
//! bits (0440, group root). The credentials-directory loader must accept that
//! file for the service user (owner root, group root), and the plain `file`
//! loader must still refuse it (any group bit). The service-user half runs
//! the same binary again under `setpriv` as uid/gid 65534.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use maki_crypto_local::keysource::{FileKeySource, KeySource};

const DIR: &str = "AUDIT2_ACL_DIR";

fn grant_read_acl(path: &Path, uid: u32) {
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (0x01u16, 4u16, u32::MAX), // USER_OBJ r
        (0x02, 4, uid),            // USER uid r
        (0x04, 0, u32::MAX),       // GROUP_OBJ ---
        (0x10, 4, u32::MAX),       // MASK r
        (0x20, 0, u32::MAX),       // OTHER ---
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&perm.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new("system.posix_acl_access").unwrap();
    // SAFETY: valid NUL-terminated strings and a live buffer.
    let rc = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    };
    assert_eq!(rc, 0, "setxattr: {}", std::io::Error::last_os_error());
}

#[test]
#[ignore = "child half of a_systemd_acl_credential_loads_for_the_service_user"]
fn audit2_acl_child() {
    let Ok(dir) = std::env::var(DIR) else {
        return;
    };
    let result = FileKeySource::credentials_directory(&dir).load_text("crypto-token");
    println!(
        "AUDIT2-ACL euid={} {}",
        unsafe { libc::geteuid() },
        match result {
            Ok(secret) => format!("ok {} bytes", secret.expose().len()),
            Err(error) => format!("err {error}"),
        }
    );
}

#[test]
fn a_systemd_acl_credential_loads_for_the_service_user() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root to create the root-owned credential");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let file = dir.path().join("crypto-token");
    std::fs::write(&file, b"token\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
    grant_read_acl(&file, 65534);
    let meta = std::fs::metadata(&file).unwrap();
    println!(
        "mode {:o} owner {}:{}",
        meta.permissions().mode() & 0o777,
        meta.uid(),
        meta.gid()
    );
    assert_eq!(meta.permissions().mode() & 0o777, 0o440);

    // The plain secret-file loader refuses any group bit.
    assert!(FileKeySource::new(dir.path()).load_text("crypto-token").is_err());

    // The service user, reading through the ACL.
    let exe = std::env::current_exe().unwrap();
    let Ok(output) = Command::new("setpriv")
        .args([
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
        ])
        .arg(&exe)
        .args(["--exact", "audit2_acl_child", "--ignored", "--nocapture"])
        .env(DIR, dir.path())
        .output()
    else {
        eprintln!("skipped: setpriv unavailable");
        return;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = stdout
        .lines()
        .find_map(|line| line.split_once("AUDIT2-ACL ").map(|(_, rest)| rest.to_owned()));
    let Some(line) = line else {
        eprintln!("skipped: the child did not run as uid 65534\n{stdout}\n{stderr}");
        return;
    };
    println!("service user: {line}");
    assert!(line.contains("euid=65534 ok"), "{line}");
}
