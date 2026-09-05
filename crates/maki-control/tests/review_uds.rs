//! Review M-017: control socket binding applies mode 0660 before any client
//! can connect, replaces a stale socket file, resolves the configured group,
//! and removes the path when the listener is dropped. Unix only.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use maki_control::server::ControlBackend;
use maki_control::uds::{bind_control_socket, resolve_gid, serve};

struct Fake;

#[async_trait]
impl ControlBackend for Fake {
    async fn status(&self) -> Value {
        json!({"state": "ready"})
    }
    async fn metrics(&self) -> Value {
        json!({})
    }
    async fn checkpoint(&self) -> Result<u64, String> {
        Ok(1)
    }
    async fn reload(&self, _section: &str, _payload: &Value) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test]
async fn bind_sets_mode_replaces_stale_socket_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    std::fs::write(&path, b"stale").unwrap();

    let listener = bind_control_socket(&path, None).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);

    let server = tokio::spawn(serve(listener, Arc::new(Fake)));
    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    maki_control::protocol::send_command(&mut wr, &maki_control::protocol::Request::new("status"))
        .await
        .unwrap();
    let response = maki_control::protocol::read_response(&mut rd)
        .await
        .unwrap();
    assert_eq!(response["ok"], json!(true));

    server.abort();
    let _ = server.await;
    assert!(
        !path.exists(),
        "socket path removed when the listener drops"
    );
}

#[tokio::test]
async fn bind_refuses_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("control.sock");
    let err = bind_control_socket(&path, None).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[tokio::test]
async fn unknown_group_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let err = bind_control_socket(&path, Some("maki-no-such-group-xyz")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
    assert!(!path.exists(), "failed bind leaves no socket behind");
}

#[cfg(target_os = "linux")]
#[test]
fn root_group_resolves_to_gid_zero() {
    assert_eq!(resolve_gid("root").unwrap(), 0);
}

/// N-11 (fifth pass): a 0660 socket is unreachable when its directory cannot
/// be traversed. systemd creates the runtime directory owner-only for the
/// daemon user, so an administrator in `control.group` could never connect.
/// The daemon gives that group search access to the socket's directory.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn socket_directory_becomes_searchable_by_the_control_group() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn group_name(gid: u32) -> String {
        // SAFETY: getgrgid returns a static buffer; read immediately.
        unsafe {
            let entry = libc::getgrgid(gid);
            assert!(!entry.is_null(), "gid {gid} has no group entry");
            std::ffi::CStr::from_ptr((*entry).gr_name)
                .to_string_lossy()
                .into_owned()
        }
    }

    let dir = tempfile::tempdir().unwrap();
    // The systemd shape: an owner-only runtime directory.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    // The caller's own primary group stands in for maki-admin.
    // SAFETY: plain getgid.
    let gid = unsafe { libc::getgid() };
    let group = group_name(gid);
    let path = dir.path().join("control.sock");
    let _listener = bind_control_socket(&path, Some(&group)).unwrap();

    let meta = std::fs::metadata(dir.path()).unwrap();
    assert_eq!(meta.gid(), gid, "directory chgrp'd to the control group");
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o750,
        "group can traverse the directory, others still cannot"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o660
    );
}
