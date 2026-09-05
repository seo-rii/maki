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
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn failed_group_setup_does_not_replace_existing_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    std::fs::write(&path, b"stale").unwrap();

    assert!(bind_control_socket(&path, Some("maki-no-such-group-xyz")).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"stale");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn publication_failure_leaves_no_temporary_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    std::fs::create_dir(&path).unwrap();

    assert!(bind_control_socket(&path, None).is_err());
    assert!(path.is_dir());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn bind_applies_the_configured_group() {
    use std::os::unix::fs::MetadataExt;

    // Look up a group already held by this process, requiring no privilege
    // or machine-specific group name to exercise the configured chgrp path.
    let gid = unsafe { libc::getegid() };
    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 16 * 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: getgrgid_r writes only to these valid output buffers.
    let rc = unsafe {
        libc::getgrgid_r(
            gid,
            &mut group,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert!(!result.is_null());
    // SAFETY: a successful lookup provides a NUL-terminated name in buffer.
    let name = unsafe { std::ffi::CStr::from_ptr(group.gr_name) }
        .to_str()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");

    let listener = bind_control_socket(&path, Some(name)).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.gid(), gid);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    drop(listener);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn bind_supports_a_maximum_length_filesystem_socket_path() {
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    // Linux sun_path holds 108 bytes, including its terminating NUL. Use a
    // one-byte filename so any intermediate directory would exceed it.
    let padding = 107 - dir.path().as_os_str().as_bytes().len() - 3;
    let parent = dir.path().join("p".repeat(padding));
    std::fs::create_dir(&parent).unwrap();
    let path = parent.join("s");
    assert_eq!(path.as_os_str().as_bytes().len(), 107);
    // Establish that this path was valid before adding private publication.
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());

    let listener = bind_control_socket(&path, None).unwrap();
    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    drop(stream);
    drop(listener);
    assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn root_group_resolves_to_gid_zero() {
    assert_eq!(resolve_gid("root").unwrap(), 0);
}
