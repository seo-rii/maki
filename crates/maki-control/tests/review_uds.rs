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

/// O-04: an `accept` failure (descriptor exhaustion during a client burst)
/// must not end the server loop, which would unlink the socket and leave
/// the daemon without a control plane for the rest of its life. Best
/// effort: descriptor pressure is created in-process, so the server may
/// or may not observe EMFILE, but the socket must serve afterwards either
/// way.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_errors_do_not_kill_the_control_server() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let listener = bind_control_socket(&path, None).unwrap();
    let server = tokio::spawn(serve(listener, Arc::new(Fake)));

    // Squeeze the descriptor table down to what is open now plus a couple.
    let mut original = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain libc calls with valid pointers.
    unsafe {
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut original);
    }
    let open = std::fs::read_dir("/proc/self/fd").unwrap().count() as u64;
    let squeezed = libc::rlimit {
        rlim_cur: (open + 3).min(original.rlim_max),
        rlim_max: original.rlim_max,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_NOFILE, &squeezed);
    }
    let mut held = Vec::new();
    for _ in 0..16 {
        match tokio::net::UnixStream::connect(&path).await {
            Ok(stream) => held.push(stream),
            Err(_) => break,
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    unsafe {
        libc::setrlimit(libc::RLIMIT_NOFILE, &original);
    }
    drop(held);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert!(path.exists(), "socket unlinked: the server loop died");
    let stream = tokio::net::UnixStream::connect(&path)
        .await
        .expect("control socket no longer accepts");
    let (mut rd, mut wr) = tokio::io::split(stream);
    maki_control::protocol::send_command(&mut wr, &maki_control::protocol::Request::new("status"))
        .await
        .unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        maki_control::protocol::read_response(&mut rd),
    )
    .await
    .expect("no response: the server loop died")
    .unwrap();
    assert_eq!(response["ok"], json!(true));
    server.abort();
}
