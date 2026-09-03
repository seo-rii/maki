//! O-04, in its own binary: the test lowers the process-wide descriptor
//! limit, which must not race the other control-socket tests.

#![cfg(unix)]

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use maki_control::server::ControlBackend;
use maki_control::uds::{bind_control_socket, serve};

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
