//! F10 (third review): control sessions are bounded. A session that sends
//! nothing is closed after the idle timeout, a client that never drains its
//! response is disconnected after the write timeout, mutating verbs run one
//! at a time (a second one is refused as busy), and only a fixed number of
//! sessions are served at once — the rest wait in the listen backlog.
//!
//! Timing uses tokio's paused clock (deterministic auto-advance), except
//! the Unix-socket backlog test, which needs real I/O.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tokio::sync::Notify;

use maki_control::protocol::{read_response, send_command, ProtocolError, Request};
use maki_control::server::{serve_connection, ControlBackend, ControlLimits, SerializedBackend};

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

/// A checkpoint that blocks until released.
struct Slow {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait]
impl ControlBackend for Slow {
    async fn status(&self) -> Value {
        json!({"state": "ready"})
    }
    async fn metrics(&self) -> Value {
        json!({})
    }
    async fn checkpoint(&self) -> Result<u64, String> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(7)
    }
    async fn reload(&self, _section: &str, _payload: &Value) -> Result<(), String> {
        Ok(())
    }
}

fn limits() -> ControlLimits {
    ControlLimits {
        max_sessions: 4,
        idle_timeout: Duration::from_secs(30),
        write_timeout: Duration::from_secs(5),
    }
}

#[tokio::test(start_paused = true)]
async fn idle_session_is_closed_after_the_idle_timeout() {
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(serve_connection(server, Arc::new(Fake), limits()));
    let (mut rd, _wr) = tokio::io::split(client);
    let mut buf = [0u8; 16];
    // The client sends nothing; the paused clock advances to the timeout
    // and the server closes its side.
    let n = rd.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "server must close an idle session");
    assert!(matches!(
        task.await.unwrap(),
        Err(ProtocolError::IdleTimeout)
    ));
}

#[tokio::test(start_paused = true)]
async fn an_active_session_outlives_the_idle_timeout() {
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(serve_connection(server, Arc::new(Fake), limits()));
    let (mut rd, mut wr) = tokio::io::split(client);
    // Ten requests spaced 10 s apart, over 100 s, against a 30 s idle limit.
    for _ in 0..10 {
        send_command(&mut wr, &Request::new("status"))
            .await
            .unwrap();
        let response = read_response(&mut rd).await.unwrap();
        assert_eq!(response["ok"], json!(true));
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    drop(wr);
    drop(rd);
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_client_that_never_reads_is_disconnected_after_the_write_timeout() {
    // An 8-byte pipe: the response cannot be written until the client
    // reads, and this client never does.
    let (client, server) = tokio::io::duplex(8);
    let task = tokio::spawn(serve_connection(server, Arc::new(Fake), limits()));
    let (_rd, mut wr) = tokio::io::split(client);
    send_command(&mut wr, &Request::new("status"))
        .await
        .unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(ProtocolError::WriteTimeout)
    ));
}

#[tokio::test]
async fn concurrent_mutating_verbs_are_refused_with_busy() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let backend = Arc::new(SerializedBackend::new(Arc::new(Slow {
        started: started.clone(),
        release: release.clone(),
    })));
    let first = {
        let backend = backend.clone();
        tokio::spawn(async move { backend.checkpoint().await })
    };
    started.notified().await;
    let second = backend.checkpoint().await.unwrap_err();
    assert!(second.contains("busy"), "{second}");
    let reload = backend.reload("cache", &json!({})).await.unwrap_err();
    assert!(reload.contains("busy"), "{reload}");
    // Queries are never blocked by an administrative verb in flight.
    assert_eq!(backend.status().await["state"], json!("ready"));
    release.notify_one();
    assert_eq!(first.await.unwrap(), Ok(7));
    // The gate is released once the first verb completes.
    release.notify_one();
    assert_eq!(backend.checkpoint().await, Ok(7));
}

/// With one session slot, a second client is not served until the first
/// disconnects; it waits in the backlog rather than getting a task. Real
/// sockets, so the negative check uses a short real timeout (best effort).
#[cfg(unix)]
#[tokio::test]
async fn extra_sessions_wait_in_the_backlog_until_a_slot_frees() {
    use maki_control::uds::{bind_control_socket, serve_with_limits};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let listener = bind_control_socket(&path, None).unwrap();
    let limits = ControlLimits {
        max_sessions: 1,
        idle_timeout: Duration::from_secs(60),
        write_timeout: Duration::from_secs(5),
    };
    let server = tokio::spawn(serve_with_limits(listener, Arc::new(Fake), limits));

    let a = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (mut ar, mut aw) = tokio::io::split(a);
    send_command(&mut aw, &Request::new("status"))
        .await
        .unwrap();
    assert_eq!(read_response(&mut ar).await.unwrap()["ok"], json!(true));

    let b = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (mut br, mut bw) = tokio::io::split(b);
    send_command(&mut bw, &Request::new("status"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), read_response(&mut br))
            .await
            .is_err(),
        "second session served while the only slot was taken"
    );

    drop(ar);
    drop(aw);
    let response = tokio::time::timeout(Duration::from_secs(10), read_response(&mut br))
        .await
        .expect("second session never served after the slot freed")
        .unwrap();
    assert_eq!(response["ok"], json!(true));
    server.abort();
}
