//! R3-008: acknowledged drain and retryable failure without admitting more I/O.
#![cfg(unix)]

use maki_backing::Backing;
use maki_control::protocol::{read_response, send_command, Request};
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_nbdkit::adapter::{NbdAdapter, ESHUTDOWN};
use maki_test_support::{crash_backing::FaultOp, CrashableBacking, FakeCryptoProvider};
use serde_json::Value;
use std::sync::Arc;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn simulated_engine_options() -> EngineOptions {
    EngineOptions {
        checkpoint: CheckpointPolicy {
            emergency_reserve_bytes: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn memory_adapter(backing: &Arc<CrashableBacking>) -> NbdAdapter {
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::new_v4(),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 4096, 512, 4104, 2 << 20, 256 << 10).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let rt = runtime();
    let engine = rt
        .block_on(Engine::attach(
            backing.clone(),
            Arc::new(FakeCryptoProvider::new(4096)),
            simulated_engine_options(),
        ))
        .unwrap();
    NbdAdapter::from_engine(engine, rt)
}

#[test]
fn failed_shutdown_retains_the_lock_and_blocks_new_io_until_retry() {
    for checkpoint_failure in [false, true] {
        let backing = Arc::new(CrashableBacking::new());
        let adapter = memory_adapter(&backing);
        adapter
            .pwrite(&[0x34; 4096], 0, checkpoint_failure)
            .unwrap();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { path } if !checkpoint_failure || path.contains("checkpoint") => {
                Some(std::io::Error::other("injected drain sync failure"))
            }
            _ => None,
        })));
        let failure = adapter
            .shutdown()
            .expect_err("sync failure must reach caller");
        assert!(
            failure.message.contains("injected drain sync failure"),
            "{failure}"
        );
        assert!(
            backing.try_lock(maki_format::layout::VOLUME_LOCK).is_err(),
            "failed drain lost volume lock"
        );
        assert_eq!(
            adapter
                .pread(&mut [0; 4096], 0)
                .expect_err("failed drain admitted new I/O")
                .errno,
            ESHUTDOWN
        );
        backing.set_fault_hook(None);
        adapter.shutdown().unwrap();
        assert!(
            backing.try_lock(maki_format::layout::VOLUME_LOCK).is_ok(),
            "successful retry retained volume lock"
        );
        adapter
            .shutdown()
            .expect("shutdown is idempotent after a completed drain");
    }
}

pub struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    root: std::path::PathBuf,
    socket: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vol");
        let socket = dir.path().join("control.sock");
        let path = dir.path().join("volume.toml");
        let raw = format!(
            r#"
config_schema_version = 1
[volume]
name = "drain"
max_virtual_size = "2MiB"
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = "{}"
[control]
socket = "{}"
"#,
            root.display(),
            socket.display()
        );
        std::fs::write(&path, &raw).unwrap();
        maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        Self {
            _dir: dir,
            path,
            root,
            socket,
        }
    }
    fn call(&self, command: &str) -> Value {
        runtime().block_on(async {
            let mut stream = tokio::net::UnixStream::connect(&self.socket).await.unwrap();
            send_command(&mut stream, &Request::new(command))
                .await
                .unwrap();
            read_response(&mut stream).await.unwrap()
        })
    }
}

#[test]
fn control_drain_acknowledges_checkpoint_and_preserves_status_until_shutdown() {
    let fixture = Fixture::new();
    let adapter = NbdAdapter::open_config(fixture.path.to_str().unwrap()).unwrap();
    adapter.pwrite(&[0x56; 4096], 0, false).unwrap();
    let drained = fixture.call("drain");
    assert_eq!(drained["ok"], true, "{drained}");
    assert!(drained["data"]["checkpoint_sequence"].as_u64().unwrap() >= 1);
    assert_eq!(fixture.call("status")["data"]["io_state"], "drained");
    assert_eq!(
        adapter.pwrite(&[1; 4096], 0, false).unwrap_err().errno,
        ESHUTDOWN
    );
    assert_eq!(fixture.call("drain"), drained, "drain must be idempotent");
    assert!(fixture.root.exists());
    assert!(
        fixture.socket.exists(),
        "acknowledgement and status keep control socket alive"
    );
    adapter.shutdown().unwrap();
    assert!(!fixture.socket.exists());
    let reopened = NbdAdapter::open_config(fixture.path.to_str().unwrap()).unwrap();
    let mut read = [0; 4096];
    reopened.pread(&mut read, 0).unwrap();
    assert_eq!(read, [0x56; 4096]);
    reopened.shutdown().unwrap();
}

/// Wait for an already admitted write even when it is still encrypting and
/// has not appended any journal record. A plain FLUSH barrier misses this case.
#[test]
fn shutdown_waits_for_the_full_active_callback() {
    use maki_crypto::clock::{Clock, SleepFuture};
    use std::time::Duration;
    struct GateClock {
        entered: std::sync::mpsc::Sender<()>,
        release: Arc<tokio::sync::Notify>,
    }
    impl Clock for GateClock {
        fn now(&self) -> Duration {
            Duration::ZERO
        }
        fn sleep(&self, _: Duration) -> SleepFuture {
            self.entered.send(()).unwrap();
            let release = self.release.clone();
            Box::pin(async move { release.notified().await })
        }
    }
    let backing = Arc::new(CrashableBacking::new());
    // Initialize separately, then reopen with the controllable provider.
    memory_adapter(&backing).shutdown().unwrap();
    let provider = Arc::new(FakeCryptoProvider::new(4096));
    let rt = runtime();
    let engine = rt
        .block_on(Engine::attach(
            backing.clone(),
            provider.clone(),
            simulated_engine_options(),
        ))
        .unwrap();
    let adapter = Arc::new(NbdAdapter::from_engine(engine, rt));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    provider.set_latency(
        Arc::new(GateClock {
            entered: entered_tx,
            release: release.clone(),
        }),
        Duration::from_secs(1),
    );
    let writer = {
        let adapter = adapter.clone();
        std::thread::spawn(move || adapter.pwrite(&[0x73; 4096], 0, false))
    };
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let closer = {
        let adapter = adapter.clone();
        std::thread::spawn(move || {
            let result = adapter.shutdown();
            done_tx.send(result).unwrap();
        })
    };
    let before_release = done_rx.recv_timeout(Duration::from_millis(100));
    // Always release the fixture, including when the regression is present.
    release.notify_one();
    writer.join().unwrap().unwrap();
    closer.join().unwrap();
    assert!(
        before_release.is_err(),
        "shutdown acknowledged before the admitted write completed"
    );
    done_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    drop(adapter);
    let rt = runtime();
    let engine = rt
        .block_on(Engine::attach(
            backing.clone(),
            Arc::new(FakeCryptoProvider::new(4096)),
            simulated_engine_options(),
        ))
        .unwrap();
    assert_eq!(rt.block_on(engine.read(0, 4096)).unwrap(), vec![0x73; 4096]);
}

/// Concurrent shutdown callers must not retain their own Engine references
/// after another caller acknowledges that the volume lock is released.
#[test]
fn concurrent_shutdown_acknowledgements_release_the_volume_lock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    let backing = Arc::new(CrashableBacking::new());
    let adapter = Arc::new(memory_adapter(&backing));
    adapter.pwrite(&[0x52; 4096], 0, true).unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release_rx = std::sync::Mutex::new(release_rx);
    let first = AtomicBool::new(true);
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(op, FaultOp::SyncData { path } if path.contains("checkpoint"))
            && first.swap(false, Ordering::SeqCst)
        {
            entered_tx.send(()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
        None
    })));
    let start = Arc::new(std::sync::Barrier::new(17));
    // Test probes must not contend with one another for the released lock.
    let probe = Arc::new(std::sync::Mutex::new(()));
    let closers: Vec<_> = (0..16)
        .map(|_| {
            let adapter = adapter.clone();
            let backing = backing.clone();
            let start = start.clone();
            let probe = probe.clone();
            std::thread::spawn(move || {
                start.wait();
                let result = adapter.shutdown();
                let _probe = probe.lock().unwrap();
                let released = backing.try_lock(maki_format::layout::VOLUME_LOCK).is_ok();
                (result, released)
            })
        })
        .collect();
    start.wait();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // Keep the first barrier pending while the other callers enter shutdown.
    std::thread::sleep(Duration::from_millis(100));
    release_tx.send(()).unwrap();
    let outcomes: Vec<_> = closers.into_iter().map(|c| c.join().unwrap()).collect();
    for (result, released) in outcomes {
        result.expect("concurrent shutdown must be idempotent");
        assert!(
            released,
            "shutdown acknowledged while a waiting caller retained the engine"
        );
    }
}
