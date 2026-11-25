//! A checkpoint the control socket asked for (`maki checkpoint`, or the one
//! `maki drain` runs) that failed left the volume degraded, and a failed
//! drain left I/O admission closed, with nothing in the daemon's log: only
//! the checkpoint worker logged its failures. The observability guide says
//! every `state: degraded` has a matching `WARN` line.
//!
//! A failed requested checkpoint and a failed drain each log one `WARN`
//! with the error; a successful one logs nothing.

use maki_backing::Backing;
use maki_control::server::ControlBackend;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_nbdkit::control::EngineControlBackend;
use maki_test_support::{
    crash_backing::FaultOp, fake_provider::FakeCryptoProvider, CrashableBacking, ManualClock,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Every event this test process logs, as level, target and fields. The
/// engine and the control backend log from runtime threads, so events are
/// matched by their text.
static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// A copy of the events logged so far. A test that panics while it reads
/// them must not fail the other tests of this process.
fn events() -> Vec<String> {
    EVENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn install_capture() {
    use std::fmt::Write;
    use tracing::field::{Field, Visit};
    use tracing::span;

    struct Line(String);
    impl Visit for Line {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            write!(self.0, " {}={value:?}", field.name()).unwrap();
        }
    }
    struct Capture;
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let metadata = event.metadata();
            let mut line = Line(format!("{} {}", metadata.level(), metadata.target()));
            event.record(&mut line);
            EVENTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line.0);
        }
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
    }
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| tracing::subscriber::set_global_default(Capture).unwrap());
}

/// The `WARN` lines logged so far that contain every one of `words`.
fn warnings(words: &[&str]) -> Vec<String> {
    events()
        .into_iter()
        .filter(|line| line.starts_with("WARN ") && words.iter().all(|word| line.contains(word)))
        .collect()
}

/// An engine without its checkpoint worker, whose own failures it logs
/// already, over a backing whose checkpoint syncs fail while `fail` holds
/// the error's text.
async fn fixture(fail: Arc<Mutex<Option<&'static str>>>) -> (Engine, EngineControlBackend) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xc4ec),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 4096, 512, 4104, 64 * 4096, 16 * 4096).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if path.contains("checkpoint") => {
            fail.lock().unwrap().map(std::io::Error::other)
        }
        _ => None,
    })));
    let engine = Engine::attach(
        backing as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(4096)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                interval: Duration::from_secs(3600),
                ..Default::default()
            },
            clock: Some(Arc::new(ManualClock::new())),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    engine.stop_checkpoint_worker().await;
    let backend = EngineControlBackend::new(engine.clone(), "requested");
    (engine, backend)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_requested_checkpoint_logs_one_warning_with_its_error() {
    install_capture();
    const FAILURE: &str = "injected requested-checkpoint sync failure";
    let fail = Arc::new(Mutex::new(None));
    let (engine, backend) = fixture(fail.clone()).await;
    engine.write(0, &[0x5a; 4096], true).await.unwrap();
    *fail.lock().unwrap() = Some(FAILURE);

    let error = backend.checkpoint().await.unwrap_err();
    assert!(error.contains(FAILURE), "{error}");
    assert!(
        matches!(engine.state(), EngineState::Degraded { reason } if reason.contains(FAILURE)),
        "the failed checkpoint degrades the volume"
    );
    assert_eq!(
        warnings(&["checkpoint", FAILURE]).len(),
        1,
        "{:?}",
        events()
    );

    *fail.lock().unwrap() = None;
    backend.checkpoint().await.unwrap();
    assert_eq!(engine.state(), EngineState::Ready);
    assert_eq!(warnings(&["checkpoint", FAILURE]).len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_drain_logs_one_warning_with_its_error() {
    install_capture();
    const FAILURE: &str = "injected drain sync failure";
    let fail = Arc::new(Mutex::new(None));
    let (engine, backend) = fixture(fail.clone()).await;
    engine.write(0, &[0x5b; 4096], true).await.unwrap();
    *fail.lock().unwrap() = Some(FAILURE);

    let error = backend.drain().await.unwrap_err();
    assert!(error.contains(FAILURE), "{error}");
    assert_eq!(backend.status().await["io_state"], "failed");
    let logged = warnings(&["drain", FAILURE]);
    assert_eq!(logged.len(), 1, "{:?}", events());
    assert!(
        logged[0].contains("admission"),
        "the line says I/O stays refused: {}",
        logged[0]
    );

    *fail.lock().unwrap() = None;
    backend.drain().await.unwrap();
    assert_eq!(backend.status().await["io_state"], "drained");
    assert_eq!(warnings(&["drain", FAILURE]).len(), 1);
}
