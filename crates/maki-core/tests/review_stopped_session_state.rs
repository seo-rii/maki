//! A rollback session that stopped for good answered every request with an
//! error while the engine kept reporting `ready`: after `maki volume
//! takeover` beside a live daemon, or with an older local anchor put back,
//! `maki status` showed `state: ready`, `maki_volume_state` 1 and no reason
//! until the checkpoint worker's next failed pass, and never when nothing
//! was left to checkpoint. Nothing was logged but the failed requests.
//!
//! A stopped session is a degraded volume at once, with a reason that names
//! the stop and what to do, and the backing logs one `WARN` when it stops.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;
#[path = "support/private_dir.rs"]
mod private_dir;

use std::io;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::RollbackBacking;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use uuid::Uuid;

const UNIT: u32 = 512;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x5e55_1015),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, 16 * UNIT as u64, 4096).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn recover(backing: Arc<RollbackBacking>) -> Volume {
    Volume::recover(
        backing,
        VolumeOptions {
            journal_segment_size: 4096,
        },
    )
    .unwrap()
}

/// An engine without its checkpoint worker: a failed worker pass would
/// degrade the volume by itself, which is not what is under test.
async fn engine(volume: Volume) -> Engine {
    let engine = Engine::attach_recovered(
        volume,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    engine.stop_checkpoint_worker().await;
    engine
}

/// Every event this test process logs, as level, target and fields. The
/// backing logs from the engine's storage threads, so events are matched by
/// their text, not by the thread that logged them.
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

/// The tests of this file run one at a time, so the lines a test counts
/// are its own.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The `WARN` lines logged since `from` (a count of [`events`]) that name a
/// stopped session.
fn stop_warnings(from: usize) -> Vec<String> {
    events()
        .split_off(from)
        .into_iter()
        .filter(|line| line.starts_with("WARN ") && line.contains("rollback session stopped"))
        .collect()
}

fn degraded_reason(state: EngineState) -> String {
    match state {
        EngineState::Degraded { reason } => reason,
        EngineState::Ready => panic!("a stopped session reported ready"),
    }
}

/// The engine's every view of its state reports the stop: `state()`, the
/// monitoring snapshot `maki status` uses, and `stats()`.
async fn assert_stopped(engine: &Engine, cause: &str) {
    let reason = degraded_reason(engine.state());
    assert!(
        reason.starts_with("rollback session stopped: ") && reason.contains(cause),
        "{reason}"
    );
    assert!(
        reason.contains("attached again"),
        "the reason says what to do: {reason}"
    );
    assert_eq!(
        degraded_reason(engine.monitoring_snapshot().stats.state),
        reason
    );
    assert_eq!(degraded_reason(engine.stats().await.state), reason);
}

struct RoleRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
}
impl Rpc for RoleRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.store.lock().unwrap().handle(self.role, request)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_takeover_beside_a_live_engine_degrades_it_at_its_first_refused_request() {
    install_capture();
    let _serial = SERIAL.lock().await;
    let logged = events().len();
    let root = tempfile::tempdir().unwrap();
    let authority = private_dir::tempdir().unwrap();
    let store = Arc::new(Mutex::new(
        StateStore::create(authority.path(), [7; 16]).unwrap(),
    ));
    let writer = Arc::new(RoleRpc {
        store: store.clone(),
        role: Role::Writer,
    });
    let admin = Arc::new(RoleRpc {
        store,
        role: Role::Admin,
    });
    let path = root.path().to_path_buf();
    let (volume, old_backing) = tokio::task::spawn_blocking(move || {
        let backing = Arc::new(RollbackBacking::create_remote(&path, writer, 1024 * 1024).unwrap());
        init::create_volume(backing.as_ref(), superblock()).unwrap();
        (recover(backing.clone()), backing)
    })
    .await
    .unwrap();
    let old = engine(volume).await;
    old.write(0, &[0x52; UNIT as usize], true).await.unwrap();
    old.checkpoint().await.unwrap();
    assert_eq!(old.state(), EngineState::Ready);

    let path = root.path().to_path_buf();
    let new_backing = tokio::task::spawn_blocking(move || {
        let current = admin
            .call(&Request {
                authorization: None,
                operation_id: [0; 16],
                expected: None,
                action: Action::Inspect,
            })
            .unwrap();
        Arc::new(RollbackBacking::takeover_remote(&path, admin, &current).unwrap())
    })
    .await
    .unwrap();
    // Nothing has asked the witness yet.
    assert_eq!(old.state(), EngineState::Ready);

    let error = old.read(0, UNIT as usize).await.unwrap_err();
    assert!(
        error.to_string().contains("remote writer revoked"),
        "{error}"
    );
    assert_stopped(&old, "remote writer revoked").await;
    assert!(old.write(0, &[0x33; UNIT as usize], true).await.is_err());
    assert!(old.flush().await.is_err());
    assert!(old.checkpoint().await.is_err());
    assert_stopped(&old, "remote writer revoked").await;
    let warnings = stop_warnings(logged);
    assert_eq!(
        warnings.len(),
        1,
        "one WARN line when the session stops: {warnings:?}"
    );
    assert!(
        warnings[0].contains("remote writer revoked"),
        "{warnings:?}"
    );

    // The new writer serves the acknowledged data.
    let new = engine(recover(new_backing.clone())).await;
    assert_eq!(
        new.read(0, UNIT as usize).await.unwrap(),
        vec![0x52; UNIT as usize]
    );
    assert_eq!(new.state(), EngineState::Ready);
    drop((old, old_backing, new, new_backing, root, authority));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_local_anchor_put_back_degrades_the_engine_at_its_first_refused_request() {
    install_capture();
    let _serial = SERIAL.lock().await;
    let logged = events().len();
    let root = tempfile::tempdir().unwrap();
    let Some(witness) = other_filesystem::tempdir(root.path()) else {
        return;
    };
    let (root_path, witness_path) = (root.path().to_path_buf(), witness.path().to_path_buf());
    let (volume, backing) = tokio::task::spawn_blocking(move || {
        let backing =
            Arc::new(RollbackBacking::create(&root_path, &witness_path, 1024 * 1024).unwrap());
        init::create_volume(backing.as_ref(), superblock()).unwrap();
        (recover(backing.clone()), backing)
    })
    .await
    .unwrap();
    let engine = engine(volume).await;
    engine.write(0, &[0x41; UNIT as usize], true).await.unwrap();
    let anchor = witness.path().join("anchor");
    let older = std::fs::read(&anchor).unwrap();
    engine
        .write(UNIT as u64, &[0x42; UNIT as usize], true)
        .await
        .unwrap();
    assert_ne!(std::fs::read(&anchor).unwrap(), older, "a FUA commits");
    assert_eq!(engine.state(), EngineState::Ready);

    let staged = witness.path().join("anchor.older");
    std::fs::write(&staged, &older).unwrap();
    std::fs::rename(&staged, &anchor).unwrap();
    let error = engine.read(0, UNIT as usize).await.unwrap_err();
    assert!(error.to_string().contains("anchor changed"), "{error}");
    assert_stopped(&engine, "anchor changed").await;
    assert!(engine.read(UNIT as u64, UNIT as usize).await.is_err());
    assert_stopped(&engine, "anchor changed").await;
    let warnings = stop_warnings(logged);
    assert_eq!(
        warnings.len(),
        1,
        "one WARN line when the session stops: {warnings:?}"
    );
    assert!(warnings[0].contains("anchor changed"), "{warnings:?}");
    drop((engine, backing, root, witness));
}
