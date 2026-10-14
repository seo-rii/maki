//! BUG-125: the engine's volume lock is an async `RwLock`, which does not
//! poison. A panic inside a storage task while it held the write lock (a
//! bug, or a dependency's assertion) became an ordinary I/O error for that
//! one request, the lock was released on unwind, and the engine went on
//! serving and acknowledging from an in-memory volume the panic may have
//! left half updated. The engine must stop instead: every later request
//! fails until the volume is attached again, and recovery from disk is the
//! only way back.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

fn backing() -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x9a41c),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 520, 1 << 20, 1 << 19).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    backing
}

/// The crash model reports no free space: run without the reserve.
fn options() -> EngineOptions {
    EngineOptions {
        checkpoint: CheckpointPolicy {
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panic_while_holding_the_volume_lock_stops_the_engine() {
    let backing = backing();
    let provider = Arc::new(FakeCryptoProvider::new(512));
    let engine = Engine::attach(backing.clone(), provider.clone(), options())
        .await
        .unwrap();
    engine.stop_checkpoint_worker().await;
    engine.write(0, &[1; 512], true).await.unwrap();

    // Panic once, inside the next journal write: the journal request holds
    // the volume write lock and is part-way through appending.
    let armed = Arc::new(AtomicBool::new(true));
    let trigger = armed.clone();
    backing.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
        if matches!(op, FaultOp::WriteAt { path, .. } if path.starts_with(layout::JOURNAL_DIR))
            && trigger.swap(false, Ordering::SeqCst)
        {
            panic!("injected storage bug");
        }
        None
    })));
    assert!(engine.write(512, &[2; 512], true).await.is_err());
    assert!(
        !armed.load(Ordering::SeqCst),
        "the injected panic never fired"
    );
    backing.set_fault_hook(None);

    // Nothing may be acknowledged or served from that state any more.
    assert!(
        engine.write(1024, &[3; 512], true).await.is_err(),
        "a write was acknowledged after a storage task panicked mid-mutation"
    );
    assert!(
        engine.flush().await.is_err(),
        "FLUSH succeeded after the panic"
    );
    assert!(
        engine.read(0, 512).await.is_err(),
        "a read was served after the panic"
    );
    assert!(
        engine.checkpoint().await.is_err(),
        "a checkpoint ran after the panic"
    );
    match engine.state() {
        EngineState::Degraded { reason } => {
            assert!(reason.contains("panic"), "unexpected reason: {reason}")
        }
        other => panic!("the engine still reports {other:?}"),
    }
    drop(engine);

    // Recovery from disk is the way back: the acknowledged write survives.
    let engine = Engine::attach(backing, provider, options()).await.unwrap();
    engine.stop_checkpoint_worker().await;
    assert_eq!(engine.read(0, 512).await.unwrap(), vec![1; 512]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ordinary_storage_error_does_not_stop_the_engine() {
    let backing = backing();
    let provider = Arc::new(FakeCryptoProvider::new(512));
    let engine = Engine::attach(backing.clone(), provider, options())
        .await
        .unwrap();
    engine.stop_checkpoint_worker().await;
    let armed = Arc::new(AtomicBool::new(true));
    let trigger = armed.clone();
    backing.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
        (matches!(op, FaultOp::WriteAt { path, .. } if path.starts_with(layout::JOURNAL_DIR))
            && trigger.swap(false, Ordering::SeqCst))
        .then(|| std::io::Error::other("injected write failure"))
    })));
    assert!(engine.write(0, &[1; 512], true).await.is_err());
    backing.set_fault_hook(None);
    engine.write(0, &[4; 512], true).await.unwrap();
    assert_eq!(engine.read(0, 512).await.unwrap(), vec![4; 512]);
}
