//! Checkpoint slot I/O must allow foreground progress while retaining the
//! captured durable horizon and serializing checkpoint publication.
#![allow(clippy::await_holding_lock)]

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{failpoints, CrashableBacking};
use rand::SeedableRng;

#[derive(Default)]
struct Gate {
    once: AtomicBool,
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: Condvar,
}

impl Gate {
    fn pause(self: &Arc<Self>, fail: bool) -> failpoints::FailpointGuard {
        let gate = self.clone();
        failpoints::set(
            "checkpoint.slot_write",
            failpoints::FailpointAction::Callback(Arc::new(move || {
                if gate.once.swap(true, Ordering::SeqCst) {
                    return None;
                }
                gate.entered.notify_one();
                let released = gate.released.lock().unwrap();
                let (_released, timeout) = gate
                    .wake
                    .wait_timeout_while(released, Duration::from_secs(5), |r| !*r)
                    .unwrap();
                assert!(!timeout.timed_out(), "checkpoint gate was never released");
                fail.then(|| io::Error::other("checkpoint data write failed"))
            })),
        )
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

fn options() -> EngineOptions {
    EngineOptions {
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: u64::MAX,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: Duration::from_secs(3600),
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn attach(backing: &Arc<CrashableBacking>) -> Engine {
    Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(1024)),
        options(),
    )
    .await
    .unwrap()
}

async fn fixture() -> (Arc<CrashableBacking>, Engine) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xc4ec),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let engine = attach(&backing).await;
    engine.write(2 * 1024, &[0x31; 1024], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine.write(0, &[0x41; 1024], true).await.unwrap();
    (backing, engine)
}

async fn concurrent_writes_during_checkpoint(failure: Option<&str>) {
    let (backing, engine) = fixture().await;
    let gate = Arc::new(Gate::default());
    let injection = gate.pause(failure == Some("checkpoint.slot_write"));
    let checkpoint_engine = engine.clone();
    let checkpoint = tokio::spawn(async move { checkpoint_engine.checkpoint().await });
    gate.entered.notified().await;

    let progress = tokio::time::timeout(Duration::from_millis(500), async {
        // Read the live overlay and an unrelated checkpointed slot.
        assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0x41; 1024]);
        assert_eq!(engine.read(2 * 1024, 1024).await.unwrap(), vec![0x31; 1024]);
        // Supersede a snapshotted unit and add an entirely new shard.
        engine.write(0, &[0x42; 1024], false).await.unwrap();
        engine.write(8 * 1024, &[0x55; 1024], true).await.unwrap();
    })
    .await;
    let publication_failure = failure
        .filter(|name| *name != "checkpoint.slot_write")
        .map(|name| failpoints::fail_n_times(name, 1, io::ErrorKind::Other, "publication failed"));
    gate.release();
    let result = checkpoint.await.unwrap();
    drop(injection);
    drop(publication_failure);
    assert!(
        progress.is_ok(),
        "checkpoint data I/O blocked foreground work"
    );

    if let Some(phase) = failure {
        assert!(result.is_err());
        assert_eq!(
            engine.stats().await.checkpoint_sequence,
            if phase == "checkpoint.dirsync" { 2 } else { 1 }
        );
        assert_eq!(engine.checkpoint().await.unwrap(), 4);
    } else {
        assert_eq!(
            result.unwrap(),
            2,
            "checkpoint must use its captured horizon"
        );
        assert_eq!(engine.stats().await.checkpoint_sequence, 2);
    }
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0x42; 1024]);
    assert_eq!(engine.read(8 * 1024, 1024).await.unwrap(), vec![0x55; 1024]);
    drop(engine);
    backing.crash(&mut rand::rngs::StdRng::seed_from_u64(0xc4ec));
    let recovered = attach(&backing).await;
    assert_eq!(recovered.read(0, 1024).await.unwrap(), vec![0x42; 1024]);
    assert_eq!(
        recovered.read(2 * 1024, 1024).await.unwrap(),
        vec![0x31; 1024]
    );
    assert_eq!(
        recovered.read(8 * 1024, 1024).await.unwrap(),
        vec![0x55; 1024]
    );
}

#[tokio::test]
async fn checkpoint_keeps_fixed_horizon_while_reads_and_new_writes_complete() {
    let _serial = failpoints::test_lock();
    concurrent_writes_during_checkpoint(None).await;
}

#[tokio::test]
async fn failed_checkpoint_preserves_concurrent_writes_for_retry_and_recovery() {
    let _serial = failpoints::test_lock();
    concurrent_writes_during_checkpoint(Some("checkpoint.slot_write")).await;
}

#[tokio::test]
async fn allocation_failure_preserves_concurrent_new_shard() {
    let _serial = failpoints::test_lock();
    concurrent_writes_during_checkpoint(Some("checkpoint.alloc_store")).await;
}

#[tokio::test]
async fn checkpoint_state_failure_preserves_concurrent_writes() {
    let _serial = failpoints::test_lock();
    concurrent_writes_during_checkpoint(Some("checkpoint.state_store")).await;
}

#[tokio::test]
async fn journal_cleanup_failure_preserves_concurrent_writes() {
    let _serial = failpoints::test_lock();
    concurrent_writes_during_checkpoint(Some("checkpoint.dirsync")).await;
}

#[tokio::test]
async fn cancelled_checkpoint_keeps_publication_serialized() {
    let _serial = failpoints::test_lock();
    let (_backing, engine) = fixture().await;
    let gate = Arc::new(Gate::default());
    let _injection = gate.pause(false);
    let first_engine = engine.clone();
    let first = tokio::spawn(async move { first_engine.checkpoint().await });
    gate.entered.notified().await;
    first.abort();
    let _ = first.await;
    let progress = tokio::time::timeout(
        Duration::from_millis(500),
        engine.write(0, &[0x43; 1024], true),
    )
    .await;
    let second_engine = engine.clone();
    let second = tokio::spawn(async move { second_engine.checkpoint().await });
    tokio::task::yield_now().await;
    let overtook = second.is_finished();
    gate.release();
    let sequence = second.await.unwrap().unwrap();
    assert!(
        progress.is_ok(),
        "cancelled checkpoint blocked foreground write"
    );
    progress.unwrap().unwrap();
    assert!(!overtook, "another checkpoint overtook unfinished data I/O");
    assert_eq!(sequence, 3);
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0x43; 1024]);
}
