//! Audit (core write path) — demonstration of a KNOWN, documented deviation
//! (docs/review-remediation.md, fourth pass: "FLUSH takes the volume's
//! exclusive lock rather than an append-ordered barrier"); not a new finding.
//! The assertion fails by design to show the cost.
//!
//! SPEC §25 says "FLUSH uses an ordered journal
//! barrier rather than a global write lock". The engine runs the whole
//! barrier (journal fdatasync, both durable-proof publications with their
//! file and directory syncs) while holding the volume's exclusive RwLock, so
//! every concurrent read — even of checkpointed data that needs no journal —
//! and every write's publication waits for the slowest fsync of each FLUSH or
//! FUA write.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_flush_blocks_an_unrelated_read() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xa0d1_f105),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 1024, 512, 1032, 64 * 1024, 16 * 1024).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(1024)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: u64::MAX,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Unit 0 is checkpointed: reading it needs only its slot.
    engine.write(0, &[0x11; 1024], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    // A volatile write to another unit so the FLUSH has something to sync.
    engine.write(8192, &[0x22; 1024], false).await.unwrap();

    // Make the journal fdatasync stall until released.
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let entered = Arc::new(AtomicBool::new(false));
    {
        let gate = gate.clone();
        let entered = entered.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| {
            if matches!(op, FaultOp::SyncData { path } if path.starts_with("journal/")) {
                entered.store(true, Ordering::SeqCst);
                let (lock, cvar) = &*gate;
                let mut open = lock.lock().unwrap();
                while !*open {
                    open = cvar.wait(open).unwrap();
                }
            }
            None
        })));
    }
    let flushing = {
        let engine = engine.clone();
        tokio::spawn(async move { engine.flush().await })
    };
    while !entered.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    // The exclusive volume lock is held while the journal fdatasync runs
    // (monitoring touches no backing state, so this is not the backing's
    // own mutex the stalled hook holds).
    let busy_during_sync = engine.monitoring_snapshot().volume_busy;
    let reading = {
        let engine = engine.clone();
        tokio::spawn(async move { engine.read(0, 1024).await })
    };
    // Give the read every chance to finish without the lock.
    for _ in 0..20_000 {
        tokio::task::yield_now().await;
        if reading.is_finished() {
            break;
        }
    }
    let blocked = !reading.is_finished();
    {
        let (lock, cvar) = &*gate;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
    flushing.await.unwrap().unwrap();
    assert_eq!(reading.await.unwrap().unwrap(), vec![0x11; 1024]);
    backing.set_fault_hook(None);
    engine.stop_checkpoint_worker().await;
    eprintln!("volume lock busy during journal fdatasync: {busy_during_sync}; read blocked: {blocked}");
    assert!(
        !busy_during_sync && !blocked,
        "a read of checkpointed data waited for the FLUSH's journal fdatasync: the barrier \
         runs under the exclusive volume lock"
    );
}
