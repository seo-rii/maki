//! BUG-085: a canary left readable by a failed first publication is not
//! durable evidence. A successful attach retry must restore both copies
//! before accepting data that an unauthenticated provider needs it to open.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_backing::Backing;
use maki_core::engine::{AttachError, CheckpointPolicy, Engine, EngineOptions};
use maki_format::ab::AbStore;
use maki_format::canary::KeyCanary;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout, FormatError};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 1024;
const KEY: u64 = 0xa115;

fn fixture() -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xca085),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, 16384, 8192).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    backing
}

async fn attach(
    backing: &Arc<CrashableBacking>,
    key: u64,
    integrity: bool,
) -> Result<Engine, AttachError> {
    let result = Engine::attach(
        backing.clone(),
        Arc::new(
            FakeCryptoProvider::new(UNIT)
                .with_key(key)
                .with_integrity_check(integrity),
        ),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    if let Ok(engine) = &result {
        engine.stop_checkpoint_worker().await;
    }
    result
}

fn load_canary(backing: &CrashableBacking) -> Option<KeyCanary> {
    AbStore::new(layout::KEY_CANARY_A, layout::KEY_CANARY_B)
        .load(backing)
        .unwrap()
}

fn assert_both_copies(backing: &CrashableBacking) {
    let a = AbStore::new(layout::KEY_CANARY_A, layout::KEY_CANARY_A)
        .load::<KeyCanary>(backing)
        .unwrap()
        .expect("canary A must be valid");
    let b = AbStore::new(layout::KEY_CANARY_B, layout::KEY_CANARY_B)
        .load::<KeyCanary>(backing)
        .unwrap()
        .expect("canary B must be valid");
    assert_eq!(a.volume_uuid, b.volume_uuid);
    assert_eq!(a.unit_index, b.unit_index);
    assert_eq!(a.ciphertext, b.ciphertext);
}

fn fail_sync_once(backing: &CrashableBacking, target: &'static str) -> Arc<AtomicBool> {
    let armed = Arc::new(AtomicBool::new(true));
    let fault = armed.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if *path == target && fault.swap(false, Ordering::SeqCst) => {
            Some(io::Error::other("canary writeback EIO"))
        }
        _ => None,
    })));
    armed
}

fn fail_canary_dirsync_once(backing: &CrashableBacking) -> Arc<AtomicBool> {
    // Recovery also syncs the root before reaching the canary. Arm only
    // after this attach has synced a canary file, to isolate its publication.
    let seen_canary = AtomicBool::new(false);
    let armed = Arc::new(AtomicBool::new(true));
    let fault = armed.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if is_canary(path) => {
            seen_canary.store(true, Ordering::SeqCst);
            None
        }
        FaultOp::SyncDir { dir }
            if dir.is_empty()
                && seen_canary.load(Ordering::SeqCst)
                && fault.swap(false, Ordering::SeqCst) =>
        {
            Some(io::Error::other("canary directory EIO"))
        }
        _ => None,
    })));
    armed
}

fn is_canary(path: &str) -> bool {
    matches!(path, layout::KEY_CANARY_A | layout::KEY_CANARY_B)
}

async fn fail_first_attach(backing: &Arc<CrashableBacking>, target: &'static str) {
    let armed = fail_sync_once(backing, target);
    assert!(matches!(
        attach(backing, KEY, false).await,
        Err(AttachError::Format(FormatError::Io(_)))
    ));
    assert!(!armed.load(Ordering::SeqCst));
    assert!(
        load_canary(backing).is_some(),
        "page cache keeps the canary"
    );
    backing.set_fault_hook(None);
}

async fn acknowledge_and_crash(backing: &Arc<CrashableBacking>, integrity: bool) {
    let engine = attach(backing, KEY, integrity).await.unwrap();
    engine.write(0, &[0x5a; UNIT as usize], true).await.unwrap();
    assert_eq!(engine.stats().await.durable_sequence, 1);
    drop(engine);
    backing.crash_all_lost();
    let engine = attach(backing, KEY, integrity)
        .await
        .unwrap_or_else(|error| panic!("FUA data must remain attachable: {error}"));
    assert_eq!(
        engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x5a; UNIT as usize]
    );
}

#[tokio::test]
async fn first_canary_sync_failure_retry_preserves_fua_data_after_power_loss() {
    let backing = fixture();
    fail_first_attach(&backing, layout::KEY_CANARY_A).await;
    // This is a process restart: the failed attach dropped its volume lock,
    // while the backing's readable page cache survives until the later crash.
    acknowledge_and_crash(&backing, false).await;
}

#[tokio::test]
async fn retry_restores_both_canary_copies_before_any_user_write() {
    for failed_copy in [layout::KEY_CANARY_A, layout::KEY_CANARY_B] {
        let backing = fixture();
        fail_first_attach(&backing, failed_copy).await;
        drop(attach(&backing, KEY, false).await.unwrap());
        backing.crash_all_lost();
        assert_both_copies(&backing);
    }
}

#[tokio::test]
async fn loaded_canary_sync_failures_keep_attach_failed_until_durable_retry() {
    let backing = fixture();
    fail_first_attach(&backing, layout::KEY_CANARY_A).await;
    for target in [layout::KEY_CANARY_A, layout::KEY_CANARY_B] {
        let armed = fail_sync_once(&backing, target);
        let result = attach(&backing, KEY, false).await;
        assert!(matches!(
            result,
            Err(AttachError::Format(FormatError::Io(_)))
        ));
        assert!(!armed.load(Ordering::SeqCst), "retry must sync {target}");
        backing.set_fault_hook(None);
    }
    acknowledge_and_crash(&backing, false).await;
    assert_both_copies(&backing);
}

#[tokio::test]
async fn loaded_canary_directory_failures_keep_attach_failed_until_durable_retry() {
    let backing = fixture();
    fail_first_attach(&backing, layout::KEY_CANARY_A).await;
    for _ in 0..2 {
        let armed = fail_canary_dirsync_once(&backing);
        assert!(attach(&backing, KEY, false).await.is_err());
        assert!(!armed.load(Ordering::SeqCst));
        backing.set_fault_hook(None);
    }
    acknowledge_and_crash(&backing, false).await;
    assert_both_copies(&backing);
}

#[tokio::test]
async fn first_canary_directory_failure_retry_preserves_both_dirents() {
    let backing = fixture();
    let armed = fail_canary_dirsync_once(&backing);
    assert!(attach(&backing, KEY, false).await.is_err());
    assert!(!armed.load(Ordering::SeqCst));
    assert!(load_canary(&backing).is_some());
    backing.set_fault_hook(None);
    drop(attach(&backing, KEY, false).await.unwrap());
    backing.crash_all_lost();
    assert_both_copies(&backing);
}

#[tokio::test]
async fn wrong_key_does_not_republish_a_loaded_canary() {
    let backing = fixture();
    fail_first_attach(&backing, layout::KEY_CANARY_A).await;
    let before = load_canary(&backing);
    let mutations = Arc::new(AtomicUsize::new(0));
    let observed = mutations.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(op, FaultOp::WriteAt { path, .. } | FaultOp::SetLen { path, .. }
            | FaultOp::SyncData { path } if is_canary(path))
        {
            observed.fetch_add(1, Ordering::SeqCst);
        }
        None
    })));
    assert!(matches!(
        attach(&backing, KEY + 1, false).await,
        Err(AttachError::KeyMismatch(_))
    ));
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
    assert_eq!(load_canary(&backing), before);
    backing.set_fault_hook(None);
}

#[tokio::test]
async fn clean_and_second_copy_failure_controls_preserve_data() {
    acknowledge_and_crash(&fixture(), false).await;
    let backing = fixture();
    fail_first_attach(&backing, layout::KEY_CANARY_B).await;
    acknowledge_and_crash(&backing, false).await;
}

#[tokio::test]
async fn authenticated_provider_can_still_rebind_from_existing_ciphertext() {
    let backing = fixture();
    let engine = attach(&backing, KEY, true).await.unwrap();
    engine.write(0, &[0x6b; UNIT as usize], true).await.unwrap();
    drop(engine);
    backing.remove(layout::KEY_CANARY_A).unwrap();
    backing.remove(layout::KEY_CANARY_B).unwrap();
    backing.sync_dir("").unwrap();
    backing.crash_all_lost();
    let engine = attach(&backing, KEY, true).await.unwrap();
    assert_eq!(
        engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x6b; UNIT as usize]
    );
    drop(engine);
    backing.crash_all_lost();
    assert_both_copies(&backing);
}
