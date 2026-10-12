//! Pending-byte limits apply between every record, including inside one request.

use maki_backing::Backing;
use maki_core::engine::{AttachError, CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_crypto::Clock;
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{fake_provider::FakeCryptoProvider, CrashableBacking, ManualClock};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
const UNIT: u32 = 1024;
const RECORD: u64 = 32 + 1024 + 8;
fn block() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xB0DE),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            512,
            UNIT,
            512,
            UNIT + 8,
            256 * UNIT as u64,
            32 * UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}
fn policy() -> CheckpointPolicy {
    CheckpointPolicy {
        journal_high_watermark_bytes: 32 * 1024,
        journal_max_bytes: 64 * 1024,
        max_pending_bytes: 16 * 1024,
        emergency_reserve_bytes: 0,
        low_space_checkpoint_bytes: 0,
        interval: Duration::from_secs(30),
    }
}
async fn engine(p: CheckpointPolicy, clock: Option<Arc<dyn Clock>>) -> Result<Engine, AttachError> {
    engine_with_backing(p, clock)
        .await
        .map(|(engine, _)| engine)
}
async fn engine_with_backing(
    p: CheckpointPolicy,
    clock: Option<Arc<dyn Clock>>,
) -> Result<(Engine, Arc<CrashableBacking>), AttachError> {
    let backing = Arc::new(CrashableBacking::new().with_tearing(17));
    init::create_volume(backing.as_ref(), block()).unwrap();
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 8192,
            },
            checkpoint: p,
            clock,
            limits: maki_core::engine::EngineLimits {
                max_request_bytes: 4096,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .map(|engine| (engine, backing))
}
fn validated_limit(limit: u64) {
    let cfg = maki_format::config::parse_config(&format!(
        r#"
config_schema_version=1
[volume]
name="journal-audit"
max_virtual_size="256KiB"
device_block_size=512
crypto_unit_size=1024
shard_logical_size="32KiB"
[crypto]
provider="remote-http"
crypto_compatibility_id="test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes=[1024]
max_ciphertext_size=1032
[[crypto.http.endpoint]]
name="audit"
url="http://127.0.0.1:1"
[crypto.http.encrypt]
method="POST"
path="/encrypt"
[crypto.http.decrypt]
method="POST"
path="/decrypt"
[backing]
root="/unused"
journal_segment_size="8KiB"
journal_max_bytes="64KiB"
[limits]
max_journal_pending_bytes="{limit}B"
[nbd]
minimum_io=512
preferred_io=1024
maximum_io="4KiB"
"#
    ))
    .unwrap();
    cfg.validate().unwrap();
    println!("config_limit={limit} validated=true");
}
#[tokio::test]
async fn one_large_request_respects_empty_pending_limit() {
    validated_limit(2 * RECORD);
    let mut p = policy();
    p.max_pending_bytes = 2 * RECORD;
    let e = engine(p.clone(), Some(Arc::new(ManualClock::new())))
        .await
        .unwrap();
    e.write(0, &[7; 4096], false).await.unwrap();
    let s = e.stats().await;
    println!(
        "empty appended={} durable={} pending={} limit={}",
        s.appended_sequence, s.durable_sequence, s.journal_pending_bytes, p.max_pending_bytes
    );
    assert!(s.journal_pending_bytes <= p.max_pending_bytes);
}
#[tokio::test]
async fn one_large_request_respects_existing_pending_limit() {
    validated_limit(2 * RECORD);
    let mut p = policy();
    p.max_pending_bytes = 2 * RECORD;
    let e = engine(p.clone(), Some(Arc::new(ManualClock::new())))
        .await
        .unwrap();
    e.write(4 * UNIT as u64, &[7; UNIT as usize], false)
        .await
        .unwrap();
    e.write(0, &[8; 4096], false).await.unwrap();
    let s = e.stats().await;
    println!(
        "existing appended={} durable={} pending={} limit={}",
        s.appended_sequence, s.durable_sequence, s.journal_pending_bytes, p.max_pending_bytes
    );
    assert!(s.journal_pending_bytes <= p.max_pending_bytes);
}
#[tokio::test]
async fn limit_below_a_record_is_rejected_by_core_attach() {
    let mut p = policy();
    p.max_pending_bytes = RECORD - 1;
    let result = engine(p, Some(Arc::new(ManualClock::new()))).await;
    println!("below_record_attach={result:?}");
    assert!(matches!(result, Err(AttachError::Config(_))));
}

#[tokio::test]
async fn one_record_pending_budget_accepts_a_multi_unit_fua() {
    let mut p = policy();
    p.max_pending_bytes = RECORD;
    let e = engine(p, Some(Arc::new(ManualClock::new()))).await.unwrap();
    e.write(0, &[5; 4096], true).await.unwrap();
    let stats = e.stats().await;
    assert_eq!(stats.appended_sequence, 4);
    assert_eq!(stats.durable_sequence, 4);
    assert_eq!(stats.journal_pending_bytes, 0);
    assert_eq!(e.read(0, 4096).await.unwrap(), vec![5; 4096]);
}

#[tokio::test]
async fn a_failed_intermediate_sync_stops_append_and_can_resume() {
    use maki_test_support::crash_backing::FaultOp;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let mut p = policy();
    p.max_pending_bytes = 2 * RECORD;
    let (e, backing) = engine_with_backing(p, Some(Arc::new(ManualClock::new())))
        .await
        .unwrap();
    let failed = Arc::new(AtomicBool::new(false));
    let observed = failed.clone();
    let records = AtomicUsize::new(0);
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(op, FaultOp::WriteAt { path, offset, len }
            if path.starts_with("journal/seg-")
                && *offset >= maki_format::journal::SEGMENT_HEADER_SIZE as u64
                && *len == RECORD as usize)
        {
            records.fetch_add(1, Ordering::SeqCst);
        }
        if matches!(op, FaultOp::SyncData { path } if path.starts_with("journal/seg-"))
            && records.load(Ordering::SeqCst) >= 2
            && !observed.swap(true, Ordering::SeqCst)
        {
            Some(std::io::Error::from_raw_os_error(5))
        } else {
            None
        }
    })));
    let result = e.write(0, &[6; 4096], false).await;
    assert!(result.is_err(), "the first intermediate sync must fail");
    assert!(failed.load(Ordering::SeqCst));
    let stats = e.stats().await;
    assert_eq!(stats.appended_sequence, 2);
    assert_eq!(stats.durable_sequence, 0);
    assert_eq!(stats.journal_pending_bytes, 2 * RECORD);
    assert_eq!(stats.admission_slots, 0);
    assert_eq!(stats.active_requests, 0);
    backing.set_fault_hook(None);
    e.flush().await.unwrap();
    assert_eq!(e.stats().await.durable_sequence, 2);
    e.write(0, &[7; 4096], true).await.unwrap();
    drop(e);
    backing.crash_all_lost();
    let reopened = Engine::attach(
        backing as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 8192,
            },
            checkpoint: policy(),
            clock: Some(Arc::new(ManualClock::new())),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(reopened.read(0, 4096).await.unwrap(), vec![7; 4096]);
}
