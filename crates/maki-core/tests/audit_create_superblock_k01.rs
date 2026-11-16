//! Audit (config-format, maki-format init.rs): `create_volume` publishes
//! superblock A with write + fdatasync. If that fdatasync fails (or the
//! process dies right before it), creation returns an error but leaves a
//! CRC-valid superblock in the page cache. A retry of `volume create` refuses
//! the root ("volume superblock already present"), `Engine::attach` accepts
//! it (recovery loads the superblock and never re-stores it), FLUSH succeeds,
//! and a power loss then removes the only superblock copy: the acknowledged
//! data is no longer reachable. K-01 / BUG-022 class, for the superblock.

use std::io;
use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xa0d1_c0de),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(UNIT, UNIT, 512, UNIT + 8, 64 * UNIT as u64, 16 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn attach(backing: &Arc<CrashableBacking>) -> Result<Engine, String> {
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
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
    .map_err(|e| e.to_string())
}

#[tokio::test]
async fn flush_acknowledged_data_survives_power_loss_after_a_failed_superblock_sync_at_create() {
    let backing = Arc::new(CrashableBacking::new());
    backing.set_fault_hook(Some(Arc::new(|op: &FaultOp<'_>| match op {
        FaultOp::SyncData { path } if *path == layout::SUPERBLOCK_A => {
            Some(io::Error::other("EIO"))
        }
        _ => None,
    })));
    assert!(init::create_volume(backing.as_ref(), superblock()).is_err());
    backing.set_fault_hook(None);
    // `maki volume create` again: refused, the root is "already a volume".
    assert!(init::create_volume(backing.as_ref(), superblock()).is_err());

    let engine = attach(&backing).await.expect("attach accepts the root");
    let data = vec![0x5a; UNIT as usize];
    engine.write(0, &data, false).await.unwrap();
    engine.flush().await.expect("FLUSH acknowledged");
    drop(engine);

    backing.crash_all_lost();
    let engine = attach(&backing)
        .await
        .unwrap_or_else(|e| panic!("FLUSH-acknowledged volume unreachable after power loss: {e}"));
    assert_eq!(engine.read(0, UNIT as usize).await.unwrap(), data);
}
