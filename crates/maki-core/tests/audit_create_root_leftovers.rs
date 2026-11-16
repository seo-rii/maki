//! Audit (config-format, maki-format init.rs): R5-018 made `create_volume`
//! refuse leftovers in `data/`, `journal/` and `checkpoint/`, but root-level
//! leftovers of an earlier volume (`canary.a/b`, `shard-catalog.a/b`) are
//! accepted. A stale key canary then makes the new volume unattachable with a
//! misleading key-mismatch error ("canary belongs to a different volume").

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::{Backing, MemBacking};
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: u32 = 512;

fn superblock(uuid: u128) -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(uuid),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(UNIT, UNIT, 512, UNIT + 8, 64 * UNIT as u64, 16 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn attach(backing: &Arc<MemBacking>) -> Result<Engine, String> {
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
async fn a_root_with_an_earlier_volumes_canary_is_refused_at_create_not_at_attach() {
    let backing = Arc::new(MemBacking::new());
    init::create_volume(backing.as_ref(), superblock(1)).unwrap();
    let engine = attach(&backing).await.unwrap(); // establishes canary.a/b
    engine.write(0, &vec![7; UNIT as usize], true).await.unwrap();
    drop(engine);
    assert!(backing.exists(layout::KEY_CANARY_A).unwrap());

    // "Superblocks removed by hand, a partial restore" (R5-018): the
    // superblocks and every file of the three layout directories are gone.
    backing.remove(layout::SUPERBLOCK_A).unwrap();
    backing.remove(layout::SUPERBLOCK_B).unwrap();
    for dir in [layout::DATA_DIR, layout::JOURNAL_DIR, layout::CHECKPOINT_DIR] {
        for name in backing.list(dir).unwrap() {
            backing.remove(&format!("{dir}/{name}")).unwrap();
        }
    }

    let created = init::create_volume(backing.as_ref(), superblock(2));
    let attached = match &created {
        Ok(_) => Some(attach(&backing).await.map(|_| ())),
        Err(_) => None,
    };
    assert!(
        created.is_err() || matches!(attached, Some(Ok(()))),
        "create accepted a root holding an earlier volume's canary, and the new volume cannot \
         attach: create {:?}, attach {:?}",
        created.as_ref().map(|_| ()),
        attached
    );
}
