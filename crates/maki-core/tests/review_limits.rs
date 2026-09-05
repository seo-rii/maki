//! F07 (third review): `nbd.maximum_io` is a real bound. The engine
//! refuses any read or write above `max_request_bytes`, and admission
//! charges every crypto unit a request touches (a partial write holds and
//! re-encrypts whole units), not the request's byte count.

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_core::CoreError;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 4096;
const DEVICE_SIZE: u64 = 64 * UNIT as u64;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xF07),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, DEVICE_SIZE, 16 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn engine(max_request_bytes: u64) -> Engine {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    Engine::attach(
        backing as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            identity: None,
            volume: VolumeOptions::default(),
            limits: EngineLimits {
                max_request_bytes,
                ..EngineLimits::default()
            },
            cache: None,
            checkpoint: Default::default(),
            clock: None,
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn requests_above_the_configured_maximum_are_refused() {
    let engine = engine(8192).await;
    assert_eq!(engine.max_request_bytes(), 8192);
    engine.write(0, &[1u8; 8192], false).await.unwrap();
    let err = engine.write(0, &[1u8; 16384], false).await.unwrap_err();
    assert!(matches!(err, CoreError::Invalid(_)), "{err}");
    let err = engine.read(0, 16384).await.unwrap_err();
    assert!(matches!(err, CoreError::Invalid(_)), "{err}");
    assert_eq!(engine.read(0, 8192).await.unwrap(), vec![1u8; 8192]);
}

#[tokio::test]
async fn admission_charges_every_touched_unit_in_full() {
    let engine = engine(1 << 20).await;
    let unit = UNIT as u64;
    // A 512-byte partial write reads, modifies and re-encrypts a whole unit.
    assert_eq!(engine.admission_cost(0, 512), unit);
    // Straddling a unit boundary touches two units.
    assert_eq!(engine.admission_cost(unit - 512, 1024), 2 * unit);
    assert_eq!(engine.admission_cost(0, 3 * UNIT as usize), 3 * unit);
    // Unaligned to units: one more unit than the length suggests.
    assert_eq!(engine.admission_cost(512, 2 * UNIT as usize), 3 * unit);
    assert_eq!(engine.admission_cost(0, 0), 0);
}
