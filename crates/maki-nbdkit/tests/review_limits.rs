//! F07 (third review): `nbd.maximum_io` is enforced at the NBD boundary.
//! The plugin cannot advertise `.block_size`, so the kernel may send larger
//! requests; the adapter splits them into pieces of at most the maximum,
//! and the engine refuses anything larger on its own.

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_core::CoreError;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_nbdkit::adapter::NbdAdapter;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const BLOCK: u32 = 512;
const UNIT: u32 = 4096;
const DEVICE_SIZE: u64 = 512 * UNIT as u64; // 2 MiB
const MAX_IO: u64 = 8192;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xF07),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(BLOCK, UNIT, 512, UNIT + 8, DEVICE_SIZE, 64 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

/// An adapter over an engine whose maximum request is `MAX_IO`, plus a
/// second handle to that engine.
fn adapter() -> (NbdAdapter, Engine) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let engine = runtime
        .block_on(Engine::attach(
            backing as Arc<dyn Backing>,
            Arc::new(FakeCryptoProvider::new(UNIT)),
            EngineOptions {
                identity: None,
                volume: VolumeOptions::default(),
                limits: EngineLimits {
                    max_request_bytes: MAX_IO,
                    ..EngineLimits::default()
                },
                cache: None,
                checkpoint: Default::default(),
                clock: None,
            },
        ))
        .unwrap();
    let probe = engine.clone();
    (NbdAdapter::from_engine(engine, runtime), probe)
}

#[test]
fn nbd_requests_above_the_maximum_are_split_and_the_engine_refuses_them() {
    let (adapter, engine) = adapter();
    assert_eq!(adapter.block_sizes().2 as u64, MAX_IO);

    // 64 KiB at an offset that is not a multiple of the maximum: eight
    // pieces, none larger than MAX_IO, the last one carrying the FUA.
    let pattern: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    adapter.pwrite(&pattern, 4096, true).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let stats = rt.block_on(engine.stats());
    assert!(stats.appended_sequence > 0);
    assert_eq!(
        stats.durable_sequence, stats.appended_sequence,
        "FUA on a split request must cover every piece"
    );

    let mut back = vec![0u8; 65536];
    adapter.pread(&mut back, 4096).unwrap();
    assert_eq!(back, pattern);
    // A partial final piece and a piece-sized read stay correct.
    let mut tail = vec![0u8; 512];
    adapter.pread(&mut tail, 4096 + 65536 - 512).unwrap();
    assert_eq!(tail, pattern[65536 - 512..]);
    let mut piece = vec![0u8; MAX_IO as usize];
    adapter.pread(&mut piece, 4096).unwrap();
    assert_eq!(piece, pattern[..MAX_IO as usize]);

    // The engine itself never accepts more than the maximum.
    let err = rt.block_on(engine.read(4096, 65536)).unwrap_err();
    assert!(matches!(err, CoreError::Invalid(_)), "{err}");
    let err = rt.block_on(engine.write(0, &pattern, false)).unwrap_err();
    assert!(matches!(err, CoreError::Invalid(_)), "{err}");

    // Invalid requests are still reported, not silently split away.
    assert!(adapter.pread(&mut [], 0).is_err(), "zero length");
    let mut big = vec![0u8; 65536];
    assert!(
        adapter.pread(&mut big, DEVICE_SIZE - 4096).is_err(),
        "past the end"
    );
    assert!(
        adapter.pwrite(&pattern[..1000], 0, false).is_err(),
        "unaligned"
    );
}
