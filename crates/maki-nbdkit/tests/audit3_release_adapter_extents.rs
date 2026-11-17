//! Round-3 audit (scope `release-arith`): the NBD adapter's extent checks
//! and chunk arithmetic must refuse wrapping offsets identically in debug
//! (overflow-checks on) and in the shipped release profile (overflow-checks
//! off). Run both:
//!
//!   cargo test -p maki-nbdkit --locked --test audit3_release_adapter_extents
//!   cargo test -p maki-nbdkit --release --locked --test audit3_release_adapter_extents
use std::sync::Arc;
use std::time::Duration;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_nbdkit::adapter::{NbdAdapter, EINVAL};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

const UNIT: u32 = 4096;
const SIZE: u64 = 64 * UNIT as u64;
const MAX_IO: u64 = 8192;

fn adapter() -> NbdAdapter {
    let backing = Arc::new(CrashableBacking::new());
    let sb = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xA3_7E1E),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, SIZE, 16 * UNIT as u64).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    init::create_volume_with_discard(backing.as_ref(), sb).unwrap();
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
                checkpoint: CheckpointPolicy {
                    emergency_reserve_bytes: 0,
                    low_space_checkpoint_bytes: 0,
                    interval: Duration::from_secs(3600),
                    ..Default::default()
                },
                limits: EngineLimits {
                    max_request_bytes: MAX_IO,
                    ..Default::default()
                },
                ..Default::default()
            },
        ))
        .unwrap();
    NbdAdapter::from_engine(engine, runtime)
}

#[test]
fn wrapping_extents_are_einval_in_every_profile() {
    let adapter = adapter();
    assert!(adapter.can_trim());
    adapter.pwrite(&[0x6b; 4096], 0, true).unwrap();
    let top = u64::MAX - 511;
    // nbdkit passes a u32 count, so lengths stay below 4 GiB.
    let extents: [(u64, usize); 6] = [
        (top, 512),
        (top, 4096),
        (u64::MAX - 4095, 16384),
        (SIZE, 512),
        (SIZE - 512, 1024),
        (1 << 63, 512),
    ];
    for (offset, len) in extents {
        let mut buf = vec![0u8; len];
        let read = adapter.pread(&mut buf, offset).map_err(|e| e.errno);
        assert_eq!(read, Err(EINVAL), "pread({offset}, {len})");
        let write = adapter
            .pwrite(&vec![0xa5; len], offset, true)
            .map_err(|e| e.errno);
        assert_eq!(write, Err(EINVAL), "pwrite({offset}, {len})");
        let trim = adapter.trim(offset, len, true).map_err(|e| e.errno);
        assert_eq!(trim, Err(EINVAL), "trim({offset}, {len})");
        for may_trim in [false, true] {
            let zero = adapter
                .zero(offset, len, may_trim, true)
                .map_err(|e| e.errno);
            assert_eq!(zero, Err(EINVAL), "zero({offset}, {len}, {may_trim})");
        }
    }
    // Data at the start and the end is unchanged.
    let mut buf = vec![0u8; 4096];
    adapter.pread(&mut buf, 0).unwrap();
    assert_eq!(buf, vec![0x6b; 4096]);
    adapter.pread(&mut buf, SIZE - 4096).unwrap();
    assert_eq!(buf, vec![0; 4096]);
    // A long (chunked) zero/trim up to the exact end is still accepted.
    adapter.zero(4096, (SIZE - 4096) as usize, true, true).unwrap();
    adapter.pread(&mut buf, 0).unwrap();
    assert_eq!(buf, vec![0x6b; 4096]);
    adapter.shutdown().unwrap();
}
