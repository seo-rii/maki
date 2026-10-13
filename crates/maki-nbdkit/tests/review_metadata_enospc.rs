//! BUG-069: metadata I/O must preserve ENOSPC at the public NBD boundary.

use std::{io, sync::Arc};

use maki_backing::Backing;
use maki_core::{
    engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions},
    volume::VolumeOptions,
};
use maki_format::{
    ab::AbRecord, allocation::AllocationMap, geometry::Geometry, init, layout,
    superblock::Superblock,
};
use maki_nbdkit::adapter::{NbdAdapter, EIO, ENOSPC};
use maki_test_support::{crash_backing::FaultOp, CrashableBacking, FakeCryptoProvider};

const UNIT: usize = 1024;

fn fixture() -> (Arc<CrashableBacking>, NbdAdapter) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Default::default(),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, UNIT as u32, 512, 1032, 65536, 16384).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let engine = runtime
        .block_on(Engine::attach(
            backing.clone(),
            Arc::new(FakeCryptoProvider::new(UNIT as u32)),
            EngineOptions {
                limits: EngineLimits {
                    max_overlay_entries: 3,
                    ..Default::default()
                },
                volume: VolumeOptions {
                    journal_segment_size: 4096,
                },
                checkpoint: CheckpointPolicy {
                    journal_high_watermark_bytes: 1 << 20,
                    journal_max_bytes: 4 << 20,
                    max_pending_bytes: 1 << 16,
                    emergency_reserve_bytes: 0,
                    low_space_checkpoint_bytes: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
        ))
        .unwrap();
    runtime.block_on(engine.stop_checkpoint_worker());
    let adapter = NbdAdapter::from_engine(engine, runtime);
    // The fourth distinct unit forces an inline checkpoint through pwrite.
    for index in 0..3 {
        adapter
            .pwrite(&[0x33; UNIT], index * UNIT as u64, false)
            .unwrap();
    }
    (backing, adapter)
}

#[derive(Clone, Copy)]
enum MetadataOperation {
    Write,
    Resize,
    Sync,
}

fn metadata_fault(backing: &CrashableBacking, operation: MetadataOperation, kind: io::ErrorKind) {
    backing.set_fault_hook(Some(Arc::new(move |event| {
        let path = match (operation, event) {
            (MetadataOperation::Write, FaultOp::WriteAt { path, .. })
            | (MetadataOperation::Resize, FaultOp::SetLen { path, .. })
            | (MetadataOperation::Sync, FaultOp::SyncData { path }) => *path,
            _ => return None,
        };
        path.contains("alloc")
            .then(|| io::Error::new(kind, "injected metadata I/O error"))
    })));
}

#[test]
fn allocation_write_enospc_is_reported_and_retry_preserves_data() {
    let (backing, adapter) = fixture();
    metadata_fault(
        &backing,
        MetadataOperation::Write,
        io::ErrorKind::StorageFull,
    );
    let error = adapter
        .pwrite(&[0x44; UNIT], 3 * UNIT as u64, false)
        .unwrap_err();
    assert_eq!(error.errno, ENOSPC, "{error}");

    backing.set_fault_hook(None);
    adapter
        .pwrite(&[0x44; UNIT], 3 * UNIT as u64, true)
        .unwrap();
    adapter.checkpoint().unwrap();
    for index in 0..4 {
        let mut data = [0; UNIT];
        adapter.pread(&mut data, index * UNIT as u64).unwrap();
        assert_eq!(data, [if index == 3 { 0x44 } else { 0x33 }; UNIT]);
    }
}

#[test]
fn allocation_resize_enospc_is_reported() {
    let (backing, adapter) = fixture();
    metadata_fault(
        &backing,
        MetadataOperation::Resize,
        io::ErrorKind::StorageFull,
    );
    let error = adapter
        .pwrite(&[0x44; UNIT], 3 * UNIT as u64, false)
        .unwrap_err();
    assert_eq!(error.errno, ENOSPC, "{error}");
}

#[test]
fn allocation_sync_enospc_is_reported() {
    let (backing, adapter) = fixture();
    metadata_fault(
        &backing,
        MetadataOperation::Sync,
        io::ErrorKind::StorageFull,
    );
    let error = adapter
        .pwrite(&[0x44; UNIT], 3 * UNIT as u64, false)
        .unwrap_err();
    assert_eq!(error.errno, ENOSPC, "{error}");
}

#[test]
fn slot_data_enospc_keeps_its_existing_classification() {
    let (backing, adapter) = fixture();
    backing.set_fault_hook(Some(Arc::new(|event| match event {
        FaultOp::WriteAt { path, .. } if path.ends_with(".dat") => Some(io::Error::new(
            io::ErrorKind::StorageFull,
            "injected disk full",
        )),
        _ => None,
    })));
    let error = adapter
        .pwrite(&[0x44; UNIT], 3 * UNIT as u64, false)
        .unwrap_err();
    assert_eq!(error.errno, ENOSPC, "{error}");
}

#[test]
fn metadata_io_other_than_enospc_remains_eio() {
    for kind in [io::ErrorKind::InvalidData, io::ErrorKind::PermissionDenied] {
        let (backing, adapter) = fixture();
        metadata_fault(&backing, MetadataOperation::Write, kind);
        let error = adapter
            .pwrite(&[0x44; UNIT], 3 * UNIT as u64, false)
            .unwrap_err();
        assert_eq!(error.errno, EIO, "{error}");
    }
}

#[test]
fn invalid_allocation_metadata_remains_eio() {
    let (backing, adapter) = fixture();
    // A valid envelope with an exhausted generation is a format error,
    // independent of available disk space. It must never become ENOSPC.
    let file = backing.open(&layout::shard_alloc_a(0), false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    let mut allocation = AllocationMap::decode(&bytes).unwrap();
    allocation.set_generation(u64::MAX);
    file.write_at(0, &allocation.encode()).unwrap();
    file.sync_data().unwrap();

    let error = adapter
        .pwrite(&[0x44; UNIT], 3 * UNIT as u64, false)
        .unwrap_err();
    assert_eq!(error.errno, EIO, "{error}");
    assert!(
        error.message.contains("generation space exhausted"),
        "{error}"
    );
}

#[test]
fn inline_checkpoint_without_a_fault_succeeds() {
    let (_, adapter) = fixture();
    adapter
        .pwrite(&[0x44; UNIT], 3 * UNIT as u64, true)
        .unwrap();
    adapter.checkpoint().unwrap();
}
