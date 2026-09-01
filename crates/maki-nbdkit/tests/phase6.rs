//! Phase 6 — nbdkit adapter (SPEC §48).
//!
//! These tests exercise the cross-platform blocking adapter — the exact
//! surface the nbdkit C ABI shim calls. Kernel-level verification (libnbd,
//! /dev/nbd fio) runs on Linux; see docs/phase-6.md.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{Engine, EngineOptions};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_nbdkit::adapter::{AdapterError, NbdAdapter};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const BLOCK: u32 = 512;
const UNIT: u32 = 4096;
const DEVICE_SIZE: u64 = 512 * UNIT as u64; // 2 MiB

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x66),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(BLOCK, UNIT, 512, UNIT + 8, DEVICE_SIZE, 64 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn adapter_over(backing: &Arc<CrashableBacking>) -> NbdAdapter {
    adapter_with_provider(backing, Arc::new(FakeCryptoProvider::new(UNIT)))
}

fn adapter_with_provider(
    backing: &Arc<CrashableBacking>,
    provider: Arc<dyn CryptoProvider>,
) -> NbdAdapter {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let engine = runtime
        .block_on(Engine::attach(
            backing.clone() as Arc<dyn Backing>,
            provider,
            EngineOptions::default(),
        ))
        .unwrap();
    NbdAdapter::from_engine(engine, runtime)
}

// ---------- get_size / block_size ----------

#[test]
fn get_size_and_block_sizes() {
    let backing = Arc::new(CrashableBacking::new());
    let adapter = adapter_over(&backing);
    assert_eq!(adapter.get_size(), DEVICE_SIZE);
    let (min, preferred, max) = adapter.block_sizes();
    assert_eq!(min, BLOCK);
    assert_eq!(preferred, UNIT);
    assert_eq!(max, 1 << 20);
}

// ---------- capability flags ----------

#[test]
fn trim_zero_and_multiconn_are_disabled() {
    let backing = Arc::new(CrashableBacking::new());
    let adapter = adapter_over(&backing);
    assert!(!adapter.can_trim(), "trim disabled (SPEC §48)");
    assert!(!adapter.can_multi_conn(), "multi-connection disabled");
    assert!(
        !adapter.can_write_zeroes(),
        "no zero callback: nbdkit falls back to pwrite"
    );
    assert!(adapter.can_flush());
    assert!(adapter.can_fua());
}

// ---------- read/write/FUA/FLUSH ----------

#[test]
fn pread_pwrite_roundtrip() {
    let backing = Arc::new(CrashableBacking::new());
    let adapter = adapter_over(&backing);
    let data = vec![0xCD; 8192];
    adapter.pwrite(&data, 4096, false).unwrap();
    let mut buf = vec![0u8; 8192];
    adapter.pread(&mut buf, 4096).unwrap();
    assert_eq!(buf, data);
    // unwritten regions read zero
    let mut buf = vec![0xFFu8; 512];
    adapter.pread(&mut buf, 0).unwrap();
    assert!(buf.iter().all(|b| *b == 0));
}

#[test]
fn unaligned_or_oob_requests_are_einval() {
    let backing = Arc::new(CrashableBacking::new());
    let adapter = adapter_over(&backing);
    let mut buf = vec![0u8; 100];
    match adapter.pread(&mut buf, 0) {
        Err(AdapterError { errno, .. }) => assert_eq!(errno, libc_einval()),
        Ok(_) => panic!("unaligned length must fail"),
    }
    let mut buf = vec![0u8; 512];
    assert!(adapter.pread(&mut buf, DEVICE_SIZE).is_err());
}

fn libc_einval() -> i32 {
    22
}

#[test]
fn fua_and_flush_are_durable() {
    let backing = Arc::new(CrashableBacking::new());
    let adapter = adapter_over(&backing);
    adapter.pwrite(&vec![0xAA; 4096], 0, true).unwrap(); // FUA
    adapter.pwrite(&vec![0xBB; 4096], 4096, false).unwrap();
    adapter.flush().unwrap(); // FLUSH covers 0xBB
    adapter.pwrite(&vec![0xCC; 4096], 8192, false).unwrap(); // volatile
    drop(adapter);

    backing.crash_all_lost();
    let adapter = adapter_over(&backing);
    let mut buf = vec![0u8; 4096];
    adapter.pread(&mut buf, 0).unwrap();
    assert_eq!(buf, vec![0xAA; 4096]);
    adapter.pread(&mut buf, 4096).unwrap();
    assert_eq!(buf, vec![0xBB; 4096]);
    adapter.pread(&mut buf, 8192).unwrap();
    assert!(buf.iter().all(|b| *b == 0), "volatile write may be lost");
}

// ---------- parallel callbacks ----------

#[test]
fn parallel_callbacks_from_many_threads() {
    let backing = Arc::new(CrashableBacking::new());
    let adapter = Arc::new(adapter_over(&backing));
    let mut handles = Vec::new();
    for t in 0..8u64 {
        let adapter = adapter.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..16u64 {
                let off = (t * 16 + i) * UNIT as u64;
                adapter
                    .pwrite(&vec![(t * 16 + i) as u8 + 1; UNIT as usize], off, false)
                    .unwrap();
                let mut buf = vec![0u8; UNIT as usize];
                adapter.pread(&mut buf, off).unwrap();
                assert_eq!(buf, vec![(t * 16 + i) as u8 + 1; UNIT as usize]);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    adapter.flush().unwrap();
}

// ---------- panic boundary ----------

struct PanickingProvider {
    inner: FakeCryptoProvider,
}

#[async_trait]
impl CryptoProvider for PanickingProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        if items.iter().any(|i| i.unit_index == 13) {
            panic!("injected provider panic");
        }
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.inner.decrypt_batch(context, items).await
    }
}

/// A panic anywhere inside the engine must surface as EIO to the C caller —
/// never unwind across the FFI boundary, never poison the adapter.
#[test]
fn panic_inside_engine_becomes_eio_and_adapter_survives() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(PanickingProvider {
        inner: FakeCryptoProvider::new(UNIT),
    });
    let adapter = adapter_with_provider(&backing, provider);

    // unit 13 → provider panics → EIO
    let err = adapter
        .pwrite(&vec![1; UNIT as usize], 13 * UNIT as u64, false)
        .unwrap_err();
    assert_eq!(err.errno, 5, "panic must map to EIO");

    // Adapter still fully functional afterwards.
    adapter.pwrite(&vec![2; UNIT as usize], 0, true).unwrap();
    let mut buf = vec![0u8; UNIT as usize];
    adapter.pread(&mut buf, 0).unwrap();
    assert_eq!(buf, vec![2; UNIT as usize]);
}

// ---------- disconnect / clean detach ----------

#[test]
fn clean_detach_flushes_checkpoints_and_releases_lock() {
    let backing = Arc::new(CrashableBacking::new());
    let adapter = adapter_over(&backing);
    adapter.pwrite(&vec![0x77; 4096], 0, false).unwrap();
    adapter.shutdown().unwrap(); // flush + checkpoint + release

    // Lock released: immediate re-attach succeeds; data durable even
    // through a lose-everything crash (shutdown checkpointed).
    backing.crash_all_lost();
    let adapter = adapter_over(&backing);
    let mut buf = vec![0u8; 4096];
    adapter.pread(&mut buf, 0).unwrap();
    assert_eq!(buf, vec![0x77; 4096]);
}

// ---------- config-driven assembly ----------

#[test]
fn adapter_opens_from_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol");
    let root_str = root.to_string_lossy().replace('\\', "/");
    let config = format!(
        r#"
config_schema_version = 1
[volume]
name = "cfgtest"
max_virtual_size = "2MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = "{root_str}"
"#
    );
    let config_path = dir.path().join("vol.toml");
    std::fs::write(&config_path, &config).unwrap();

    // maki volume create, then adapter open.
    maki_nbdkit::daemon::create_volume_from_config_str(&config).unwrap();
    let adapter = NbdAdapter::open_config(config_path.to_str().unwrap()).unwrap();
    assert_eq!(adapter.get_size(), 2 << 20);
    adapter.pwrite(&vec![0x42; 4096], 0, true).unwrap();
    adapter.shutdown().unwrap();

    // Re-open (recovery path) and verify.
    let adapter = NbdAdapter::open_config(config_path.to_str().unwrap()).unwrap();
    let mut buf = vec![0u8; 4096];
    adapter.pread(&mut buf, 0).unwrap();
    assert_eq!(buf, vec![0x42; 4096]);
}
