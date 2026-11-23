//! Audit round 4 (#249/#296 cache reads, #254 RMW, #272 owned whole-unit
//! reads, #286 random prefix): with a provider that never copies plaintext
//! outside `SecretBuffer`, no engine path (full and partial writes, RMW from
//! cache and from ciphertext, cached/uncached/unaligned reads, random-prefix
//! padding, cache resize, checkpoint) may free a heap block that still holds
//! plaintext. Every freed or reallocated block is scanned for a marker.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_backing::MemBacking;
use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, RandomPrefixProvider, SecretBuffer,
};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use uuid::Uuid;

const MARKER: [u8; 16] = *b"\xA7audit4-ENGINEy\x5C";
const UNIT: u32 = 4096;
const PREFIX: u32 = 32;

static SCAN: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static HIT_SIZE: AtomicUsize = AtomicUsize::new(0);

struct Scanner;
// SAFETY: delegates to System; reads only the live block being freed.
unsafe impl GlobalAlloc for Scanner {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if SCAN.load(Ordering::Relaxed) && layout.size() >= MARKER.len() {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if bytes.windows(MARKER.len()).any(|w| w == MARKER) {
                HITS.fetch_add(1, Ordering::SeqCst);
                HIT_SIZE.store(layout.size(), Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scanner = Scanner;

/// Static plaintext source: never freed, so it cannot produce a hit.
static SOURCE: [u8; 4 * UNIT as usize] = {
    let mut s = [0u8; 4 * UNIT as usize];
    let mut i = 0;
    while i < s.len() {
        s[i] = MARKER[i % 16];
        i += 1;
    }
    s
};

/// XOR "cipher" that keeps plaintext only in guarded buffers.
struct GuardedXor {
    unit: u32,
    profile: &'static str,
}

#[async_trait]
impl CryptoProvider for GuardedXor {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "guarded-xor".into(),
            crypto_compatibility_id: self.profile.into(),
            supported_plaintext_sizes: vec![self.unit],
            max_ciphertext_size: self.unit,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 64,
                max_bytes: 1 << 22,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        })
    }
    async fn encrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        Ok(items
            .iter()
            .map(|i| CiphertextUnit {
                unit_index: i.unit_index,
                data: i.data.expose().iter().map(|b| b ^ 0x5A).collect(),
            })
            .collect())
    }
    async fn decrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        Ok(items
            .iter()
            .map(|i| {
                let mut data = SecretBuffer::zeroed(i.data.len());
                for (out, b) in data.expose_mut().iter_mut().zip(&i.data) {
                    *out = b ^ 0x5A;
                }
                PlaintextUnit {
                    unit_index: i.unit_index,
                    data,
                }
            })
            .collect())
    }
}

async fn engine(prefixed: bool, cache: Option<u64>, verify_on_hit: bool) -> Engine {
    let (provider, profile, wire): (Arc<dyn CryptoProvider>, &str, u32) = if prefixed {
        (
            Arc::new(
                RandomPrefixProvider::new(
                    Arc::new(GuardedXor {
                        unit: UNIT + PREFIX,
                        profile: "xor-wire",
                    }),
                    UNIT,
                    PREFIX,
                    "xor-prefixed".into(),
                )
                .await
                .unwrap(),
            ),
            "xor-prefixed",
            UNIT + PREFIX,
        )
    } else {
        (
            Arc::new(GuardedXor {
                unit: UNIT,
                profile: "xor",
            }),
            "xor",
            UNIT,
        )
    };
    let backing = Arc::new(MemBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xE4A5),
            provider_type: "fake".into(),
            crypto_compatibility_id: profile.into(),
            key_identity: "fixture".into(),
            format_version: 1,
            created_unix: 0,
            geometry: Geometry::compute(512, UNIT, 512, wire + 8, 16 << 12, 16 << 12).unwrap(),
        },
    )
    .unwrap();
    Engine::attach(
        backing,
        provider,
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 1 << 20,
            },
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                ..Default::default()
            },
            cache: cache.map(|max_bytes| EngineCacheConfig {
                max_bytes,
                ttl: Duration::from_secs(3600),
                verify_on_hit,
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

async fn workload(engine: &Engine) {
    let u = u64::from(UNIT);
    // Full units, then partial (RMW) writes over written and unwritten units.
    engine
        .write(0, &SOURCE[..2 * UNIT as usize], true)
        .await
        .unwrap();
    engine
        .write(5 * u, &SOURCE[..UNIT as usize], false)
        .await
        .unwrap();
    engine.write(512, &SOURCE[..1024], false).await.unwrap(); // RMW on unit 0
    engine
        .write(9 * u + 512, &SOURCE[..u as usize], false)
        .await
        .unwrap(); // units 9,10
    for _ in 0..2 {
        for (off, len) in [
            (0, UNIT as usize),
            (u + 512, 3072),
            (0, 3 * UNIT as usize),
            (5 * u, UNIT as usize),
            (9 * u, 2 * UNIT as usize),
        ] {
            drop(engine.read_secret(off, len).await.unwrap());
        }
    }
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap();
    // RMW from cache/slots after checkpoint, and reads from slots.
    engine.write(u + 1024, &SOURCE[..512], true).await.unwrap();
    for (off, len) in [
        (0, 2 * UNIT as usize),
        (u, UNIT as usize),
        (9 * u + 512, 512),
    ] {
        drop(engine.read_secret(off, len).await.unwrap());
    }
    // Shrink the cache to force compaction/eviction, then grow and reread.
    engine.resize_cache(UNIT as u64);
    drop(engine.read_secret(0, 3 * UNIT as usize).await.unwrap());
    engine.resize_cache(0);
    engine.resize_cache(64 << 20);
    drop(engine.read_secret(0, 11 * UNIT as usize).await.unwrap());
    engine
        .write(512, &SOURCE[..UNIT as usize], true)
        .await
        .unwrap();
    drop(engine.read_secret(0, 2 * UNIT as usize).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_paths_free_no_plaintext() {
    maki_crypto::secret::set_page_locking(true);
    let mut report = Vec::new();
    for prefixed in [false, true] {
        for (cache, verify) in [
            (None, false),
            (Some(5 * u64::from(UNIT)), false),
            (Some(64 << 20), true),
        ] {
            let engine = engine(prefixed, cache, verify).await;
            SCAN.store(true, Ordering::SeqCst);
            let before = HITS.load(Ordering::SeqCst);
            workload(&engine).await;
            engine.stop_checkpoint_worker().await;
            drop(engine);
            SCAN.store(false, Ordering::SeqCst);
            let after = HITS.load(Ordering::SeqCst);
            if after != before {
                report.push(format!(
                    "prefixed={prefixed} cache={cache:?} verify={verify}: {} plaintext block(s) \
                     freed un-erased (last {} bytes)",
                    after - before,
                    HIT_SIZE.load(Ordering::SeqCst)
                ));
            }
        }
    }
    // Positive control.
    SCAN.store(true, Ordering::SeqCst);
    let before = HITS.load(Ordering::SeqCst);
    drop(SOURCE[..64].to_vec());
    assert_eq!(HITS.load(Ordering::SeqCst), before + 1);
    SCAN.store(false, Ordering::SeqCst);
    assert!(report.is_empty(), "{report:#?}");
}
