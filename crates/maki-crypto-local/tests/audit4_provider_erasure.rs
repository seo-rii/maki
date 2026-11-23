//! Audit round 4 (#295 gcm-frame, #302 gcm-aad, #286/#323 random prefix,
//! #316 plaintext scan): no plaintext byte may reach the allocator un-erased
//! on any success or rejection path of the local AEAD providers and the
//! wrappers stacked on them. Every freed (or reallocated) heap block is
//! scanned for a 16-byte marker the plaintext is built from.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    RandomPrefixProvider, SecretBuffer,
};
use maki_crypto_local::{keysource::MapKeySource, AesGcmSivProvider, AesXtsProvider};
use uuid::Uuid;

const MARKER: [u8; 16] = *b"\xA7audit4-PLAINxy\x5C";
const UNIT: usize = 4096;

static SCAN: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static HIT_SIZE: AtomicUsize = AtomicUsize::new(0);

struct Scanner;

/// First 16 bytes of every test key (AES-256 round key 0 under AES-NI).
const KEYMARK: [u8; 16] = *b"\xC3audit4-KEYMATy\x3C";

fn contains_marker(bytes: &[u8]) -> bool {
    bytes
        .windows(MARKER.len())
        .any(|w| w == MARKER || w == KEYMARK)
}

// SAFETY: everything is delegated to System; the scan only reads the block
// being freed, which is still live and `layout.size()` bytes long.
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
            if contains_marker(bytes) {
                HITS.fetch_add(1, Ordering::SeqCst);
                HIT_SIZE.store(layout.size(), Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
    // The default realloc copies and then calls `dealloc` on the old block.
}

#[global_allocator]
static ALLOCATOR: Scanner = Scanner;

fn plaintext(len: usize) -> SecretBuffer {
    let mut b = SecretBuffer::zeroed(len);
    for chunk in b.expose_mut().chunks_mut(MARKER.len()) {
        chunk.copy_from_slice(&MARKER[..chunk.len()]);
    }
    b
}

fn units(len: usize, count: u64) -> Vec<PlaintextUnit> {
    (0..count)
        .map(|unit_index| PlaintextUnit {
            unit_index,
            data: plaintext(len),
        })
        .collect()
}

fn context(profile: &str) -> CryptoContext {
    CryptoContext {
        volume_uuid: Uuid::from_u128(0xA4),
        format_version: 3,
        crypto_compatibility_id: profile.into(),
    }
}

/// Echoes (shapes of) its plaintext as "ciphertext" in ordinary Vecs: the
/// caller-side checks must erase every such buffer when they reject it.
struct Echo {
    unit: u32,
    shape: &'static str,
}

#[async_trait]
impl CryptoProvider for Echo {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "echo".into(),
            crypto_compatibility_id: "echo-v1".into(),
            supported_plaintext_sizes: vec![self.unit],
            max_ciphertext_size: self.unit + 64,
            stateless: true,
            retry_safe: true,
            batch: maki_crypto::BatchCapability {
                supported: true,
                max_items: 64,
                max_bytes: 1 << 24,
            },
            integrity: maki_crypto::Capability::Verified,
            context_binding: maki_crypto::Capability::Verified,
            replay_protection: maki_crypto::Capability::Absent,
        })
    }
    async fn encrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let mut out: Vec<CiphertextUnit> = items
            .iter()
            .map(|i| {
                // Exact capacity: the echo itself must not leave copies behind.
                let mut data = Vec::with_capacity(12 + i.data.len() + 16);
                data.extend_from_slice(&[0u8; 12]);
                data.extend_from_slice(i.data.expose());
                data.extend_from_slice(&[0u8; 16]);
                CiphertextUnit {
                    unit_index: i.unit_index,
                    data,
                }
            })
            .collect();
        match self.shape {
            "extra" => out.push(CiphertextUnit {
                unit_index: 99,
                data: items[0].data.expose().to_vec(),
            }),
            "short" => {
                use zeroize::Zeroize;
                out.pop().unwrap().data.zeroize();
            }
            "wrong-index" => out[0].unit_index += 1000,
            _ => {}
        }
        Ok(out)
    }
    async fn decrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        Ok(items
            .iter()
            .map(|i| PlaintextUnit {
                unit_index: i.unit_index,
                data: SecretBuffer::from_slice(&i.data[12..i.data.len() - 16]),
            })
            .collect())
    }
}

fn hits() -> usize {
    HITS.load(Ordering::SeqCst)
}

async fn roundtrip(provider: &dyn CryptoProvider, profile: &str, len: usize) {
    let ctx = context(profile);
    let input = units(len, 5);
    let mut cts = provider.encrypt_batch(&ctx, &input).await.unwrap();
    let plain = provider.decrypt_batch(&ctx, &cts).await.unwrap();
    for (p, i) in plain.iter().zip(&input) {
        assert!(p.data == i.data);
    }
    drop(plain);
    // Tamper: authentication (or size) failure after plaintext was produced.
    cts[2].data[20] ^= 1;
    let _ = provider.decrypt_batch(&ctx, &cts).await;
    let shorter = cts[2].data.len() - 1;
    cts[2].data.truncate(shorter);
    let _ = provider.decrypt_batch(&ctx, &cts).await;
    // Wrong size input to encrypt after earlier items were produced.
    let mut bad = units(len, 3);
    bad[2].data.truncate(len - 1);
    assert!(provider.encrypt_batch(&ctx, &bad).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn no_plaintext_reaches_the_allocator_unerased() {
    maki_crypto::secret::set_page_locking(true);
    let mut keys = MapKeySource::new();
    let mut gcm_key = KEYMARK.to_vec();
    gcm_key.extend_from_slice(&[0x11; 16]);
    keys.insert("gcm", gcm_key);
    let mut xts_key = KEYMARK.to_vec();
    xts_key.extend_from_slice(&[0x22; 48]);
    xts_key[40] = 0x33;
    keys.insert("xts", xts_key);
    let gcm: Arc<dyn CryptoProvider> =
        Arc::new(AesGcmSivProvider::new(&keys, "gcm", UNIT as u32, "gcm-v1").unwrap());
    let gcm_wire: Arc<dyn CryptoProvider> =
        Arc::new(AesGcmSivProvider::new(&keys, "gcm", (UNIT + 32) as u32, "gcm-v1").unwrap());
    let xts: Arc<dyn CryptoProvider> =
        Arc::new(AesXtsProvider::new(&keys, "xts", UNIT as u32, "xts-v1").unwrap());

    SCAN.store(true, Ordering::SeqCst);
    let mut report = Vec::new();
    let mut step = |name: &str, before: usize| {
        let after = hits();
        if after != before {
            report.push(format!(
                "{name}: {} freed block(s) held plaintext (last {} bytes)",
                after - before,
                HIT_SIZE.load(Ordering::SeqCst)
            ));
        }
        after
    };

    let mut h = hits();
    roundtrip(gcm.as_ref(), "gcm-v1", UNIT).await;
    h = step("gcm-siv", h);
    roundtrip(xts.as_ref(), "xts-v1", UNIT).await;
    h = step("xts", h);
    let checked = CheckedProvider::pinned(gcm.clone(), UNIT as u32);
    roundtrip(&checked, "gcm-v1", UNIT).await;
    h = step("checked gcm-siv", h);
    let prefixed = RandomPrefixProvider::new(gcm_wire.clone(), UNIT as u32, 32, "pfx-v1".into())
        .await
        .unwrap();
    roundtrip(&prefixed, "pfx-v1", UNIT).await;
    h = step("random prefix over gcm-siv", h);
    let outer = CheckedProvider::pinned(Arc::new(prefixed), UNIT as u32);
    roundtrip(&outer, "pfx-v1", UNIT).await;
    h = step("checked random prefix", h);

    for shape in ["echo", "extra", "short", "wrong-index"] {
        let echo = CheckedProvider::new(Arc::new(Echo {
            unit: UNIT as u32,
            shape,
        }));
        assert!(echo
            .encrypt_batch(&context("echo-v1"), &units(UNIT, 3))
            .await
            .is_err());
        h = step(&format!("checked rejection {shape}"), h);
        let prefixed = RandomPrefixProvider::new(
            Arc::new(Echo {
                unit: (UNIT + 32) as u32,
                shape,
            }),
            UNIT as u32,
            32,
            "pfx-echo".into(),
        )
        .await
        .unwrap();
        assert!(prefixed
            .encrypt_batch(&context("pfx-echo"), &units(UNIT, 3))
            .await
            .is_err());
        h = step(&format!("random prefix rejection {shape}"), h);
    }
    // Provider (cipher objects, key schedules) teardown while scanning.
    drop(gcm);
    drop(gcm_wire);
    drop(xts);
    drop(checked);
    drop(outer);
    h = step("provider and key schedule teardown", h);
    let _ = h;
    // Positive control: an ordinary copy of plaintext is detected when freed.
    let before = hits();
    drop(plaintext(UNIT).expose().to_vec());
    assert_eq!(hits(), before + 1, "scanner missed a plaintext copy");
    SCAN.store(false, Ordering::SeqCst);
    assert!(report.is_empty(), "{report:#?}");
}
