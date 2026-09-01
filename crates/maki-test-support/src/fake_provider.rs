//! `FakeCryptoProvider` — deterministic crypto fake (SPEC §42).
//!
//! Ciphertext layout: `MAGIC(4) || crc32(plaintext)(4) || plaintext ⊕ keystream || pad`.
//! The keystream is seeded from the provider key and (when context binding is
//! enabled) the volume UUID, compatibility ID and unit index — so ciphertext
//! moved to another unit or volume fails integrity, like a real bound AEAD.
//!
//! Injection points: queued errors, per-call latency via a `Clock`, and
//! deliberate contract misbehavior (reorder / drop / duplicate / oversize)
//! used to test the caller-side batch validator.

use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use maki_crypto::clock::Clock;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};

const MAGIC: &[u8; 4] = b"MKF1";

/// Deliberate provider-contract violations, for validator tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misbehavior {
    /// Swap the first two results.
    ReorderResults,
    /// Drop the last result.
    DropLastItem,
    /// Duplicate the first result.
    DuplicateFirstItem,
    /// Return ciphertext larger than max_ciphertext_size.
    OversizeCiphertext,
    /// Return results with a wrong unit_index.
    MismatchedIndex,
}

pub struct FakeCryptoProvider {
    unit_size: u32,
    overhead: u32,
    context_binding: bool,
    key_seed: u64,
    compat_id: String,
    max_batch_items: u32,
    max_batch_bytes: u64,
    fail_queue: Mutex<VecDeque<CryptoError>>,
    latency: Mutex<Option<(Arc<dyn Clock>, Duration)>>,
    misbehavior: Mutex<Option<Misbehavior>>,
    encrypt_calls: AtomicUsize,
    decrypt_calls: AtomicUsize,
    current_calls: Arc<AtomicUsize>,
    max_concurrent: Arc<AtomicUsize>,
}

/// RAII guard tracking concurrent provider calls.
struct ConcurrencyGuard {
    current: Arc<AtomicUsize>,
}

impl ConcurrencyGuard {
    fn enter(current: &Arc<AtomicUsize>, max: &Arc<AtomicUsize>) -> Self {
        let now = current.fetch_add(1, Ordering::SeqCst) + 1;
        max.fetch_max(now, Ordering::SeqCst);
        Self {
            current: current.clone(),
        }
    }
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        self.current.fetch_sub(1, Ordering::SeqCst);
    }
}

impl FakeCryptoProvider {
    pub fn new(unit_size: u32) -> Self {
        Self {
            unit_size,
            overhead: 8,
            context_binding: true,
            key_seed: 0x6d616b69,
            compat_id: "test-profile-v1".to_string(),
            max_batch_items: 128,
            max_batch_bytes: 1 << 20,
            fail_queue: Mutex::new(VecDeque::new()),
            latency: Mutex::new(None),
            misbehavior: Mutex::new(None),
            encrypt_calls: AtomicUsize::new(0),
            decrypt_calls: AtomicUsize::new(0),
            current_calls: Arc::new(AtomicUsize::new(0)),
            max_concurrent: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Highest number of overlapping encrypt/decrypt calls observed.
    pub fn max_concurrent_calls(&self) -> usize {
        self.max_concurrent.load(Ordering::SeqCst)
    }

    pub fn with_key(mut self, key_seed: u64) -> Self {
        self.key_seed = key_seed;
        self
    }

    pub fn with_compat_id(mut self, id: &str) -> Self {
        self.compat_id = id.to_string();
        self
    }

    pub fn with_overhead(mut self, overhead: u32) -> Self {
        assert!(overhead >= 8);
        self.overhead = overhead;
        self
    }

    pub fn with_context_binding(mut self, on: bool) -> Self {
        self.context_binding = on;
        self
    }

    pub fn with_max_batch(mut self, items: u32, bytes: u64) -> Self {
        self.max_batch_items = items;
        self.max_batch_bytes = bytes;
        self
    }

    /// Queue errors returned (one per call) before real work resumes.
    pub fn fail_next(&self, errors: impl IntoIterator<Item = CryptoError>) {
        self.fail_queue.lock().extend(errors);
    }

    pub fn queued_failures(&self) -> usize {
        self.fail_queue.lock().len()
    }

    pub fn set_latency(&self, clock: Arc<dyn Clock>, d: Duration) {
        *self.latency.lock() = Some((clock, d));
    }

    pub fn set_misbehavior(&self, m: Option<Misbehavior>) {
        *self.misbehavior.lock() = m;
    }

    pub fn encrypt_calls(&self) -> usize {
        self.encrypt_calls.load(Ordering::SeqCst)
    }

    pub fn decrypt_calls(&self) -> usize {
        self.decrypt_calls.load(Ordering::SeqCst)
    }

    fn keystream(&self, context: &CryptoContext, unit_index: u64, len: usize) -> Vec<u8> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.key_seed.hash(&mut hasher);
        if self.context_binding {
            context.volume_uuid.hash(&mut hasher);
            context.format_version.hash(&mut hasher);
            context.crypto_compatibility_id.hash(&mut hasher);
            unit_index.hash(&mut hasher);
        }
        let mut rng = ChaCha8Rng::seed_from_u64(hasher.finish());
        let mut out = vec![0u8; len];
        rng.fill_bytes(&mut out);
        out
    }

    async fn common(&self, context: &CryptoContext, items: usize) -> Result<(), CryptoError> {
        let latency = { self.latency.lock().clone() };
        if let Some((clock, d)) = latency {
            clock.sleep(d).await;
        }
        if let Some(err) = self.fail_queue.lock().pop_front() {
            return Err(err);
        }
        if context.crypto_compatibility_id != self.compat_id {
            return Err(CryptoError::ProviderFatal(format!(
                "crypto compatibility mismatch: volume={} provider={}",
                context.crypto_compatibility_id, self.compat_id
            )));
        }
        if items as u32 > self.max_batch_items {
            return Err(CryptoError::NonRetryableRequest(format!(
                "batch of {items} exceeds max_items {}",
                self.max_batch_items
            )));
        }
        Ok(())
    }

    fn misbehave_ct(&self, mut out: Vec<CiphertextUnit>) -> Vec<CiphertextUnit> {
        match *self.misbehavior.lock() {
            None => out,
            Some(Misbehavior::ReorderResults) => {
                if out.len() >= 2 {
                    out.swap(0, 1);
                }
                out
            }
            Some(Misbehavior::DropLastItem) => {
                out.pop();
                out
            }
            Some(Misbehavior::DuplicateFirstItem) => {
                if let Some(first) = out.first().cloned() {
                    out.push(first);
                }
                out
            }
            Some(Misbehavior::OversizeCiphertext) => {
                if let Some(first) = out.first_mut() {
                    first
                        .data
                        .extend(std::iter::repeat(0u8).take(self.overhead as usize + 64));
                }
                out
            }
            Some(Misbehavior::MismatchedIndex) => {
                if let Some(first) = out.first_mut() {
                    first.unit_index = first.unit_index.wrapping_add(1_000_000);
                }
                out
            }
        }
    }
}

#[async_trait]
impl CryptoProvider for FakeCryptoProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "fake".to_string(),
            crypto_compatibility_id: self.compat_id.clone(),
            supported_plaintext_sizes: vec![self.unit_size],
            max_ciphertext_size: self.unit_size + self.overhead,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: self.max_batch_items,
                max_bytes: self.max_batch_bytes,
            },
            integrity: Capability::Contractual,
            context_binding: if self.context_binding {
                Capability::Contractual
            } else {
                Capability::Absent
            },
            replay_protection: Capability::Absent,
        })
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let _guard = ConcurrencyGuard::enter(&self.current_calls, &self.max_concurrent);
        self.encrypt_calls.fetch_add(1, Ordering::SeqCst);
        self.common(context, items.len()).await?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let pt = item.data.expose();
            if pt.len() != self.unit_size as usize {
                return Err(CryptoError::NonRetryableRequest(format!(
                    "unsupported plaintext size {}",
                    pt.len()
                )));
            }
            let ks = self.keystream(context, item.unit_index, pt.len());
            let mut data = Vec::with_capacity(pt.len() + self.overhead as usize);
            data.extend_from_slice(MAGIC);
            data.extend_from_slice(&crc32fast::hash(pt).to_le_bytes());
            data.extend(pt.iter().zip(ks.iter()).map(|(p, k)| p ^ k));
            data.resize(pt.len() + self.overhead as usize, 0);
            out.push(CiphertextUnit {
                unit_index: item.unit_index,
                data,
            });
        }
        Ok(self.misbehave_ct(out))
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let _guard = ConcurrencyGuard::enter(&self.current_calls, &self.max_concurrent);
        self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        self.common(context, items.len()).await?;
        let expected_len = (self.unit_size + self.overhead) as usize;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let ct = &item.data;
            if ct.len() != expected_len {
                return Err(CryptoError::Integrity(format!(
                    "ciphertext length {} != {}",
                    ct.len(),
                    expected_len
                )));
            }
            if &ct[0..4] != MAGIC {
                return Err(CryptoError::Integrity("bad magic".to_string()));
            }
            let crc = u32::from_le_bytes(ct[4..8].try_into().unwrap());
            let body = &ct[8..8 + self.unit_size as usize];
            let ks = self.keystream(context, item.unit_index, body.len());
            let pt: Vec<u8> = body.iter().zip(ks.iter()).map(|(c, k)| c ^ k).collect();
            if crc32fast::hash(&pt) != crc {
                return Err(CryptoError::Integrity(
                    "ciphertext failed integrity verification".to_string(),
                ));
            }
            out.push(PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_vec(pt),
            });
        }
        Ok(out)
    }
}
