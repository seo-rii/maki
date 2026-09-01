//! The block engine: byte-addressed encrypted device semantics over the
//! ciphertext volume (SPEC §23 write path, §28 per-unit concurrency, §46).
//!
//! - Reads take a consistent per-unit ciphertext snapshot (shared volume
//!   lock), decrypt in one batch, and never require unit locks: a racing
//!   read sees a unit's old or new content, never a mix.
//! - Writes lock their units in ascending order (no deadlocks), perform
//!   read-modify-write for partial units, encrypt as one batch *outside* the
//!   volume lock, then append + publish under the exclusive volume lock.
//! - FUA syncs after all of the request's records are appended (SPEC §24);
//!   FLUSH is the journal barrier (SPEC §25).
//! - Attach refuses crypto-profile mismatches and providers whose contract
//!   does not fit the volume geometry (SPEC §12, §27).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, RwLock};

use maki_backing::Backing;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    CiphertextUnit, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_format::geometry::Geometry;

use crate::error::CoreError;
use crate::recovery::RecoveryError;
use crate::volume::{Volume, VolumeOptions};

#[derive(Debug, thiserror::Error)]
pub enum AttachError {
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("configuration: {0}")]
    Config(String),
}

/// Admission limits at the block-core entry (SPEC §30): both request count
/// and byte count are bounded.
#[derive(Debug, Clone)]
pub struct EngineLimits {
    pub max_active_callbacks: u32,
    pub max_plaintext_bytes: u64,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_active_callbacks: 64,
            max_plaintext_bytes: 128 << 20,
        }
    }
}

/// Plaintext read-cache settings (SPEC §29). `None` = mode off.
#[derive(Debug, Clone)]
pub struct EngineCacheConfig {
    pub max_bytes: u64,
    pub ttl: std::time::Duration,
}

#[derive(Debug, Clone, Default)]
pub struct EngineOptions {
    pub volume: VolumeOptions,
    pub limits: EngineLimits,
    pub cache: Option<EngineCacheConfig>,
}

struct UnitLocks {
    locks: parking_lot::Mutex<HashMap<u64, Arc<AsyncMutex<()>>>>,
}

impl UnitLocks {
    fn new() -> Self {
        Self {
            locks: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Lock a unit range in ascending order.
    async fn lock_range(&self, first: u64, last: u64) -> Vec<OwnedMutexGuard<()>> {
        let mut guards = Vec::with_capacity((last - first + 1) as usize);
        for unit in first..=last {
            let mutex = {
                let mut map = self.locks.lock();
                if map.len() > 8192 {
                    map.retain(|_, m| Arc::strong_count(m) > 1);
                }
                map.entry(unit)
                    .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                    .clone()
            };
            guards.push(mutex.lock_owned().await);
        }
        guards
    }
}

struct EngineInner {
    volume: RwLock<Volume>,
    provider: CheckedProvider,
    context: CryptoContext,
    geometry: Geometry,
    unit_locks: UnitLocks,
    /// Provider batch contract (SPEC §16): calls are chunked to fit.
    batch_max_items: usize,
    batch_max_bytes: u64,
    /// Request-count + plaintext-byte admission (SPEC §30).
    admission: maki_crypto::flow::DualSemaphore,
    /// Versioned plaintext read cache (SPEC §29). `None` = mode off.
    cache: Option<maki_cache::VersionedLruCache>,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("size", &self.inner.geometry.max_virtual_size)
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Recover the volume, verify the provider (self-test + compatibility +
    /// geometry contract), and return a ready engine.
    pub async fn attach(
        backing: Arc<dyn Backing>,
        provider: Arc<dyn CryptoProvider>,
        options: EngineOptions,
    ) -> Result<Self, AttachError> {
        let volume = Volume::recover(backing, options.volume)?;
        let superblock = volume.superblock().clone();
        let geometry = superblock.geometry.clone();

        let context = CryptoContext {
            volume_uuid: superblock.volume_uuid,
            format_version: superblock.format_version,
            crypto_compatibility_id: superblock.crypto_compatibility_id.clone(),
        };

        let caps = provider.capabilities().await?;
        if caps.max_ciphertext_size > geometry.max_ciphertext_size {
            return Err(AttachError::Config(format!(
                "provider max_ciphertext_size {} exceeds volume contract {}",
                caps.max_ciphertext_size, geometry.max_ciphertext_size
            )));
        }
        provider_self_test(
            provider.as_ref(),
            &context,
            geometry.crypto_unit_size as usize,
            &superblock.crypto_compatibility_id,
        )
        .await?;

        let (batch_max_items, batch_max_bytes) = if caps.batch.supported {
            (caps.batch.max_items.max(1) as usize, caps.batch.max_bytes.max(1))
        } else {
            (1, u64::MAX)
        };

        Ok(Self {
            inner: Arc::new(EngineInner {
                volume: RwLock::new(volume),
                provider: CheckedProvider::new(provider),
                context,
                geometry,
                unit_locks: UnitLocks::new(),
                batch_max_items,
                batch_max_bytes,
                admission: maki_crypto::flow::DualSemaphore::new(
                    options.limits.max_active_callbacks,
                    options.limits.max_plaintext_bytes,
                ),
                cache: options.cache.map(|c| {
                    maki_cache::VersionedLruCache::new(
                        maki_cache::CacheConfig {
                            max_bytes: c.max_bytes,
                            ttl: c.ttl,
                            zeroize_on_evict: true,
                        },
                        Arc::new(maki_crypto::SystemClock::new()),
                    )
                }),
            }),
        })
    }

    /// Split `count` items with `size_of(i)` bytes each into chunk ranges
    /// respecting the provider's batch limits (at least one item per chunk).
    fn batch_chunks(
        &self,
        count: usize,
        mut size_of: impl FnMut(usize) -> usize,
    ) -> Vec<std::ops::Range<usize>> {
        let mut chunks = Vec::new();
        let mut start = 0usize;
        let mut bytes = 0u64;
        for i in 0..count {
            let sz = size_of(i) as u64;
            let over_items = i - start >= self.inner.batch_max_items;
            let over_bytes = i > start && bytes + sz > self.inner.batch_max_bytes;
            if over_items || over_bytes {
                chunks.push(start..i);
                start = i;
                bytes = 0;
            }
            bytes += sz;
        }
        if start < count {
            chunks.push(start..count);
        }
        chunks
    }

    /// Virtual device size in bytes.
    pub fn size(&self) -> u64 {
        self.inner.geometry.max_virtual_size
    }

    pub fn geometry(&self) -> &Geometry {
        &self.inner.geometry
    }

    fn check_range(&self, offset: u64, len: usize) -> Result<(), CoreError> {
        let block = self.inner.geometry.device_block_size as u64;
        if len == 0
            || offset % block != 0
            || len as u64 % block != 0
            || offset.checked_add(len as u64).map(|end| end > self.size()) != Some(false)
        {
            return Err(CoreError::Invalid(format!(
                "bad request range: offset {offset}, len {len}"
            )));
        }
        Ok(())
    }

    fn unit_size(&self) -> u64 {
        self.inner.geometry.crypto_unit_size as u64
    }

    /// Decrypt a batch of ciphertext units into plaintext keyed by unit.
    async fn decrypt_units(
        &self,
        cts: Vec<CiphertextUnit>,
    ) -> Result<HashMap<u64, SecretBuffer>, CoreError> {
        if cts.is_empty() {
            return Ok(HashMap::new());
        }
        let mut out = HashMap::with_capacity(cts.len());
        for range in self.batch_chunks(cts.len(), |i| cts[i].data.len()) {
            let pts = self
                .inner
                .provider
                .decrypt_batch(&self.inner.context, &cts[range])
                .await?;
            out.extend(pts.into_iter().map(|pt| (pt.unit_index, pt.data)));
        }
        Ok(out)
    }

    /// Read `len` bytes at `offset`.
    pub async fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, CoreError> {
        self.check_range(offset, len)?;
        let _admission = self.inner.admission.acquire(len as u64).await;
        let unit_size = self.unit_size();
        let first = offset / unit_size;
        let last = (offset + len as u64 - 1) / unit_size;

        // Consistent per-unit ciphertext snapshot; cache hits (keyed by the
        // unit's current write sequence, SPEC §29) skip decryption.
        let mut cached: HashMap<u64, std::sync::Arc<SecretBuffer>> = HashMap::new();
        let mut cts = Vec::new();
        let mut seqs: HashMap<u64, u64> = HashMap::new();
        {
            let volume = self.inner.volume.read().await;
            for unit in first..=last {
                if let Some((seq, data)) = volume.read_ct(unit)? {
                    if let Some(cache) = &self.inner.cache {
                        if let Some(buf) = cache.get(unit, seq) {
                            cached.insert(unit, buf);
                            continue;
                        }
                    }
                    seqs.insert(unit, seq);
                    cts.push(CiphertextUnit {
                        unit_index: unit,
                        data,
                    });
                }
            }
        }
        let mut plain = self.decrypt_units(cts).await?;

        if let Some(cache) = &self.inner.cache {
            for (unit, buf) in plain.iter() {
                cache.put(*unit, seqs[unit], buf.duplicate());
            }
        }

        let mut out = Vec::with_capacity(len);
        for unit in first..=last {
            let unit_start = unit * unit_size;
            let from = offset.max(unit_start) - unit_start;
            let to = (offset + len as u64).min(unit_start + unit_size) - unit_start;
            if let Some(buf) = plain.remove(&unit) {
                out.extend_from_slice(&buf.expose()[from as usize..to as usize]);
            } else if let Some(buf) = cached.remove(&unit) {
                out.extend_from_slice(&buf.expose()[from as usize..to as usize]);
            } else {
                out.extend(std::iter::repeat(0u8).take((to - from) as usize));
            }
        }
        Ok(out)
    }

    /// Write `data` at `offset`; with `fua`, all of the request's records are
    /// durable before returning.
    pub async fn write(&self, offset: u64, data: &[u8], fua: bool) -> Result<(), CoreError> {
        self.check_range(offset, data.len())?;
        let _admission = self.inner.admission.acquire(data.len() as u64).await;
        let unit_size = self.unit_size();
        let first = offset / unit_size;
        let last = (offset + data.len() as u64 - 1) / unit_size;

        // Serialize against other writers/RMW of the same units (SPEC §28).
        let _guards = self.inner.unit_locks.lock_range(first, last).await;

        // Build plaintext for each touched unit (RMW for partial coverage).
        let mut rmw_cts = Vec::new();
        let mut need_rmw = Vec::new();
        {
            let volume = self.inner.volume.read().await;
            for unit in first..=last {
                let unit_start = unit * unit_size;
                let full =
                    offset <= unit_start && offset + data.len() as u64 >= unit_start + unit_size;
                if !full {
                    need_rmw.push(unit);
                    if let Some((_seq, ct)) = volume.read_ct(unit)? {
                        rmw_cts.push(CiphertextUnit {
                            unit_index: unit,
                            data: ct,
                        });
                    }
                }
            }
        }
        let mut existing = self.decrypt_units(rmw_cts).await?;

        let mut items = Vec::with_capacity((last - first + 1) as usize);
        for unit in first..=last {
            let unit_start = unit * unit_size;
            let mut buf = if need_rmw.contains(&unit) {
                existing
                    .remove(&unit)
                    .unwrap_or_else(|| SecretBuffer::zeroed(unit_size as usize))
            } else {
                SecretBuffer::zeroed(unit_size as usize)
            };
            let dst_from = offset.max(unit_start) - unit_start;
            let dst_to = (offset + data.len() as u64).min(unit_start + unit_size) - unit_start;
            let src_from = offset.max(unit_start) - offset;
            buf.expose_mut()[dst_from as usize..dst_to as usize].copy_from_slice(
                &data[src_from as usize..src_from as usize + (dst_to - dst_from) as usize],
            );
            items.push(PlaintextUnit {
                unit_index: unit,
                data: buf,
            });
        }

        // Encrypt outside the volume lock, chunked to the batch contract.
        let mut cts = Vec::with_capacity(items.len());
        for range in self.batch_chunks(items.len(), |i| items[i].data.len()) {
            cts.extend(
                self.inner
                    .provider
                    .encrypt_batch(&self.inner.context, &items[range])
                    .await?,
            );
        }

        // Journal + publish under the exclusive volume lock.
        {
            let mut volume = self.inner.volume.write().await;
            for ct in &cts {
                volume.write_ct(ct.unit_index, &ct.data, false)?;
                // Any cached plaintext of an older version is now dead. The
                // version key alone already prevents stale reads; this frees
                // the space eagerly.
                if let Some(cache) = &self.inner.cache {
                    cache.invalidate(ct.unit_index);
                }
            }
            if fua {
                volume.flush()?;
            }
        }
        Ok(())
    }

    /// Hot-resize the plaintext read cache (SPEC §20; 0 disables).
    pub fn resize_cache(&self, max_bytes: u64) {
        if let Some(cache) = &self.inner.cache {
            cache.set_max_bytes(max_bytes);
        }
    }

    /// FLUSH barrier: everything acknowledged before this call is durable
    /// when it returns.
    pub async fn flush(&self) -> Result<(), CoreError> {
        let mut volume = self.inner.volume.write().await;
        volume.flush()
    }

    pub async fn checkpoint(&self) -> Result<u64, CoreError> {
        let mut volume = self.inner.volume.write().await;
        volume.checkpoint()
    }

    /// Journal/checkpoint/cache observability (metrics inputs, SPEC §40).
    pub async fn stats(&self) -> EngineStats {
        let cache = self
            .inner
            .cache
            .as_ref()
            .map(|c| c.stats())
            .unwrap_or_default();
        let volume = self.inner.volume.read().await;
        EngineStats {
            durable_sequence: volume.journal_durable_sequence(),
            appended_sequence: volume.journal_appended_sequence(),
            checkpoint_sequence: volume.checkpoint_sequence(),
            journal_segments: volume.journal_segment_count(),
            journal_pending_bytes: volume.journal_pending_bytes(),
            overlay_units: volume.overlay_len(),
            overlay_bytes: volume.overlay_bytes(),
            cache_hits: cache.hits,
            cache_misses: cache.misses,
            cache_bytes: cache.bytes,
            cache_entries: cache.entries,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    pub durable_sequence: u64,
    pub appended_sequence: u64,
    pub checkpoint_sequence: u64,
    pub journal_segments: usize,
    pub journal_pending_bytes: u64,
    pub overlay_units: usize,
    pub overlay_bytes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_bytes: u64,
    pub cache_entries: usize,
}
