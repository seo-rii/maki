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
//!   does not fit the volume geometry (SPEC §12, §27), and — through the key
//!   canary — a provider or key other than the one the volume was written
//!   with.
//! - The journal is bounded (SPEC §12 "all internal queues are bounded",
//!   review M-004): a background worker checkpoints on a size watermark, on
//!   low backing free space, and on a time interval; the write path forces a
//!   journal sync when unsynced bytes exceed their limit, checkpoints inline
//!   at the hard journal limit, and refuses writes (ENOSPC) when the backing
//!   is below its emergency reserve or the journal cannot be reclaimed. A
//!   failed reclaim puts the engine in a `Degraded` state that the next
//!   successful checkpoint clears.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedMutexGuard, RwLock};

use maki_backing::Backing;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    CiphertextUnit, Clock, CryptoContext, CryptoError, CryptoProvider, ErrorClass, PlaintextUnit,
    SecretBuffer, SystemClock,
};
use maki_format::ab::AbStore;
use maki_format::canary::{canary_plaintext, KeyCanary, CANARY_UNIT_INDEX};
use maki_format::geometry::Geometry;
use maki_format::{layout, FormatError};

use crate::error::CoreError;
use crate::recovery::RecoveryError;
use crate::volume::{Volume, VolumeOptions};

#[derive(Debug, thiserror::Error)]
pub enum AttachError {
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("configuration: {0}")]
    Config(String),
    /// The configured provider type or key identity differs from what the
    /// superblock records (SPEC §20: immutable after creation).
    #[error("crypto identity mismatch: {0}")]
    IdentityMismatch(String),
    /// The provider could not decrypt the volume's key canary back to its
    /// known plaintext: wrong key, wrong provider, or damaged canary.
    #[error("key canary verification failed: {0} — attach refused")]
    KeyMismatch(String),
    /// The volume holds data but no canary, and the provider offers no
    /// integrity with which to probe existing ciphertext instead.
    #[error("volume has data but no key canary: {0}")]
    MissingCanary(String),
}

/// Admission limits at the block-core entry (SPEC §30): both request count
/// and byte count are bounded.
#[derive(Debug, Clone)]
pub struct EngineLimits {
    pub max_active_callbacks: u32,
    /// Plaintext-byte admission budget. A request is charged every crypto
    /// unit it touches in full (see [`Engine::admission_cost`]).
    pub max_plaintext_bytes: u64,
    /// Largest single read or write the engine accepts (`nbd.maximum_io`).
    /// Larger requests are refused as invalid; the NBD adapter splits
    /// kernel requests to fit, so the value is a real bound on the memory
    /// one request can pin (third review, F07). Must be a multiple of the
    /// device block size.
    pub max_request_bytes: u64,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_active_callbacks: 64,
            max_plaintext_bytes: 128 << 20,
            max_request_bytes: 1 << 20,
        }
    }
}

/// Plaintext read-cache settings (SPEC §29). `None` = mode off.
#[derive(Debug, Clone)]
pub struct EngineCacheConfig {
    pub max_bytes: u64,
    pub ttl: std::time::Duration,
}

/// What the configuration says the volume's crypto identity is; compared
/// against the superblock at attach (SPEC §20 immutable fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachIdentity {
    pub provider_type: String,
    pub key_identity: String,
}

/// How the journal is kept bounded (SPEC §26, §30; review M-004).
#[derive(Debug, Clone)]
pub struct CheckpointPolicy {
    /// Journal bytes on disk at which the background worker checkpoints.
    pub journal_high_watermark_bytes: u64,
    /// Hard limit on journal bytes on disk. A write that would exceed it
    /// first syncs and checkpoints inline; if that cannot reclaim enough
    /// space the write fails with ENOSPC and the engine is degraded.
    pub journal_max_bytes: u64,
    /// Appended-but-unsynced journal bytes at which the write path forces a
    /// journal sync before appending more.
    pub max_pending_bytes: u64,
    /// Backing free space below which writes are refused with ENOSPC
    /// (0 disables). Reads always continue.
    pub emergency_reserve_bytes: u64,
    /// Backing free space below which the worker checkpoints eagerly to
    /// reclaim journal segments (0 disables).
    pub low_space_checkpoint_bytes: u64,
    /// The worker checkpoints at least this often while anything is
    /// pending; unsynced records are synced first so they can be applied.
    pub interval: Duration,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            journal_high_watermark_bytes: 2 << 30,
            journal_max_bytes: 4 << 30,
            max_pending_bytes: 64 << 20,
            emergency_reserve_bytes: 1 << 30,
            low_space_checkpoint_bytes: 4 << 30,
            interval: Duration::from_secs(30),
        }
    }
}

/// Operational state (SPEC §40 `maki_volume_state`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EngineState {
    #[default]
    Ready,
    /// A journal reclaim (checkpoint) failed; writes may be refused until a
    /// later checkpoint succeeds. Reads are unaffected.
    Degraded { reason: String },
}

#[derive(Clone, Default)]
pub struct EngineOptions {
    pub volume: VolumeOptions,
    pub limits: EngineLimits,
    pub cache: Option<EngineCacheConfig>,
    /// `None` skips the identity string comparison (the canary still
    /// applies); the daemon always sets it from configuration.
    pub identity: Option<AttachIdentity>,
    pub checkpoint: CheckpointPolicy,
    /// Time source for the checkpoint worker and free-space cache
    /// (`None` = system clock; tests inject `ManualClock`).
    pub clock: Option<Arc<dyn Clock>>,
}

impl std::fmt::Debug for EngineOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineOptions")
            .field("volume", &self.volume)
            .field("limits", &self.limits)
            .field("cache", &self.cache)
            .field("identity", &self.identity)
            .field("checkpoint", &self.checkpoint)
            .field("clock", &self.clock.as_ref().map(|_| "custom"))
            .finish()
    }
}

struct UnitLocks {
    locks: parking_lot::Mutex<HashMap<u64, Arc<AsyncMutex<()>>>>,
    /// Table size above which the next idle-entry sweep runs.
    sweep_threshold: AtomicUsize,
    /// Sweeps performed (observability for the amortization test).
    sweeps: AtomicU64,
}

impl UnitLocks {
    fn new() -> Self {
        Self {
            locks: parking_lot::Mutex::new(HashMap::new()),
            sweep_threshold: AtomicUsize::new(8192),
            sweeps: AtomicU64::new(0),
        }
    }

    /// Lock a unit range in ascending order.
    ///
    /// Idle entries are swept out amortized: a sweep runs only once the
    /// table has doubled since the last one (never below 8192 entries), so
    /// a workload that *holds* many locks (large requests on small units,
    /// many parallel callbacks) does not pay a full-table scan per unit
    /// (K-04).
    async fn lock_range(&self, first: u64, last: u64) -> Vec<OwnedMutexGuard<()>> {
        let mut guards = Vec::with_capacity((last - first + 1) as usize);
        for unit in first..=last {
            let mutex = {
                let mut map = self.locks.lock();
                if map.len() > self.sweep_threshold.load(Ordering::Relaxed) {
                    map.retain(|_, m| Arc::strong_count(m) > 1);
                    self.sweeps.fetch_add(1, Ordering::Relaxed);
                    self.sweep_threshold
                        .store(map.len().saturating_mul(2).max(8192), Ordering::Relaxed);
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

#[cfg(test)]
mod unit_lock_tests {
    use super::*;

    /// Holding many locks must not turn every further acquisition into a
    /// full-table sweep: sweeps stay logarithmic in the table size.
    #[tokio::test]
    async fn sweeps_are_amortized_while_many_locks_are_held() {
        let locks = UnitLocks::new();
        let _held = locks.lock_range(0, 8_999).await;
        let before = locks.sweeps.load(Ordering::Relaxed);
        let _more = locks.lock_range(9_000, 13_095).await;
        let sweeps = locks.sweeps.load(Ordering::Relaxed) - before;
        assert!(sweeps <= 2, "{sweeps} sweeps for 4096 acquisitions");
        // Released entries are eventually reclaimed.
        drop(_more);
        drop(_held);
        let _again = locks.lock_range(50_000, 60_000).await;
        assert!(locks.locks.lock().len() <= 10_001 + 8192);
    }
}

/// How long a free-space reading is reused before the backing is asked
/// again.
const FREE_SPACE_CACHE_TTL: Duration = Duration::from_secs(1);

struct EngineInner {
    volume: RwLock<Volume>,
    backing: Arc<dyn Backing>,
    provider: CheckedProvider,
    context: CryptoContext,
    geometry: Geometry,
    unit_locks: UnitLocks,
    /// Provider batch contract (SPEC §16): calls are chunked to fit.
    batch_max_items: usize,
    batch_max_bytes: u64,
    /// Request-count + plaintext-byte admission (SPEC §30).
    admission: maki_crypto::flow::DualSemaphore,
    /// Hard bound on one request's length (F07).
    max_request_bytes: u64,
    /// Versioned plaintext read cache (SPEC §29). `None` = mode off.
    cache: Option<maki_cache::VersionedLruCache>,
    policy: CheckpointPolicy,
    clock: Arc<dyn Clock>,
    /// Wakes the checkpoint worker early (watermark crossed, shutdown).
    checkpoint_notify: Arc<Notify>,
    state: parking_lot::Mutex<EngineState>,
    checkpoints_total: AtomicU64,
    checkpoint_failures_total: AtomicU64,
    last_checkpoint_at: parking_lot::Mutex<Duration>,
    free_space: parking_lot::Mutex<Option<(Option<u64>, Duration)>>,
    /// Published samples have their own memory-only locks: `free_space`
    /// may be held across a stalled statvfs, and `volume` across storage I/O.
    observed_free_space: parking_lot::Mutex<Option<(Option<u64>, Duration)>>,
    observed_volume: parking_lot::Mutex<VolumeSnapshot>,
    /// Mirrors `Volume::journal_writeback_uncertain` after every journal
    /// operation, so [`Engine::state`] can report it without the volume
    /// lock: a journal that cannot be synced is a degraded volume.
    journal_uncertain: AtomicBool,
    /// FLUSH and FUA latency (SPEC §40 `maki_flush_seconds`,
    /// `maki_fua_seconds`), measured on the engine clock.
    flush_latency: LatencyStats,
    fua_latency: LatencyStats,
}

/// Sum, count and maximum of a latency series, in nanoseconds.
#[derive(Default)]
struct LatencyStats {
    nanos_sum: AtomicU64,
    count: AtomicU64,
    nanos_max: AtomicU64,
}

impl LatencyStats {
    fn record(&self, elapsed: Duration) {
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.nanos_sum.fetch_add(nanos, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.nanos_max.fetch_max(nanos, Ordering::Relaxed);
    }

    fn snapshot(&self) -> LatencySnapshot {
        LatencySnapshot {
            seconds_sum: self.nanos_sum.load(Ordering::Relaxed) as f64 / 1e9,
            count: self.count.load(Ordering::Relaxed),
            seconds_max: self.nanos_max.load(Ordering::Relaxed) as f64 / 1e9,
        }
    }
}

/// A latency series as reported in [`EngineStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LatencySnapshot {
    pub seconds_sum: f64,
    pub count: u64,
    pub seconds_max: f64,
}

impl Drop for EngineInner {
    fn drop(&mut self) {
        // Let a sleeping worker observe that the engine is gone.
        self.checkpoint_notify.notify_one();
    }
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

fn enospc(msg: impl Into<String>) -> CoreError {
    CoreError::Io(std::io::Error::new(
        std::io::ErrorKind::StorageFull,
        msg.into(),
    ))
}

/// Encoded on-disk size of one journal record for `ct`: the fixed record
/// header plus its ciphertext payload — the amount `JournalWriter::append`
/// advances the active segment by. Journal admission's incoming-byte total and
/// its append-footprint accounting must agree on this, so both go through here.
fn record_len(ct: &CiphertextUnit) -> u64 {
    maki_format::journal::RECORD_HEADER_SIZE as u64 + ct.data.len() as u64
}

impl Engine {
    /// Recover the volume, verify the provider (self-test + compatibility +
    /// geometry contract + identity + key canary), start the checkpoint
    /// worker, and return a ready engine.
    pub async fn attach(
        backing: Arc<dyn Backing>,
        provider: Arc<dyn CryptoProvider>,
        options: EngineOptions,
    ) -> Result<Self, AttachError> {
        let volume = Volume::recover(backing, options.volume.clone())?;
        Self::attach_recovered(volume, provider, options).await
    }

    /// Finish attaching an already recovered volume without releasing its
    /// exclusive lock while the daemon validates individual remote endpoints.
    pub async fn attach_recovered(
        volume: Volume,
        provider: Arc<dyn CryptoProvider>,
        options: EngineOptions,
    ) -> Result<Self, AttachError> {
        let backing = volume.backing().clone();
        let superblock = volume.superblock().clone();
        let geometry = superblock.geometry.clone();

        if let Some(identity) = &options.identity {
            if identity.provider_type != superblock.provider_type {
                return Err(AttachError::IdentityMismatch(format!(
                    "volume was created with provider {:?}, configuration says {:?}",
                    superblock.provider_type, identity.provider_type
                )));
            }
            if identity.key_identity != superblock.key_identity {
                return Err(AttachError::IdentityMismatch(format!(
                    "volume was created with key identity {:?}, configuration says {:?}",
                    superblock.key_identity, identity.key_identity
                )));
            }
        }
        if geometry.num_units() > CANARY_UNIT_INDEX {
            return Err(AttachError::Config(format!(
                "volume addresses {} units, which reaches the reserved canary unit index",
                geometry.num_units()
            )));
        }
        // The NBD adapter advertises and enforces this size, so a bound that is
        // not a block multiple would make every large request fail as
        // misaligned instead of being served.
        let block = geometry.device_block_size as u64;
        if options.limits.max_request_bytes == 0
            || !options.limits.max_request_bytes.is_multiple_of(block)
        {
            return Err(AttachError::Config(format!(
                "max_request_bytes {} must be a positive multiple of the device block size {block}",
                options.limits.max_request_bytes
            )));
        }

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

        let provider =
            CheckedProvider::pinned(provider, volume.superblock().geometry.crypto_unit_size);
        verify_key_canary(&volume, &provider, &context, caps.integrity.present()).await?;

        let (batch_max_items, batch_max_bytes) = if caps.batch.supported {
            (
                caps.batch.max_items.max(1) as usize,
                caps.batch.max_bytes.max(1),
            )
        } else {
            (1, u64::MAX)
        };

        let clock: Arc<dyn Clock> = options
            .clock
            .unwrap_or_else(|| Arc::new(SystemClock::new()));
        let notify = Arc::new(Notify::new());
        let observed_volume = VolumeSnapshot::new(&volume, EngineState::Ready, clock.now());
        let inner = Arc::new(EngineInner {
            volume: RwLock::new(volume),
            backing,
            provider,
            context,
            geometry,
            unit_locks: UnitLocks::new(),
            batch_max_items,
            batch_max_bytes,
            admission: maki_crypto::flow::DualSemaphore::new(
                options.limits.max_active_callbacks,
                options.limits.max_plaintext_bytes,
            ),
            max_request_bytes: options.limits.max_request_bytes,
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
            policy: options.checkpoint,
            last_checkpoint_at: parking_lot::Mutex::new(clock.now()),
            clock,
            checkpoint_notify: notify.clone(),
            state: parking_lot::Mutex::new(EngineState::Ready),
            checkpoints_total: AtomicU64::new(0),
            checkpoint_failures_total: AtomicU64::new(0),
            free_space: parking_lot::Mutex::new(None),
            observed_free_space: parking_lot::Mutex::new(None),
            observed_volume: parking_lot::Mutex::new(observed_volume),
            journal_uncertain: AtomicBool::new(false),
            flush_latency: LatencyStats::default(),
            fua_latency: LatencyStats::default(),
        });
        spawn_checkpoint_worker(Arc::downgrade(&inner), notify, inner.clock.clone());
        Ok(Self { inner })
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

    /// Current operational state. A journal whose last sync failed and has
    /// not been rewritten and synced since counts as degraded (SPEC §26:
    /// a persistence failure must be visible), whatever the checkpoint
    /// state says.
    pub fn state(&self) -> EngineState {
        let state = self.inner.state.lock().clone();
        self.inner.effective_state(state)
    }

    fn check_range(&self, offset: u64, len: usize) -> Result<(), CoreError> {
        let block = self.inner.geometry.device_block_size as u64;
        if len == 0
            || !offset.is_multiple_of(block)
            || !(len as u64).is_multiple_of(block)
            || offset.checked_add(len as u64).map(|end| end > self.size()) != Some(false)
        {
            return Err(CoreError::Invalid(format!(
                "bad request range: offset {offset}, len {len}"
            )));
        }
        if len as u64 > self.inner.max_request_bytes {
            return Err(CoreError::Invalid(format!(
                "request of {len} bytes exceeds the maximum I/O size {} (nbd.maximum_io)",
                self.inner.max_request_bytes
            )));
        }
        Ok(())
    }

    /// Largest read or write [`Engine::read_secret`] / [`Engine::write`]
    /// accept, in bytes.
    pub fn max_request_bytes(&self) -> u64 {
        self.inner.max_request_bytes
    }

    /// Plaintext bytes a request charges against the admission budget:
    /// every crypto unit it touches, in full. A partial write reads,
    /// modifies and re-encrypts whole units and a read decrypts whole
    /// units, so the request length under-counts what is actually held in
    /// memory (F07).
    pub fn admission_cost(&self, offset: u64, len: usize) -> u64 {
        if len == 0 {
            return 0;
        }
        let unit = self.unit_size();
        let first = offset / unit;
        let last = (offset + len as u64 - 1) / unit;
        (last - first + 1) * unit
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
        let unit_size = self.inner.geometry.crypto_unit_size as usize;
        for range in self.batch_chunks(cts.len(), |i| cts[i].data.len()) {
            let pts = self
                .inner
                .provider
                .decrypt_batch(&self.inner.context, &cts[range])
                .await?;
            for pt in pts {
                // The provider contract pins plaintext to *this volume's*
                // unit size, not merely to a size the provider supports:
                // anything else would be sliced out of range or silently
                // re-encrypted at the wrong length (K-08).
                if pt.data.len() != unit_size {
                    return Err(CoreError::Crypto(CryptoError::Contract(format!(
                        "decrypt of unit {} returned {} bytes, volume unit size is {unit_size}",
                        pt.unit_index,
                        pt.data.len()
                    ))));
                }
                out.insert(pt.unit_index, pt.data);
            }
        }
        Ok(out)
    }

    /// Read `len` bytes at `offset` into a zeroizing buffer (the data
    /// path; SPEC §36).
    pub async fn read_secret(&self, offset: u64, len: usize) -> Result<SecretBuffer, CoreError> {
        self.check_range(offset, len)?;
        let _admission = self
            .inner
            .admission
            .acquire(self.admission_cost(offset, len))
            .await?;
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

        let mut out = SecretBuffer::zeroed(len);
        let mut cursor = 0usize;
        for unit in first..=last {
            let unit_start = unit * unit_size;
            let from = (offset.max(unit_start) - unit_start) as usize;
            let to = ((offset + len as u64).min(unit_start + unit_size) - unit_start) as usize;
            let dst = &mut out.expose_mut()[cursor..cursor + (to - from)];
            if let Some(buf) = plain.remove(&unit) {
                dst.copy_from_slice(&buf.expose()[from..to]);
            } else if let Some(buf) = cached.remove(&unit) {
                dst.copy_from_slice(&buf.expose()[from..to]);
            }
            cursor += to - from;
        }
        Ok(out)
    }

    /// Read `len` bytes at `offset`. Convenience for tests and tools: the
    /// returned vector is not zeroized on drop; the daemon uses
    /// [`Engine::read_secret`].
    pub async fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, CoreError> {
        self.read_secret(offset, len)
            .await
            .map(SecretBuffer::into_vec)
    }

    /// Write `data` at `offset`; with `fua`, all of the request's records are
    /// durable before returning.
    pub async fn write(&self, offset: u64, data: &[u8], fua: bool) -> Result<(), CoreError> {
        self.check_range(offset, data.len())?;
        let _admission = self
            .inner
            .admission
            .acquire(self.admission_cost(offset, data.len()))
            .await?;
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
        // A ciphertext the volume cannot hold must never reach the journal:
        // the slot store would refuse it at every checkpoint and recovery
        // classifies an oversized record as corruption (K-06/K-08).
        let max_ct = self.inner.geometry.max_ciphertext_size as usize;
        if let Some(bad) = cts
            .iter()
            .find(|c| c.data.is_empty() || c.data.len() > max_ct)
        {
            return Err(CoreError::Crypto(CryptoError::Contract(format!(
                "encrypt of unit {} returned {} bytes, volume maximum is {max_ct}",
                bad.unit_index,
                bad.data.len()
            ))));
        }
        let incoming: u64 = cts.iter().map(record_len).sum();

        // Journal + publish under the exclusive volume lock.
        {
            let mut volume = self.inner.volume.write().await;
            let outcome = self.journal_request(&mut volume, incoming, &cts, fua);
            // Whatever happened, the state report must know whether the
            // journal can still be synced.
            self.inner.note_journal(&volume);
            outcome?;
            if volume.journal_total_bytes() >= self.inner.policy.journal_high_watermark_bytes {
                self.inner.checkpoint_notify.notify_one();
            }
        }
        Ok(())
    }

    /// Admit, append and publish one request's records; with `fua`, sync
    /// them (SPEC §24) and account the FUA latency.
    fn journal_request(
        &self,
        volume: &mut Volume,
        incoming: u64,
        cts: &[CiphertextUnit],
        fua: bool,
    ) -> Result<(), CoreError> {
        self.admit_journal(volume, incoming, cts)?;
        for ct in cts {
            volume.write_ct(ct.unit_index, &ct.data, false)?;
            // Any cached plaintext of an older version is now dead. The
            // version key alone already prevents stale reads; this frees
            // the space eagerly.
            if let Some(cache) = &self.inner.cache {
                cache.invalidate(ct.unit_index);
            }
        }
        if fua {
            let started = self.inner.clock.now();
            volume.flush()?;
            self.inner
                .fua_latency
                .record(self.inner.clock.now().saturating_sub(started));
        }
        Ok(())
    }

    /// Journal admission for one request (SPEC §30 "journal queue"; review
    /// M-004): emergency free-space reserve, unsynced-bytes barrier, and the
    /// hard journal limit with inline reclaim.
    ///
    /// `incoming` is the record bytes (headers + payloads) the request adds;
    /// it drives the pending-barrier flush, whose unsynced tail never includes
    /// a roll's segment header (a roll syncs both the sealed segment and the
    /// new header immediately). The hard limit, though, bounds the on-disk
    /// *total*, which does count those headers, so it is checked against the
    /// exact append footprint (records + any new segment headers), recomputed
    /// after reclaim because reclaim can change the active segment (R08).
    fn admit_journal(
        &self,
        volume: &mut Volume,
        incoming: u64,
        cts: &[CiphertextUnit],
    ) -> Result<(), CoreError> {
        let policy = &self.inner.policy;
        if policy.emergency_reserve_bytes > 0 {
            if let Some(free) = self.backing_free_bytes() {
                if free < policy.emergency_reserve_bytes {
                    return Err(enospc(format!(
                        "backing free space {free} below emergency reserve {}",
                        policy.emergency_reserve_bytes
                    )));
                }
            }
        }
        let pending = volume.journal_pending_bytes();
        if pending > 0 && pending.saturating_add(incoming) > policy.max_pending_bytes {
            volume.flush()?;
        }
        let footprint =
            |volume: &Volume| volume.journal_append_footprint(cts.iter().map(record_len));
        if volume
            .journal_total_bytes()
            .saturating_add(footprint(volume))
            > policy.journal_max_bytes
        {
            // Everything sealed becomes reclaimable once it is durable.
            volume.flush()?;
            self.inner.checkpoint_locked(volume)?;
            if volume
                .journal_total_bytes()
                .saturating_add(footprint(volume))
                > policy.journal_max_bytes
            {
                return Err(enospc(format!(
                    "journal at hard limit {} bytes and cannot be reclaimed",
                    policy.journal_max_bytes
                )));
            }
        }
        Ok(())
    }

    /// Cached backing free space (`None` = unknown).
    fn backing_free_bytes(&self) -> Option<u64> {
        let now = self.inner.clock.now();
        let mut cache = self.inner.free_space.lock();
        if let Some((value, at)) = *cache {
            if now.saturating_sub(at) < FREE_SPACE_CACHE_TTL {
                return value;
            }
        }
        let value = match self.inner.backing.free_bytes() {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("backing free-space query failed: {e}");
                None
            }
        };
        *cache = Some((value, now));
        *self.inner.observed_free_space.lock() = Some((value, now));
        value
    }

    /// Hot-resize the plaintext read cache (SPEC §20; 0 disables).
    /// Resize the plaintext read cache. Returns `false` when the engine runs
    /// without a cache (`cache.mode = off`): there is nothing to apply, and
    /// a caller must not report the change as applied (O-09).
    pub fn resize_cache(&self, max_bytes: u64) -> bool {
        match &self.inner.cache {
            Some(cache) => {
                cache.set_max_bytes(max_bytes);
                true
            }
            None => false,
        }
    }

    /// FLUSH barrier: everything acknowledged before this call is durable
    /// when it returns.
    pub async fn flush(&self) -> Result<(), CoreError> {
        let mut volume = self.inner.volume.write().await;
        let started = self.inner.clock.now();
        let outcome = volume.flush();
        self.inner.note_journal(&volume);
        outcome?;
        self.inner
            .flush_latency
            .record(self.inner.clock.now().saturating_sub(started));
        Ok(())
    }

    pub async fn checkpoint(&self) -> Result<u64, CoreError> {
        let mut volume = self.inner.volume.write().await;
        let outcome = self.inner.checkpoint_locked(&mut volume);
        self.inner.note_journal(&volume);
        outcome
    }

    /// Journal/checkpoint/cache observability (metrics inputs, SPEC §40).
    pub async fn stats(&self) -> EngineStats {
        let cache = self
            .inner
            .cache
            .as_ref()
            .map(|c| c.stats())
            .unwrap_or_default();
        let backing_free_bytes = self.backing_free_bytes();
        let volume = self.inner.volume.read().await;
        let snapshot = VolumeSnapshot::new(&volume, self.state(), self.inner.clock.now());
        self.stats_from_snapshot(&snapshot, cache, backing_free_bytes)
    }

    /// Monitoring never acquires the storage lock or refreshes free space.
    /// A busy volume uses its last completed observation, with age and busy
    /// flags; cache contention is explicitly unavailable. The snapshot is
    /// observational and cannot authorize writes, drain or workload startup.
    pub fn monitoring_snapshot(&self) -> MonitoringSnapshot {
        let now = self.inner.clock.now();
        let (volume, volume_busy) = match self.inner.volume.try_read() {
            Ok(volume) => (VolumeSnapshot::new(&volume, self.state(), now), false),
            Err(_) => (self.inner.observed_volume.lock().clone(), true),
        };
        let cache = self
            .inner
            .cache
            .as_ref()
            .map(|cache| cache.try_stats())
            .unwrap_or(Some(maki_cache::CacheStats::default()));
        let free_space = *self.inner.observed_free_space.lock();
        MonitoringSnapshot {
            stats: self.stats_from_snapshot(
                &volume,
                cache.unwrap_or_default(),
                free_space.and_then(|(bytes, _)| bytes),
            ),
            volume_busy,
            volume_snapshot_age: now.saturating_sub(volume.at),
            cache,
            backing_space_age: free_space.map(|(_, at)| now.saturating_sub(at)),
        }
    }

    fn stats_from_snapshot(
        &self,
        volume: &VolumeSnapshot,
        cache: maki_cache::CacheStats,
        backing_free_bytes: Option<u64>,
    ) -> EngineStats {
        let admission = &self.inner.admission;
        EngineStats {
            active_callbacks: (admission.max_items() - admission.available_items()) as u64,
            plaintext_bytes_in_flight: admission.max_bytes() - admission.available_bytes(),
            flush_latency: self.inner.flush_latency.snapshot(),
            fua_latency: self.inner.fua_latency.snapshot(),
            durable_sequence: volume.durable_sequence,
            appended_sequence: volume.appended_sequence,
            checkpoint_sequence: volume.checkpoint_sequence,
            journal_segments: volume.journal_segments,
            journal_pending_bytes: volume.journal_pending_bytes,
            journal_total_bytes: volume.journal_total_bytes,
            journal_sync_failures_total: volume.journal_sync_failures_total,
            journal_writeback_uncertain: volume.journal_writeback_uncertain,
            overlay_units: volume.overlay_units,
            overlay_bytes: volume.overlay_bytes,
            cache_hits: cache.hits,
            cache_misses: cache.misses,
            cache_bytes: cache.bytes,
            cache_entries: cache.entries,
            backing_free_bytes,
            checkpoints_total: self.inner.checkpoints_total.load(Ordering::Relaxed),
            checkpoint_failures_total: self.inner.checkpoint_failures_total.load(Ordering::Relaxed),
            state: volume.state.clone(),
        }
    }
}

impl EngineInner {
    /// Remember whether the journal has unsynced bytes a failed sync left
    /// in an unknown state (read under the volume lock the caller holds).
    fn note_journal(&self, volume: &Volume) {
        self.journal_uncertain
            .store(volume.journal_writeback_uncertain(), Ordering::SeqCst);
        let snapshot = VolumeSnapshot::new(
            volume,
            self.effective_state(self.state.lock().clone()),
            self.clock.now(),
        );
        *self.observed_volume.lock() = snapshot;
    }

    /// The reported state: a checkpoint-degraded volume stays degraded; a
    /// ready one is degraded while its journal cannot be synced.
    fn effective_state(&self, state: EngineState) -> EngineState {
        match state {
            EngineState::Ready if self.journal_uncertain.load(Ordering::SeqCst) => {
                EngineState::Degraded {
                    reason: "journal sync failed; FLUSH and FUA fail until the unsynced records \
                             are rewritten and synced"
                        .to_string(),
                }
            }
            other => other,
        }
    }

    /// Run a checkpoint under the (already held) volume lock and record the
    /// outcome in counters and state.
    fn checkpoint_locked(&self, volume: &mut Volume) -> Result<u64, CoreError> {
        match volume.checkpoint() {
            Ok(seq) => {
                self.checkpoints_total.fetch_add(1, Ordering::Relaxed);
                *self.last_checkpoint_at.lock() = self.clock.now();
                *self.state.lock() = EngineState::Ready;
                Ok(seq)
            }
            Err(e) => {
                self.checkpoint_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                *self.state.lock() = EngineState::Degraded {
                    reason: format!("checkpoint failed: {e}"),
                };
                Err(e)
            }
        }
    }

    /// One worker pass: checkpoint if the journal crossed its watermark,
    /// the backing is low on space, or the interval elapsed with work
    /// pending (unsynced records are synced first so they can be applied).
    async fn worker_pass(&self) {
        let (total, appended, checkpointed, durable, covered) = {
            let v = self.volume.read().await;
            (
                v.journal_total_bytes(),
                v.journal_appended_sequence(),
                v.checkpoint_sequence(),
                v.journal_durable_sequence(),
                v.journal_covered_segment_count(),
            )
        };
        if appended <= checkpointed && covered == 0 {
            return; // nothing to apply and nothing to reclaim
        }
        let by_size = total >= self.policy.journal_high_watermark_bytes;
        let by_space = self.policy.low_space_checkpoint_bytes > 0
            && self
                .backing
                .free_bytes()
                .ok()
                .flatten()
                .map(|free| free < self.policy.low_space_checkpoint_bytes)
                .unwrap_or(false);
        let elapsed = self
            .clock
            .now()
            .saturating_sub(*self.last_checkpoint_at.lock());
        let by_time = elapsed >= self.policy.interval;
        if !(by_size || by_space || by_time) {
            return;
        }
        let mut volume = self.volume.write().await;
        if by_time && durable < appended {
            let flushed = volume.flush();
            self.note_journal(&volume);
            if let Err(e) = flushed {
                tracing::warn!("checkpoint worker: journal sync failed: {e}");
                return;
            }
        }
        if let Err(e) = self.checkpoint_locked(&mut volume) {
            tracing::warn!("checkpoint worker: checkpoint failed: {e}");
        }
        self.note_journal(&volume);
    }
}

/// The background checkpoint worker. Holds only a weak reference so it
/// exits once the engine is dropped (the engine's drop wakes it).
fn spawn_checkpoint_worker(weak: Weak<EngineInner>, notify: Arc<Notify>, clock: Arc<dyn Clock>) {
    let interval = weak
        .upgrade()
        .map(|i| i.policy.interval)
        .unwrap_or(Duration::from_secs(30));
    tokio::spawn(async move {
        loop {
            let sleep = clock.sleep(interval);
            tokio::select! {
                _ = sleep => {}
                _ = notify.notified() => {}
            }
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.worker_pass().await;
        }
    });
}

/// Key-canary check (SPEC §12, review M-001).
///
/// - Canary present: decrypt it and compare with the known plaintext; any
///   mismatch or integrity failure refuses attach. Transport-class errors
///   are surfaced as such rather than as a key mismatch.
/// - Canary absent on a pristine volume: establish it now. The first attach
///   binds the provider and key to the volume.
/// - Canary absent on a volume with data (written before canaries existed):
///   with an integrity-capable provider, decrypt one existing unit as the
///   proof instead, then establish the canary; without integrity there is
///   no proof, so attach is refused.
pub async fn verify_key_canary(
    volume: &Volume,
    provider: &CheckedProvider,
    context: &CryptoContext,
    provider_has_integrity: bool,
) -> Result<(), AttachError> {
    let backing = volume.backing().clone();
    let superblock = volume.superblock();
    let unit_size = superblock.geometry.crypto_unit_size as usize;
    let expected = canary_plaintext(&superblock.volume_uuid, unit_size);
    let ab = AbStore::new(layout::KEY_CANARY_A, layout::KEY_CANARY_B);

    if let Some(canary) = ab.load::<KeyCanary>(backing.as_ref())? {
        if canary.volume_uuid != superblock.volume_uuid {
            return Err(AttachError::KeyMismatch(
                "canary belongs to a different volume".to_string(),
            ));
        }
        let plain = decrypt_probe(
            provider,
            context,
            CiphertextUnit {
                unit_index: canary.unit_index,
                data: canary.ciphertext,
            },
        )
        .await?;
        if plain.expose() != expected.as_slice() {
            return Err(AttachError::KeyMismatch(
                "canary decrypted to unexpected plaintext (wrong key or provider)".to_string(),
            ));
        }
        return Ok(());
    }

    if !volume.is_pristine() {
        if !provider_has_integrity {
            return Err(AttachError::MissingCanary(
                "the provider offers no integrity, so existing ciphertext cannot prove the key; \
                 attach with the integrity-capable provider the volume was written with"
                    .to_string(),
            ));
        }
        let Some((unit, data)) = volume.first_ciphertext_unit()? else {
            return Err(AttachError::MissingCanary(
                "volume has history but no readable ciphertext to probe".to_string(),
            ));
        };
        // Authenticated decrypt of real data is the proof; the plaintext is
        // discarded (dropped as a SecretBuffer).
        let _ = decrypt_probe(
            provider,
            context,
            CiphertextUnit {
                unit_index: unit,
                data,
            },
        )
        .await?;
    }

    // Establish: encrypt the fixed plaintext at the reserved index and make
    // both copies plus their dirents durable before the volume is exposed.
    let cts = provider
        .encrypt_batch(
            context,
            &[PlaintextUnit {
                unit_index: CANARY_UNIT_INDEX,
                data: SecretBuffer::from_slice(&expected),
            }],
        )
        .await?;
    let ct = cts.into_iter().next().ok_or_else(|| {
        AttachError::Crypto(CryptoError::Contract(
            "canary encrypt returned no item".to_string(),
        ))
    })?;
    // Verify the freshly-written canary decrypts back to its known plaintext at
    // the reserved index *before* publishing it. The self-test exercises unit
    // indices 0..2, never this large reserved index, so a provider that
    // mishandles it (or a wrong key routing) would otherwise persist an
    // unverifiable canary that only surfaces as a key mismatch on the next
    // attach (FUP-010). The daemon separately verifies every remote endpoint
    // against this same persisted canary before it can serve volume I/O.
    let decrypted = decrypt_probe(
        provider,
        context,
        CiphertextUnit {
            unit_index: CANARY_UNIT_INDEX,
            data: ct.data.clone(),
        },
    )
    .await?;
    if decrypted.expose() != expected.as_slice() {
        return Err(AttachError::KeyMismatch(
            "the freshly written key canary did not decrypt back to its known plaintext at the \
             reserved index; refusing to publish an unverifiable canary"
                .to_string(),
        ));
    }
    let mut record = KeyCanary {
        generation: 0,
        volume_uuid: superblock.volume_uuid,
        unit_index: CANARY_UNIT_INDEX,
        ciphertext: ct.data,
    };
    ab.store(backing.as_ref(), &mut record)?;
    ab.store(backing.as_ref(), &mut record)?;
    backing.sync_dir("")?;
    Ok(())
}

/// Decrypt one unit for verification, classifying failures: integrity,
/// request, provider-fatal and contract errors mean the key/provider does
/// not match; transport-class errors are reported as themselves.
async fn decrypt_probe(
    provider: &CheckedProvider,
    context: &CryptoContext,
    unit: CiphertextUnit,
) -> Result<SecretBuffer, AttachError> {
    match provider.decrypt_batch(context, &[unit]).await {
        Ok(mut pts) => Ok(pts.remove(0).data),
        Err(e)
            if matches!(
                e.class(),
                ErrorClass::Retryable | ErrorClass::Throttled | ErrorClass::EndpointFatal
            ) =>
        {
            Err(AttachError::Crypto(e))
        }
        Err(e) => Err(AttachError::KeyMismatch(e.to_string())),
    }
}

/// Last coherent volume metadata observation. No backing operations occur
/// while constructing or publishing it.
#[derive(Clone)]
struct VolumeSnapshot {
    at: Duration,
    state: EngineState,
    durable_sequence: u64,
    appended_sequence: u64,
    checkpoint_sequence: u64,
    journal_segments: usize,
    journal_pending_bytes: u64,
    journal_total_bytes: u64,
    journal_sync_failures_total: u64,
    journal_writeback_uncertain: bool,
    overlay_units: usize,
    overlay_bytes: u64,
}

impl VolumeSnapshot {
    fn new(volume: &Volume, state: EngineState, at: Duration) -> Self {
        Self {
            at,
            state,
            durable_sequence: volume.journal_durable_sequence(),
            appended_sequence: volume.journal_appended_sequence(),
            checkpoint_sequence: volume.checkpoint_sequence(),
            journal_segments: volume.journal_segment_count(),
            journal_pending_bytes: volume.journal_pending_bytes(),
            journal_total_bytes: volume.journal_total_bytes(),
            journal_sync_failures_total: volume.journal_sync_failures(),
            journal_writeback_uncertain: volume.journal_writeback_uncertain(),
            overlay_units: volume.overlay_len(),
            overlay_bytes: volume.overlay_bytes(),
        }
    }
}

/// An observation for status/metrics, which must remain usable during stalls.
#[derive(Debug, Clone)]
pub struct MonitoringSnapshot {
    /// Volume fields use the observation described by `volume_busy` and
    /// `volume_snapshot_age`; admission and latency counters are sampled now.
    /// Use `cache` for cache fields: `stats` has placeholders if unavailable.
    pub stats: EngineStats,
    pub volume_busy: bool,
    pub volume_snapshot_age: Duration,
    /// `None` while a cache insertion, eviction or resize owns its lock.
    pub cache: Option<maki_cache::CacheStats>,
    /// `None` before a storage operation has completed a free-space query.
    /// An available sample can still report unknown free bytes.
    pub backing_space_age: Option<Duration>,
}

#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    /// Requests currently admitted (SPEC §40 `maki_active_callbacks`).
    pub active_callbacks: u64,
    /// Plaintext bytes currently charged against the admission budget
    /// (`maki_plaintext_bytes`).
    pub plaintext_bytes_in_flight: u64,
    /// Successful FLUSH barriers (`maki_flush_seconds`).
    pub flush_latency: LatencySnapshot,
    /// Successful FUA syncs (`maki_fua_seconds`).
    pub fua_latency: LatencySnapshot,
    pub durable_sequence: u64,
    pub appended_sequence: u64,
    pub checkpoint_sequence: u64,
    pub journal_segments: usize,
    /// Appended but not yet fdatasync'd bytes.
    pub journal_pending_bytes: u64,
    /// Every journal segment on disk.
    pub journal_total_bytes: u64,
    /// Journal segment syncs that failed since attach (F01).
    pub journal_sync_failures_total: u64,
    /// A failed journal sync has not been followed by a successful rewrite
    /// and sync yet: FLUSH and FUA are failing until it is.
    pub journal_writeback_uncertain: bool,
    pub overlay_units: usize,
    pub overlay_bytes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_bytes: u64,
    pub cache_entries: usize,
    /// `None` when the backing cannot report free space.
    pub backing_free_bytes: Option<u64>,
    pub checkpoints_total: u64,
    pub checkpoint_failures_total: u64,
    pub state: EngineState,
}
