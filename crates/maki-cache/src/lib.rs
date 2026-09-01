//! `maki-cache` — versioned plaintext LRU read cache (SPEC §29).
//!
//! Cache key: `(unit_index, write_sequence)`. A lookup hits only when the
//! caller's current write sequence matches the cached one, so stale
//! plaintext is never returned after a concurrent overwrite. Only read
//! caching exists — no write-back, no dirty entries, no persistence.
//!
//! Bounded by bytes with LRU eviction, TTL expiry, runtime resize, and
//! zeroize-on-evict (plaintext lives in `SecretBuffer`, which zeroizes on
//! drop; eviction drops the buffer immediately).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use maki_crypto::clock::Clock;
use maki_crypto::SecretBuffer;

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_bytes: u64,
    pub ttl: Duration,
    /// Kept for config parity; buffers always zeroize on drop via
    /// `SecretBuffer`, so eviction is zeroizing regardless.
    pub zeroize_on_evict: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: usize,
    pub bytes: u64,
    pub hits: u64,
    pub misses: u64,
}

struct Entry {
    write_sequence: u64,
    data: Arc<SecretBuffer>,
    inserted_at: Duration,
    /// Monotonic recency stamp for LRU.
    last_used: u64,
}

struct Inner {
    map: HashMap<u64, Entry>,
    bytes: u64,
    max_bytes: u64,
    tick: u64,
}

impl Inner {
    fn remove(&mut self, unit: u64) {
        if let Some(entry) = self.map.remove(&unit) {
            self.bytes -= entry.data.len() as u64;
        }
    }

    /// Evict LRU entries until `need` bytes fit within the budget.
    fn make_room(&mut self, need: u64) {
        while self.bytes + need > self.max_bytes {
            let Some((&unit, _)) = self.map.iter().min_by_key(|(_, e)| e.last_used) else {
                return;
            };
            self.remove(unit);
        }
    }
}

pub struct VersionedLruCache {
    ttl: Mutex<Duration>,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl VersionedLruCache {
    pub fn new(config: CacheConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            ttl: Mutex::new(config.ttl),
            clock,
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                bytes: 0,
                max_bytes: config.max_bytes,
                tick: 0,
            }),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Cache the plaintext of `(unit, write_sequence)`. Replaces any older
    /// version of the unit. Oversized entries are silently not cached.
    pub fn put(&self, unit: u64, write_sequence: u64, data: SecretBuffer) {
        let len = data.len() as u64;
        let now = self.clock.now();
        let mut inner = self.inner.lock();
        inner.remove(unit);
        if len > inner.max_bytes || inner.max_bytes == 0 {
            return; // dropped => zeroized
        }
        inner.make_room(len);
        inner.tick += 1;
        let tick = inner.tick;
        inner.map.insert(
            unit,
            Entry {
                write_sequence,
                data: Arc::new(data),
                inserted_at: now,
                last_used: tick,
            },
        );
        inner.bytes += len;
    }

    /// Plaintext for `(unit, current_write_sequence)`, or None. A version
    /// mismatch (stale entry) evicts and misses; TTL expiry evicts and
    /// misses.
    pub fn get(&self, unit: u64, write_sequence: u64) -> Option<Arc<SecretBuffer>> {
        let now = self.clock.now();
        let ttl = *self.ttl.lock();
        let mut inner = self.inner.lock();
        let result = match inner.map.get_mut(&unit) {
            Some(entry)
                if entry.write_sequence == write_sequence
                    && now.saturating_sub(entry.inserted_at) < ttl =>
            {
                Some(entry.data.clone())
            }
            Some(_) => {
                // stale version or expired: evict
                inner.remove(unit);
                None
            }
            None => None,
        };
        if let Some(data) = result {
            inner.tick += 1;
            let tick = inner.tick;
            if let Some(entry) = inner.map.get_mut(&unit) {
                entry.last_used = tick;
            }
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(data)
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Remove a unit (write path invalidation).
    pub fn invalidate(&self, unit: u64) {
        self.inner.lock().remove(unit);
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.map.clear();
        inner.bytes = 0;
    }

    /// Runtime resize (hot-reloadable, SPEC §20). Shrinking evicts
    /// immediately; zero disables caching.
    pub fn set_max_bytes(&self, max_bytes: u64) {
        let mut inner = self.inner.lock();
        inner.max_bytes = max_bytes;
        if max_bytes == 0 {
            inner.map.clear();
            inner.bytes = 0;
        } else {
            inner.make_room(0);
        }
    }

    pub fn set_ttl(&self, ttl: Duration) {
        *self.ttl.lock() = ttl;
    }

    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock();
        CacheStats {
            entries: inner.map.len(),
            bytes: inner.bytes,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}
