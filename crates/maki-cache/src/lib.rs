//! `maki-cache` — versioned plaintext LRU read cache (SPEC §29).
//!
//! Cache key: `(unit_index, write_sequence)`. A lookup hits only when the
//! caller's current write sequence matches the cached one, so stale
//! plaintext is never returned after a concurrent overwrite. Only read
//! caching exists — no write-back, no dirty entries, no persistence.
//!
//! Bounded by bytes with LRU eviction, TTL expiry, runtime resize, and
//! lazy TTL checks. Eviction releases the cache's `Arc`; plaintext is
//! zeroized when the last `Arc<SecretBuffer>` is dropped. Callers may retain
//! a buffer beyond its TTL or eviction, so neither is a deletion deadline.
//!
//! Recency is tracked in an ordered index keyed by a monotonic tick, so an
//! eviction is O(log n) rather than a scan of every entry: a full cache of
//! tens of thousands of units evicts on every insert, and a linear scan
//! there would turn the hot read path quadratic.

// Diagnostics go through `tracing`: the `print!` family panics when the
// write fails (a closed pipe, a full disk). Tests may print.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use maki_crypto::clock::Clock;
use maki_crypto::SecretBuffer;

#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Limit on the sum of retained plaintext buffer capacities.
    pub max_bytes: u64,
    pub ttl: Duration,
    /// Kept for config parity; buffers always zeroize on drop via
    /// `SecretBuffer` after the final owner releases them. Eviction alone
    /// does not zeroize buffers still held by callers.
    pub zeroize_on_evict: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: usize,
    /// Sum of retained plaintext buffer capacities, including spare bytes.
    pub bytes: u64,
    pub hits: u64,
    pub misses: u64,
}

struct Entry {
    write_sequence: u64,
    data: Arc<SecretBuffer>,
    inserted_at: Duration,
    /// Monotonic recency stamp for LRU; also the key in `recency`.
    last_used: u64,
}

struct Inner {
    map: HashMap<u64, Entry>,
    /// last_used tick -> unit, oldest first. Ticks are unique.
    recency: BTreeMap<u64, u64>,
    /// Cache-owned fixed-size read units with spare capacity, largest last.
    padded_units: BTreeSet<(usize, u64)>,
    bytes: u64,
    max_bytes: u64,
    tick: u64,
}

impl Inner {
    fn remove(&mut self, unit: u64) {
        if let Some(entry) = self.map.remove(&unit) {
            self.recency.remove(&entry.last_used);
            self.bytes -= entry.data.capacity() as u64;
            if entry.data.capacity() > entry.data.len() {
                self.padded_units.remove(&(entry.data.capacity(), unit));
            }
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Mark `unit` most recently used.
    fn touch(&mut self, unit: u64) {
        if let Some(entry) = self.map.get_mut(&unit) {
            if entry.last_used == self.tick {
                return;
            }
            self.recency.remove(&entry.last_used);
            self.tick += 1;
            entry.last_used = self.tick;
            self.recency.insert(self.tick, unit);
        }
    }

    /// Let sparse reads retain their provider allocations. Reserve one vacant
    /// logical slot per temporarily padded entry, so filling each subsequent
    /// slot needs at most one old entry repacked. Padding that fits even at
    /// full occupancy can stay indefinitely.
    fn fit_read_unit(&mut self, data: SecretBuffer) -> SecretBuffer {
        let units = self.max_bytes / data.len() as u64;
        let per_unit = self.max_bytes / units;
        let vacant_after_insert = units.saturating_sub(self.map.len() as u64 + 1);

        let to_compact = self.padded_units.last().copied().filter(|&(capacity, _)| {
            capacity as u64 > per_unit && self.padded_units.len() as u64 > vacant_after_insert
        });
        if let Some((capacity, unit)) = to_compact {
            let entry = self.map.get_mut(&unit).expect("padded unit exists");
            let compact = entry.data.duplicate();
            self.bytes = self.bytes - capacity as u64 + compact.capacity() as u64;
            self.padded_units.pop_last();
            entry.data = Arc::new(compact);
        }

        let capacity = data.capacity() as u64;
        if capacity > per_unit
            && (capacity - per_unit > per_unit
                || self.padded_units.len() as u64 >= vacant_after_insert)
        {
            data.duplicate()
        } else {
            data
        }
    }

    /// Evict LRU entries until `need` bytes fit within the budget.
    fn make_room(&mut self, need: u64) {
        while self.bytes > self.max_bytes.saturating_sub(need) {
            let Some((&_, &unit)) = self.recency.iter().next() else {
                return;
            };
            self.remove(unit);
        }
    }

    fn clear(&mut self) {
        self.map.clear();
        self.recency.clear();
        self.padded_units.clear();
        self.bytes = 0;
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
                recency: BTreeMap::new(),
                padded_units: BTreeSet::new(),
                bytes: 0,
                max_bytes: config.max_bytes,
                tick: 0,
            }),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Cache the plaintext of `(unit, write_sequence)`. Replaces any older
    /// version of the unit; a newer cached version is kept, since a slow
    /// reader may finish decrypting an older version after a faster one
    /// cached the current one (R5-020). Empty and oversized entries are not
    /// cached; a rejected current/newer version invalidates the old entry.
    pub fn put(&self, unit: u64, write_sequence: u64, data: SecretBuffer) {
        self.insert(unit, write_sequence, data, false);
    }

    /// Cache one fixed-size volume unit. Spare capacity in provider buffers
    /// may be released to preserve the number of logical units that fit.
    pub fn put_read_unit(&self, unit: u64, write_sequence: u64, data: SecretBuffer) {
        self.insert(unit, write_sequence, data, true);
    }

    fn insert(&self, unit: u64, write_sequence: u64, data: SecretBuffer, read_unit: bool) {
        let mut inner = self.inner.lock();
        if inner
            .map
            .get(&unit)
            .is_some_and(|entry| entry.write_sequence > write_sequence)
        {
            return; // dropped => zeroized
        }
        inner.remove(unit);
        if data.is_empty() || data.len() as u64 > inner.max_bytes {
            return;
        }
        let data = if read_unit && (data.capacity() > data.len() || !inner.padded_units.is_empty())
        {
            inner.fit_read_unit(data)
        } else {
            data
        };
        let allocation = data.capacity() as u64;
        if allocation > inner.max_bytes {
            return;
        }
        inner.make_room(allocation);
        if read_unit && data.capacity() > data.len() {
            inner.padded_units.insert((data.capacity(), unit));
        }
        let tick = inner.next_tick();
        inner.map.insert(
            unit,
            Entry {
                write_sequence,
                data: Arc::new(data),
                inserted_at: self.clock.now(),
                last_used: tick,
            },
        );
        inner.recency.insert(tick, unit);
        inner.bytes += allocation;
    }

    /// A read can skip its cache-only header probe when an entire unit
    /// cannot fit. Insertion rechecks the limit after concurrent resizing.
    pub fn can_hold(&self, bytes: u64) -> bool {
        bytes != 0 && bytes <= self.inner.lock().max_bytes
    }

    /// Plaintext for `(unit, current_write_sequence)`, or None. A version
    /// mismatch (stale entry) evicts and misses; TTL expiry evicts and
    /// misses. TTL is evaluated on lookup, not by a background timer. The
    /// returned owner remains valid until dropped, including after eviction.
    pub fn get(&self, unit: u64, write_sequence: u64) -> Option<Arc<SecretBuffer>> {
        let ttl = self.ttl.lock();
        let mut inner = self.inner.lock();
        let now = self.clock.now();
        let result = match inner.map.get(&unit) {
            Some(entry)
                if entry.write_sequence == write_sequence
                    && now.saturating_sub(entry.inserted_at) < *ttl =>
            {
                Some(entry.data.clone())
            }
            // A lookup for an older version (a slow reader) leaves the
            // newer entry in place (R5-020).
            Some(entry)
                if entry.write_sequence > write_sequence
                    && now.saturating_sub(entry.inserted_at) < *ttl =>
            {
                None
            }
            Some(_) => {
                // stale version or expired: evict
                inner.remove(unit);
                None
            }
            None => None,
        };
        if let Some(data) = result {
            inner.touch(unit);
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
        self.inner.lock().clear();
    }

    /// Runtime resize (hot-reloadable, SPEC §20). Shrinking evicts
    /// immediately; zero disables caching.
    pub fn set_max_bytes(&self, max_bytes: u64) {
        self.reconfigure(max_bytes, None);
    }

    /// Apply a byte limit and optional TTL as one configuration change.
    /// Lookups use the same TTL-then-entries lock order and cannot observe a
    /// mixture. TTL changes retain the entries' original insertion times.
    pub fn reconfigure(&self, max_bytes: u64, ttl: Option<Duration>) {
        let mut current_ttl = self.ttl.lock();
        let mut inner = self.inner.lock();
        if let Some(ttl) = ttl {
            *current_ttl = ttl;
        }
        inner.max_bytes = max_bytes;
        if max_bytes == 0 {
            inner.clear();
            inner.map.shrink_to_fit();
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

    /// Observe the cache without waiting for insertion, eviction or resize.
    /// `None` means unavailable, rather than an empty cache or zero counters.
    pub fn try_stats(&self) -> Option<CacheStats> {
        let inner = self.inner.try_lock()?;
        Some(CacheStats {
            entries: inner.map.len(),
            bytes: inner.bytes,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        })
    }
}

#[cfg(test)]
mod monitoring_tests {
    use super::*;

    #[test]
    fn repeated_hits_keep_the_most_recent_entry_in_place() {
        let cache = VersionedLruCache::new(
            CacheConfig {
                max_bytes: 12,
                ttl: Duration::from_secs(60),
                zeroize_on_evict: true,
            },
            Arc::new(maki_crypto::SystemClock::new()),
        );
        for unit in 0..12 {
            cache.put(unit, 1, SecretBuffer::from_slice(&[1]));
        }
        // Promote an older entry once, then check repeated hits and eviction.
        assert!(cache.get(0, 1).is_some());
        let tick = cache.inner.lock().map[&0].last_used;
        for _ in 0..16 {
            assert!(cache.get(0, 1).is_some());
        }
        assert_eq!(cache.inner.lock().map[&0].last_used, tick);
        cache.set_max_bytes(11);
        assert!(cache.get(1, 1).is_none());
        assert!(cache.get(0, 1).is_some());
    }

    #[test]
    fn disabling_the_cache_releases_the_empty_hash_table() {
        let cache = VersionedLruCache::new(
            CacheConfig {
                max_bytes: 4096,
                ttl: Duration::from_secs(60),
                zeroize_on_evict: true,
            },
            Arc::new(maki_crypto::SystemClock::new()),
        );
        for unit in 0..1024 {
            cache.put(unit, 1, SecretBuffer::from_slice(&[1]));
        }
        assert!(cache.inner.lock().map.capacity() >= 1024);
        cache.set_max_bytes(0);
        assert_eq!(cache.inner.lock().map.capacity(), 0);
        cache.set_max_bytes(8);
        cache.put(1, 2, SecretBuffer::from_slice(&[2]));
        assert_eq!(cache.get(1, 2).unwrap().expose(), &[2]);
    }

    #[test]
    fn observation_does_not_wait_for_cache_mutation() {
        let cache = Arc::new(VersionedLruCache::new(
            CacheConfig {
                max_bytes: 4096,
                ttl: Duration::from_secs(60),
                zeroize_on_evict: true,
            },
            Arc::new(maki_crypto::SystemClock::new()),
        ));
        let mutation = cache.inner.lock();
        let (tx, rx) = std::sync::mpsc::channel();
        let observer = {
            let cache = cache.clone();
            std::thread::spawn(move || tx.send(cache.try_stats()).unwrap())
        };
        let during = rx.recv_timeout(Duration::from_millis(250));
        drop(mutation);
        observer.join().unwrap();
        assert_eq!(during.expect("monitoring waited for cache mutation"), None);
        assert_eq!(cache.try_stats(), Some(cache.stats()));
    }
}

#[cfg(test)]
mod ttl_tests {
    use super::*;
    use maki_crypto::clock::SleepFuture;

    #[derive(Default)]
    struct InterleavingClock {
        millis: AtomicU64,
        on_sample: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl Clock for InterleavingClock {
        fn now(&self) -> Duration {
            let time = Duration::from_millis(self.millis.load(Ordering::SeqCst));
            let action = self.on_sample.lock().take();
            if let Some(action) = action {
                action();
            }
            time
        }

        fn sleep(&self, _: Duration) -> SleepFuture {
            unreachable!()
        }
    }

    #[test]
    fn overlapping_puts_cannot_shorten_the_refreshed_ttl() {
        let clock = Arc::new(InterleavingClock::default());
        let cache = Arc::new(VersionedLruCache::new(
            CacheConfig {
                max_bytes: 4096,
                ttl: Duration::from_millis(10),
                zeroize_on_evict: true,
            },
            clock.clone(),
        ));
        let refreshed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finish_refresh = refreshed.clone();
        let refreshing = cache.clone();
        let advancing = clock.clone();
        *clock.on_sample.lock() = Some(Box::new(move || {
            advancing.millis.store(5, Ordering::SeqCst);
            // Complete the second put before publication if the first put
            // sampled time without holding the entries lock.
            if refreshing.inner.try_lock().is_some() {
                refreshing.put(0, 4, SecretBuffer::from_slice(&[42]));
                finish_refresh.store(true, Ordering::SeqCst);
            }
        }));
        cache.put(0, 4, SecretBuffer::from_slice(&[42]));
        if !refreshed.load(Ordering::SeqCst) {
            cache.put(0, 4, SecretBuffer::from_slice(&[42]));
        }
        clock.millis.store(11, Ordering::SeqCst);
        assert!(cache.get(0, 4).is_some(), "the 5ms refresh expires at 15ms");
        clock.millis.store(15, Ordering::SeqCst);
        assert!(cache.get(0, 4).is_none());
    }

    #[test]
    fn lookup_cannot_combine_an_old_timestamp_with_a_new_ttl() {
        let clock = Arc::new(InterleavingClock::default());
        let cache = Arc::new(VersionedLruCache::new(
            CacheConfig {
                max_bytes: 4096,
                ttl: Duration::from_millis(100),
                zeroize_on_evict: true,
            },
            clock.clone(),
        ));
        cache.put(1, 1, SecretBuffer::from_slice(&[42]));
        clock.millis.store(150, Ordering::SeqCst);
        let changing = cache.clone();
        let advancing = clock.clone();
        *clock.on_sample.lock() = Some(Box::new(move || {
            // If lookup allows reconfiguration after sampling time, publish
            // the longer TTL at age 300ms. Neither TTL ever covers this read.
            advancing.millis.store(300, Ordering::SeqCst);
            if changing.ttl.try_lock().is_some() && changing.inner.try_lock().is_some() {
                changing.reconfigure(4096, Some(Duration::from_millis(200)));
            }
        }));
        assert!(cache.get(1, 1).is_none());
    }
}
