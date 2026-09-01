//! Phase 10 — versioned plaintext LRU cache (SPEC §29, §52).

use std::sync::Arc;
use std::time::Duration;

use maki_cache::{CacheConfig, CacheStats, VersionedLruCache};
use maki_crypto::SecretBuffer;
use maki_test_support::ManualClock;

fn cache(max_bytes: u64, ttl: Duration) -> (VersionedLruCache, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new());
    let cache = VersionedLruCache::new(
        CacheConfig {
            max_bytes,
            ttl,
            zeroize_on_evict: true,
        },
        clock.clone(),
    );
    (cache, clock)
}

fn buf(fill: u8, len: usize) -> SecretBuffer {
    SecretBuffer::from_vec(vec![fill; len])
}

// ---------- versioned behavior / stale-read prevention ----------

#[test]
fn hit_requires_matching_write_sequence() {
    let (cache, _clock) = cache(1 << 20, Duration::from_secs(60));
    cache.put(7, 3, buf(0xAA, 512));
    // Same unit + same sequence: hit.
    assert_eq!(cache.get(7, 3).unwrap().expose(), &vec![0xAA; 512][..]);
    // Same unit, NEWER sequence (concurrent overwrite happened): miss —
    // stale plaintext must never be returned (SPEC §29).
    assert!(cache.get(7, 4).is_none());
    // The stale entry is dropped on the mismatch.
    assert_eq!(cache.stats().entries, 0);
}

#[test]
fn overwrite_replaces_cached_version() {
    let (cache, _clock) = cache(1 << 20, Duration::from_secs(60));
    cache.put(1, 1, buf(0x01, 256));
    cache.put(1, 2, buf(0x02, 256));
    assert!(cache.get(1, 1).is_none(), "old version unreachable");
    // put(1,2) evicted (1,1); the get(1,1) miss dropped nothing extra.
    cache.put(1, 2, buf(0x02, 256));
    assert_eq!(cache.get(1, 2).unwrap().expose(), &vec![0x02; 256][..]);
    let stats = cache.stats();
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.bytes, 256);
}

#[test]
fn invalidate_removes_unit() {
    let (cache, _clock) = cache(1 << 20, Duration::from_secs(60));
    cache.put(5, 1, buf(0x05, 128));
    cache.invalidate(5);
    assert!(cache.get(5, 1).is_none());
    assert_eq!(cache.stats().entries, 0);
}

// ---------- TTL ----------

#[test]
fn entries_expire_after_ttl() {
    let (cache, clock) = cache(1 << 20, Duration::from_secs(30));
    cache.put(1, 1, buf(0x11, 100));
    clock.advance(Duration::from_secs(29));
    assert!(cache.get(1, 1).is_some(), "within TTL");
    clock.advance(Duration::from_secs(2));
    assert!(cache.get(1, 1).is_none(), "expired");
    assert_eq!(cache.stats().entries, 0, "expired entry evicted");
}

// ---------- LRU eviction & byte bound ----------

#[test]
fn lru_evicts_least_recently_used_within_byte_budget() {
    let (cache, _clock) = cache(1024, Duration::from_secs(600));
    cache.put(1, 1, buf(1, 400));
    cache.put(2, 1, buf(2, 400));
    // Touch unit 1 so unit 2 is LRU.
    assert!(cache.get(1, 1).is_some());
    // Inserting 400 more exceeds 1024: unit 2 must go, not unit 1.
    cache.put(3, 1, buf(3, 400));
    assert!(cache.get(1, 1).is_some(), "recently used survives");
    assert!(cache.get(2, 1).is_none(), "LRU evicted");
    assert!(cache.get(3, 1).is_some());
    assert!(cache.stats().bytes <= 1024, "byte bound violated");
}

#[test]
fn oversized_entry_is_not_cached() {
    let (cache, _clock) = cache(512, Duration::from_secs(60));
    cache.put(1, 1, buf(1, 4096));
    assert!(cache.get(1, 1).is_none());
    assert_eq!(cache.stats().bytes, 0);
}

// ---------- runtime resize ----------

#[test]
fn runtime_resize_shrinks_and_grows() {
    let (cache, _clock) = cache(4096, Duration::from_secs(600));
    for unit in 0..8u64 {
        cache.put(unit, 1, buf(unit as u8, 512));
    }
    assert_eq!(cache.stats().entries, 8);
    // Shrink: immediate eviction down to the new budget.
    cache.set_max_bytes(1024);
    let stats = cache.stats();
    assert!(stats.bytes <= 1024, "resize must evict: {} bytes", stats.bytes);
    assert!(stats.entries <= 2);
    // Grow: capacity available again.
    cache.set_max_bytes(4096);
    for unit in 10..16u64 {
        cache.put(unit, 1, buf(unit as u8, 512));
    }
    assert!(cache.stats().entries >= 6);
}

/// mode = off ⇒ resize to zero disables caching entirely.
#[test]
fn zero_budget_disables_cache() {
    let (cache, _clock) = cache(4096, Duration::from_secs(60));
    cache.put(1, 1, buf(1, 100));
    cache.set_max_bytes(0);
    assert_eq!(cache.stats().entries, 0);
    cache.put(2, 1, buf(2, 100));
    assert!(cache.get(2, 1).is_none());
}

// ---------- metrics ----------

#[test]
fn hit_and_miss_counters() {
    let (cache, _clock) = cache(1 << 20, Duration::from_secs(60));
    cache.put(1, 1, buf(1, 64));
    let _ = cache.get(1, 1); // hit
    let _ = cache.get(1, 1); // hit
    let _ = cache.get(2, 1); // miss
    let _ = cache.get(1, 9); // version mismatch = miss
    let stats: CacheStats = cache.stats();
    assert_eq!(stats.hits, 2);
    assert_eq!(stats.misses, 2);
}

// ---------- zeroization ----------

/// Evicted plaintext is dropped through SecretBuffer (zeroize-on-drop);
/// the cache never hands back or retains a buffer after eviction.
#[test]
fn eviction_drops_buffers() {
    let (cache, clock) = cache(1024, Duration::from_secs(5));
    cache.put(1, 1, buf(0xEE, 800));
    cache.put(2, 1, buf(0xDD, 800)); // evicts unit 1 (byte budget)
    assert!(cache.get(1, 1).is_none());
    clock.advance(Duration::from_secs(6));
    assert!(cache.get(2, 1).is_none(), "TTL eviction");
    let stats = cache.stats();
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.bytes, 0, "all buffers released (and zeroized on drop)");
}
