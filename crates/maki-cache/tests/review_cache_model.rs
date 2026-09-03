//! Model-based randomized test of the versioned LRU cache (SPEC §29):
//! thousands of random put/get/invalidate/resize/TTL operations against an
//! independent reference model. Checks exact hit/miss semantics (version
//! match, TTL), LRU eviction order, byte accounting, the size bound after
//! every operation, and that a stale version is never served.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_cache::{CacheConfig, VersionedLruCache};
use maki_crypto::{Clock, SecretBuffer};
use maki_test_support::ManualClock;

#[derive(Debug)]
struct Entry {
    seq: u64,
    len: u64,
    inserted_at: Duration,
    last_used: u64,
}

#[derive(Debug, Default)]
struct Model {
    entries: BTreeMap<u64, Entry>,
    max_bytes: u64,
    ttl: Duration,
    tick: u64,
}

impl Model {
    fn bytes(&self) -> u64 {
        self.entries.values().map(|e| e.len).sum()
    }

    fn evict_lru(&mut self) {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(u, _)| *u);
        if let Some(u) = victim {
            self.entries.remove(&u);
        }
    }

    fn put(&mut self, unit: u64, seq: u64, len: u64, now: Duration) {
        self.entries.remove(&unit);
        if len > self.max_bytes || self.max_bytes == 0 {
            return;
        }
        while self.bytes() + len > self.max_bytes {
            self.evict_lru();
        }
        self.tick += 1;
        self.entries.insert(
            unit,
            Entry {
                seq,
                len,
                inserted_at: now,
                last_used: self.tick,
            },
        );
    }

    /// Expected hit (true) or miss (false), applying the side effects.
    fn get(&mut self, unit: u64, seq: u64, now: Duration) -> bool {
        let hit = match self.entries.get(&unit) {
            Some(e) => e.seq == seq && now.saturating_sub(e.inserted_at) < self.ttl,
            None => false,
        };
        if hit {
            self.tick += 1;
            self.entries.get_mut(&unit).unwrap().last_used = self.tick;
        } else {
            self.entries.remove(&unit);
        }
        hit
    }

    fn resize(&mut self, max_bytes: u64) {
        self.max_bytes = max_bytes;
        if max_bytes == 0 {
            self.entries.clear();
        }
        while self.bytes() > self.max_bytes {
            self.evict_lru();
        }
    }
}

fn data(unit: u64, seq: u64, len: usize) -> SecretBuffer {
    let mut v = vec![0u8; len];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (unit as u8) ^ (seq as u8).wrapping_mul(7) ^ (i as u8);
    }
    SecretBuffer::from_slice(&v)
}

#[test]
fn cache_matches_reference_model_under_random_operations() {
    for seed in 0..12u64 {
        run(seed);
    }
}

fn run(seed: u64) {
    let mut rng = StdRng::seed_from_u64(0xCAC4E + seed);
    let clock = Arc::new(ManualClock::new());
    let ttl = Duration::from_millis(rng.random_range(50..500));
    let max_bytes = rng.random_range(1..=24u64) * 256;
    let cache = VersionedLruCache::new(
        CacheConfig {
            max_bytes,
            ttl,
            zeroize_on_evict: true,
        },
        clock.clone(),
    );
    let mut model = Model {
        max_bytes,
        ttl,
        ..Default::default()
    };
    let mut latest_seq: BTreeMap<u64, u64> = BTreeMap::new();
    let (mut hits, mut misses) = (0u64, 0u64);

    for step in 0..4000 {
        let unit = rng.random_range(0..24u64);
        let now = clock.now();
        match rng.random_range(0..100u32) {
            0..=39 => {
                // put a (possibly new) version
                let seq = if rng.random_bool(0.7) {
                    let s = latest_seq.get(&unit).copied().unwrap_or(0) + 1;
                    latest_seq.insert(unit, s);
                    s
                } else {
                    latest_seq.get(&unit).copied().unwrap_or(1)
                };
                let len = [64usize, 128, 256, 512, 1024][rng.random_range(0..5)];
                cache.put(unit, seq, data(unit, seq, len));
                model.put(unit, seq, len as u64, now);
            }
            40..=79 => {
                // get: mostly the current version, sometimes a stale one
                let current = latest_seq.get(&unit).copied().unwrap_or(1);
                let seq = if rng.random_bool(0.85) {
                    current
                } else {
                    current.saturating_sub(1).max(1)
                };
                let expect_hit = model.get(unit, seq, now);
                let got = cache.get(unit, seq);
                assert_eq!(
                    got.is_some(),
                    expect_hit,
                    "seed {seed} step {step}: get({unit},{seq}) hit mismatch; model {:?}",
                    model.entries.get(&unit)
                );
                if let Some(buf) = got {
                    let expected = data(unit, seq, buf.len());
                    assert_eq!(
                        buf.expose(),
                        expected.expose(),
                        "served bytes for a different version"
                    );
                    hits += 1;
                } else {
                    misses += 1;
                }
            }
            80..=86 => {
                cache.invalidate(unit);
                model.entries.remove(&unit);
            }
            87..=91 => {
                let advance = Duration::from_millis(rng.random_range(1..200));
                clock.advance(advance);
            }
            92..=95 => {
                let new_max = if rng.random_bool(0.1) {
                    0
                } else {
                    rng.random_range(1..=24u64) * 256
                };
                cache.set_max_bytes(new_max);
                model.resize(new_max);
            }
            96..=97 => {
                let new_ttl = Duration::from_millis(rng.random_range(10..800));
                cache.set_ttl(new_ttl);
                model.ttl = new_ttl;
            }
            _ => {
                cache.clear();
                model.entries.clear();
            }
        }
        let stats = cache.stats();
        assert_eq!(
            stats.entries,
            model.entries.len(),
            "seed {seed} step {step}: entry count"
        );
        assert_eq!(
            stats.bytes,
            model.bytes(),
            "seed {seed} step {step}: byte accounting"
        );
        assert!(
            stats.bytes <= model.max_bytes,
            "seed {seed} step {step}: over budget"
        );
        assert_eq!(stats.hits, hits);
        assert_eq!(stats.misses, misses);
    }
}

/// A resize that evicts must remove the least recently used entries first,
/// regardless of insertion order.
#[test]
fn resize_evicts_in_recency_order() {
    let clock = Arc::new(ManualClock::new());
    let cache = VersionedLruCache::new(
        CacheConfig {
            max_bytes: 4 * 100,
            ttl: Duration::from_secs(60),
            zeroize_on_evict: true,
        },
        clock,
    );
    for unit in 0..4u64 {
        cache.put(unit, 1, SecretBuffer::from_slice(&[unit as u8; 100]));
    }
    // Touch 0 and 1 so 2 and 3 become the oldest.
    assert!(cache.get(0, 1).is_some());
    assert!(cache.get(1, 1).is_some());
    cache.set_max_bytes(200);
    assert!(cache.get(2, 1).is_none());
    assert!(cache.get(3, 1).is_none());
    assert!(cache.get(0, 1).is_some());
    assert!(cache.get(1, 1).is_some());
}
