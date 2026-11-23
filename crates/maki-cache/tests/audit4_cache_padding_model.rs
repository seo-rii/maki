//! Audit round 4 (#286 capacity charge, #296 padded read units, #249 touch,
//! #280/#296 TTL): randomized put/put_read_unit/get/invalidate/reconfigure
//! with provider-style spare capacity. Checks after every step that the
//! retained capacity stays within the limit, that a hit serves exactly the
//! version asked for, that the byte counter returns to zero once every
//! entry is gone (no accounting drift), and that no plaintext block is ever
//! freed un-erased (allocator scan for a marker).

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_cache::{CacheConfig, VersionedLruCache};
use maki_crypto::SecretBuffer;
use maki_test_support::ManualClock;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const MARKER: [u8; 16] = *b"\xA7audit4-CACHExy\x5C";
const UNIT: usize = 512;

static SCAN: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);

struct Scanner;

// SAFETY: delegates to System; the scan reads only the live block being freed.
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
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scanner = Scanner;

/// Plaintext of `(unit, seq)`: marker body, identity trailer.
fn unit_data(unit: u64, seq: u64, capacity: usize) -> SecretBuffer {
    let mut b = SecretBuffer::with_capacity(capacity).unwrap();
    for _ in 0..(UNIT - 16) / 16 {
        b.try_extend_from_slice(&MARKER).unwrap();
    }
    b.try_extend_from_slice(&unit.to_le_bytes()).unwrap();
    b.try_extend_from_slice(&seq.to_le_bytes()).unwrap();
    b
}

fn identity(b: &SecretBuffer) -> (u64, u64) {
    let tail = &b.expose()[UNIT - 16..];
    (
        u64::from_le_bytes(tail[..8].try_into().unwrap()),
        u64::from_le_bytes(tail[8..].try_into().unwrap()),
    )
}

#[test]
fn randomized_padded_cache_keeps_bounds_versions_and_erasure() {
    SCAN.store(true, Ordering::SeqCst);
    let mut problems = Vec::new();
    for seed in 0..60u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let clock = Arc::new(ManualClock::new());
        let mut max_bytes = UNIT as u64 * rng.random_range(1..12) + rng.random_range(0..300);
        let cache = VersionedLruCache::new(
            CacheConfig {
                max_bytes,
                ttl: Duration::from_secs(rng.random_range(1..50)),
                zeroize_on_evict: true,
            },
            clock.clone(),
        );
        let mut seqs: HashMap<u64, u64> = HashMap::new();
        let mut held: Vec<Arc<SecretBuffer>> = Vec::new();
        for step in 0..3000 {
            let unit = rng.random_range(0..16u64);
            match rng.random_range(0..20) {
                0..=7 => {
                    let seq = *seqs.entry(unit).or_insert(1) + rng.random_range(0..2);
                    seqs.insert(unit, seq);
                    let slack = [0, 0, 16, 32, 256, UNIT, 2 * UNIT + 7][rng.random_range(0..7)];
                    let data = unit_data(unit, seq, UNIT + slack);
                    if rng.random_bool(0.85) {
                        cache.put_read_unit(unit, seq, data);
                    } else {
                        cache.put(unit, seq, data);
                    }
                }
                8 => {
                    // A slow reader publishing an older version.
                    let seq = seqs.get(&unit).copied().unwrap_or(1).saturating_sub(1);
                    cache.put_read_unit(unit, seq, unit_data(unit, seq, UNIT + 16));
                }
                9..=14 => {
                    let seq = seqs.get(&unit).copied().unwrap_or(1);
                    if let Some(hit) = cache.get(unit, seq) {
                        if hit.len() != UNIT || identity(&hit) != (unit, seq) {
                            problems.push(format!(
                                "seed {seed} step {step}: get({unit},{seq}) served {:?} len {}",
                                identity(&hit),
                                hit.len()
                            ));
                        }
                        if rng.random_bool(0.3) {
                            held.push(hit);
                        }
                    }
                }
                15 => cache.invalidate(unit),
                16 => {
                    max_bytes = match rng.random_range(0..4) {
                        0 => 0,
                        1 => UNIT as u64 * rng.random_range(1..4),
                        _ => UNIT as u64 * rng.random_range(1..16) + rng.random_range(0..600),
                    };
                    let ttl = rng
                        .random_bool(0.5)
                        .then(|| Duration::from_secs(rng.random_range(1..50)));
                    cache.reconfigure(max_bytes, ttl);
                }
                17 => clock.advance(Duration::from_secs(rng.random_range(0..10))),
                18 => {
                    held.clear();
                }
                _ => {
                    if !held.is_empty() {
                        held.swap_remove(rng.random_range(0..held.len()));
                    }
                }
            }
            let stats = cache.stats();
            if stats.bytes > max_bytes {
                problems.push(format!(
                    "seed {seed} step {step}: {} bytes retained over limit {max_bytes}",
                    stats.bytes
                ));
            }
        }
        for unit in 0..16 {
            cache.invalidate(unit);
        }
        let stats = cache.stats();
        if stats.bytes != 0 || stats.entries != 0 {
            problems.push(format!(
                "seed {seed}: counter drift after removing every entry: {stats:?}"
            ));
        }
        drop(held);
        drop(cache);
        if problems.len() > 20 {
            break;
        }
    }
    SCAN.store(false, Ordering::SeqCst);
    assert_eq!(HITS.load(Ordering::SeqCst), 0, "plaintext freed un-erased");
    assert!(problems.is_empty(), "{problems:#?}");
}
