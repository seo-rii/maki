//! R5-020: a slow reader that decrypted an older version of a unit must not
//! displace the newer version a faster reader already cached, neither by
//! `put` (it replaced the unit's entry unconditionally) nor by a `get` for
//! its older sequence (a mismatch evicted whatever was cached). Stale data
//! was never served, but the newer entry was lost and the next read paid a
//! payload read and a decryption again.

use std::sync::Arc;
use std::time::Duration;

use maki_cache::{CacheConfig, VersionedLruCache};
use maki_crypto::SecretBuffer;
use maki_test_support::ManualClock;

fn cache() -> VersionedLruCache {
    VersionedLruCache::new(
        CacheConfig {
            max_bytes: 1 << 20,
            ttl: Duration::from_secs(60),
            zeroize_on_evict: true,
        },
        Arc::new(ManualClock::new()),
    )
}

fn buf(fill: u8) -> SecretBuffer {
    SecretBuffer::from_vec(vec![fill; 512])
}

#[test]
fn an_older_put_keeps_the_newer_entry() {
    let cache = cache();
    cache.put(7, 5, buf(0x55));
    cache.put(7, 3, buf(0x33));
    assert_eq!(cache.get(7, 5).unwrap().expose(), &[0x55; 512][..]);
    assert!(cache.get(7, 3).is_none());
}

#[test]
fn an_older_lookup_keeps_the_newer_entry() {
    let cache = cache();
    cache.put(7, 5, buf(0x55));
    assert!(cache.get(7, 3).is_none());
    assert_eq!(cache.get(7, 5).unwrap().expose(), &[0x55; 512][..]);
}

#[test]
fn a_newer_version_still_replaces_and_evicts_the_older_one() {
    let cache = cache();
    cache.put(7, 3, buf(0x33));
    cache.put(7, 5, buf(0x55));
    assert!(cache.get(7, 3).is_none());
    assert_eq!(cache.get(7, 5).unwrap().expose(), &[0x55; 512][..]);
    cache.put(8, 3, buf(0x33));
    assert!(cache.get(8, 4).is_none(), "a stale entry misses");
    assert_eq!(cache.stats().entries, 1, "and is dropped");
}
