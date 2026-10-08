//! Observe only live allocations initialized by the test allocator.
use crate::{Buf, Bytes, BytesMut};
use alloc::vec::Vec;
use maki_test_allocator::watch;

fn buffer() -> BytesMut {
    let mut bytes = BytesMut::with_capacity(64);
    bytes.extend_from_slice(b"private-prefix-public-tail");
    bytes
}

fn assert_zero(pointer: *const u8, len: usize) {
    // Every byte of the still-live allocation is initialized by the observer.
    // These tests have no concurrent access to the observed ranges. The
    // caller derives a fresh raw pointer from the owner after mutation;
    // pointers derived from a previous shared slice would be invalidated.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, len) };
    assert!(
        bytes.iter().all(|byte| *byte == 0),
        "discarded live range retained bytes"
    );
}

#[test]
fn truncate_erases_discarded_suffix_immediately() {
    let mut bytes = buffer();
    let len = bytes.len();
    bytes.truncate(7);
    let pointer = bytes.ptr.as_ptr();
    assert_eq!(&bytes[..], b"private");
    assert_zero(unsafe { pointer.add(7) }, len - 7);
}

#[test]
fn clear_erases_before_reuse() {
    let mut bytes = buffer();
    let len = bytes.len();
    bytes.clear();
    bytes.extend_from_slice(b"new");
    let pointer = bytes.ptr.as_ptr();
    assert_eq!(&bytes[..], b"new");
    assert_zero(unsafe { pointer.add(3) }, len - 3);
}

#[test]
fn advance_erases_consumed_prefix_immediately() {
    let mut bytes = buffer();
    bytes.advance(15);
    let pointer = unsafe { bytes.ptr.as_ptr().sub(15) };
    assert_eq!(&bytes[..], b"public-tail");
    assert_zero(pointer, 15);
}

#[test]
fn unique_drop_erases_full_capacity_including_caller_written_spare() {
    let mut bytes = buffer();
    for byte in bytes.spare_capacity_mut() {
        byte.write(b'X');
    }
    let released = watch(bytes.as_ptr());
    drop(bytes);
    released.assert_zeroized();
}

#[test]
fn growth_erases_retired_allocation() {
    let mut bytes = buffer();
    let released = watch(bytes.as_ptr());
    bytes.reserve(256);
    assert_eq!(&bytes[..], b"private-prefix-public-tail");
    released.assert_zeroized();
}

#[test]
fn mutable_split_drop_erases_its_range_and_preserves_sibling() {
    let mut bytes = buffer();
    let prefix = bytes.split_to(15);
    assert_eq!(&prefix[..], b"private-prefix-");
    assert_eq!(&bytes[..], b"public-tail");
    drop(prefix);
    let pointer = unsafe { bytes.ptr.as_ptr().sub(15) };
    assert_zero(pointer, 15);
    assert_eq!(&bytes[..], b"public-tail");
}

#[test]
fn mutable_split_full_backing_erases_when_last_owner_releases() {
    let mut bytes = buffer();
    let released = watch(bytes.as_ptr());
    let prefix = bytes.split_to(15);
    drop(bytes);
    assert_eq!(&prefix[..], b"private-prefix-");
    drop(prefix);
    released.assert_zeroized();
}

#[test]
fn shared_growth_erases_abandoned_exclusive_view() {
    let mut bytes = buffer();
    let prefix = bytes.split_to(15).freeze();
    let shared = bytes.data;
    bytes.reserve(256);
    assert_eq!(&bytes[..], b"public-tail");
    assert_eq!(&prefix[..], b"private-prefix-");
    // The frozen sibling keeps this allocation alive. Obtain fresh backing
    // provenance after the mutable owner erased and abandoned its view.
    let pointer = unsafe { (*shared).vec.as_ptr() };
    assert_zero(unsafe { pointer.add(15) }, 11);
}

#[test]
fn reclaim_erases_duplicate_tail_after_compaction() {
    let mut bytes = BytesMut::with_capacity(64);
    bytes.extend_from_slice(b"discard-this-prefix-and-keep");
    let address = bytes.as_ptr().addr();
    bytes.advance(24);
    assert_eq!(&bytes[..], b"keep");
    assert!(bytes.try_reclaim(60));
    assert_eq!(&bytes[..], b"keep");
    assert_eq!(bytes.as_ptr().addr(), address);
    let pointer = bytes.ptr.as_ptr();
    assert_zero(unsafe { pointer.add(4) }, 24);
}

#[test]
fn shared_reclaim_erases_duplicate_tail_after_compaction() {
    let mut bytes = BytesMut::with_capacity(64);
    bytes.extend_from_slice(b"discard-this-prefix-and-keep");
    let address = bytes.as_ptr().addr();
    let prefix = bytes.split_to(24);
    drop(prefix);
    assert!(bytes.try_reclaim(60));
    assert_eq!(&bytes[..], b"keep");
    assert_eq!(bytes.as_ptr().addr(), address);
    let pointer = bytes.ptr.as_ptr();
    assert_zero(unsafe { pointer.add(4) }, 24);
}

#[test]
fn frozen_aliases_remain_intact_until_final_drop() {
    let bytes = buffer();
    let released = watch(bytes.as_ptr());
    let bytes = bytes.freeze();
    let alias = bytes.slice(15..);
    drop(bytes);
    assert_eq!(&alias[..], b"public-tail");
    drop(alias);
    released.assert_zeroized();
}

#[test]
fn owned_box_and_promoted_bytes_erase_allocation() {
    for shared in [false, true] {
        let value = Vec::from(&b"private-prefix-public-tail"[..]).into_boxed_slice();
        let released = watch(value.as_ptr());
        let mut bytes = Bytes::from(value);
        if shared {
            drop(bytes.clone());
        }
        bytes.advance(15);
        assert_eq!(&bytes[..], b"public-tail");
        drop(bytes);
        released.assert_zeroized();
    }
}

#[test]
fn owned_vec_bytes_erase_full_capacity() {
    let mut value = Vec::with_capacity(64);
    value.extend_from_slice(b"private-prefix-public-tail");
    let released = watch(value.as_ptr());
    let bytes = Bytes::from(value);
    drop(bytes);
    released.assert_zeroized();
}

#[test]
fn mutable_to_vec_transfers_visible_bytes_and_erases_hidden_tail() {
    let mut bytes = buffer();
    bytes.advance(15);
    let vec = Vec::from(bytes);
    assert_eq!(&vec, b"public-tail");
    assert_zero(
        unsafe { vec.as_ptr().add(vec.len()) },
        vec.capacity() - vec.len(),
    );
}

#[test]
fn frozen_to_vec_transfers_visible_bytes_and_erases_hidden_tail() {
    for shared in [false, true] {
        let mut bytes = buffer().freeze();
        if shared {
            drop(bytes.clone());
        }
        bytes.advance(15);
        let vec = Vec::from(bytes);
        assert_eq!(&vec, b"public-tail");
        assert_zero(
            unsafe { vec.as_ptr().add(vec.len()) },
            vec.capacity() - vec.len(),
        );
    }
}

#[test]
fn unsplit_transfers_ownership_without_erasing_merged_bytes() {
    let mut bytes = buffer();
    let prefix = bytes.split_to(15);
    let mut prefix = prefix;
    prefix.unsplit(bytes);
    assert_eq!(&prefix[..], b"private-prefix-public-tail");
}

#[test]
fn static_and_custom_owners_remain_untouched() {
    let bytes = Bytes::from_static(b"caller-owned");
    drop(bytes.clone());
    assert_eq!(&bytes[..], b"caller-owned");
    let owner = std::sync::Arc::new(Vec::from(&b"custom-owner"[..]));
    struct Owner(std::sync::Arc<Vec<u8>>);
    impl AsRef<[u8]> for Owner {
        fn as_ref(&self) -> &[u8] {
            &self.0[..]
        }
    }
    let bytes = Bytes::from_owner(Owner(owner.clone()));
    drop(bytes);
    assert_eq!(&owner[..], b"custom-owner");
}
