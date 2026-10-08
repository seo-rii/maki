//! Erasure for allocations and exclusive ranges owned by this crate.
use alloc::vec::Vec;
use core::{
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

/// Erase a writable range without reading potentially uninitialized capacity.
///
/// # Safety
/// The range must be in a live allocation and exclusively writable. No live
/// immutable or mutable view may overlap it. A zero length permits a dangling
/// pointer because the loop performs no pointer arithmetic or writes.
pub(crate) unsafe fn wipe(pointer: *mut u8, len: usize) {
    for index in 0..len {
        // SAFETY: The caller owns this entire range; writing initializes each
        // byte and never constructs a reference to uninitialized storage.
        unsafe { pointer.add(index).write_volatile(0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub(crate) fn wipe_vec(vec: &mut Vec<u8>) {
    // SAFETY: A mutable Vec owns its full allocation, including spare capacity.
    unsafe { wipe(vec.as_mut_ptr(), vec.capacity()) };
}

/// Allocate before erasing the retired buffer; Vec::reserve may use realloc
/// and release the previous allocation before we can erase it.
pub(crate) fn reserve_vec(vec: &mut Vec<u8>, additional: usize) {
    let required = vec
        .len()
        .checked_add(additional)
        .expect("capacity overflow");
    if required <= vec.capacity() {
        return;
    }
    let capacity = required.max(vec.capacity().saturating_mul(2)).max(8);
    let mut next = Vec::with_capacity(capacity);
    // SAFETY: The new buffer is disjoint and large enough. Raw copying also
    // preserves any uninitialized discarded prefix tracked internally by
    // BytesMut without reading it through a Rust reference.
    unsafe {
        ptr::copy_nonoverlapping(vec.as_ptr(), next.as_mut_ptr(), vec.len());
        next.set_len(vec.len());
    }
    wipe_vec(vec);
    *vec = next;
}
