//! Observe initialized allocations while the allocator still owns them.
use super::*;
use crate::common::io::Compat;
use maki_test_allocator::watch;
use tokio_test::io::Builder as Mock;

fn secret() -> &'static [u8] {
    b"maki HTTP framing secret"
}

#[test]
fn maki_flatten_growth_erases_retired_buffer() {
    let mut write = WriteBuf::<Bytes>::new(WriteStrategy::Flatten);
    write.buffer(Bytes::from_static(secret()));
    let old = watch(write.headers.bytes.as_ptr());
    let more = vec![b'X'; write.headers.bytes.capacity() + 1];
    write.buffer(Bytes::from(more.clone()));
    assert!(write.chunk().starts_with(secret()));
    assert_eq!(&write.chunk()[secret().len()..], more.as_slice());
    old.assert_zeroized();
}

#[test]
fn maki_header_growth_erases_retired_buffer() {
    let mut write = WriteBuf::<Bytes>::new(WriteStrategy::Queue);
    write.headers_mut().bytes.extend_from_slice(secret());
    let old = watch(write.headers.bytes.as_ptr());
    let capacity = write.headers.bytes.capacity();
    write
        .headers_mut()
        .bytes
        .extend_from_slice(&vec![b'H'; capacity]);
    assert!(write.chunk().starts_with(secret()));
    assert_eq!(write.remaining(), secret().len() + capacity);
    old.assert_zeroized();
}

#[test]
fn maki_partial_write_erases_consumed_prefix() {
    let mut write = WriteBuf::<Bytes>::new(WriteStrategy::Flatten);
    write.buffer(Bytes::from_static(secret()));
    write.advance(5);
    assert_eq!(write.chunk(), &secret()[5..]);
    assert_eq!(&write.headers.bytes[..5], &[0; 5]);
}

#[test]
fn maki_compaction_erases_obsolete_tail() {
    let mut write = WriteBuf::<Bytes>::new(WriteStrategy::Flatten);
    write.buffer(Bytes::from_static(secret()));
    let original_len = write.headers.bytes.len();
    write.advance(original_len - 4);
    let available = write.headers.bytes.capacity() - original_len;
    write.headers_mut().maybe_unshift(available + 1);
    assert_eq!(write.chunk(), &secret()[original_len - 4..]);
    // The test allocator initializes spare capacity. Obtain the discarded
    // range through its canonical mutable owner rather than extending a slice
    // pointer beyond the current initialized-length borrow.
    let spare = write.headers.bytes.spare_capacity_mut();
    assert!(spare[..original_len - 4].iter().all(|byte| {
        // SAFETY: the observing allocator initializes every allocated byte,
        // including this canonical owner's live spare capacity.
        (unsafe { byte.assume_init() }) == 0
    }));
}

#[test]
fn maki_completed_write_erases_reused_capacity() {
    let mut write = WriteBuf::<Bytes>::new(WriteStrategy::Flatten);
    write.buffer(Bytes::from_static(secret()));
    let allocation = watch(write.headers.bytes.as_ptr());
    write.advance(secret().len());
    assert!(!write.has_remaining());
    // The write buffer deliberately keeps its allocation for the next request.
    let spare = write.headers.bytes.spare_capacity_mut();
    assert!(spare[..secret().len()].iter().all(|byte| {
        // SAFETY: the observing allocator initializes every allocated byte,
        // including this canonical owner's live spare capacity.
        (unsafe { byte.assume_init() }) == 0
    }));
    drop(write);
    allocation.assert_zeroized();
}

#[test]
fn maki_abandoned_write_erases_buffer() {
    let mut write = WriteBuf::<Bytes>::new(WriteStrategy::Flatten);
    write.buffer(Bytes::from_static(secret()));
    let allocation = watch(write.headers.bytes.as_ptr());
    drop(write);
    allocation.assert_zeroized();
}

#[tokio::test]
async fn maki_failed_write_erases_buffer_on_drop() {
    let mock = Mock::new()
        .write_error(io::ErrorKind::BrokenPipe.into())
        .build();
    let mut buffered = Buffered::<_, Bytes>::new(Compat::new(mock));
    buffered.set_write_strategy_flatten();
    buffered.buffer(Bytes::from_static(secret()));
    let allocation = watch(buffered.write_buf.headers.bytes.as_ptr());
    let error = buffered.flush().await.expect_err("mock write must fail");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    drop(buffered);
    allocation.assert_zeroized();
}
