use alloc::vec::Vec;
use core::mem;
use core::ops::Range;
#[cfg(feature = "std")]
use std::io;
use zeroize::Zeroize;
#[cfg(feature = "std")]
use zeroize::Zeroizing;

#[cfg(feature = "std")]
use crate::msgs::message::MAX_WIRE_SIZE;

/// Conversion from a slice within a larger buffer into
/// a `Range` offset within.
#[derive(Debug)]
pub(crate) struct Locator {
    bounds: Range<*const u8>,
}

impl Locator {
    #[inline]
    pub(crate) fn new(slice: &[u8]) -> Self {
        Self {
            bounds: slice.as_ptr_range(),
        }
    }

    #[inline]
    pub(crate) fn locate(&self, slice: &[u8]) -> Range<usize> {
        let bounds = slice.as_ptr_range();
        debug_assert!(self.fully_contains(slice));
        let start = bounds.start as usize - self.bounds.start as usize;
        let len = bounds.end as usize - bounds.start as usize;
        Range {
            start,
            end: start + len,
        }
    }

    #[inline]
    pub(crate) fn fully_contains(&self, slice: &[u8]) -> bool {
        let bounds = slice.as_ptr_range();
        bounds.start >= self.bounds.start && bounds.end <= self.bounds.end
    }
}

/// Conversion from a `Range` offset to the original slice.
pub(crate) struct Delocator<'b> {
    slice: &'b [u8],
}

impl<'b> Delocator<'b> {
    #[inline]
    pub(crate) fn new(slice: &'b [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn slice_from_range(&'_ self, range: &Range<usize>) -> &'b [u8] {
        // safety: this unwrap is safe so long as `range` came from `locate()`
        // for the same buffer
        self.slice.get(range.clone()).unwrap()
    }

    #[inline]
    pub(crate) fn locator(self) -> Locator {
        Locator::new(self.slice)
    }
}

/// Reordering the underlying buffer based on ranges.
pub(crate) struct Coalescer<'b> {
    slice: &'b mut [u8],
}

impl<'b> Coalescer<'b> {
    #[inline]
    pub(crate) fn new(slice: &'b mut [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn copy_within(&mut self, from: Range<usize>, to: Range<usize>) {
        debug_assert!(from.len() == to.len());
        debug_assert!(self.slice.get(from.clone()).is_some());
        debug_assert!(self.slice.get(to.clone()).is_some());
        self.slice.copy_within(from, to.start);
    }

    #[inline]
    pub(crate) fn delocator(self) -> Delocator<'b> {
        Delocator::new(self.slice)
    }
}

/// Accounting structure tracking progress in parsing a single buffer.
#[derive(Clone, Debug)]
pub(crate) struct BufferProgress {
    /// Prefix of the buffer that has been processed so far.
    ///
    /// `processed` may exceed `discard`, that means we have parsed
    /// some buffer, but are still using it.  This happens due to
    /// in-place decryption of incoming records, and in-place
    /// reassembly of handshake messages.
    ///
    /// 0 <= processed <= len
    processed: usize,

    /// Prefix of the buffer that can be removed.
    ///
    /// If `discard` exceeds `processed`, that means we are ignoring
    /// data without processing it.
    ///
    /// 0 <= discard <= len
    discard: usize,
}

impl BufferProgress {
    pub(super) fn new(processed: usize) -> Self {
        Self {
            processed,
            discard: 0,
        }
    }

    #[inline]
    pub(crate) fn add_discard(&mut self, discard: usize) {
        self.discard += discard;
    }

    #[inline]
    pub(crate) fn add_processed(&mut self, processed: usize) {
        self.processed += processed;
    }

    #[inline]
    pub(crate) fn take_discard(&mut self) -> usize {
        // the caller is about to discard `discard` bytes
        // from the front of the buffer.  adjust `processed`
        // down by the same amount.
        self.processed = self
            .processed
            .saturating_sub(self.discard);
        mem::take(&mut self.discard)
    }

    #[inline]
    pub(crate) fn processed(&self) -> usize {
        self.processed
    }
}

#[derive(Default, Debug)]
pub(crate) struct DeframerVecBuffer {
    /// Buffer of data read from the socket, in the process of being parsed into messages.
    ///
    /// For buffer size management, checkout out the [`DeframerVecBuffer::prepare_read()`] method.
    buf: Vec<u8>,

    /// What size prefix of `buf` is used.
    used: usize,
}

impl DeframerVecBuffer {
    /// Discard `taken` bytes from the start of our buffer.
    pub(crate) fn discard(&mut self, taken: usize) {
        let previously_used = self.used;
        #[allow(clippy::comparison_chain)]
        if taken < self.used {
            /* Before:
             * +----------+----------+----------+
             * | taken    | pending  |xxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ taken    ^ self.used
             *
             * After:
             * +----------+----------+----------+
             * | pending  |xxxxxxxxxxxxxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ self.used
             */

            self.buf
                .copy_within(taken..self.used, 0);
            self.used -= taken;
        } else if taken >= self.used {
            self.used = 0;
        }
        self.buf[self.used..previously_used].zeroize();
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }

    pub(crate) fn filled(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl Drop for DeframerVecBuffer {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(feature = "std")]
impl DeframerVecBuffer {
    /// Read some bytes from `rd`, and add them to the buffer.
    pub(crate) fn read(&mut self, rd: &mut dyn io::Read, in_handshake: bool) -> io::Result<usize> {
        if let Err(err) = self.prepare_read(in_handshake) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        // Try to do the largest reads possible. Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        let new_bytes = rd.read(&mut self.buf[self.used..])?;
        self.used += new_bytes;
        Ok(new_bytes)
    }

    /// Resize the internal `buf` if necessary for reading more bytes.
    fn prepare_read(&mut self, is_joining_hs: bool) -> Result<(), &'static str> {
        /// TLS allows for handshake messages of up to 16MB.  We
        /// restrict that to 64KB to limit potential for denial-of-
        /// service.
        const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

        const READ_SIZE: usize = 4096;

        // We allow a maximum of 64k of buffered data for handshake messages only. Enforce this
        // by varying the maximum allowed buffer size here based on whether a prefix of a
        // handshake payload is currently being buffered. Given that the first read of such a
        // payload will only ever be 4k bytes, the next time we come around here we allow a
        // larger buffer size. Once the large message and any following handshake messages in
        // the same flight have been consumed, `pop()` will call `discard()` to reset `used`.
        // At this point, the buffer resizing logic below should reduce the buffer size.
        let allow_max = match is_joining_hs {
            true => MAX_HANDSHAKE_SIZE as usize,
            false => MAX_WIRE_SIZE,
        };

        if self.used >= allow_max {
            return Err("message buffer full");
        }

        // If we can and need to increase the buffer size to allow a 4k read, do so. After
        // dealing with a large handshake message (exceeding `OutboundOpaqueMessage::MAX_WIRE_SIZE`),
        // make sure to reduce the buffer size again (large messages should be rare).
        // Also, reduce the buffer size if there are neither full nor partial messages in it,
        // which usually means that the other side suspended sending data.
        let need_capacity = Ord::min(allow_max, self.used + READ_SIZE);
        if need_capacity > self.buf.len() || self.used == 0 || self.buf.len() > allow_max {
            self.resize_zeroizing(need_capacity);
        }

        Ok(())
    }

    /// Keep live records while erasing the old allocation before releasing it.
    /// Vec::resize/shrink_to alone may return plaintext to the allocator.
    fn resize_zeroizing(&mut self, length: usize) {
        if length >= self.buf.len() && length <= self.buf.capacity() {
            self.buf.resize(length, 0);
            return;
        }

        let mut replacement = Zeroizing::new(Vec::with_capacity(length));
        replacement.resize(length, 0);
        let preserved = Ord::min(self.used, length);
        replacement[..preserved].copy_from_slice(&self.buf[..preserved]);
        self.buf.zeroize();
        self.buf = mem::take(&mut *replacement);
    }

    /// Append `bytes` to the end of this buffer.
    ///
    /// Return a `Range` saying where it went.
    pub(crate) fn extend(&mut self, bytes: &[u8]) -> Range<usize> {
        let len = bytes.len();
        let start = self.used;
        let end = start + len;
        if self.buf.len() < end {
            self.resize_zeroizing(end);
        }
        self.buf[start..end].copy_from_slice(bytes);
        self.used += len;
        Range { start, end }
    }
}

/// A borrowed version of [`DeframerVecBuffer`] that tracks discard operations
#[derive(Debug)]
pub(crate) struct DeframerSliceBuffer<'a> {
    // a fully initialized buffer that will be deframed
    buf: &'a mut [u8],
    // number of bytes to discard from the front of `buf` at a later time
    discard: usize,
}

#[cfg(all(test, feature = "std"))]
mod maki_erasure_tests {
    use alloc::vec;

    use super::DeframerVecBuffer;

    #[test]
    fn maki_deframer_discard_zeroes_obsolete_plaintext_without_corrupting_pending() {
        let mut buffer = DeframerVecBuffer {
            buf: b"decryptedpending".to_vec(),
            used: 16,
        };
        buffer.discard(9);
        assert_eq!(buffer.filled(), b"pending");
        assert_eq!(&buffer.buf[7..16], &[0; 9]);
        buffer.discard(7);
        assert!(buffer.filled().is_empty());
        assert!(buffer.buf.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn maki_deframer_drop_zeroes_live_plaintext_before_release() {
        let buffer = DeframerVecBuffer {
            buf: b"decrypted record awaiting processing".to_vec(),
            used: 36,
        };
        let watch = maki_test_allocator::watch(buffer.buf.as_ptr());
        drop(buffer);
        watch.assert_zeroized();
    }

    #[test]
    fn maki_deframer_growth_zeroes_old_allocation_and_preserves_pending_record() {
        let mut buffer = DeframerVecBuffer {
            buf: b"secret".to_vec(),
            used: 6,
        };
        let watch = maki_test_allocator::watch(buffer.buf.as_ptr());
        let incoming = vec![b'x'; 4096];
        buffer.extend(&incoming);
        assert_eq!(&buffer.filled()[..6], b"secret");
        assert_eq!(&buffer.filled()[6..], &incoming);
        watch.assert_zeroized();
    }

    #[test]
    fn maki_deframer_read_growth_zeroes_old_allocation() {
        let mut buffer = DeframerVecBuffer {
            buf: b"secret".to_vec(),
            used: 6,
        };
        let watch = maki_test_allocator::watch(buffer.buf.as_ptr());
        buffer.prepare_read(false).unwrap();
        assert_eq!(buffer.filled(), b"secret");
        watch.assert_zeroized();
    }

    #[test]
    fn maki_deframer_shrink_zeroes_released_allocation() {
        let mut buffer = DeframerVecBuffer {
            buf: vec![b's'; 65535],
            used: 0,
        };
        let watch = maki_test_allocator::watch(buffer.buf.as_ptr());
        buffer.prepare_read(false).unwrap();
        assert_eq!(buffer.buf.len(), 4096);
        watch.assert_zeroized();
    }
}

impl<'a> DeframerSliceBuffer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, discard: 0 }
    }

    /// Tracks a pending discard operation of `num_bytes`
    pub(crate) fn queue_discard(&mut self, num_bytes: usize) {
        self.discard += num_bytes;
    }

    pub(crate) fn pending_discard(&self) -> usize {
        self.discard
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.discard..]
    }
}
