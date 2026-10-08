//! A buffer for reading data from the network.
//!
//! The `ReadBuffer` is a buffer of bytes similar to a first-in, first-out queue.
//! It is filled by reading from a stream supporting `Read` and is then
//! accessible as a cursor for reading bytes.

use std::io::{Cursor, Read, Result as IoResult};

use bytes::Buf;
use zeroize::Zeroize;

/// A FIFO buffer for reading packets from the network.
#[derive(Debug)]
pub struct ReadBuffer<const CHUNK_SIZE: usize> {
    storage: Cursor<Vec<u8>>,
    chunk: Box<[u8; CHUNK_SIZE]>,
}

impl<const CHUNK_SIZE: usize> ReadBuffer<CHUNK_SIZE> {
    /// Create a new empty input buffer.
    pub fn new() -> Self {
        Self::with_capacity(CHUNK_SIZE)
    }

    /// Create a new empty input buffer with a given `capacity`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_partially_read(Vec::with_capacity(capacity))
    }

    /// Create a input buffer filled with previously read data.
    pub fn from_partially_read(part: Vec<u8>) -> Self {
        Self { storage: Cursor::new(part), chunk: Box::new([0; CHUNK_SIZE]) }
    }

    /// Get a cursor to the data storage.
    pub fn as_cursor(&self) -> &Cursor<Vec<u8>> {
        &self.storage
    }

    /// Get a cursor to the mutable data storage.
    ///
    /// Direct mutation or extraction of the exposed vector is caller-owned.
    /// The caller must erase allocations it releases by growing that vector.
    pub fn as_cursor_mut(&mut self) -> &mut Cursor<Vec<u8>> {
        &mut self.storage
    }

    /// Consume the `ReadBuffer` and get the internal storage.
    /// The returned vector transfers to the caller, including erasure responsibility.
    pub fn into_vec(mut self) -> Vec<u8> {
        // Current implementation of `tungstenite-rs` expects that the `into_vec()` drains
        // the data from the container that has already been read by the cursor.
        self.clean_up();

        // Now we can safely return the internal container.
        std::mem::take(self.storage.get_mut())
    }

    /// Read next portion of data from the given input stream.
    pub fn read_from<S: Read>(&mut self, stream: &mut S) -> IoResult<usize> {
        self.clean_up();
        let result = stream.read(&mut *self.chunk);
        if let Ok(size) = result {
            crate::maki_buffer::reserve(self.storage.get_mut(), size);
            self.storage.get_mut().extend_from_slice(&self.chunk[..size]);
        }
        // A Read implementation may have changed the chunk before returning
        // an error. Wipe the entire owned chunk on either result.
        self.chunk[..].zeroize();
        result
    }

    /// Cleans ups the part of the vector that has been already read by the cursor.
    fn clean_up(&mut self) {
        let pos = self.storage.position() as usize;
        crate::maki_buffer::consume(self.storage.get_mut(), pos);
        self.storage.set_position(0);
    }
}

impl<const CHUNK_SIZE: usize> Drop for ReadBuffer<CHUNK_SIZE> {
    fn drop(&mut self) {
        self.storage.get_mut().zeroize();
        self.chunk[..].zeroize();
    }
}

impl<const CHUNK_SIZE: usize> Buf for ReadBuffer<CHUNK_SIZE> {
    fn remaining(&self) -> usize {
        Buf::remaining(self.as_cursor())
    }

    fn chunk(&self) -> &[u8] {
        Buf::chunk(self.as_cursor())
    }

    fn advance(&mut self, cnt: usize) {
        let position = self.storage.position() as usize;
        assert!(cnt <= self.remaining());
        self.storage.get_mut()[position..position + cnt].zeroize();
        Buf::advance(self.as_cursor_mut(), cnt);
    }
}

impl<const CHUNK_SIZE: usize> Default for ReadBuffer<CHUNK_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_reading() {
        let mut input = Cursor::new(b"Hello World!".to_vec());
        let mut buffer = ReadBuffer::<4096>::new();
        let size = buffer.read_from(&mut input).unwrap();
        assert_eq!(size, 12);
        assert_eq!(buffer.chunk(), b"Hello World!");
    }

    #[test]
    fn reading_in_chunks() {
        let mut inp = Cursor::new(b"Hello World!".to_vec());
        let mut buf = ReadBuffer::<4>::new();

        let size = buf.read_from(&mut inp).unwrap();
        assert_eq!(size, 4);
        assert_eq!(buf.chunk(), b"Hell");

        buf.advance(2);
        assert_eq!(buf.chunk(), b"ll");
        assert_eq!(buf.storage.get_mut(), b"\0\0ll");

        let size = buf.read_from(&mut inp).unwrap();
        assert_eq!(size, 4);
        assert_eq!(buf.chunk(), b"llo Wo");
        assert_eq!(buf.storage.get_mut(), b"llo Wo");

        let size = buf.read_from(&mut inp).unwrap();
        assert_eq!(size, 4);
        assert_eq!(buf.chunk(), b"llo World!");
    }
}

#[cfg(test)]
mod maki_erasure_tests {
    use super::*;
    use maki_test_allocator::watch;

    #[test]
    fn maki_read_buffer_drop_erases_storage_and_read_chunk() {
        let mut buffer = ReadBuffer::<64>::new();
        buffer
            .read_from(&mut Cursor::new(b"maki handshake and early payload"))
            .unwrap();
        let storage = watch(buffer.storage.get_ref().as_ptr());
        let chunk = watch(buffer.chunk.as_ptr());
        drop(buffer);
        storage.assert_zeroized();
        chunk.assert_zeroized();
    }

    #[test]
    fn maki_read_buffer_growth_erases_retired_storage() {
        let mut buffer = ReadBuffer::<32>::with_capacity(32);
        buffer.read_from(&mut Cursor::new([b'x'; 32])).unwrap();
        let released = watch(buffer.storage.get_ref().as_ptr());
        buffer.read_from(&mut Cursor::new([b'y'; 32])).unwrap();
        released.assert_zeroized();
    }

    #[test]
    fn maki_read_buffer_cleanup_erases_consumed_tail() {
        let mut buffer = ReadBuffer::<32>::new();
        buffer
            .read_from(&mut Cursor::new(b"secret-header-and-payload"))
            .unwrap();
        let initialized = buffer.storage.get_ref().len();
        buffer.advance(14);
        let tail = buffer.into_vec();
        assert_eq!(&tail, b"and-payload");
        let discarded = unsafe {
            std::slice::from_raw_parts(tail.as_ptr().add(tail.len()), initialized - tail.len())
        };
        assert!(discarded.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn maki_read_buffer_chunk_erased_after_read_error() {
        struct PartialError;
        impl Read for PartialError {
            fn read(&mut self, destination: &mut [u8]) -> IoResult<usize> {
                destination[..6].copy_from_slice(b"secret");
                Err(std::io::ErrorKind::Interrupted.into())
            }
        }
        let mut buffer = ReadBuffer::<32>::new();
        assert!(buffer.read_from(&mut PartialError).is_err());
        assert!(buffer.chunk.iter().all(|byte| *byte == 0));
        assert_eq!(buffer.remaining(), 0);
    }

    #[test]
    fn maki_read_buffer_chunk_erased_after_copy() {
        let mut buffer = ReadBuffer::<32>::new();
        buffer
            .read_from(&mut Cursor::new(b"maki chunk secret"))
            .unwrap();
        assert!(buffer.chunk.iter().all(|byte| *byte == 0));
    }
}
