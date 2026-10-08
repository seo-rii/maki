//! Utilities to work with raw WebSocket frames.

pub mod coding;

#[allow(clippy::module_inception)]
mod frame;
mod mask;
mod utf8;

pub use self::{
    frame::{CloseFrame, Frame, FrameHeader},
    utf8::Utf8Bytes,
};

use crate::{
    error::{CapacityError, Error, ProtocolError, Result},
    protocol::frame::mask::apply_mask,
    Message,
};
use bytes::BytesMut;
use log::*;
use std::io::{self, Cursor, Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use zeroize::Zeroizing;

/// Read buffer size used for `FrameSocket`.
const READ_BUF_LEN: usize = 128 * 1024;

/// A reader and writer for WebSocket frames.
#[derive(Debug)]
pub struct FrameSocket<Stream> {
    /// The underlying network stream.
    stream: Stream,
    /// Codec for reading/writing frames.
    codec: FrameCodec,
}

impl<Stream> FrameSocket<Stream> {
    /// Create a new frame socket.
    pub fn new(stream: Stream) -> Self {
        FrameSocket { stream, codec: FrameCodec::new(READ_BUF_LEN) }
    }

    /// Create a new frame socket from partially read data.
    pub fn from_partially_read(stream: Stream, part: Vec<u8>) -> Self {
        FrameSocket { stream, codec: FrameCodec::from_partially_read(part, READ_BUF_LEN) }
    }

    /// Extract a stream from the socket.
    pub fn into_inner(self) -> (Stream, BytesMut) {
        (self.stream, self.codec.in_buffer)
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &Stream {
        &self.stream
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }
}

impl<Stream> FrameSocket<Stream>
where
    Stream: Read,
{
    /// Read a frame from stream.
    pub fn read(&mut self, max_size: Option<usize>) -> Result<Option<Frame>> {
        self.codec.read_frame(&mut self.stream, max_size, false, true)
    }
}

impl<Stream> FrameSocket<Stream>
where
    Stream: Write,
{
    /// Writes and immediately flushes a frame.
    /// Equivalent to calling [`write`](Self::write) then [`flush`](Self::flush).
    pub fn send(&mut self, frame: Frame) -> Result<()> {
        self.write(frame)?;
        self.flush()
    }

    /// Write a frame to stream.
    ///
    /// A subsequent call should be made to [`flush`](Self::flush) to flush writes.
    ///
    /// This function guarantees that the frame is queued unless [`Error::WriteBufferFull`]
    /// is returned.
    /// In order to handle WouldBlock or Incomplete, call [`flush`](Self::flush) afterwards.
    pub fn write(&mut self, frame: Frame) -> Result<()> {
        self.codec.buffer_frame(&mut self.stream, frame)
    }

    /// Flush writes.
    pub fn flush(&mut self) -> Result<()> {
        self.codec.write_out_buffer(&mut self.stream)?;
        Ok(self.stream.flush()?)
    }
}

/// A codec for WebSocket frames.
#[derive(Debug)]
pub(super) struct FrameCodec {
    /// Buffer to read data from the stream.
    in_buffer: BytesMut,
    /// Buffer to send packets to the network.
    out_buffer: Zeroizing<Vec<u8>>,
    /// Capacity limit for `out_buffer`.
    max_out_buffer_len: usize,
    /// Buffer target length to reach before writing to the stream
    /// on calls to `buffer_frame`.
    ///
    /// Setting this to non-zero will buffer small writes from hitting
    /// the stream.
    out_buffer_write_len: usize,
    /// Header and remaining size of the incoming packet being processed.
    header: Option<(FrameHeader, u64)>,
}

impl FrameCodec {
    /// Create a new frame codec.
    pub(super) fn new(in_buf_len: usize) -> Self {
        Self {
            in_buffer: BytesMut::with_capacity(in_buf_len),
            out_buffer: <_>::default(),
            max_out_buffer_len: usize::MAX,
            out_buffer_write_len: 0,
            header: None,
        }
    }

    /// Create a new frame codec from partially read data.
    pub(super) fn from_partially_read(part: Vec<u8>, min_in_buf_len: usize) -> Self {
        let part = crate::maki_buffer::OwnedBuffer::from_vec(part);
        let mut in_buffer = BytesMut::from(&part[..]);
        in_buffer.reserve(min_in_buf_len.saturating_sub(in_buffer.len()));
        Self {
            in_buffer,
            out_buffer: <_>::default(),
            max_out_buffer_len: usize::MAX,
            out_buffer_write_len: 0,
            header: None,
        }
    }

    /// Sets a maximum size for the out buffer.
    pub(super) fn set_max_out_buffer_len(&mut self, max: usize) {
        self.max_out_buffer_len = max;
    }

    /// Sets [`Self::buffer_frame`] buffer target length to reach before
    /// writing to the stream.
    pub(super) fn set_out_buffer_write_len(&mut self, len: usize) {
        self.out_buffer_write_len = len;
    }

    /// Read a frame from the provided stream.
    pub(super) fn read_frame(
        &mut self,
        stream: &mut impl Read,
        max_size: Option<usize>,
        unmask: bool,
        accept_unmasked: bool,
    ) -> Result<Option<Frame>> {
        let max_size = max_size.unwrap_or_else(usize::max_value);

        let mut payload = loop {
            {
                if self.header.is_none() {
                    let mut cursor = Cursor::new(&mut self.in_buffer);
                    self.header = FrameHeader::parse(&mut cursor)?;
                    let advanced = cursor.position();
                    bytes::Buf::advance(&mut self.in_buffer, advanced as _);
                }

                if let Some((_, len)) = &self.header {
                    let len = *len as usize;

                    // Enforce frame size limit early and make sure `length`
                    // is not too big (fits into `usize`).
                    if len > max_size {
                        return Err(Error::Capacity(CapacityError::MessageTooLong {
                            size: len,
                            max_size,
                        }));
                    }

                    if len <= self.in_buffer.len() {
                        break self.in_buffer.split_to(len);
                    }
                }
            }

            // Not enough data in buffer.
            self.in_buffer.reserve(self.header.as_ref().map(|(_, l)| *l as usize).unwrap_or(6));
            if self.read_in(stream)? == 0 {
                trace!("no frame received");
                return Ok(None);
            }
        };

        let (mut header, length) = self.header.take().expect("Bug: no frame header");
        debug_assert_eq!(payload.len() as u64, length);

        if unmask {
            if let Some(mask) = header.mask.take() {
                // A server MUST remove masking for data frames received from a client
                // as described in Section 5.3. (RFC 6455)
                apply_mask(&mut payload, mask);
            } else if !accept_unmasked {
                // The server MUST close the connection upon receiving a
                // frame that is not masked. (RFC 6455)
                // The only exception here is if the user explicitly accepts given
                // stream by setting WebSocketConfig.accept_unmasked_frames to true
                return Err(Error::Protocol(ProtocolError::UnmaskedFrameFromClient));
            }
        }

        let frame = Frame::from_payload(header, payload.freeze());
        trace!("received frame {frame}");
        Ok(Some(frame))
    }

    /// Read into available `in_buffer` capacity.
    fn read_in(&mut self, stream: &mut impl Read) -> io::Result<usize> {
        let len = self.in_buffer.len();
        debug_assert!(self.in_buffer.capacity() > len);
        self.in_buffer.resize(self.in_buffer.capacity(), 0);
        let size = stream.read(&mut self.in_buffer[len..]);
        self.in_buffer.truncate(len + size.as_ref().copied().unwrap_or(0));
        size
    }

    /// Writes a frame into the `out_buffer`.
    /// If the out buffer size is over the `out_buffer_write_len` will also write
    /// the out buffer into the provided `stream`.
    ///
    /// To ensure buffered frames are written call [`Self::write_out_buffer`].
    ///
    /// May write to the stream, will **not** flush.
    pub(super) fn buffer_frame<Stream>(&mut self, stream: &mut Stream, frame: Frame) -> Result<()>
    where
        Stream: Write,
    {
        if frame.len() + self.out_buffer.len() > self.max_out_buffer_len {
            return Err(Error::WriteBufferFull(Message::Frame(frame)));
        }

        trace!("writing frame {frame}");

        crate::maki_buffer::reserve(&mut self.out_buffer, frame.len());
        frame.format_into_buf(&mut self.out_buffer).expect("Bug: can't write to vector");

        if self.out_buffer.len() > self.out_buffer_write_len {
            self.write_out_buffer(stream)
        } else {
            Ok(())
        }
    }

    /// Writes the out_buffer to the provided stream.
    ///
    /// Does **not** flush.
    pub(super) fn write_out_buffer<Stream>(&mut self, stream: &mut Stream) -> Result<()>
    where
        Stream: Write,
    {
        while !self.out_buffer.is_empty() {
            let len = stream.write(&self.out_buffer)?;
            if len == 0 {
                // This is the same as "Connection reset by peer"
                return Err(IoError::new(
                    IoErrorKind::ConnectionReset,
                    "Connection reset while sending",
                )
                .into());
            }
            crate::maki_buffer::consume(&mut self.out_buffer, len);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::error::{CapacityError, Error};

    use super::{Frame, FrameSocket};

    use std::io::Cursor;

    #[test]
    fn read_frames() {
        env_logger::init();

        let raw = Cursor::new(vec![
            0x82, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x82, 0x03, 0x03, 0x02, 0x01,
            0x99,
        ]);
        let mut sock = FrameSocket::new(raw);

        assert_eq!(
            sock.read(None).unwrap().unwrap().into_payload(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07][..]
        );
        assert_eq!(sock.read(None).unwrap().unwrap().into_payload(), &[0x03, 0x02, 0x01][..]);
        assert!(sock.read(None).unwrap().is_none());

        let (_, rest) = sock.into_inner();
        assert_eq!(rest, vec![0x99]);
    }

    #[test]
    fn from_partially_read() {
        let raw = Cursor::new(vec![0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let mut sock = FrameSocket::from_partially_read(raw, vec![0x82, 0x07, 0x01]);
        assert_eq!(
            sock.read(None).unwrap().unwrap().into_payload(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07][..]
        );
    }

    #[test]
    fn write_frames() {
        let mut sock = FrameSocket::new(Vec::new());

        let frame = Frame::ping(vec![0x04, 0x05]);
        sock.send(frame).unwrap();

        let frame = Frame::pong(vec![0x01]);
        sock.send(frame).unwrap();

        let (buf, _) = sock.into_inner();
        assert_eq!(buf, vec![0x89, 0x02, 0x04, 0x05, 0x8a, 0x01, 0x01]);
    }

    #[test]
    fn parse_overflow() {
        let raw = Cursor::new(vec![
            0x83, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        ]);
        let mut sock = FrameSocket::new(raw);
        let _ = sock.read(None); // should not crash
    }

    #[test]
    fn size_limit_hit() {
        let raw = Cursor::new(vec![0x82, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let mut sock = FrameSocket::new(raw);
        assert!(matches!(
            sock.read(Some(5)),
            Err(Error::Capacity(CapacityError::MessageTooLong { size: 7, max_size: 5 }))
        ));
    }
}

#[cfg(test)]
mod maki_erasure_tests {
    use super::*;
    use crate::protocol::frame::coding::{Data, OpCode};
    use maki_test_allocator::watch;

    struct ShortWrite {
        first: usize,
    }
    impl Write for ShortWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.first == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let count = self.first.min(bytes.len());
            self.first = 0;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn queued() -> FrameCodec {
        let mut codec = FrameCodec::new(0);
        codec.set_out_buffer_write_len(usize::MAX);
        codec
            .buffer_frame(
                &mut io::sink(),
                Frame::message(
                    BytesMut::from(&b"maki websocket secret payload"[..]).freeze(),
                    OpCode::Data(Data::Binary),
                    true,
                ),
            )
            .unwrap();
        codec
    }

    #[test]
    fn maki_outbound_drop_erases_abandoned_payload() {
        let codec = queued();
        let released = watch(codec.out_buffer.as_ptr());
        drop(codec);
        released.assert_zeroized();
    }

    #[test]
    fn maki_outbound_growth_erases_retired_allocation() {
        let mut codec = queued();
        let released = watch(codec.out_buffer.as_ptr());
        let payload = vec![b'x'; codec.out_buffer.capacity() + 1];
        codec
            .buffer_frame(
                &mut io::sink(),
                Frame::message(payload, OpCode::Data(Data::Binary), true),
            )
            .unwrap();
        released.assert_zeroized();
    }

    #[test]
    fn maki_outbound_flush_erases_live_spare_capacity() {
        let mut codec = queued();
        let initialized = codec.out_buffer.len();
        codec.write_out_buffer(&mut io::sink()).unwrap();
        assert!(codec.out_buffer.is_empty());
        // This initializes and examines still-owned storage, never freed memory.
        // Vec::resize writes only newly initialized bytes. The allocator also
        // initialized all capacity, so observing it before resize is defined.
        let bytes = unsafe { std::slice::from_raw_parts(codec.out_buffer.as_ptr(), initialized) };
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn maki_outbound_partial_write_erases_compaction_tail() {
        let mut codec = queued();
        let before = codec.out_buffer.clone();
        let initialized = codec.out_buffer.len();
        assert!(matches!(
            codec.write_out_buffer(&mut ShortWrite { first: 7 }),
            Err(Error::Io(_))
        ));
        assert_eq!(&codec.out_buffer[..], &before[7..]);
        let discarded = unsafe {
            std::slice::from_raw_parts(
                codec.out_buffer.as_ptr().add(codec.out_buffer.len()),
                initialized - codec.out_buffer.len(),
            )
        };
        assert!(discarded.iter().all(|byte| *byte == 0));
        let released = watch(codec.out_buffer.as_ptr());
        drop(codec);
        released.assert_zeroized();
    }

    #[test]
    fn maki_socket_into_inner_erases_queued_output_and_transfers_input() {
        let mut socket = FrameSocket::new(io::sink());
        socket.codec = queued();
        socket
            .codec
            .in_buffer
            .extend_from_slice(b"remaining incoming data");
        let released = watch(socket.codec.out_buffer.as_ptr());
        let (_, incoming) = socket.into_inner();
        assert_eq!(&incoming[..], b"remaining incoming data");
        released.assert_zeroized();
    }

    #[test]
    fn maki_partially_read_transfer_erases_original_vec() {
        let part = b"maki partial frame secret".to_vec();
        let released = watch(part.as_ptr());
        let codec = FrameCodec::from_partially_read(part, 64);
        assert_eq!(&codec.in_buffer[..], b"maki partial frame secret");
        released.assert_zeroized();
    }
}
