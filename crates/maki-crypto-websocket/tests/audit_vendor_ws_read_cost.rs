//! Audit (vendor-erasure): the patched tungstenite `FrameCodec::read_in`
//! resizes `in_buffer` to its full capacity before every read and truncates
//! it afterwards. With the patched `bytes`, `BytesMut::truncate` wipes the
//! whole unused tail with byte-wise volatile writes, so every short read of a
//! large frame pays a full-capacity erasure. Reading one frame of N bytes in
//! fixed-size chunks therefore costs O(N^2 / chunk) volatile writes.
//!
//! This test reads a single unmasked server->client binary frame through the
//! real (vendored) tungstenite WebSocket reader, with a transport that hands
//! out at most `CHUNK` bytes per `read()` (the size of one TLS record), and
//! prints how the read time scales with the frame size.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use tokio_tungstenite::tungstenite::protocol::{Role, WebSocket, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;

const CHUNK: usize = 16 * 1024;

struct ChunkedPeer {
    data: Vec<u8>,
    pos: usize,
}

impl Read for ChunkedPeer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(CHUNK).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for ChunkedPeer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn server_binary_frame(len: usize) -> Vec<u8> {
    let mut wire = vec![0x82, 127];
    wire.extend_from_slice(&(len as u64).to_be_bytes());
    wire.extend(std::iter::repeat(0x5a).take(len));
    wire
}

fn read_one(len: usize) -> Duration {
    let peer = ChunkedPeer {
        data: server_binary_frame(len),
        pos: 0,
    };
    let config = WebSocketConfig::default()
        .max_message_size(Some(64 << 20))
        .max_frame_size(Some(64 << 20));
    let mut socket = WebSocket::from_raw_socket(peer, Role::Client, Some(config));
    let start = Instant::now();
    let message = socket.read().expect("frame");
    let elapsed = start.elapsed();
    match message {
        Message::Binary(payload) => assert_eq!(payload.len(), len),
        other => panic!("unexpected message {other:?}"),
    }
    elapsed
}

#[test]
fn audit_large_frame_read_cost_scales_quadratically() {
    // Warm up allocator / page faults.
    let _ = read_one(256 * 1024);
    let small = 1 << 20;
    let large = 4 << 20;
    let t_small = read_one(small);
    let t_large = read_one(large);
    let ratio = t_large.as_secs_f64() / t_small.as_secs_f64();
    let reads_large = large / CHUNK;
    eprintln!(
        "frame {small} B: {t_small:?}; frame {large} B: {t_large:?}; \
         4x size -> {ratio:.1}x time ({reads_large} reads of <= {CHUNK} B)"
    );
    // A linear reader would take ~4x as long for 4x the data. The full-
    // capacity resize+wipe on every read makes it grow much faster.
    assert!(
        ratio > 8.0,
        "expected super-linear (quadratic) scaling, got {ratio:.1}x"
    );
}
