//! Receiving WebSocket data must cost work proportional to the bytes received,
//! not to the read buffer's spare capacity.
//!
//! The pinned tungstenite frame reader used to zero-fill its whole spare
//! capacity before every `read` and wipe it again afterwards. One large frame
//! leaves a multi-MiB capacity behind, so every later read on that connection,
//! even of a six-byte frame, rewrote megabytes; accumulating one large frame
//! in TLS-record-sized reads was quadratic in its size.
//!
//! The assertions count pages, not time. The peer stream discards (with
//! `MADV_DONTNEED`) the page-aligned spare capacity it was handed beyond what
//! it wrote, which for anonymous memory is equivalent to writing zeros into
//! its own output buffer. Any later store by the reader into those pages takes
//! a minor fault on this thread, so the thread's fault count bounds how much
//! of the spare capacity each read touched.
#![cfg(target_os = "linux")]

use std::collections::VecDeque;
use std::ffi::{c_int, c_void};
use std::io::{self, Read, Write};

use tokio_tungstenite::tungstenite::protocol::{Role, WebSocket, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Bytes, Message};

extern "C" {
    fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int;
}

const MADV_DONTNEED: c_int = 4;
const MADV_NOHUGEPAGE: c_int = 15;
/// A multiple of every Linux base page size, so aligned ranges are valid for
/// `madvise` whatever the kernel's page size is.
const ALIGN: usize = 64 * 1024;
/// Bytes after the written data that are left resident, so the next reads'
/// data lands in pages this stream has not discarded.
const MARGIN: usize = 64 * 1024;
/// The smallest page size, used to turn byte counts into a fault bound. A
/// kernel with larger pages takes fewer faults for the same work.
const SMALL_PAGE: usize = 4096;
/// One TLS record's worth of plaintext per read.
const RECORD: usize = 16 * 1024;

/// A peer that returns at most one queued segment per `read` and discards the
/// page-aligned spare capacity of the buffer it was handed.
struct DiscardingPeer {
    segments: VecDeque<Vec<u8>>,
    largest_buffer: usize,
}

impl DiscardingPeer {
    fn new(segments: VecDeque<Vec<u8>>) -> Self {
        Self {
            segments,
            largest_buffer: 0,
        }
    }
}

impl Read for DiscardingPeer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.largest_buffer = self.largest_buffer.max(buf.len());
        let Some(front) = self.segments.front_mut() else {
            return Ok(0);
        };
        let n = buf.len().min(front.len());
        buf[..n].copy_from_slice(&front[..n]);
        front.drain(..n);
        if front.is_empty() {
            self.segments.pop_front();
        }
        let base = buf.as_mut_ptr() as usize;
        let start = (base + n + MARGIN).next_multiple_of(ALIGN);
        let end = (base + buf.len()) / ALIGN * ALIGN;
        if start < end {
            // SAFETY: [start, end) lies inside `buf`, which this call may
            // overwrite; discarding anonymous pages makes them read as zeros.
            unsafe {
                let addr = start as *mut c_void;
                assert_eq!(madvise(addr, end - start, MADV_NOHUGEPAGE), 0);
                assert_eq!(madvise(addr, end - start, MADV_DONTNEED), 0);
            }
        }
        Ok(n)
    }
}

impl Write for DiscardingPeer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Minor page faults taken by the calling thread.
fn minor_faults() -> u64 {
    let stat = std::fs::read_to_string("/proc/thread-self/stat").expect("thread stat");
    // Fields after the parenthesised command name: state, ppid, pgrp, session,
    // tty_nr, tpgid, flags, minflt.
    let fields = &stat[stat.rfind(')').expect("command name") + 1..];
    fields
        .split_whitespace()
        .nth(7)
        .expect("minflt")
        .parse()
        .expect("minflt value")
}

fn server_binary_frame(payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x82, 127];
    wire.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

fn client(segments: VecDeque<Vec<u8>>) -> WebSocket<DiscardingPeer> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(64 << 20))
        .max_frame_size(Some(64 << 20));
    WebSocket::from_raw_socket(DiscardingPeer::new(segments), Role::Client, Some(config))
}

fn read_binary(socket: &mut WebSocket<DiscardingPeer>) -> Bytes {
    match socket.read().expect("frame") {
        Message::Binary(payload) => payload,
        other => panic!("unexpected message {other:?}"),
    }
}

#[test]
fn small_reads_after_a_large_frame_do_not_touch_its_retained_capacity() {
    const LARGE: usize = 4 << 20;
    const SMALL_FRAMES: u64 = 16;
    let large = vec![0x5a; LARGE];
    let wire = server_binary_frame(&large);
    // Two record-sized reads make the reader grow its buffer twice for the
    // announced frame length, as on a TLS connection; the remainder arrives in
    // one read to keep the setup short.
    let mut segments = VecDeque::from([
        wire[..RECORD].to_vec(),
        wire[RECORD..2 * RECORD].to_vec(),
        wire[2 * RECORD..].to_vec(),
    ]);
    for index in 0..SMALL_FRAMES {
        segments.push_back(vec![0x82, 4, b'p', b'i', b'n', index as u8]);
    }
    let mut socket = client(segments);
    assert!(read_binary(&mut socket) == large);

    socket.get_mut().largest_buffer = 0;
    let before = minor_faults();
    for index in 0..SMALL_FRAMES {
        assert_eq!(
            read_binary(&mut socket),
            &[b'p', b'i', b'n', index as u8][..]
        );
    }
    let faults = minor_faults() - before;
    let retained = socket.get_ref().largest_buffer;
    // The scenario: every small read is offered the large frame's capacity.
    assert!(retained >= LARGE / 2, "retained read capacity {retained} B");
    // Rewriting the retained capacity costs about `retained / 4096` faults per
    // read; receiving six bytes needs at most a few.
    assert!(
        faults < SMALL_FRAMES * 16,
        "{SMALL_FRAMES} six-byte reads with {retained} B of spare capacity took {faults} page faults"
    );
}

#[test]
fn accumulating_a_large_frame_is_linear_in_its_size() {
    const LARGE: usize = 1 << 20;
    let large = vec![0xa5; LARGE];
    let segments = server_binary_frame(&large)
        .chunks(RECORD)
        .map(<[u8]>::to_vec)
        .collect();
    let mut socket = client(segments);

    let before = minor_faults();
    let payload = read_binary(&mut socket);
    let faults = minor_faults() - before;
    assert!(payload == large);
    // Initializing each new allocation once and writing the received data is
    // linear in the frame size; the buffer's capacity doubles while the frame
    // accumulates, so this takes about four units. Rewriting the spare
    // capacity on each of the `LARGE / RECORD` reads takes about
    // `1.5 * LARGE / RECORD` (here 96) units.
    let linear = (LARGE / SMALL_PAGE) as u64;
    assert!(
        faults < 16 * linear,
        "a {LARGE} B frame in {RECORD} B reads took {faults} page faults (linear unit {linear})"
    );
}
