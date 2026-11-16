//! Audit (vendor-erasure): behaviour of the vendored `bytes` 1.12.1 erasure
//! patch as seen by a workspace consumer.

use std::time::Instant;

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Upstream tungstenite's `FrameCodec::read_in` pattern: grow `len` to the
/// full capacity with zeros, read into the tail, truncate back. Upstream
/// `BytesMut::truncate` is `set_len`; the patched one wipes the whole unused
/// tail with volatile byte stores, on every read.
fn read_in_pattern(frame: usize, chunk: usize, patched_truncate: bool) -> std::time::Duration {
    let mut buf = BytesMut::with_capacity(frame + 128 * 1024);
    let data = vec![0x5au8; chunk];
    let start = Instant::now();
    while buf.len() < frame {
        let len = buf.len();
        let cap = buf.capacity();
        buf.resize(cap, 0);
        let n = chunk.min(frame - len);
        buf[len..len + n].copy_from_slice(&data[..n]);
        if patched_truncate {
            buf.truncate(len + n);
        } else {
            // What upstream truncate does: shrink the length only.
            unsafe { buf.set_len(len + n) };
        }
    }
    start.elapsed()
}

#[test]
fn audit_truncate_wipe_dominates_tungstenite_read_in_pattern() {
    let frame = 2 << 20;
    let chunk = 16 * 1024;
    let upstream_like = read_in_pattern(frame, chunk, false);
    let patched = read_in_pattern(frame, chunk, true);
    eprintln!(
        "read_in pattern, {frame} B frame in {chunk} B reads: resize+set_len {upstream_like:?}, \
         resize+patched truncate {patched:?} ({:.1}x)",
        patched.as_secs_f64() / upstream_like.as_secs_f64()
    );
    assert!(patched > upstream_like * 4);
}

/// Sanity of sharing semantics after the patch: discarding one handle must not
/// corrupt bytes visible through another.
#[test]
fn audit_sharing_semantics_preserved() {
    // split_to + freeze: the frozen prefix survives the mutable owner's drop,
    // advance and growth.
    let mut m = BytesMut::with_capacity(64);
    m.extend_from_slice(b"prefix-data|tail-data");
    let head = m.split_to(12).freeze();
    let alias = head.slice(2..6);
    m.advance(5);
    m.reserve(4096);
    m.extend_from_slice(b"more");
    drop(m);
    assert_eq!(&head[..], b"prefix-data|");
    assert_eq!(&alias[..], b"efix");

    // split_off with at > len: both handles write their own capacity.
    let mut a = BytesMut::with_capacity(32);
    a.extend_from_slice(b"abc");
    let mut b = a.split_off(16);
    b.extend_from_slice(b"xyz");
    a.extend_from_slice(b"def");
    let frozen_b = b.freeze();
    drop(a);
    assert_eq!(&frozen_b[..], b"xyz");

    // try_into_mut on a unique slice keeps exactly the visible bytes.
    let original = Bytes::from(b"0123456789".to_vec());
    let mut sliced = original.slice(3..7);
    drop(original);
    assert!(sliced.is_unique());
    let mut sliced_mut = std::mem::take(&mut sliced).try_into_mut().unwrap();
    assert_eq!(&sliced_mut[..], b"3456");
    sliced_mut.put_slice(b"!");
    assert_eq!(&sliced_mut[..], b"3456!");

    // Static bytes are never written.
    let s = Bytes::from_static(b"static");
    let c = s.clone();
    drop(s);
    assert_eq!(&c[..], b"static");
    let m = BytesMut::from(c);
    assert_eq!(&m[..], b"static");

    // Vec round trip of a frozen, advanced, unique buffer.
    let mut f = BytesMut::from(&b"hello world"[..]).freeze();
    f.advance(6);
    assert_eq!(Vec::from(f), b"world".to_vec());

    // unsplit of contiguous halves keeps all data.
    let mut whole = BytesMut::with_capacity(64);
    whole.extend_from_slice(b"aaaabbbb");
    let second = whole.split_off(4);
    whole.unsplit(second);
    assert_eq!(&whole[..], b"aaaabbbb");
}

/// The hyper/tungstenite read-buffer pattern: frames are `split_to(n).freeze()`
/// views of a long-lived read buffer. After the consumer drops every frame,
/// the read buffer becomes unique again, but a `reserve` that fits the
/// remaining capacity (tungstenite's `reserve(6)`) is a no-op and leaves the
/// discarded frame's bytes in the allocation: they are erased only on a later
/// copying reclaim or on the read buffer's final release (connection drop).
#[test]
fn audit_dropped_frame_bytes_remain_in_live_read_buffer() {
    let mut read_buf = BytesMut::with_capacity(8192);
    read_buf.extend_from_slice(b"SECRET-RESPONSE-BODY");
    let base = read_buf.as_ptr();
    let frame = read_buf.split_to(20).freeze();
    drop(frame); // consumer copied it into guarded storage and released it
    // Next read on the same (pooled) connection reserves a little more space.
    read_buf.reserve(16);
    assert_eq!(read_buf.as_ptr(), unsafe { base.add(20) });
    // The allocation is still owned by read_buf and was fully initialised by
    // the writes above, so reading the discarded prefix is defined.
    let stale = unsafe { std::slice::from_raw_parts(base, 20) };
    eprintln!("stale prefix after frame release: {:?}", String::from_utf8_lossy(stale));
    assert_eq!(stale, b"SECRET-RESPONSE-BODY");
}
