//! Round-2 audit: wire behaviour of the patched hyper HTTP/1 chunked decoder
//! (vendor/hyper/src/proto/h1/decode.rs) through the public client API.
//!
//! Every response is written by a raw TCP server; the client is
//! `hyper::client::conn::http1`. Assertions state RFC 9112 / upstream hyper
//! behaviour; `report` lines record behaviour that is only printed.
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::Body as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct Io(tokio::net::TcpStream);

impl hyper::rt::Read for Io {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut tmp = vec![0u8; buf.remaining().min(64 * 1024)];
        let mut read = tokio::io::ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.get_mut().0).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                buf.put_slice(read.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl hyper::rt::Write for Io {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Body(Vec<u8>, Vec<(String, String)>),
    /// Error with `true` when a typed hyper parse error is in the chain.
    Error(bool, String),
}

fn has_parse(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(current) = cause {
        if current
            .downcast_ref::<hyper::Error>()
            .is_some_and(hyper::Error::is_parse)
        {
            return true;
        }
        if let Some(io) = current.downcast_ref::<io::Error>() {
            if let Some(inner) = io.get_ref() {
                if has_parse(inner) {
                    return true;
                }
            }
        }
        cause = current.source();
    }
    false
}

/// Serve one response whose body bytes are written in `pieces` (each flushed).
async fn fetch(pieces: Vec<Vec<u8>>) -> Outcome {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buffer).await.unwrap();
            if n == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..n]);
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        for piece in pieces {
            if socket.write_all(&piece).await.is_err() {
                return;
            }
            let _ = socket.flush().await;
        }
        let _ = socket.shutdown().await;
    });
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake::<_, String>(Io(stream))
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let request = hyper::Request::get("/")
        .header("host", "audit.invalid")
        .body(String::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let mut body = response.into_body();
    let mut data = Vec::new();
    let mut trailers = Vec::new();
    let outcome = loop {
        match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            None => break Outcome::Body(data, trailers),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(chunk) => data.extend_from_slice(&chunk),
                Err(frame) => {
                    let map = frame.into_trailers().ok().unwrap();
                    for (name, value) in map.iter() {
                        trailers.push((
                            name.as_str().to_owned(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        ));
                    }
                }
            },
            Some(Err(error)) => break Outcome::Error(has_parse(&error), error.to_string()),
        }
    };
    connection.abort();
    server.abort();
    outcome
}

fn whole(body: &[u8]) -> Vec<Vec<u8>> {
    vec![body.to_vec()]
}

fn bytewise(body: &[u8]) -> Vec<Vec<u8>> {
    body.iter().map(|b| vec![*b]).collect()
}

fn ok(data: &[u8]) -> Outcome {
    Outcome::Body(data.to_vec(), Vec::new())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit2_chunked_decoder_accepts_rfc_framing_edge_cases() {
    let big = vec![b'z'; 300_000];
    let mut big_wire = format!("{:x}\r\n", big.len()).into_bytes();
    big_wire.extend_from_slice(&big);
    big_wire.extend_from_slice(b"\r\n0\r\n\r\n");
    let max_ext = format!("1;{}\r\nx\r\n0\r\n\r\n", "e".repeat(16 * 1024 - 2));
    let cases: Vec<(&str, Vec<u8>, Outcome)> = vec![
        ("simple", b"5\r\nhello\r\n0\r\n\r\n".to_vec(), ok(b"hello")),
        ("leading zeros", b"0005\r\nhello\r\n0000\r\n\r\n".to_vec(), ok(b"hello")),
        ("upper hex", b"A\r\n0123456789\r\n0\r\n\r\n".to_vec(), ok(b"0123456789")),
        ("lower hex", b"a\r\n0123456789\r\n0\r\n\r\n".to_vec(), ok(b"0123456789")),
        (
            "extensions",
            b"5;name=value;flag\r\nhello\r\n0;last=\"q\"\r\n\r\n".to_vec(),
            ok(b"hello"),
        ),
        ("bws before CRLF", b"5 \t \r\nhello\r\n0\r\n\r\n".to_vec(), ok(b"hello")),
        ("bws before ext", b"5 ;e\r\nhello\r\n0\r\n\r\n".to_vec(), ok(b"hello")),
        ("many chunks", b"1\r\na\r\n2\r\nbc\r\n3\r\ndef\r\n0\r\n\r\n".to_vec(), ok(b"abcdef")),
        ("16 KiB-1 of extensions", max_ext.into_bytes(), ok(b"x")),
        ("300 kB chunk", big_wire, ok(&big)),
        ("empty body", b"0\r\n\r\n".to_vec(), ok(b"")),
        (
            "trailers",
            b"3\r\nabc\r\n0\r\nx-a: 1\r\nx-b: two words\r\n\r\n".to_vec(),
            Outcome::Body(
                b"abc".to_vec(),
                vec![("x-a".into(), "1".into()), ("x-b".into(), "two words".into())],
            ),
        ),
    ];
    for (label, wire, expected) in cases {
        for (mode, pieces) in [("whole", whole(&wire)), ("bytewise", bytewise(&wire))] {
            if mode == "bytewise" && wire.len() > 20_000 {
                continue;
            }
            let outcome = fetch(pieces).await;
            assert_eq!(outcome, expected, "{label} ({mode})");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit2_chunked_decoder_rejects_malformed_framing_with_parse_provenance() {
    let over_ext = format!("1;{}\r\nx\r\n0\r\n\r\n", "e".repeat(16 * 1024));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("missing size", b"\r\nhello\r\n0\r\n\r\n".to_vec()),
        ("non-hex size", b"5g\r\nhello\r\n0\r\n\r\n".to_vec()),
        ("digit after bws", b"5 5\r\nhello\r\n0\r\n\r\n".to_vec()),
        ("bare LF after size", b"5\nhello\r\n0\r\n\r\n".to_vec()),
        ("LF in extension", b"5;a\nhello\r\n0\r\n\r\n".to_vec()),
        ("CR without LF in extension", b"5;a\rb\r\nhello\r\n0\r\n\r\n".to_vec()),
        ("data longer than size", b"5\r\nhelloX\r\n0\r\n\r\n".to_vec()),
        ("bare LF after data", b"5\r\nhello\n0\r\n\r\n".to_vec()),
        ("size overflow", b"10000000000000000\r\n".to_vec()),
        ("16 KiB of extensions", over_ext.into_bytes()),
        ("trailer without colon", b"0\r\nbroken trailer\r\n\r\n".to_vec()),
        ("CR CR after last chunk", b"0\r\n\r\r".to_vec()),
        ("trailer CR without LF", b"0\r\nx-a: 1\rX\r\n\r\n".to_vec()),
    ];
    for (label, wire) in cases {
        for (mode, pieces) in [("whole", whole(&wire)), ("bytewise", bytewise(&wire))] {
            if mode == "bytewise" && wire.len() > 20_000 {
                continue;
            }
            match fetch(pieces).await {
                Outcome::Error(parse, message) => {
                    assert!(parse, "{label} ({mode}): no parse provenance: {message}")
                }
                other => panic!("{label} ({mode}): accepted malformed framing: {other:?}"),
            }
        }
    }
    // Truncation is an incomplete body, never a peer parse failure.
    for (label, wire) in [
        ("eof in size", b"5".to_vec()),
        ("eof in data", b"5\r\nhel".to_vec()),
        ("eof after data", b"5\r\nhello".to_vec()),
        ("eof before last CRLF", b"0\r\n".to_vec()),
        ("huge size then eof", b"ffffffffffffffff\r\nabc".to_vec()),
    ] {
        match fetch(whole(&wire)).await {
            Outcome::Error(parse, message) => {
                assert!(!parse, "{label}: truncation classified as parse error: {message}")
            }
            other => panic!("{label}: accepted truncated body: {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit2_chunked_trailer_limits_report() {
    // Duplicate trailer names and the default 100-trailer bound: print the
    // behaviour so a reviewer can compare it with the upstream release.
    let duplicate = fetch(whole(b"0\r\nx-a: 1\r\nx-a: 2\r\n\r\n")).await;
    println!("report: duplicate trailer names -> {duplicate:?}");
    for count in [99usize, 100, 101] {
        let mut wire = b"0\r\n".to_vec();
        for i in 0..count {
            wire.extend_from_slice(format!("x-{i}: v\r\n").as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        let outcome = match fetch(whole(&wire)).await {
            Outcome::Body(_, trailers) => format!("accepted {} trailers", trailers.len()),
            Outcome::Error(parse, message) => format!("error parse={parse}: {message}"),
        };
        println!("report: {count} trailers -> {outcome}");
    }
    let _ = Bytes::new();
}
