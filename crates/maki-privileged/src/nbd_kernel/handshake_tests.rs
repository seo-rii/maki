//! The helper's NBD handshake against scripted servers on a socketpair:
//! the exact bytes it sends, what it accepts, and every way an
//! unprivileged daemon can make it refuse, stall or end early.

use super::handshake::*;

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const SIZE: u64 = 2 * 1024 * 1024;
/// What Maki's plugin advertises on a volume without discard.
const FLAGS: u16 =
    NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA | NBD_FLAG_SEND_WRITE_ZEROES;
/// Long enough for any scripted exchange; a test that expects an early
/// refusal asserts it came well before this.
const PATIENCE: Duration = Duration::from_secs(10);

/// The client's whole side of a handshake with a server that offers
/// `NO_ZEROES` or not: its flags, then `NBD_OPT_GO` for the default export
/// with no information requests.
fn expected_request(no_zeroes: bool) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, if no_zeroes { 3 } else { 1 }];
    bytes.extend_from_slice(b"IHAVEOPT");
    bytes.extend_from_slice(&[0, 0, 0, 7]); // NBD_OPT_GO
    bytes.extend_from_slice(&[0, 0, 0, 6]); // option length
    bytes.extend_from_slice(&[0, 0, 0, 0]); // export name length: the default export
    bytes.extend_from_slice(&[0, 0]); // no information requests
    bytes
}

fn greeting(flags: u16) -> Vec<u8> {
    let mut bytes = b"NBDMAGIC".to_vec();
    bytes.extend_from_slice(b"IHAVEOPT");
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes
}

fn reply(option: u32, kind: u32, data: &[u8]) -> Vec<u8> {
    let mut bytes = REPLY_MAGIC.to_be_bytes().to_vec();
    bytes.extend_from_slice(&option.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

fn info(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut payload = kind.to_be_bytes().to_vec();
    payload.extend_from_slice(data);
    reply(NBD_OPT_GO, NBD_REP_INFO, &payload)
}

fn info_export(size: u64, flags: u16) -> Vec<u8> {
    let mut data = size.to_be_bytes().to_vec();
    data.extend_from_slice(&flags.to_be_bytes());
    info(NBD_INFO_EXPORT, &data)
}

fn ack() -> Vec<u8> {
    reply(NBD_OPT_GO, NBD_REP_ACK, &[])
}

fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// How the scripted server ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Then {
    /// It keeps its end open and reads until the client closes.
    Wait,
    /// It ends its side of the stream after writing (the client still
    /// writes into an open socket) and reads until the client closes.
    End,
}

struct Outcome {
    result: io::Result<Export>,
    /// Everything the client sent, read after it closed its end.
    sent: Vec<u8>,
    elapsed: Duration,
}

/// Write `script` to the client up front (the server does not wait for
/// the client's request: the kernel's socket buffer holds it), then end as
/// `then` says, and negotiate with `deadline` from now. A client that does
/// not return within [`PATIENCE`] beyond its deadline fails the test.
fn exchange(script: Vec<u8>, then: Then, deadline: Duration) -> Outcome {
    let (client, mut server) = UnixStream::pair().unwrap();
    let serving = thread::spawn(move || {
        // A client that stops reading may close while this writes.
        let _ = server.write_all(&script);
        if then == Then::End {
            server.shutdown(std::net::Shutdown::Write).unwrap();
        }
        server.set_read_timeout(Some(PATIENCE * 2)).unwrap();
        let mut sent = Vec::new();
        let _ = server.read_to_end(&mut sent);
        sent
    });
    let (done, finished) = mpsc::channel();
    let started = Instant::now();
    let negotiating = thread::spawn(move || {
        let result = negotiate(&client, Instant::now() + deadline);
        let elapsed = started.elapsed();
        // The client's end closes here, which ends the server's read.
        drop(client);
        let _ = done.send((result, elapsed));
    });
    let (result, elapsed) = finished
        .recv_timeout(deadline + PATIENCE)
        .expect("negotiate did not return by its deadline");
    negotiating.join().unwrap();
    let sent = serving.join().unwrap();
    Outcome {
        result,
        sent,
        elapsed,
    }
}

/// `(SO_RCVTIMEO, SO_SNDTIMEO, O_NONBLOCK)` of a socket.
fn socket_state(stream: &UnixStream) -> (libc::timeval, libc::timeval, bool) {
    let timeout = |option| {
        let mut value = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut length = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        // SAFETY: value and length describe a writable timeval.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut libc::timeval).cast(),
                &mut length,
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        value
    };
    // SAFETY: F_GETFL on an open descriptor.
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    (
        timeout(libc::SO_RCVTIMEO),
        timeout(libc::SO_SNDTIMEO),
        flags & libc::O_NONBLOCK != 0,
    )
}

fn happy(flags: u16) -> Vec<u8> {
    concat(&[greeting(flags), info_export(SIZE, FLAGS), ack()])
}

#[track_caller]
fn refused(outcome: &Outcome, needle: &str) {
    match &outcome.result {
        Err(error) => {
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
            assert!(
                error.to_string().contains(needle),
                "{error:?} does not mention {needle:?}"
            );
            assert!(
                outcome.elapsed < PATIENCE / 2,
                "the refusal took {:?}: the client waited for more",
                outcome.elapsed
            );
        }
        Ok(export) => panic!("accepted {export:?}; expected a refusal naming {needle:?}"),
    }
}

#[test]
fn the_client_sends_its_flags_and_one_go_for_the_default_export_and_nothing_else() {
    let flags = NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES;
    assert_eq!(client_request(flags), expected_request(true));
    let outcome = exchange(happy(flags), Then::Wait, PATIENCE);
    assert_eq!(
        outcome.result.unwrap(),
        Export {
            size: SIZE,
            transmission_flags: FLAGS,
        }
    );
    // No structured replies, extended headers, metadata contexts, TLS or
    // NBD_OPT_EXPORT_NAME, before GO or after the acknowledgement.
    assert_eq!(outcome.sent, expected_request(true));
}

#[test]
fn no_zeroes_is_echoed_only_when_the_server_offers_it() {
    for (server, no_zeroes) in [
        (NBD_FLAG_FIXED_NEWSTYLE, false),
        (NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES, true),
        // Bits the client does not know are never echoed.
        (!NBD_FLAG_NO_ZEROES, false),
        (0xffff, true),
    ] {
        assert_eq!(client_request(server), expected_request(no_zeroes));
        let outcome = exchange(happy(server), Then::Wait, PATIENCE);
        assert!(outcome.result.is_ok(), "{server:#x}: {:?}", outcome.result);
        assert_eq!(outcome.sent, expected_request(no_zeroes), "{server:#x}");
    }
}

#[test]
fn the_transmission_flags_are_returned_exactly_as_the_server_sent_them() {
    for flags in [
        FLAGS,
        REQUIRED_TRANSMISSION_FLAGS,
        FLAGS | NBD_FLAG_SEND_TRIM,
        FLAGS | NBD_FLAG_READ_ONLY | NBD_FLAG_ROTATIONAL | NBD_FLAG_CAN_MULTI_CONN,
        0xffff,
    ] {
        let script = concat(&[
            greeting(NBD_FLAG_FIXED_NEWSTYLE),
            info_export(SIZE, flags),
            ack(),
        ]);
        let outcome = exchange(script, Then::Wait, PATIENCE);
        assert_eq!(outcome.result.unwrap().transmission_flags, flags);
    }
}

#[test]
fn the_negotiated_socket_keeps_no_timeout_or_nonblocking_mode() {
    // The kernel reads and writes this socket after the handshake: a
    // receive timeout left on it would fail the device once it idles.
    let (client, mut server) = UnixStream::pair().unwrap();
    server
        .write_all(&happy(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES))
        .unwrap();
    negotiate(&client, Instant::now() + PATIENCE).unwrap();
    let (receive, send, nonblocking) = socket_state(&client);
    assert_eq!((receive.tv_sec, receive.tv_usec), (0, 0), "SO_RCVTIMEO");
    assert_eq!((send.tv_sec, send.tv_usec), (0, 0), "SO_SNDTIMEO");
    assert!(!nonblocking, "O_NONBLOCK");
}

#[test]
fn information_the_client_did_not_ask_for_is_skipped() {
    let mut block_size = Vec::new();
    for value in [512u32, 4096, 1 << 20] {
        block_size.extend_from_slice(&value.to_be_bytes());
    }
    let script = concat(&[
        greeting(NBD_FLAG_FIXED_NEWSTYLE),
        info(NBD_INFO_NAME, b"volume"),
        info(NBD_INFO_BLOCK_SIZE, &block_size),
        info(NBD_INFO_DESCRIPTION, &[b'd'; 4096]),
        info(0x7777, &[0xa5; 100]),
        info(0x7778, &[]),
        info_export(SIZE, FLAGS),
        info(NBD_INFO_NAME, b""),
        ack(),
    ]);
    let outcome = exchange(script, Then::Wait, PATIENCE);
    assert_eq!(outcome.result.unwrap().size, SIZE);
    assert_eq!(outcome.sent, expected_request(false));
}

#[test]
fn a_server_without_fixed_newstyle_is_refused_before_any_option() {
    for flags in [0, NBD_FLAG_NO_ZEROES, 0xfffe] {
        let outcome = exchange(happy(flags), Then::Wait, PATIENCE);
        refused(&outcome, "fixed-newstyle");
        assert_eq!(outcome.sent, b"", "{flags:#x}");
    }
}

#[test]
fn an_oldstyle_server_or_another_magic_is_refused_before_anything_is_sent() {
    let mut oldstyle = b"NBDMAGIC".to_vec();
    oldstyle.extend_from_slice(&OLDSTYLE_MAGIC.to_be_bytes());
    oldstyle.extend_from_slice(&SIZE.to_be_bytes());
    oldstyle.extend_from_slice(&u32::from(FLAGS).to_be_bytes());
    oldstyle.extend_from_slice(&[0; 124]);
    let outcome = exchange(oldstyle, Then::Wait, PATIENCE);
    refused(&outcome, "oldstyle");
    assert_eq!(outcome.sent, b"");

    for script in [
        concat(&[
            b"NBDMAGIX".to_vec(),
            happy(NBD_FLAG_FIXED_NEWSTYLE)[8..].to_vec(),
        ]),
        concat(&[
            b"NBDMAGIC".to_vec(),
            b"IHAVEOPX".to_vec(),
            NBD_FLAG_FIXED_NEWSTYLE.to_be_bytes().to_vec(),
        ]),
        b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec(),
    ] {
        let outcome = exchange(script, Then::Wait, PATIENCE);
        refused(&outcome, "magic");
        assert_eq!(outcome.sent, b"");
    }
}

#[test]
fn every_error_reply_to_go_is_a_refusal_without_a_fallback() {
    for (kind, name) in [
        (NBD_REP_ERR_UNSUP, "NBD_REP_ERR_UNSUP"),
        (NBD_REP_ERR_POLICY, "NBD_REP_ERR_POLICY"),
        (NBD_REP_ERR_INVALID, "NBD_REP_ERR_INVALID"),
        (NBD_REP_ERR_PLATFORM, "NBD_REP_ERR_PLATFORM"),
        (NBD_REP_ERR_TLS_REQD, "NBD_REP_ERR_TLS_REQD"),
        (NBD_REP_ERR_UNKNOWN, "NBD_REP_ERR_UNKNOWN"),
        (NBD_REP_ERR_SHUTDOWN, "NBD_REP_ERR_SHUTDOWN"),
        (NBD_REP_ERR_BLOCK_SIZE_REQD, "NBD_REP_ERR_BLOCK_SIZE_REQD"),
        (NBD_REP_ERR_TOO_BIG, "NBD_REP_ERR_TOO_BIG"),
        (NBD_REP_ERR_EXT_HEADER_REQD, "NBD_REP_ERR_EXT_HEADER_REQD"),
        (NBD_REP_FLAG_ERROR | 0x7fff, "0x80007fff"),
    ] {
        for message in [&b""[..], b"not this export", &[0xff; 4096]] {
            let script = concat(&[
                greeting(NBD_FLAG_FIXED_NEWSTYLE),
                reply(NBD_OPT_GO, kind, message),
            ]);
            let outcome = exchange(script, Then::Wait, PATIENCE);
            refused(&outcome, name);
            // Neither NBD_OPT_EXPORT_NAME nor another option follows.
            assert_eq!(outcome.sent, expected_request(false), "{name}");
        }
    }
}

#[test]
fn go_must_report_the_export_exactly_once_before_its_acknowledgement() {
    let missing = concat(&[greeting(NBD_FLAG_FIXED_NEWSTYLE), ack()]);
    refused(&exchange(missing, Then::Wait, PATIENCE), "NBD_INFO_EXPORT");

    let only_other_information = concat(&[
        greeting(NBD_FLAG_FIXED_NEWSTYLE),
        info(NBD_INFO_NAME, b"x"),
        ack(),
    ]);
    refused(
        &exchange(only_other_information, Then::Wait, PATIENCE),
        "NBD_INFO_EXPORT",
    );

    for second in [info_export(SIZE, FLAGS), info_export(SIZE * 2, FLAGS)] {
        let repeated = concat(&[
            greeting(NBD_FLAG_FIXED_NEWSTYLE),
            info_export(SIZE, FLAGS),
            second,
            ack(),
        ]);
        refused(&exchange(repeated, Then::Wait, PATIENCE), "more than once");
    }

    for length in [0, 1, 9, 11, 13, 4096] {
        let malformed = concat(&[
            greeting(NBD_FLAG_FIXED_NEWSTYLE),
            info(NBD_INFO_EXPORT, &vec![0x11; length]),
            ack(),
        ]);
        refused(
            &exchange(malformed, Then::Wait, PATIENCE),
            "NBD_INFO_EXPORT",
        );
    }
}

#[test]
fn a_reply_of_another_shape_is_refused() {
    let base = || greeting(NBD_FLAG_FIXED_NEWSTYLE);
    for (script, needle) in [
        // A reply type GO never produces.
        (
            concat(&[base(), reply(NBD_OPT_GO, NBD_REP_SERVER, b"\0\0\0\0")]),
            "reply type",
        ),
        (
            concat(&[base(), reply(NBD_OPT_GO, 0x55, &[])]),
            "reply type",
        ),
        // A reply to an option the client never sent.
        (concat(&[base(), reply(1, NBD_REP_ACK, &[])]), "option"),
        (concat(&[base(), reply(8, NBD_REP_ACK, &[])]), "option"),
        // An acknowledgement that carries data.
        (
            concat(&[
                base(),
                info_export(SIZE, FLAGS),
                reply(NBD_OPT_GO, NBD_REP_ACK, b"x"),
            ]),
            "acknowledgement",
        ),
        // An information reply too short for its type.
        (
            concat(&[base(), reply(NBD_OPT_GO, NBD_REP_INFO, b"\0")]),
            "information",
        ),
        // Another magic.
        (
            concat(&[base(), {
                let mut bad = ack();
                bad[7] ^= 1;
                bad
            }]),
            "magic",
        ),
    ] {
        refused(&exchange(script, Then::Wait, PATIENCE), needle);
    }
}

#[test]
fn a_reply_longer_than_the_cap_is_refused_before_any_of_it_is_read() {
    for length in [MAX_REPLY_LENGTH + 1, u32::MAX] {
        // Only the header: a client that tried to read the payload would
        // wait for bytes that never come.
        let mut header = reply(NBD_OPT_GO, NBD_REP_INFO, &[]);
        header[16..20].copy_from_slice(&length.to_be_bytes());
        let script = concat(&[greeting(NBD_FLAG_FIXED_NEWSTYLE), header]);
        refused(&exchange(script, Then::Wait, PATIENCE), "longer than");
    }
    // The cap itself is read and skipped.
    let script = concat(&[
        greeting(NBD_FLAG_FIXED_NEWSTYLE),
        info(
            NBD_INFO_DESCRIPTION,
            &vec![b'x'; MAX_REPLY_LENGTH as usize - 2],
        ),
        info_export(SIZE, FLAGS),
        ack(),
    ]);
    assert!(exchange(script, Then::Wait, PATIENCE).result.is_ok());
    // Error messages too.
    let script = concat(&[
        greeting(NBD_FLAG_FIXED_NEWSTYLE),
        reply(
            NBD_OPT_GO,
            NBD_REP_ERR_POLICY,
            &vec![b'x'; MAX_REPLY_LENGTH as usize + 1],
        ),
    ]);
    refused(&exchange(script, Then::Wait, PATIENCE), "longer than");
}

#[test]
fn the_whole_handshake_has_a_byte_limit() {
    // Each reply is within the cap; together they are not, and a valid
    // export and acknowledgement follow.
    let per_reply = 20 + MAX_REPLY_LENGTH as usize;
    let replies = MAX_HANDSHAKE_BYTES / per_reply + 1;
    let mut parts = vec![greeting(NBD_FLAG_FIXED_NEWSTYLE)];
    for _ in 0..replies {
        parts.push(info(
            NBD_INFO_NAME,
            &vec![b'n'; MAX_REPLY_LENGTH as usize - 2],
        ));
    }
    parts.push(info_export(SIZE, FLAGS));
    parts.push(ack());
    refused(
        &exchange(concat(&parts), Then::Wait, PATIENCE),
        "byte limit",
    );

    // Just below the limit everything is read.
    let mut parts = vec![greeting(NBD_FLAG_FIXED_NEWSTYLE)];
    let fixed = 18 + (20 + 12) + 20;
    for _ in 0..(MAX_HANDSHAKE_BYTES - fixed) / per_reply {
        parts.push(info(
            NBD_INFO_NAME,
            &vec![b'n'; MAX_REPLY_LENGTH as usize - 2],
        ));
    }
    parts.push(info_export(SIZE, FLAGS));
    parts.push(ack());
    assert!(concat(&parts).len() <= MAX_HANDSHAKE_BYTES);
    assert!(exchange(concat(&parts), Then::Wait, PATIENCE)
        .result
        .is_ok());
}

#[test]
fn a_stream_that_ends_early_is_an_unexpected_end() {
    let full = happy(NBD_FLAG_FIXED_NEWSTYLE);
    // Cut inside the greeting, the export reply's header and data, and
    // the acknowledgement, and right after the greeting.
    for cut in [0, 7, 12, 17, 18, 18 + 10, 18 + 20 + 5, full.len() - 1] {
        let outcome = exchange(full[..cut].to_vec(), Then::End, PATIENCE);
        match outcome.result {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{cut}: {error}"),
            Ok(export) => panic!("{cut}: accepted {export:?}"),
        }
    }
}

#[test]
fn a_server_that_stalls_is_left_at_the_deadline() {
    let deadline = Duration::from_millis(200);
    let full = happy(NBD_FLAG_FIXED_NEWSTYLE);
    for stall in [0, 10, 18, 18 + 20, full.len() - 1] {
        let outcome = exchange(full[..stall].to_vec(), Then::Wait, deadline);
        match outcome.result {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{stall}: {error}"),
            Ok(export) => panic!("{stall}: accepted {export:?}"),
        }
        assert!(
            outcome.elapsed >= deadline && outcome.elapsed < deadline + Duration::from_secs(2),
            "{stall}: returned after {:?}",
            outcome.elapsed
        );
    }
    // A deadline that has passed already ends the handshake before it reads.
    let outcome = exchange(full, Then::Wait, Duration::ZERO);
    assert_eq!(outcome.result.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[test]
fn an_export_without_flush_fua_or_flags_is_refused() {
    for (flags, needle) in [
        (FLAGS & !NBD_FLAG_SEND_FUA, "NBD_FLAG_SEND_FUA"),
        (FLAGS & !NBD_FLAG_SEND_FLUSH, "NBD_FLAG_SEND_FLUSH"),
        (FLAGS & !NBD_FLAG_HAS_FLAGS, "NBD_FLAG_HAS_FLAGS"),
        (NBD_FLAG_HAS_FLAGS, "NBD_FLAG_SEND_FLUSH"),
        (0, "NBD_FLAG_HAS_FLAGS"),
        (!NBD_FLAG_SEND_FUA, "NBD_FLAG_SEND_FUA"),
    ] {
        let script = concat(&[
            greeting(NBD_FLAG_FIXED_NEWSTYLE),
            info_export(SIZE, flags),
            ack(),
        ]);
        refused(&exchange(script, Then::Wait, PATIENCE), needle);
    }
}

#[test]
fn an_export_of_size_zero_or_beyond_the_kernels_range_is_refused() {
    for size in [0, MAX_EXPORT_SIZE + 1, u64::MAX] {
        let script = concat(&[
            greeting(NBD_FLAG_FIXED_NEWSTYLE),
            info_export(size, FLAGS),
            ack(),
        ]);
        refused(&exchange(script, Then::Wait, PATIENCE), "size");
    }
    for size in [1, 512, MAX_EXPORT_SIZE] {
        let script = concat(&[
            greeting(NBD_FLAG_FIXED_NEWSTYLE),
            info_export(size, FLAGS),
            ack(),
        ]);
        assert_eq!(
            exchange(script, Then::Wait, PATIENCE).result.unwrap().size,
            size
        );
    }
}
