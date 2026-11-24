//! Seeded property tests of the two parsers that read what root does not
//! control: the handshake, whose bytes an unprivileged daemon sends, and the
//! netlink answer. Whatever arrives, neither panics nor reads past its
//! limits, and only the shapes SPEC §6 names are accepted. The socket is
//! also run against the kernel's own generic netlink controller, which
//! every kernel has.

use super::handshake::{
    negotiate, Export, IHAVEOPT, MAX_HANDSHAKE_BYTES, NBDMAGIC, NBD_FLAG_FIXED_NEWSTYLE,
    NBD_FLAG_NO_ZEROES, NBD_INFO_EXPORT, NBD_OPT_GO, NBD_REP_ACK, NBD_REP_INFO, REPLY_MAGIC,
    REQUIRED_TRANSMISSION_FLAGS,
};
use super::netlink::{
    self, Answer, Received, Socket, Unacknowledged, CTRL_CMD_GETFAMILY, GENL_ID_CTRL, NLMSG_ERROR,
    NLM_F_ACK, NLM_F_REQUEST,
};

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// xorshift64*: reproducible noise.
struct Noise(u64);

impl Noise {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next() as u8).collect()
    }

    /// Fewer than `bound` bytes.
    fn some(&mut self, bound: usize) -> Vec<u8> {
        let length = self.below(bound);
        self.bytes(length)
    }
}

fn reply(kind: u32, data: &[u8]) -> Vec<u8> {
    let mut bytes = REPLY_MAGIC.to_be_bytes().to_vec();
    bytes.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

/// A handshake a server could send: the greeting, an information reply the
/// client did not ask for, the export and the acknowledgement.
fn transcript(size: u64, flags: u16) -> Vec<u8> {
    let mut export = NBD_INFO_EXPORT.to_be_bytes().to_vec();
    export.extend_from_slice(&size.to_be_bytes());
    export.extend_from_slice(&flags.to_be_bytes());
    let mut bytes = NBDMAGIC.to_be_bytes().to_vec();
    bytes.extend_from_slice(&IHAVEOPT.to_be_bytes());
    bytes.extend_from_slice(&(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES).to_be_bytes());
    bytes.extend(reply(
        NBD_REP_INFO,
        &[0, 3, 0, 0, 2, 0, 0, 0, 16, 0, 2, 0, 0, 0],
    ));
    bytes.extend(reply(NBD_REP_INFO, &export));
    bytes.extend(reply(NBD_REP_ACK, &[]));
    bytes
}

/// The greeting's length: two magics and the handshake flags.
const GREETING: usize = 18;

/// Run the client against a server that writes `chunks`, pausing `gap`
/// between them, and never reads. Returns the client's result and how many
/// of the server's bytes the client consumed.
fn against(chunks: Vec<Vec<u8>>, gap: Duration) -> (std::io::Result<Export>, usize) {
    let total: usize = chunks.iter().map(Vec::len).sum();
    let (client, mut server) = UnixStream::pair().unwrap();
    let writer = std::thread::spawn(move || {
        for chunk in chunks {
            if server.write_all(&chunk).is_err() {
                return;
            }
            if !gap.is_zero() {
                std::thread::sleep(gap);
            }
        }
        let _ = server.shutdown(std::net::Shutdown::Write);
        // Keep the socket until the client is done with it.
        let mut sink = [0; 256];
        while matches!(server.read(&mut sink), Ok(count) if count > 0) {}
    });
    let result = negotiate(&client, Instant::now() + Duration::from_secs(30));
    // What the client left unread belongs to whoever uses the socket next,
    // the kernel: count it.
    let mut left = 0;
    let mut reader = &client;
    let mut buffer = [0; 65536];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => left += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    drop(client);
    writer.join().unwrap();
    (result, total - left)
}

/// Whatever a server sends, the client returns, reads no more than its byte
/// limit, and accepts only an export the kernel may use.
#[test]
fn a_handshake_of_any_bytes_stays_within_its_limits() {
    let valid = transcript(1 << 30, REQUIRED_TRANSMISSION_FLAGS | 0x20);
    let mut noise = Noise(0x8a5c_d789_635d_2dff);
    let (mut accepted, mut most) = (0, 0);
    for round in 0..1500 {
        let mut bytes = match round % 5 {
            // Noise, sometimes far beyond the limit.
            0 if round % 50 == 0 => noise.bytes(200_000),
            0 => noise.some(600),
            // A valid greeting, then noise.
            1 => [valid[..GREETING].to_vec(), noise.some(400)].concat(),
            // A valid greeting, then many information replies to skip.
            2 => {
                let mut bytes = valid[..GREETING].to_vec();
                for _ in 0..noise.below(4000) {
                    let mut data = vec![0, 1];
                    data.extend(noise.some(40));
                    bytes.extend(reply(NBD_REP_INFO, &data));
                }
                bytes.extend_from_slice(&valid[GREETING..]);
                bytes
            }
            // The valid transcript with a few bytes changed.
            3 => {
                let mut bytes = valid.clone();
                for _ in 0..1 + noise.below(3) {
                    let at = noise.below(bytes.len());
                    bytes[at] = noise.next() as u8;
                }
                bytes
            }
            // The valid transcript cut short, or with a tail.
            _ => {
                let mut bytes = valid.clone();
                if noise.below(2) == 0 {
                    bytes.truncate(noise.below(bytes.len() + 1));
                } else {
                    bytes.extend(noise.some(64));
                }
                bytes
            }
        };
        if bytes.is_empty() {
            bytes.push(0);
        }
        let tail = bytes.split_off(noise.below(bytes.len()));
        let started = Instant::now();
        let (result, consumed) = against(vec![bytes, tail], Duration::ZERO);
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "round {round}: the client waited {:?} on a server that had finished",
            started.elapsed()
        );
        assert!(
            consumed <= MAX_HANDSHAKE_BYTES,
            "round {round}: the client read {consumed} bytes"
        );
        most = most.max(consumed);
        if let Ok(export) = result {
            accepted += 1;
            assert!(
                (1..=i64::MAX as u64).contains(&export.size),
                "round {round}: {export:?}"
            );
            assert_eq!(
                export.transmission_flags & REQUIRED_TRANSMISSION_FLAGS,
                REQUIRED_TRANSMISSION_FLAGS,
                "round {round}: {export:?}"
            );
        }
    }
    assert!(accepted > 50, "{accepted} handshakes were accepted");
    assert!(most > 60_000, "no round came near the limit (most {most})");
}

/// Partial reads, a server that sends everything before it reads, and bytes
/// after the acknowledgement: the client reads exactly the handshake. What
/// follows it is the transmission phase, which is the kernel's to read.
#[test]
fn a_handshake_reads_exactly_its_own_bytes() {
    let flags = REQUIRED_TRANSMISSION_FLAGS | 0x20;
    let valid = transcript(8 << 30, flags);
    let expected = Export {
        size: 8 << 30,
        transmission_flags: flags,
    };
    let (result, consumed) = against(
        valid.iter().map(|byte| vec![*byte]).collect(),
        Duration::from_micros(200),
    );
    assert_eq!(result.unwrap(), expected, "one byte per write");
    assert_eq!(consumed, valid.len());
    for trailing in [0usize, 1, 16, 37, 4096] {
        let mut bytes = valid.clone();
        bytes.extend(std::iter::repeat_n(0xa5, trailing));
        let (result, consumed) = against(vec![bytes], Duration::ZERO);
        assert_eq!(result.unwrap(), expected, "{trailing} trailing bytes");
        assert_eq!(consumed, valid.len(), "{trailing} trailing bytes");
    }
}

const SEQ: u32 = 2;
const PORT: u32 = 0x1234_5678;
const FAMILY: u16 = 0x1e;

fn message(kind: u16, seq: u32, port: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = ((16 + payload.len()) as u32).to_ne_bytes().to_vec();
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(&0u16.to_ne_bytes());
    bytes.extend_from_slice(&seq.to_ne_bytes());
    bytes.extend_from_slice(&port.to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

/// `struct nlmsgerr`: the errno, then the request's header.
fn verdict(errno: i32) -> Vec<u8> {
    [errno.to_ne_bytes().as_slice(), &[0; 16]].concat()
}

/// A datagram of any bytes never panics the answer reader, the family
/// reader or the connect-reply reader. An answer is the kernel's verdict
/// only from port 0, for this request and this socket, with a complete
/// `NLMSG_ERROR` as the datagram's last message.
#[test]
fn only_the_kernels_verdict_is_read_from_a_datagram_of_any_bytes() {
    let mut noise = Noise(0x9e37_79b9_7f4a_7c15);
    let (mut verdicts, mut pending, mut refused) = (0, 0, 0);
    for round in 0..100_000 {
        let mut datagram = Vec::new();
        for _ in 0..1 + noise.below(4) {
            let kind = match noise.below(8) {
                0..=2 => NLMSG_ERROR,
                3..=5 => FAMILY,
                6 => netlink::NLMSG_DONE,
                _ => noise.next() as u16,
            };
            let seq = if noise.below(12) == 0 {
                noise.next() as u32
            } else {
                SEQ
            };
            let port = if noise.below(12) == 0 {
                noise.next() as u32
            } else {
                PORT
            };
            let payload = match noise.below(6) {
                0 => noise.some(40),
                1 => verdict(0),
                2 => verdict(-libc::EBUSY),
                3 => vec![1, 1, 0, 0, 8, 0, 1, 0, 3, 0, 0, 0],
                4 => verdict(noise.next() as i32),
                _ => Vec::new(),
            };
            datagram.extend(message(kind, seq, port, &payload));
        }
        // Sometimes damage the framing.
        match noise.below(10) {
            0 => datagram.truncate(noise.below(datagram.len() + 1)),
            1 => {
                let at = noise.below(datagram.len());
                datagram[at] = noise.next() as u8;
            }
            2 => datagram = noise.some(64),
            _ => {}
        }
        let sender = if noise.below(10) == 0 {
            1 + noise.next() as u32 % 1000
        } else {
            0
        };
        let taken = Answer::new(SEQ, PORT, FAMILY).take(sender, &datagram);
        let _ = netlink::family(&datagram);
        let _ = netlink::connected_index(&datagram);
        let errno = match taken {
            Ok(Received::Acknowledged(_)) => 0,
            Ok(Received::Refused(errno)) => {
                assert!(errno > 0, "round {round}: errno {errno}");
                -errno
            }
            Ok(Received::Pending) => {
                pending += 1;
                continue;
            }
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        verdicts += 1;
        assert_eq!(sender, 0, "round {round}: a verdict from port {sender}");
        // Read the datagram again, independently: every message lies
        // within it and is for this request and socket, and the last one
        // is a complete NLMSG_ERROR that carries the errno.
        let mut rest = &datagram[..];
        let mut last = None;
        while !rest.is_empty() {
            assert!(rest.len() >= 16, "round {round}: a cut header");
            let length = u32::from_ne_bytes(rest[..4].try_into().unwrap()) as usize;
            assert!((16..=rest.len()).contains(&length), "round {round}");
            let kind = u16::from_ne_bytes(rest[4..6].try_into().unwrap());
            assert_eq!(u32::from_ne_bytes(rest[8..12].try_into().unwrap()), SEQ);
            assert_eq!(u32::from_ne_bytes(rest[12..16].try_into().unwrap()), PORT);
            last = Some((kind, &rest[16..length]));
            rest = &rest[length.next_multiple_of(4).min(rest.len())..];
        }
        let (kind, payload) = last.expect("a message");
        assert_eq!(kind, NLMSG_ERROR, "round {round}");
        assert!(payload.len() >= 20, "round {round}");
        assert_eq!(
            i32::from_ne_bytes(payload[..4].try_into().unwrap()),
            errno,
            "round {round}"
        );
    }
    assert!(
        verdicts > 500 && pending > 500 && refused > 500,
        "{verdicts} verdicts, {pending} pending, {refused} refused"
    );

    // An answer the kernel sends, cut at every length, is never a verdict.
    let mut whole = message(FAMILY, SEQ, PORT, &[1, 1, 0, 0, 8, 0, 1, 0, 3, 0, 0, 0]);
    whole.extend(message(NLMSG_ERROR, SEQ, PORT, &verdict(0)));
    for cut in 0..whole.len() {
        let taken = Answer::new(SEQ, PORT, FAMILY).take(0, &whole[..cut]);
        assert!(
            !matches!(
                taken,
                Ok(Received::Acknowledged(_)) | Ok(Received::Refused(_))
            ),
            "{cut} of {} bytes were a verdict: {taken:?}",
            whole.len()
        );
    }
    assert!(matches!(
        Answer::new(SEQ, PORT, FAMILY).take(0, &whole),
        Ok(Received::Acknowledged(replies)) if replies.len() == 1
    ));
}

/// `CTRL_CMD_GETFAMILY` for `name`, as [`netlink::family_request`] builds
/// it for "nbd", with the given type and flags.
fn lookup(name: &str, kind: u16, seq: u32, flags: u16) -> Vec<u8> {
    let mut attribute = ((4 + name.len() + 1) as u16).to_ne_bytes().to_vec();
    attribute.extend_from_slice(&netlink::CTRL_ATTR_FAMILY_NAME.to_ne_bytes());
    attribute.extend_from_slice(name.as_bytes());
    attribute.push(0);
    attribute.resize(attribute.len().next_multiple_of(4), 0);
    let mut bytes = ((16 + 4 + attribute.len()) as u32).to_ne_bytes().to_vec();
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&seq.to_ne_bytes());
    bytes.extend_from_slice(&0u32.to_ne_bytes());
    bytes.extend_from_slice(&[CTRL_CMD_GETFAMILY, netlink::CTRL_VERSION, 0, 0]);
    bytes.extend_from_slice(&attribute);
    bytes
}

/// The socket against the kernel's generic netlink controller: an answered
/// request, an answer to another request, a multipart answer and a request
/// the kernel does not answer. Only the first is an answer; the others
/// leave the outcome unknown, the last one at its deadline.
#[test]
fn the_socket_reads_only_its_requests_answer_from_the_kernel() {
    const ACKED: u16 = NLM_F_REQUEST | NLM_F_ACK;
    let soon = || Instant::now() + Duration::from_secs(20);
    assert_eq!(
        netlink::family_request(1),
        lookup("nbd", GENL_ID_CTRL, 1, ACKED)
    );

    let socket = Socket::open().unwrap();
    let replies = socket
        .exchange(
            &lookup("nlctrl", GENL_ID_CTRL, 2, ACKED),
            2,
            GENL_ID_CTRL,
            soon(),
        )
        .unwrap_or_else(|error| panic!("the controller's own lookup: {error:?}"));
    assert_eq!(replies.len(), 1);
    assert_eq!(
        netlink::family(&replies[0]).unwrap_err(),
        "a reply about another family"
    );

    match socket.exchange(
        &lookup("nlctrl", GENL_ID_CTRL, 7, ACKED),
        8,
        GENL_ID_CTRL,
        soon(),
    ) {
        Err(Unacknowledged::Unanswered(error)) => {
            assert!(
                error.to_string().contains("a message for request 7, not 8"),
                "{error}"
            )
        }
        other => panic!("{other:?}"),
    }

    // NLM_F_DUMP (0x300): NLM_F_MULTI parts and an NLMSG_DONE.
    let socket = Socket::open().unwrap();
    let dump = lookup("nlctrl", GENL_ID_CTRL, 3, ACKED | 0x300);
    match socket.exchange(&dump, 3, GENL_ID_CTRL, soon()) {
        Err(Unacknowledged::Unanswered(_)) => {}
        other => panic!("a dump was taken for an answer: {other:?}"),
    }

    // NLMSG_NOOP without NLM_F_ACK: the kernel says nothing.
    let socket = Socket::open().unwrap();
    let silent = lookup("nlctrl", netlink::NLMSG_NOOP, 4, NLM_F_REQUEST);
    let patience = Duration::from_millis(300);
    let started = Instant::now();
    match socket.exchange(&silent, 4, GENL_ID_CTRL, started + patience) {
        Err(Unacknowledged::Unanswered(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}")
        }
        other => panic!("{other:?}"),
    }
    assert!(started.elapsed() >= patience, "{:?}", started.elapsed());
}
