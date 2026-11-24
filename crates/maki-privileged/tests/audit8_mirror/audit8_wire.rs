//! Round-8 audit (slug `privileged-nbd`): the helper's wire code as an attack
//! surface. Root parses bytes an unprivileged daemon sends (the NBD
//! handshake) and datagrams from a netlink socket. These are property and
//! fuzz tests of `nbd_kernel::handshake` and `nbd_kernel::netlink`, compiled
//! from the production sources through `tests/audit8_mirror/`, and probes of
//! the netlink socket against this host's kernel (its generic netlink
//! controller; the `nbd` module is not needed).

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::nbd_kernel::handshake::{
    self, negotiate, Export, IHAVEOPT, MAX_HANDSHAKE_BYTES, NBDMAGIC, NBD_FLAG_FIXED_NEWSTYLE,
    NBD_FLAG_NO_ZEROES, NBD_INFO_EXPORT, NBD_OPT_GO, NBD_REP_ACK, NBD_REP_INFO, REPLY_MAGIC,
    REQUIRED_TRANSMISSION_FLAGS,
};
use crate::nbd_kernel::netlink::{
    self, Answer, Received, Socket, Unacknowledged, CTRL_CMD_GETFAMILY, GENL_ID_CTRL, NLMSG_ERROR,
    NLM_F_ACK, NLM_F_REQUEST,
};

/// xorshift64*: the tests need reproducible noise, not quality.
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
    /// Up to `bound - 1` bytes.
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

fn info_export(size: u64, flags: u16) -> Vec<u8> {
    let mut data = NBD_INFO_EXPORT.to_be_bytes().to_vec();
    data.extend_from_slice(&size.to_be_bytes());
    data.extend_from_slice(&flags.to_be_bytes());
    reply(NBD_REP_INFO, &data)
}

/// A handshake nbdkit could send: the greeting, one information reply the
/// client did not ask for, the export and the acknowledgement.
fn transcript(size: u64, flags: u16) -> Vec<u8> {
    let mut bytes = NBDMAGIC.to_be_bytes().to_vec();
    bytes.extend_from_slice(&IHAVEOPT.to_be_bytes());
    bytes.extend_from_slice(&(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES).to_be_bytes());
    bytes.extend_from_slice(&reply(
        NBD_REP_INFO,
        &[0, 3, 0, 0, 2, 0, 0, 0, 16, 0, 2, 0, 0, 0],
    ));
    bytes.extend_from_slice(&info_export(size, flags));
    bytes.extend_from_slice(&reply(NBD_REP_ACK, &[]));
    bytes
}

/// Run the client against a server that writes `chunks`, pausing `gap`
/// between them, and never reads. Returns the client's result and how many
/// of the server's bytes the client consumed.
fn against(
    chunks: Vec<Vec<u8>>,
    gap: Duration,
    deadline: Duration,
) -> (std::io::Result<Export>, usize) {
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
    let result = negotiate(&client, Instant::now() + deadline);
    // What the client left unread belongs to whoever uses the socket next
    // (the kernel): count it.
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

/// Whatever an unprivileged server sends, the client returns (no panic, no
/// hang), reads no more than its byte limit, and accepts only an export the
/// kernel may use.
#[test]
fn audit8_wire_handshake_fuzz_stays_within_its_limits() {
    let valid = transcript(1 << 30, REQUIRED_TRANSMISSION_FLAGS | 0x20);
    let mut noise = Noise(0x8a5c_d789_635d_2dff);
    let mut accepted = 0;
    let mut most = 0;
    for round in 0..4000 {
        let mut bytes = match round % 5 {
            // Pure noise, sometimes far beyond the limit.
            0 => {
                let length = if round % 50 == 0 {
                    200_000
                } else {
                    noise.below(600)
                };
                noise.bytes(length)
            }
            // A valid greeting, then noise.
            1 => {
                let mut bytes = valid[..18].to_vec();
                bytes.extend(noise.some(400));
                bytes
            }
            // A valid greeting, then many skipped information replies.
            2 => {
                let mut bytes = valid[..18].to_vec();
                for _ in 0..noise.below(4000) {
                    let length = 2 + noise.below(40);
                    let mut data = vec![0, 1];
                    data.extend(noise.bytes(length - 2));
                    bytes.extend(reply(NBD_REP_INFO, &data));
                }
                bytes.extend_from_slice(&valid[18..]);
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
            // The valid transcript cut short or with a tail.
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
        let split = noise.below(bytes.len());
        let tail = bytes.split_off(split);
        let started = Instant::now();
        let (result, consumed) =
            against(vec![bytes, tail], Duration::ZERO, Duration::from_secs(20));
        assert!(
            started.elapsed() < Duration::from_secs(10),
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
                export.size >= 1 && export.size <= i64::MAX as u64,
                "round {round}: {export:?}"
            );
            assert_eq!(
                export.transmission_flags & REQUIRED_TRANSMISSION_FLAGS,
                REQUIRED_TRANSMISSION_FLAGS,
                "round {round}: {export:?}"
            );
        }
    }
    assert!(accepted > 100, "{accepted} handshakes were accepted");
    assert!(most > 60_000, "no round came near the limit (most {most})");
}

/// Partial reads, a server that sends everything before it reads, and bytes
/// after the acknowledgement: the client reads exactly the handshake.
#[test]
fn audit8_wire_handshake_partial_coalesced_and_trailing_bytes() {
    let flags = REQUIRED_TRANSMISSION_FLAGS | 0x20;
    let valid = transcript(8 << 30, flags);
    let expected = Export {
        size: 8 << 30,
        transmission_flags: flags,
    };
    // One byte per write.
    let (result, consumed) = against(
        valid.iter().map(|byte| vec![*byte]).collect(),
        Duration::from_micros(200),
        Duration::from_secs(20),
    );
    assert_eq!(result.unwrap(), expected);
    assert_eq!(consumed, valid.len());
    // Everything at once, with the first bytes of the transmission phase.
    for trailing in [0usize, 1, 16, 37, 4096] {
        let mut bytes = valid.clone();
        bytes.extend(std::iter::repeat_n(0xa5, trailing));
        let (result, consumed) = against(vec![bytes], Duration::ZERO, Duration::from_secs(20));
        assert_eq!(result.unwrap(), expected, "{trailing} trailing bytes");
        assert_eq!(
            consumed,
            valid.len(),
            "the client read {} of {trailing} bytes that follow the acknowledgement",
            consumed - valid.len().min(consumed)
        );
    }
}

extern "C" fn no_op(_: libc::c_int) {}

/// Signals that interrupt every wait neither end the handshake early nor
/// stretch it past its deadline.
#[test]
fn audit8_wire_handshake_under_a_signal_storm() {
    // SAFETY: a handler that does nothing, installed without SA_RESTART so
    // that every blocking call it meets returns EINTR.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = no_op as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()),
            0
        );
    }
    let this = unsafe { libc::pthread_self() } as usize;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let storm = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut sent = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                // SAFETY: the target thread outlives the storm (it joins it).
                unsafe { libc::pthread_kill(this as libc::pthread_t, libc::SIGUSR1) };
                sent += 1;
                std::thread::sleep(Duration::from_micros(150));
            }
            sent
        })
    };
    let flags = REQUIRED_TRANSMISSION_FLAGS;
    let valid = transcript(1 << 20, flags);
    // A slow, honest server: about 150 ms of one-byte writes.
    let (result, consumed) = against(
        valid.iter().map(|byte| vec![*byte]).collect(),
        Duration::from_millis(2),
        Duration::from_secs(20),
    );
    let slow = result.map(|export| (export, consumed));
    // A server that stops after the greeting: the deadline, not a signal,
    // ends the wait.
    let started = Instant::now();
    let (client, mut server) = UnixStream::pair().unwrap();
    server.write_all(&valid[..18]).unwrap();
    let stalled = negotiate(&client, Instant::now() + Duration::from_millis(700));
    let waited = started.elapsed();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let signals = storm.join().unwrap();
    assert!(signals > 500, "only {signals} signals were sent");
    let (export, consumed) = slow.expect("the slow handshake");
    assert_eq!((export.size, consumed), (1 << 20, valid.len()));
    assert_eq!(stalled.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(
        waited >= Duration::from_millis(700) && waited < Duration::from_millis(1500),
        "the stalled handshake ended after {waited:?}"
    );
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

fn acknowledgement(errno: i32) -> Vec<u8> {
    let mut payload = errno.to_ne_bytes().to_vec();
    payload.extend_from_slice(&[0; 16]);
    message(NLMSG_ERROR, SEQ, PORT, &payload)
}

/// Arbitrary datagrams never panic the answer parser, the family parser or
/// the connect-reply parser, and an answer is taken as the kernel's verdict
/// only from port 0, for this request and this socket, with the
/// acknowledgement as the datagram's last, complete message.
#[test]
fn audit8_wire_netlink_fuzz_accepts_only_the_kernels_verdict() {
    let mut noise = Noise(0x9e37_79b9_7f4a_7c15);
    let (mut verdicts, mut pending, mut refused_shapes) = (0, 0, 0);
    for round in 0..200_000 {
        // A datagram of up to four messages, mostly plausible.
        let mut datagram = Vec::new();
        let mut plan = Vec::new();
        for _ in 0..1 + noise.below(4) {
            let kind = match noise.below(8) {
                0..=2 => NLMSG_ERROR,
                3..=5 => FAMILY,
                6 => 3, // NLMSG_DONE
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
                1 => 0i32.to_ne_bytes().iter().copied().chain([0; 16]).collect(),
                2 => (-16i32)
                    .to_ne_bytes()
                    .iter()
                    .copied()
                    .chain([0; 16])
                    .collect(),
                3 => vec![1, 1, 0, 0, 8, 0, 1, 0, 3, 0, 0, 0],
                4 => (noise.next() as i32)
                    .to_ne_bytes()
                    .iter()
                    .copied()
                    .chain([0; 16])
                    .collect(),
                _ => Vec::new(),
            };
            plan.push((kind, seq, port, payload.clone()));
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
        let mut answer = Answer::new(SEQ, PORT, FAMILY);
        let taken = answer.take(sender, &datagram);
        let _ = netlink::family(&datagram);
        let _ = netlink::connected_index(&datagram);
        match taken {
            Ok(Received::Acknowledged(_)) | Ok(Received::Refused(_)) => {
                verdicts += 1;
                assert_eq!(sender, 0, "round {round}: a verdict from port {sender}");
                // Re-read the datagram independently: every message is
                // within it and for this request and socket, and the last
                // one is a complete NLMSG_ERROR.
                let mut rest = &datagram[..];
                let mut last = None;
                while !rest.is_empty() {
                    assert!(rest.len() >= 16, "round {round}: a cut header was accepted");
                    let length = u32::from_ne_bytes(rest[..4].try_into().unwrap()) as usize;
                    assert!(length >= 16 && length <= rest.len(), "round {round}");
                    let kind = u16::from_ne_bytes(rest[4..6].try_into().unwrap());
                    assert_eq!(u32::from_ne_bytes(rest[8..12].try_into().unwrap()), SEQ);
                    assert_eq!(u32::from_ne_bytes(rest[12..16].try_into().unwrap()), PORT);
                    last = Some((kind, rest[16..length].to_vec()));
                    rest = &rest[length.next_multiple_of(4).min(rest.len())..];
                }
                let (kind, payload) = last.expect("a message");
                assert_eq!(kind, NLMSG_ERROR, "round {round}");
                assert!(payload.len() >= 20, "round {round}");
                let errno = i32::from_ne_bytes(payload[..4].try_into().unwrap());
                match taken {
                    Ok(Received::Acknowledged(_)) => assert_eq!(errno, 0, "round {round}"),
                    Ok(Received::Refused(code)) => {
                        assert!(
                            errno < 0 && code == -errno && code > 0,
                            "round {round}: {errno}"
                        )
                    }
                    _ => unreachable!(),
                }
            }
            Ok(Received::Pending) => pending += 1,
            Err(_) => refused_shapes += 1,
        }
    }
    assert!(
        verdicts > 1000 && pending > 1000 && refused_shapes > 1000,
        "{verdicts} verdicts, {pending} pending, {refused_shapes} refused shapes"
    );

    // The shapes the kernel sends, cut at every length: a cut datagram is
    // never a verdict.
    let mut whole = message(FAMILY, SEQ, PORT, &[1, 1, 0, 0, 8, 0, 1, 0, 3, 0, 0, 0]);
    whole.extend(acknowledgement(0));
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

/// A `CTRL_CMD_GETFAMILY` for `name`, as `netlink::family_request` builds
/// it for "nbd", with the given header flags.
fn getfamily(name: &str, seq: u32, flags: u16) -> Vec<u8> {
    let mut attribute = ((4 + name.len() + 1) as u16).to_ne_bytes().to_vec();
    attribute.extend_from_slice(&2u16.to_ne_bytes()); // CTRL_ATTR_FAMILY_NAME
    attribute.extend_from_slice(name.as_bytes());
    attribute.push(0);
    attribute.resize(attribute.len().next_multiple_of(4), 0);
    let mut bytes = ((16 + 4 + attribute.len()) as u32).to_ne_bytes().to_vec();
    bytes.extend_from_slice(&GENL_ID_CTRL.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&seq.to_ne_bytes());
    bytes.extend_from_slice(&0u32.to_ne_bytes());
    bytes.extend_from_slice(&[CTRL_CMD_GETFAMILY, 1, 0, 0]);
    bytes.extend_from_slice(&attribute);
    bytes
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

/// The helper's netlink socket against this host's kernel.
#[test]
fn audit8_wire_netlink_socket_against_this_kernel() {
    let socket = match Socket::open() {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("audit8: skipped, no netlink socket here: {error}");
            return;
        }
    };
    // The helper's own builder and a hand-built request agree.
    assert_eq!(
        netlink::family_request(1),
        getfamily("nbd", 1, NLM_F_REQUEST | NLM_F_ACK)
    );

    // 1. The lookup the helper sends. Without the module the kernel refuses
    //    with ENOENT; with it, the reply names the family.
    match socket.exchange(&netlink::family_request(1), 1, GENL_ID_CTRL, soon()) {
        Err(Unacknowledged::Refused(errno)) => {
            eprintln!("audit8: the kernel refused the nbd lookup: errno {errno}");
            assert_eq!(errno, libc::ENOENT);
        }
        Ok(replies) => {
            assert_eq!(replies.len(), 1);
            let family = netlink::family(&replies[0]).unwrap();
            eprintln!("audit8: the kernel has the nbd family: {family:?}");
        }
        Err(Unacknowledged::Unanswered(error)) => panic!("the nbd lookup went unanswered: {error}"),
    }

    // 2. A family every kernel has: one reply, then the acknowledgement, and
    //    the reply is refused as "another family" by the nbd reader.
    let replies = socket
        .exchange(
            &getfamily("nlctrl", 2, NLM_F_REQUEST | NLM_F_ACK),
            2,
            GENL_ID_CTRL,
            soon(),
        )
        .unwrap_or_else(|error| panic!("the nlctrl lookup: {error:?}"));
    assert_eq!(replies.len(), 1);
    assert_eq!(
        netlink::family(&replies[0]).unwrap_err(),
        "a reply about another family"
    );

    // 3. An answer to another request (a sequence number the caller does not
    //    expect) leaves the outcome unknown.
    match socket.exchange(
        &getfamily("nlctrl", 7, NLM_F_REQUEST | NLM_F_ACK),
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
}

/// A dump (multipart) answer, a request the kernel does not answer, and a
/// receive buffer the kernel overran: each leaves the outcome unknown, by
/// the deadline, and never passes for an acknowledgement.
#[test]
fn audit8_wire_netlink_multipart_silence_and_overrun_are_unknown() {
    let open = || match Socket::open() {
        Ok(socket) => Some(socket),
        Err(error) => {
            eprintln!("audit8: skipped, no netlink socket here: {error}");
            None
        }
    };
    // 1. NLM_F_DUMP (0x300): NLM_F_MULTI parts and an NLMSG_DONE.
    let Some(socket) = open() else { return };
    match socket.exchange(
        &getfamily("nlctrl", 3, NLM_F_REQUEST | NLM_F_ACK | 0x300),
        3,
        GENL_ID_CTRL,
        soon(),
    ) {
        Err(Unacknowledged::Unanswered(error)) => eprintln!("audit8: a dump is {error}"),
        other => panic!("a dump was taken for an answer: {other:?}"),
    }

    // 2. No NLM_F_ACK on a request that needs no reply (NLMSG_NOOP): the
    //    kernel says nothing, and the wait ends at the deadline.
    let Some(socket) = open() else { return };
    let mut silent = getfamily("nlctrl", 4, NLM_F_REQUEST);
    silent[4..6].copy_from_slice(&1u16.to_ne_bytes()); // NLMSG_NOOP
    let started = Instant::now();
    match socket.exchange(
        &silent,
        4,
        GENL_ID_CTRL,
        Instant::now() + Duration::from_millis(400),
    ) {
        Err(Unacknowledged::Unanswered(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}")
        }
        other => panic!("{other:?}"),
    }
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(400) && waited < Duration::from_millis(1200),
        "{waited:?}"
    );

    // 3. An overrun: the smallest receive buffer, and more answers than fit.
    let Some(socket) = open() else { return };
    let fd = socket.as_raw_fd();
    let tiny: libc::c_int = 1;
    // SAFETY: an int option of the given size on an open socket.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&tiny as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0);
    // SAFETY: sockaddr_nl is plain data; zeroes address the kernel.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    for _ in 0..64 {
        let request = getfamily("nlctrl", 5, NLM_F_REQUEST | NLM_F_ACK);
        // SAFETY: the request's bytes and the kernel's address.
        let sent = unsafe {
            libc::sendto(
                fd,
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        assert_eq!(sent as usize, request.len());
    }
    match socket.exchange(
        &getfamily("nlctrl", 6, NLM_F_REQUEST | NLM_F_ACK),
        6,
        GENL_ID_CTRL,
        soon(),
    ) {
        Err(Unacknowledged::Unanswered(error)) => eprintln!("audit8: after an overrun: {error}"),
        other => panic!("an overrun socket gave {other:?}"),
    }
}

/// The busy retry negotiates a fresh connection for every attempt. A server
/// that serves one connection at a time, as Maki's plugin does, refuses that
/// handshake until it has closed the previous connection
/// (`crates/maki-nbdkit/tests/audit8_helper_reconnect.rs` measures how long
/// that takes). The retry does not wait for it: a refused handshake ends the
/// connect at once, with almost the whole busy window left.
#[test]
fn audit8_wire_a_refused_handshake_ends_the_busy_retry() {
    use crate::nbd_kernel::{
        connect_retrying, Attempts, NbdError, BUSY_RETRY_INTERVAL, BUSY_RETRY_WINDOW,
    };

    struct Scripted {
        clock: Instant,
        attempts: usize,
        slept: Duration,
    }
    impl Attempts for Scripted {
        fn connect(&mut self, _seq: u32) -> Result<Result<Vec<Vec<u8>>, Unacknowledged>, NbdError> {
            self.attempts += 1;
            match self.attempts {
                // udev still has the unconnected device open.
                1 => Ok(Err(Unacknowledged::Refused(libc::EBUSY))),
                // 100 ms later the daemon has not yet run the plugin's close
                // for the first connection: what `open_export` returns then.
                2 => Err(NbdError::Failed(
                    "the NBD handshake on /run/maki/pg/nbd.sock failed: the server refused \
                     NBD_OPT_GO with NBD_REP_ERR_UNKNOWN (no default export)"
                        .into(),
                )),
                // The device is free and the daemon is ready: never reached.
                _ => Ok(Ok(Vec::new())),
            }
        }
        fn shows_connection(&mut self) -> Result<bool, NbdError> {
            Ok(false)
        }
        fn now(&self) -> Instant {
            self.clock
        }
        fn sleep(&mut self, duration: Duration) {
            self.clock += duration;
            self.slept += duration;
        }
    }
    let mut scripted = Scripted {
        clock: Instant::now(),
        attempts: 0,
        slept: Duration::ZERO,
    };
    let deadline = scripted.clock + Duration::from_secs(120);
    let result = connect_retrying(3, deadline, &mut scripted);
    match &result {
        Err(NbdError::Failed(message)) => {
            assert!(message.contains("NBD_REP_ERR_UNKNOWN"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(scripted.attempts, 2, "no third attempt");
    assert_eq!(scripted.slept, BUSY_RETRY_INTERVAL);
    assert!(BUSY_RETRY_WINDOW - scripted.slept > Duration::from_secs(4));
}

/// The five-second busy window starts before the first attempt, whose
/// handshake the daemon paces: after a first handshake that took 4.95 s, a
/// busy answer is final at once, although the device has been known to be
/// busy for no time at all.
#[test]
fn audit8_wire_the_busy_window_includes_the_first_handshake() {
    use crate::nbd_kernel::{connect_retrying, Attempts, NbdError};

    struct Slow {
        clock: Instant,
        attempts: usize,
    }
    impl Attempts for Slow {
        fn connect(&mut self, _seq: u32) -> Result<Result<Vec<Vec<u8>>, Unacknowledged>, NbdError> {
            self.attempts += 1;
            if self.attempts == 1 {
                // The daemon answers the handshake slowly; udev has the
                // device open for a few milliseconds.
                self.clock += Duration::from_millis(4950);
                return Ok(Err(Unacknowledged::Refused(libc::EBUSY)));
            }
            Ok(Ok(Vec::new()))
        }
        fn shows_connection(&mut self) -> Result<bool, NbdError> {
            Ok(false)
        }
        fn now(&self) -> Instant {
            self.clock
        }
        fn sleep(&mut self, duration: Duration) {
            self.clock += duration;
        }
    }
    let mut slow = Slow {
        clock: Instant::now(),
        attempts: 0,
    };
    let deadline = slow.clock + Duration::from_secs(120);
    match connect_retrying(3, deadline, &mut slow) {
        Err(NbdError::Failed(message)) => {
            assert!(message.contains("Device or resource busy"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(slow.attempts, 1, "the busy device was never retried");
}
