//! The root helper's code, which is built on Linux only: its NBD handshake
//! and its reading of the kernel's netlink answer
//! (`maki_privileged::nbd_kernel`), and the executor's readers of command
//! output and of sysfs (`maki_privileged::exec`). All of them run in a root
//! process on bytes it does not control: the volume daemon, an unprivileged
//! user, sends the handshake, the netlink socket the answer, and the
//! commands and the kernel report what LVM metadata, partition tables,
//! filesystems and device-mapper tables on the volume's device say.

use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use maki_privileged::nbd_kernel::fuzzing;
use maki_privileged::nbd_kernel::handshake::{
    client_request, negotiate, Export, IHAVEOPT, MAX_EXPORT_SIZE, MAX_HANDSHAKE_BYTES, NBDMAGIC,
    NBD_FLAG_FIXED_NEWSTYLE, NBD_FLAG_HAS_FLAGS, NBD_FLAG_NO_ZEROES, NBD_FLAG_SEND_FLUSH,
    NBD_FLAG_SEND_FUA, NBD_FLAG_SEND_TRIM, NBD_INFO_BLOCK_SIZE, NBD_INFO_DESCRIPTION,
    NBD_INFO_EXPORT, NBD_INFO_NAME, NBD_OPT_GO, NBD_REP_ACK, NBD_REP_ERR_POLICY,
    NBD_REP_ERR_UNKNOWN, NBD_REP_INFO, OLDSTYLE_MAGIC, REPLY_MAGIC, REQUIRED_TRANSMISSION_FLAGS,
};

use crate::seeds::{framed, Noise};

/// Far beyond any wait of a handshake whose server has sent everything.
const DEADLINE: Duration = Duration::from_secs(30);

/// The greeting: two magics and the handshake flags.
const GREETING: usize = 18;

/// The helper's NBD handshake (`nbd_kernel::handshake::negotiate`) against
/// a server that sends `data` and then closes its side. The client must
/// end without waiting, read at most its byte limit, send nothing but its
/// one request (and that only after a greeting that offers fixed-newstyle
/// negotiation), and accept only an export the kernel may use, reading
/// exactly the handshake: what follows the acknowledgement is the
/// transmission phase, the kernel's to read. An input is accepted when the
/// client returns an export.
///
/// The server runs on the calling thread, and a call frees every heap
/// block it allocates before it returns
/// (`tests/review_fuzz_entry_threads.rs`): the input is in the socket and
/// the server's sending side is closed before the client starts, and the
/// client's request is read once the client has closed its socket.
/// libFuzzer leak-checks a call that ends with more mallocs than frees, in
/// any thread, and stops checking after 1,000 such calls; under
/// AddressSanitizer a thread per input grows the process's memory with
/// every input. Only an input the socket cannot hold is written by a thread
/// of the call's own ([`queue`]).
pub fn nbd_handshake(data: &[u8]) -> bool {
    let (client, mut server) = UnixStream::pair().expect("a socket pair");
    let queued = queue(&server, data);
    let (result, left) = if queued == data.len() {
        let _ = server.shutdown(Shutdown::Write);
        client_side(client)
    } else {
        std::thread::scope(|scope| {
            let server = &server;
            scope.spawn(move || {
                // The client stops reading at its first error; the bytes
                // it left are drained by `client_side`, so this write
                // always ends.
                let mut writer = server;
                let _ = writer.write_all(&data[queued..]);
                let _ = server.shutdown(Shutdown::Write);
            });
            client_side(client)
        })
    };
    // The client has closed its socket: its request is in the server's
    // receive queue, followed by the end of the stream.
    let mut request = Vec::new();
    let _ = server.read_to_end(&mut request);
    let consumed = data.len() - left;
    assert!(
        consumed <= MAX_HANDSHAKE_BYTES,
        "the client read {consumed} bytes"
    );
    if let Err(error) = &result {
        assert_ne!(
            error.kind(),
            ErrorKind::TimedOut,
            "the client waited on a server that had finished: {error}"
        );
    }
    match greeting(data) {
        Some(flags) => assert_eq!(request, client_request(flags), "the client's request"),
        None => assert!(
            request.is_empty(),
            "the client sent {} bytes after a greeting it refuses",
            request.len()
        ),
    }
    let Ok(export) = result else {
        return false;
    };
    assert!((1..=MAX_EXPORT_SIZE).contains(&export.size), "{export:?}");
    assert_eq!(
        export.transmission_flags & REQUIRED_TRANSMISSION_FLAGS,
        REQUIRED_TRANSMISSION_FLAGS,
        "{export:?}"
    );
    assert_eq!(
        consumed,
        handshake_length(data),
        "the client did not read exactly the handshake"
    );
    true
}

/// Write as much of `data` into the server's socket as it takes without
/// waiting, and return how much that was. Nothing reads the server's
/// bytes before the client starts, so the input must fit in the socket's
/// send buffer: `net.core.wmem_default` when the pair is made, 212,992
/// bytes by default. On Linux 6.18 that buffer took 219,264 bytes in one
/// write, and a smaller one an input up to 128 bytes shorter than itself,
/// so the target's `-max_len` of 70,000 bytes fits unless the buffer is
/// below 70,128 bytes. Where it does not fit, a thread writes the rest
/// while the client reads.
fn queue(server: &UnixStream, data: &[u8]) -> usize {
    server
        .set_nonblocking(true)
        .expect("a nonblocking server socket");
    let mut writer = server;
    let mut queued = 0;
    while queued < data.len() {
        match writer.write(&data[queued..]) {
            Ok(0) => break,
            Ok(count) => queued += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => panic!("writing the input: {error}"),
        }
    }
    server
        .set_nonblocking(false)
        .expect("a blocking server socket");
    queued
}

/// The client: the helper's handshake on `client`, then the number of the
/// server's bytes it left unread. The client's socket is closed when this
/// returns, and also when it unwinds, so a thread still writing to it ends.
fn client_side(client: UnixStream) -> (io::Result<Export>, usize) {
    let result = negotiate(&client, Instant::now() + DEADLINE);
    let mut left = 0;
    let mut reader = &client;
    let mut buffer = [0; 65536];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => left += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => panic!("draining the client: {error}"),
        }
    }
    (result, left)
}

/// The server's handshake flags, if `data` starts with a greeting that
/// offers fixed-newstyle negotiation.
fn greeting(data: &[u8]) -> Option<u16> {
    let greeting = data.get(..GREETING)?;
    let flags = u16::from_be_bytes([greeting[16], greeting[17]]);
    (greeting[..8] == NBDMAGIC.to_be_bytes()
        && greeting[8..16] == IHAVEOPT.to_be_bytes()
        && flags & NBD_FLAG_FIXED_NEWSTYLE != 0)
        .then_some(flags)
}

/// How long the handshake an accepted `data` starts with is: the greeting,
/// then option replies up to and including the acknowledgement.
fn handshake_length(data: &[u8]) -> usize {
    let mut at = GREETING;
    loop {
        let header = data
            .get(at..at + 20)
            .expect("an accepted handshake has whole replies");
        let word =
            |offset: usize| u32::from_be_bytes(header[offset..offset + 4].try_into().unwrap());
        at += 20 + word(16) as usize;
        if word(12) == NBD_REP_ACK {
            return at;
        }
    }
}

/// The helper's reading of the kernel's netlink answer
/// (`nbd_kernel::fuzzing::netlink_answer`, which describes the input).
pub fn nbd_netlink(data: &[u8]) -> bool {
    fuzzing::netlink_answer(data)
}

/// The committed seeds of `nbd_netlink`.
pub(crate) fn netlink_seeds() -> Vec<(String, Vec<u8>)> {
    fuzzing::seeds()
}

fn reply(kind: u32, data: &[u8]) -> Vec<u8> {
    let mut bytes = REPLY_MAGIC.to_be_bytes().to_vec();
    bytes.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

fn greeting_bytes(flags: u16) -> Vec<u8> {
    let mut bytes = NBDMAGIC.to_be_bytes().to_vec();
    bytes.extend_from_slice(&IHAVEOPT.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes
}

fn info(kind: u16, value: &[u8]) -> Vec<u8> {
    reply(NBD_REP_INFO, &framed(&kind.to_be_bytes(), value))
}

fn export(size: u64, flags: u16) -> Vec<u8> {
    info(
        NBD_INFO_EXPORT,
        &framed(&size.to_be_bytes(), &flags.to_be_bytes()),
    )
}

/// The handshake nbdkit sends Maki's plugin's clients: its greeting, the
/// export's information and the acknowledgement. Maki has no NBD server of
/// its own; these are nbdkit's bytes.
fn transcript(size: u64, flags: u16) -> Vec<u8> {
    [
        greeting_bytes(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES),
        info(
            NBD_INFO_BLOCK_SIZE,
            &[0, 0, 2, 0, 0, 0, 16, 0, 0x02, 0, 0, 0],
        ),
        export(size, flags),
        reply(NBD_REP_ACK, &[]),
    ]
    .concat()
}

/// The committed seeds of `nbd_handshake`.
pub(crate) fn handshake_seeds() -> Vec<(String, Vec<u8>)> {
    let flags = REQUIRED_TRANSMISSION_FLAGS | NBD_FLAG_SEND_TRIM;
    let valid = transcript(8 << 30, flags);
    let greeting = greeting_bytes(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES);
    let ack = reply(NBD_REP_ACK, &[]);
    let good_export = export(1 << 30, flags);
    let with = |middle: &[Vec<u8>]| -> Vec<u8> {
        let mut bytes = greeting.clone();
        for part in middle {
            bytes.extend_from_slice(part);
        }
        bytes
    };
    // Information the client did not ask for, until the byte limit is near.
    let mut skipped = greeting.clone();
    while skipped.len() < MAX_HANDSHAKE_BYTES - 200 {
        skipped.extend(info(NBD_INFO_NAME, &[b'n'; 40]));
    }
    let mut beyond = skipped.clone();
    beyond.extend(info(NBD_INFO_NAME, &[b'n'; 400]));
    beyond.extend_from_slice(&good_export);
    beyond.extend_from_slice(&ack);
    skipped.extend_from_slice(&good_export);
    skipped.extend_from_slice(&ack);
    let mut oldstyle = NBDMAGIC.to_be_bytes().to_vec();
    oldstyle.extend_from_slice(&OLDSTYLE_MAGIC.to_be_bytes());
    oldstyle.extend_from_slice(&(1u64 << 30).to_be_bytes());
    oldstyle.extend_from_slice(&[0; 128]);
    let mut wrong_magic = with(&[good_export.clone(), ack.clone()]);
    wrong_magic[GREETING] ^= 0x01;
    let mut other_option = with(&[good_export.clone(), ack.clone()]);
    other_option[GREETING + 11] = 1;
    let mut long_reply = reply(NBD_REP_INFO, &[0; 4099]);
    // Skippable information: a client that read it would go on to the export.
    long_reply[20..22].copy_from_slice(&NBD_INFO_NAME.to_be_bytes());
    let mut noise = Noise::new(0x0bd0_0bd0);
    let mut seeds: Vec<(&str, Vec<u8>)> = vec![
        ("valid-nbdkit", valid.clone()),
        (
            "valid-minimal",
            [
                greeting_bytes(NBD_FLAG_FIXED_NEWSTYLE),
                export(
                    4096,
                    NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA,
                ),
                ack.clone(),
            ]
            .concat(),
        ),
        (
            "valid-unrequested-information",
            with(&[
                info(NBD_INFO_NAME, b"maki"),
                info(NBD_INFO_DESCRIPTION, b"a description"),
                info(99, b""),
                good_export.clone(),
                ack.clone(),
            ]),
        ),
        (
            "valid-transmission-bytes-follow",
            framed(&valid, &[0x25, 0x60, 0x95, 0x13, 0, 0, 0, 0, 0xa5, 0xa5]),
        ),
        ("valid-near-the-byte-limit", skipped),
        ("refused-beyond-the-byte-limit", beyond),
        ("refused-oldstyle", oldstyle),
        (
            "refused-no-fixed-newstyle",
            framed(
                &greeting_bytes(0),
                &[good_export.clone(), ack.clone()].concat(),
            ),
        ),
        (
            "refused-unknown-second-magic",
            framed(&greeting[..8], &[0x5a; 10]),
        ),
        ("refused-reply-magic", wrong_magic),
        ("refused-reply-to-another-option", other_option),
        (
            "refused-reply-longer-than-the-limit",
            with(&[long_reply, good_export.clone(), ack.clone()]),
        ),
        (
            "refused-export-unavailable",
            with(&[reply(NBD_REP_ERR_UNKNOWN, b"no export")]),
        ),
        ("refused-policy", with(&[reply(NBD_REP_ERR_POLICY, b"")])),
        (
            "refused-acknowledgement-with-data",
            with(&[good_export.clone(), reply(NBD_REP_ACK, &[0])]),
        ),
        (
            "refused-acknowledgement-without-export",
            with(&[info(NBD_INFO_NAME, b"maki"), ack.clone()]),
        ),
        (
            "refused-export-twice",
            with(&[good_export.clone(), good_export.clone(), ack.clone()]),
        ),
        (
            "refused-export-size-zero",
            with(&[export(0, flags), ack.clone()]),
        ),
        (
            "refused-export-beyond-the-kernels-limit",
            with(&[export(MAX_EXPORT_SIZE + 1, flags), ack.clone()]),
        ),
        (
            "refused-export-without-flush",
            with(&[export(1 << 30, flags & !NBD_FLAG_SEND_FLUSH), ack.clone()]),
        ),
        (
            "refused-export-without-fua",
            with(&[export(1 << 30, flags & !NBD_FLAG_SEND_FUA), ack.clone()]),
        ),
        (
            "refused-export-of-eleven-bytes",
            with(&[info(NBD_INFO_EXPORT, &[0; 9]), ack.clone()]),
        ),
        (
            "refused-information-shorter-than-its-type",
            with(&[reply(NBD_REP_INFO, &[0]), good_export.clone(), ack.clone()]),
        ),
        (
            "refused-unknown-reply-type",
            with(&[reply(2, &[0; 4]), good_export.clone(), ack.clone()]),
        ),
        ("refused-greeting-cut", valid[..10].to_vec()),
        ("refused-reply-cut", valid[..valid.len() - 22].to_vec()),
        ("refused-empty", Vec::new()),
    ];
    for name in ["noise-nbdkit-a", "noise-nbdkit-b", "noise-nbdkit-c"] {
        seeds.push((name, noise.changed(&valid, GREETING)));
    }
    seeds
        .into_iter()
        .map(|(name, bytes)| (name.to_string(), bytes))
        .collect()
}

/// The root helper's readers of the output of the commands it runs as root:
/// LVM's report, `blkid`, `dmsetup info` and `blockdev`
/// (`maki_privileged::exec::fuzzing::reports`, which describes the input).
/// An input is accepted when the reader accepts the output.
pub fn helper_reports(data: &[u8]) -> bool {
    maki_privileged::exec::fuzzing::reports(data)
}

/// The root helper's readers of the kernel's block topology in sysfs and of
/// the mount table: detach's observation, device allocation, recovery's
/// proof and observations, LVM preflight's candidates and mapping check,
/// the displaced-record check and the connection attributes
/// (`maki_privileged::exec::fuzzing::sysfs`, which describes the input).
/// An input is accepted when the reader accepts what it observed.
pub fn helper_sysfs(data: &[u8]) -> bool {
    maki_privileged::exec::fuzzing::sysfs(data)
}

/// The committed seeds of `helper_reports`.
pub(crate) fn report_seeds() -> Vec<(String, Vec<u8>)> {
    maki_privileged::exec::fuzzing::report_seeds()
}

/// The committed seeds of `helper_sysfs`.
pub(crate) fn sysfs_seeds() -> Vec<(String, Vec<u8>)> {
    maki_privileged::exec::fuzzing::sysfs_seeds()
}
