//! The fuzz harness's way into the helper's reading of the kernel's netlink
//! answer (`fuzz/harness`, target `nbd_netlink`). Built only with the
//! `fuzzing` feature, which only the harness enables: nothing here is part
//! of the helper.
//!
//! An input is the answer to one request: its first byte selects the
//! request (modulo 3: the `nbd` family lookup, `NBD_CMD_CONNECT`,
//! `NBD_CMD_DISCONNECT`), and each datagram follows as its sender (0 is the
//! kernel, any other byte a netlink port of that number), its length as a
//! little-endian `u16` and as many bytes as remain of it. A length above
//! [`netlink::MAX_DATAGRAM`] is a datagram that did not fit the buffer
//! (`MSG_TRUNC`). The datagrams go through [`netlink::collect`], the
//! helper's own loop, then the reply goes to the reader of the request it
//! answers.

use std::io;

use super::netlink::{
    self, Answer, Unacknowledged, COMMAND_SEQUENCE, CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME,
    CTRL_ATTR_MAXATTR, CTRL_CMD_NEWFAMILY, FAMILY_SEQUENCE, GENL_HDRLEN, GENL_ID_CTRL,
    MAX_DATAGRAM, MAX_DATAGRAMS, NBD_ATTR_BACKEND_IDENTIFIER, NBD_ATTR_INDEX, NBD_CMD_CONNECT,
    NLMSG_ERROR, NLMSG_HDRLEN,
};
use super::{check_family, connected, disconnected, resolved};

/// The netlink port of the helper's socket.
const PORT: u32 = 0x0000_1f4b;
/// The `nbd` family's id, as a lookup would have resolved it.
const FAMILY: u16 = 0x1e;
/// The device a connect or a disconnect names.
const INDEX: u32 = 3;

/// The request an answer is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Request {
    Lookup,
    Connect,
    Disconnect,
}

impl Request {
    fn of(selector: u8) -> Self {
        match selector % 3 {
            0 => Self::Lookup,
            1 => Self::Connect,
            _ => Self::Disconnect,
        }
    }

    fn selector(self) -> u8 {
        match self {
            Self::Lookup => 0,
            Self::Connect => 1,
            Self::Disconnect => 2,
        }
    }

    /// The request's sequence number and the type of its replies.
    fn seq_and_family(self) -> (u32, u16) {
        match self {
            Self::Lookup => (FAMILY_SEQUENCE, GENL_ID_CTRL),
            Self::Connect | Self::Disconnect => (COMMAND_SEQUENCE, FAMILY),
        }
    }
}

/// One datagram as the socket delivered it.
struct Delivered {
    sender: u32,
    bytes: Vec<u8>,
}

/// Feed the answer in `data` to the helper's reader, and return whether the
/// request it answers succeeded: the family lookup found a family the
/// helper can use, the connect connected [`INDEX`], the disconnect was
/// acknowledged without a reply. Panics where the reader took for the
/// kernel's verdict what the kernel does not send.
pub fn netlink_answer(data: &[u8]) -> bool {
    let Some((&selector, mut rest)) = data.split_first() else {
        return false;
    };
    let request = Request::of(selector);
    let (seq, family) = request.seq_and_family();
    let mut delivered = Vec::new();
    let answer = netlink::collect(Answer::new(seq, PORT, family), |buffer| {
        let Some((&sender, after)) = rest.split_first() else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the kernel's netlink answer did not finish by its deadline",
            ));
        };
        let (length, after) = match after.split_first_chunk::<2>() {
            Some((length, after)) => (usize::from(u16::from_le_bytes(*length)), after),
            None => (after.len(), &[][..]),
        };
        let (bytes, after) = after.split_at(length.min(after.len()));
        rest = after;
        // recvfrom(2) with MSG_TRUNC: the datagram's length, and what fits.
        let copied = bytes.len().min(buffer.len());
        buffer[..copied].copy_from_slice(&bytes[..copied]);
        delivered.push(Delivered {
            sender: u32::from(sender),
            bytes: bytes[..copied].to_vec(),
        });
        let reported = if length > buffer.len() {
            length
        } else {
            bytes.len()
        };
        Ok((reported, u32::from(sender)))
    });
    match &answer {
        Ok(replies) => verdict(&delivered, seq, family, 0, replies),
        Err(Unacknowledged::Refused(errno)) => {
            assert!(*errno > 0, "a refusal with errno {errno}");
            verdict(&delivered, seq, family, -errno, &[]);
        }
        Err(Unacknowledged::Unanswered(_)) => {}
    }
    // The readers `connect` and `disconnect` hand the answer to.
    match (request, answer) {
        (Request::Lookup, answer) => resolved(answer).is_ok_and(|found| {
            assert_ne!(found.id, 0, "a family without an id");
            check_family(&found).is_ok()
        }),
        (Request::Connect, Ok(replies)) => {
            let ok = connected(INDEX, &replies).is_ok();
            if ok {
                assert!(replies.len() <= 1, "{} replies connected", replies.len());
                for reply in &replies {
                    assert_eq!(netlink::connected_index(reply), Ok(INDEX));
                }
            }
            ok
        }
        // A refusal goes to the busy retries, which other tests cover.
        (Request::Connect, Err(_)) => false,
        (Request::Disconnect, answer) => disconnected(INDEX, answer).is_ok(),
    }
}

/// Check, reading the datagrams again, that what was taken for the
/// kernel's verdict is one: every datagram came from the kernel, every
/// message lies within its datagram and is for this request and this
/// socket, the replies are the messages of the request's family, each with
/// its generic netlink header and no more of them than the kernel sends,
/// and the last message of the last datagram is a complete `NLMSG_ERROR`
/// that carries `errno` (0, or a negative errno).
fn verdict(delivered: &[Delivered], seq: u32, family: u16, errno: i32, replies: &[Vec<u8>]) {
    let mut found = Vec::new();
    let mut last = None;
    for (number, datagram) in delivered.iter().enumerate() {
        assert_eq!(
            datagram.sender, 0,
            "a verdict from port {}",
            datagram.sender
        );
        assert!(last.is_none(), "datagram {number} follows the verdict");
        let mut rest = &datagram.bytes[..];
        while !rest.is_empty() {
            assert!(rest.len() >= NLMSG_HDRLEN, "a cut header");
            let field = |at: usize| u32::from_ne_bytes(rest[at..at + 4].try_into().unwrap());
            let length = field(0) as usize;
            assert!(
                (NLMSG_HDRLEN..=rest.len()).contains(&length),
                "a {length}-byte message where {} remain",
                rest.len()
            );
            assert_eq!(field(8), seq);
            assert_eq!(field(12), PORT);
            let kind = u16::from_ne_bytes([rest[4], rest[5]]);
            let payload = &rest[NLMSG_HDRLEN..length];
            rest = &rest[length.next_multiple_of(4).min(rest.len())..];
            if kind == NLMSG_ERROR {
                assert!(rest.is_empty(), "messages after the verdict");
                last = Some(payload);
            } else {
                assert_eq!(kind, family, "a message of type {kind:#x}");
                assert!(payload.len() >= GENL_HDRLEN);
                found.push(payload.to_vec());
            }
        }
    }
    let last = last.expect("a verdict ends with NLMSG_ERROR");
    assert!(
        last.len() >= 4 + NLMSG_HDRLEN,
        "an error message without the request's header"
    );
    assert_eq!(i32::from_ne_bytes(last[..4].try_into().unwrap()), errno);
    assert!(found.len() <= MAX_DATAGRAMS);
    if errno == 0 {
        assert_eq!(found, replies, "the replies are not the family's messages");
    }
}

/// A netlink message as the kernel sends it, padded to four bytes.
fn message(kind: u16, seq: u32, port: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = ((NLMSG_HDRLEN + payload.len()) as u32)
        .to_ne_bytes()
        .to_vec();
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(&0u16.to_ne_bytes());
    bytes.extend_from_slice(&seq.to_ne_bytes());
    bytes.extend_from_slice(&port.to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

/// A netlink attribute, padded to four bytes.
fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = ((4 + value.len()) as u16).to_ne_bytes().to_vec();
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

/// `struct nlmsgerr`: the errno, then the request's header.
fn error(seq: u32, errno: i32) -> Vec<u8> {
    let mut payload = errno.to_ne_bytes().to_vec();
    payload.extend(&message(GENL_ID_CTRL, seq, PORT, &[])[..NLMSG_HDRLEN]);
    message(NLMSG_ERROR, seq, PORT, &payload)
}

/// The controller's `CTRL_CMD_NEWFAMILY` about a family, as the kernel
/// answers a lookup (it also sends the family's version, header size,
/// operations and multicast groups, which the helper skips).
fn family_reply(name: &str, id: u16, max_attr: u32) -> Vec<u8> {
    let mut payload = vec![CTRL_CMD_NEWFAMILY, 2, 0, 0];
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    payload.extend(attribute(CTRL_ATTR_FAMILY_NAME, &name));
    payload.extend(attribute(CTRL_ATTR_FAMILY_ID, &id.to_ne_bytes()));
    payload.extend(attribute(3, &1u32.to_ne_bytes()));
    payload.extend(attribute(4, &0u32.to_ne_bytes()));
    payload.extend(attribute(CTRL_ATTR_MAXATTR, &max_attr.to_ne_bytes()));
    payload.extend(attribute(
        6,
        &attribute(1, &attribute(1, &1u32.to_ne_bytes())),
    ));
    message(GENL_ID_CTRL, FAMILY_SEQUENCE, PORT, &payload)
}

/// The `NBD_CMD_CONNECT` reply that names the connected device.
fn connect_reply(index: u32) -> Vec<u8> {
    let mut payload = vec![NBD_CMD_CONNECT, 1, 0, 0];
    payload.extend(attribute(NBD_ATTR_INDEX, &index.to_ne_bytes()));
    message(FAMILY, COMMAND_SEQUENCE, PORT, &payload)
}

/// An input: the request, then each datagram with its sender.
fn input(request: Request, datagrams: &[(u8, &[u8])]) -> Vec<u8> {
    let mut bytes = vec![request.selector()];
    for (sender, datagram) in datagrams {
        bytes.push(*sender);
        bytes.extend_from_slice(&(datagram.len() as u16).to_le_bytes());
        bytes.extend_from_slice(datagram);
    }
    bytes
}

/// The committed seeds of `nbd_netlink`: answers the kernel sends, then
/// answers it does not send or that the helper must refuse. A seed's name
/// says what [`netlink_answer`] returns for it (`valid-` true, `refused-`
/// false).
pub fn seeds() -> Vec<(String, Vec<u8>)> {
    let lookup = family_reply("nbd", FAMILY, u32::from(NBD_ATTR_BACKEND_IDENTIFIER));
    let acked = error(FAMILY_SEQUENCE, 0);
    let command_ack = error(COMMAND_SEQUENCE, 0);
    let both = [lookup.clone(), acked.clone()].concat();
    let mut repeated = lookup.clone();
    let mut extra = attribute(CTRL_ATTR_MAXATTR, &10u32.to_ne_bytes());
    repeated.append(&mut extra);
    let length = repeated.len() as u32;
    repeated[..4].copy_from_slice(&length.to_ne_bytes());
    let connect = connect_reply(INDEX);
    let too_many: Vec<u8> = std::iter::repeat_n(connect.clone(), MAX_DATAGRAMS + 1)
        .flatten()
        .chain(command_ack.clone())
        .collect();
    let oversized = vec![0u8; MAX_DATAGRAM + 4];
    let positive = {
        let mut verdict = command_ack.clone();
        verdict[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].copy_from_slice(&5i32.to_ne_bytes());
        verdict
    };
    let wrong_port = message(
        GENL_ID_CTRL,
        FAMILY_SEQUENCE,
        PORT + 1,
        &lookup[NLMSG_HDRLEN..],
    );
    let seeds: Vec<(&str, Vec<u8>)> = vec![
        (
            "valid-lookup",
            input(Request::Lookup, &[(0, &lookup), (0, &acked)]),
        ),
        (
            "valid-lookup-one-datagram",
            input(Request::Lookup, &[(0, &both)]),
        ),
        (
            "valid-connect",
            input(Request::Connect, &[(0, &connect), (0, &command_ack)]),
        ),
        (
            "valid-connect-acknowledged-without-reply",
            input(Request::Connect, &[(0, &command_ack)]),
        ),
        (
            "valid-disconnect",
            input(Request::Disconnect, &[(0, &command_ack)]),
        ),
        (
            "refused-lookup-module-not-loaded",
            input(Request::Lookup, &[(0, &error(FAMILY_SEQUENCE, -2))]),
        ),
        (
            "refused-lookup-kernel-without-backend-identifier",
            input(
                Request::Lookup,
                &[(0, &family_reply("nbd", FAMILY, 8)), (0, &acked)],
            ),
        ),
        (
            "refused-lookup-another-family",
            input(
                Request::Lookup,
                &[(0, &family_reply("nlctrl", GENL_ID_CTRL, 10)), (0, &acked)],
            ),
        ),
        (
            "refused-lookup-family-id-zero",
            input(
                Request::Lookup,
                &[(0, &family_reply("nbd", 0, 10)), (0, &acked)],
            ),
        ),
        (
            "refused-lookup-repeated-attribute",
            input(Request::Lookup, &[(0, &repeated), (0, &acked)]),
        ),
        (
            "refused-lookup-two-replies",
            input(Request::Lookup, &[(0, &lookup), (0, &lookup), (0, &acked)]),
        ),
        (
            "refused-lookup-from-another-port",
            input(Request::Lookup, &[(0, &lookup), (7, &acked)]),
        ),
        (
            "refused-lookup-for-another-socket",
            input(Request::Lookup, &[(0, &wrong_port), (0, &acked)]),
        ),
        (
            "refused-lookup-for-another-request",
            input(
                Request::Lookup,
                &[(0, &lookup), (0, &error(COMMAND_SEQUENCE, 0))],
            ),
        ),
        (
            "refused-lookup-unanswered",
            input(Request::Lookup, &[(0, &lookup)]),
        ),
        (
            "refused-lookup-cut-header",
            input(Request::Lookup, &[(0, &lookup[..10])]),
        ),
        (
            "refused-lookup-cut-message",
            input(Request::Lookup, &[(0, &both[..both.len() - 8])]),
        ),
        (
            "refused-lookup-datagram-beyond-the-buffer",
            input(Request::Lookup, &[(0, &oversized)]),
        ),
        (
            "refused-connect-busy",
            input(Request::Connect, &[(0, &error(COMMAND_SEQUENCE, -16))]),
        ),
        (
            "refused-connect-another-device",
            input(
                Request::Connect,
                &[(0, &connect_reply(INDEX + 1)), (0, &command_ack)],
            ),
        ),
        (
            "refused-connect-messages-after-the-verdict",
            input(
                Request::Connect,
                &[(0, &[command_ack.clone(), connect.clone()].concat())],
            ),
        ),
        (
            "refused-connect-more-replies-than-the-kernel-sends",
            input(Request::Connect, &[(0, &too_many)]),
        ),
        (
            "refused-disconnect-with-a-reply",
            input(Request::Disconnect, &[(0, &connect), (0, &command_ack)]),
        ),
        (
            "refused-disconnect-positive-errno",
            input(Request::Disconnect, &[(0, &positive)]),
        ),
        (
            "refused-disconnect-more-datagrams-than-the-kernel-sends",
            input(
                Request::Disconnect,
                &std::iter::repeat_n((0, &connect[..]), MAX_DATAGRAMS + 1).collect::<Vec<_>>(),
            ),
        ),
    ];
    seeds
        .into_iter()
        .map(|(name, bytes)| (name.to_string(), bytes))
        .collect()
}
