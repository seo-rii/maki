//! The generic netlink messages the helper sends, byte for byte, and how
//! it reads the kernel's answers. Netlink is host byte order: the golden
//! bytes are little-endian, as on every target CI builds.

use super::netlink::*;

const FAMILY: u16 = 0x1e;
const PORT: u32 = 0x0123_4567;
const IDENTIFIER: &str = "maki-0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

fn connect() -> Connect<'static> {
    Connect {
        index: 3,
        size: 2 * 1024 * 1024,
        block_size: 4096,
        // HAS_FLAGS | SEND_FLUSH | SEND_FUA | SEND_WRITE_ZEROES
        server_flags: 0x4d,
        socket: 7,
        identifier: IDENTIFIER,
    }
}

#[cfg(target_endian = "little")]
#[test]
fn the_family_lookup_is_libnls_getfamily_request() {
    #[rustfmt::skip]
    let expected: &[u8] = &[
        28, 0, 0, 0,    // nlmsg_len
        0x10, 0,        // GENL_ID_CTRL
        0x05, 0,        // NLM_F_REQUEST | NLM_F_ACK
        1, 0, 0, 0,     // sequence number
        0, 0, 0, 0,     // port: the kernel fills it in
        3, 1, 0, 0,     // CTRL_CMD_GETFAMILY, version 1
        8, 0, 2, 0,     // CTRL_ATTR_FAMILY_NAME
        b'n', b'b', b'd', 0,
    ];
    assert_eq!(family_request(1), expected);
}

#[cfg(target_endian = "little")]
#[test]
fn connect_carries_nbd_clients_attributes_in_its_order_and_nesting() {
    let mut identifier = IDENTIFIER.as_bytes().to_vec();
    identifier.extend_from_slice(&[0, 0, 0]); // NUL, then padding to 4 bytes
    #[rustfmt::skip]
    let expected: Vec<u8> = [
        &[
            128, 0, 0, 0,   // nlmsg_len
            FAMILY as u8, 0,
            0x05, 0,        // NLM_F_REQUEST | NLM_F_ACK
            2, 0, 0, 0,     // sequence number
            0, 0, 0, 0,     // port
            1, 1, 0, 0,     // NBD_CMD_CONNECT, NBD_GENL_VERSION
            8, 0, 1, 0,     3, 0, 0, 0,                     // NBD_ATTR_INDEX
            12, 0, 2, 0,    0, 0, 0x20, 0, 0, 0, 0, 0,      // NBD_ATTR_SIZE_BYTES
            12, 0, 3, 0,    0, 0x10, 0, 0, 0, 0, 0, 0,      // NBD_ATTR_BLOCK_SIZE_BYTES
            12, 0, 5, 0,    0x4d, 0, 0, 0, 0, 0, 0, 0,      // NBD_ATTR_SERVER_FLAGS
            46, 0, 10, 0,                                   // NBD_ATTR_BACKEND_IDENTIFIER
        ][..],
        &identifier,
        &[
            16, 0, 7, 0x80,                 // NBD_ATTR_SOCKETS | NLA_F_NESTED
            12, 0, 1, 0x80,                 // NBD_SOCK_ITEM | NLA_F_NESTED
            8, 0, 1, 0,     7, 0, 0, 0,     // NBD_SOCK_FD
        ],
    ]
    .concat();
    assert_eq!(connect_request(FAMILY, 2, &connect()), expected);
}

#[cfg(target_endian = "little")]
#[test]
fn disconnect_names_only_the_device_index() {
    #[rustfmt::skip]
    let expected: &[u8] = &[
        28, 0, 0, 0,
        FAMILY as u8, 0,
        0x05, 0,
        2, 0, 0, 0,
        0, 0, 0, 0,
        2, 1, 0, 0,     // NBD_CMD_DISCONNECT, NBD_GENL_VERSION
        8, 0, 1, 0,     15, 0, 0, 0,    // NBD_ATTR_INDEX
    ];
    assert_eq!(disconnect_request(FAMILY, 2, 15), expected);
}

/// The top-level attributes of a generic netlink message, parsed the way
/// `nla_parse_deprecated` does: flags masked out of the type, every
/// attribute within its parent and padded to four bytes.
fn attributes(payload: &[u8]) -> Vec<(u16, u16, &[u8])> {
    let mut found = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        assert!(rest.len() >= 4, "attribute header cut short");
        let length = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        let kind = u16::from_ne_bytes([rest[2], rest[3]]);
        assert!(
            length >= 4 && length <= rest.len(),
            "attribute length {length}"
        );
        found.push((
            kind & NLA_TYPE_MASK,
            kind & !NLA_TYPE_MASK,
            &rest[4..length],
        ));
        rest = &rest[length.next_multiple_of(4).min(rest.len())..];
    }
    found
}

#[test]
fn the_kernel_reads_the_connect_request_it_expects() {
    let request = connect_request(FAMILY, 2, &connect());
    assert_eq!(
        usize::try_from(u32::from_ne_bytes(request[..4].try_into().unwrap())).unwrap(),
        request.len()
    );
    assert_eq!(request.len() % 4, 0);
    let top = attributes(&request[NLMSG_HDRLEN + GENL_HDRLEN..]);
    let kinds: Vec<u16> = top.iter().map(|(kind, _, _)| *kind).collect();
    assert_eq!(
        kinds,
        [
            NBD_ATTR_INDEX,
            NBD_ATTR_SIZE_BYTES,
            NBD_ATTR_BLOCK_SIZE_BYTES,
            NBD_ATTR_SERVER_FLAGS,
            NBD_ATTR_BACKEND_IDENTIFIER,
            NBD_ATTR_SOCKETS,
        ],
        "no timeout, dead-connection timeout or client flags are set"
    );
    let value = |kind| top.iter().find(|(k, _, _)| *k == kind).unwrap().2;
    assert_eq!(value(NBD_ATTR_INDEX), 3u32.to_ne_bytes());
    assert_eq!(value(NBD_ATTR_SIZE_BYTES), (2u64 << 20).to_ne_bytes());
    assert_eq!(value(NBD_ATTR_BLOCK_SIZE_BYTES), 4096u64.to_ne_bytes());
    assert_eq!(value(NBD_ATTR_SERVER_FLAGS), 0x4du64.to_ne_bytes());
    // NLA_STRING: the kernel's nla_strdup stops at the NUL.
    let mut identifier = IDENTIFIER.as_bytes().to_vec();
    identifier.push(0);
    assert_eq!(value(NBD_ATTR_BACKEND_IDENTIFIER), identifier);
    // nla_for_each_nested over NBD_SOCK_ITEM entries, each parsed with
    // nla_parse_nested_deprecated for NBD_SOCK_FD.
    let (_, flags, sockets) = top[5];
    assert_eq!(flags, NLA_F_NESTED);
    let items = attributes(sockets);
    assert_eq!(items.len(), 1);
    assert_eq!((items[0].0, items[0].1), (NBD_SOCK_ITEM, NLA_F_NESTED));
    let fds = attributes(items[0].2);
    assert_eq!(fds.len(), 1);
    assert_eq!((fds[0].0, fds[0].1), (NBD_SOCK_FD, 0));
    assert_eq!(fds[0].2, 7u32.to_ne_bytes());
}

fn message(kind: u16, flags: u16, seq: u32, port: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u32::try_from(NLMSG_HDRLEN + payload.len())
            .unwrap()
            .to_ne_bytes(),
    );
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&seq.to_ne_bytes());
    bytes.extend_from_slice(&port.to_ne_bytes());
    bytes.extend_from_slice(payload);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u16::try_from(NLA_HDRLEN + value.len())
            .unwrap()
            .to_ne_bytes(),
    );
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}

/// The `NLMSG_ERROR` the kernel answers a request with: the errno, then
/// the request's own header.
fn error(seq: u32, errno: i32, request_kind: u16) -> Vec<u8> {
    let mut payload = errno.to_ne_bytes().to_vec();
    payload.extend_from_slice(
        &message(request_kind, NLM_F_REQUEST | NLM_F_ACK, seq, PORT, &[])[..NLMSG_HDRLEN],
    );
    message(NLMSG_ERROR, 0x100, seq, PORT, &payload)
}

fn genl(command: u8, version: u8, attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = vec![command, version, 0, 0];
    for attribute in attributes {
        payload.extend_from_slice(attribute);
    }
    payload
}

/// What `ctrl_fill_info` sends for the `nbd` family, in its order.
fn family_reply(id: &[u8], name: &[u8], max_attr: Option<u32>) -> Vec<u8> {
    let mut attributes = vec![
        attribute(CTRL_ATTR_FAMILY_NAME, name),
        attribute(CTRL_ATTR_FAMILY_ID, id),
        attribute(3, &1u32.to_ne_bytes()),
        attribute(4, &0u32.to_ne_bytes()),
    ];
    if let Some(max_attr) = max_attr {
        attributes.push(attribute(CTRL_ATTR_MAXATTR, &max_attr.to_ne_bytes()));
    }
    let op = [
        attribute(1, &1u32.to_ne_bytes()),
        attribute(2, &0x0au32.to_ne_bytes()),
    ]
    .concat();
    attributes.push(attribute(
        6 | NLA_F_NESTED,
        &attribute(1 | NLA_F_NESTED, &op),
    ));
    let group = [
        attribute(2, b"nbd_mc_group\0"),
        attribute(1, &3u32.to_ne_bytes()),
    ]
    .concat();
    attributes.push(attribute(
        7 | NLA_F_NESTED,
        &attribute(1 | NLA_F_NESTED, &group),
    ));
    genl(CTRL_CMD_NEWFAMILY, 2, &attributes)
}

#[test]
fn the_family_reply_gives_the_id_and_the_highest_attribute() {
    let reply = family_reply(&FAMILY.to_ne_bytes(), b"nbd\0", Some(10));
    assert_eq!(
        family(&reply).unwrap(),
        Family {
            id: FAMILY,
            max_attr: 10
        }
    );
    for (bad, what) in [
        (
            family_reply(&FAMILY.to_ne_bytes(), b"nbx\0", Some(10)),
            "another family",
        ),
        (
            family_reply(&FAMILY.to_ne_bytes(), b"nbd", Some(10)),
            "a name without its NUL",
        ),
        (
            family_reply(&[0x1e], b"nbd\0", Some(10)),
            "a short family id",
        ),
        (
            family_reply(&[0x1e, 0, 0, 0], b"nbd\0", Some(10)),
            "a long family id",
        ),
        (
            family_reply(&0u16.to_ne_bytes(), b"nbd\0", Some(10)),
            "family id 0",
        ),
        (
            family_reply(&FAMILY.to_ne_bytes(), b"nbd\0", None),
            "no highest attribute",
        ),
        (
            genl(
                CTRL_CMD_NEWFAMILY,
                2,
                &[attribute(CTRL_ATTR_FAMILY_NAME, b"nbd\0")],
            ),
            "no family id",
        ),
        (genl(CTRL_CMD_GETFAMILY, 2, &[]), "another command"),
        (vec![CTRL_CMD_NEWFAMILY, 2, 0], "a cut-off header"),
        (
            {
                let mut cut = family_reply(&FAMILY.to_ne_bytes(), b"nbd\0", Some(10));
                cut[4] = 200; // the first attribute claims more than there is
                cut
            },
            "an attribute longer than the reply",
        ),
    ] {
        assert!(family(&bad).is_err(), "accepted {what}");
    }
}

#[test]
fn the_connect_reply_names_the_device_index() {
    let reply = genl(
        NBD_CMD_CONNECT,
        1,
        &[attribute(NBD_ATTR_INDEX, &3u32.to_ne_bytes())],
    );
    assert_eq!(connected_index(&reply).unwrap(), 3);
    for (bad, what) in [
        (genl(NBD_CMD_CONNECT, 1, &[]), "no index"),
        (
            genl(
                NBD_CMD_DISCONNECT,
                1,
                &[attribute(NBD_ATTR_INDEX, &3u32.to_ne_bytes())],
            ),
            "another command",
        ),
        (
            genl(
                NBD_CMD_CONNECT,
                1,
                &[attribute(NBD_ATTR_INDEX, &3u16.to_ne_bytes())],
            ),
            "a short index",
        ),
        (vec![NBD_CMD_CONNECT], "a cut-off header"),
    ] {
        assert!(connected_index(&bad).is_err(), "accepted {what}");
    }
}

#[test]
fn an_acknowledged_request_returns_the_replies_before_the_acknowledgement() {
    let reply = genl(
        NBD_CMD_CONNECT,
        1,
        &[attribute(NBD_ATTR_INDEX, &3u32.to_ne_bytes())],
    );
    // The kernel sends the reply and the acknowledgement as two datagrams.
    let mut answer = Answer::new(2, PORT, FAMILY);
    assert_eq!(
        answer
            .take(0, &message(FAMILY, 0, 2, PORT, &reply))
            .unwrap(),
        Received::Pending
    );
    assert_eq!(
        answer.take(0, &error(2, 0, FAMILY)).unwrap(),
        Received::Acknowledged(vec![reply.clone()])
    );
    // One datagram may hold both.
    let mut answer = Answer::new(2, PORT, FAMILY);
    let both = [message(FAMILY, 0, 2, PORT, &reply), error(2, 0, FAMILY)].concat();
    assert_eq!(
        answer.take(0, &both).unwrap(),
        Received::Acknowledged(vec![reply])
    );
    // A disconnect is acknowledged without a reply.
    let mut answer = Answer::new(2, PORT, FAMILY);
    assert_eq!(
        answer.take(0, &error(2, 0, FAMILY)).unwrap(),
        Received::Acknowledged(Vec::new())
    );
}

#[test]
fn a_negative_errno_is_the_kernels_refusal() {
    for errno in [libc::EPERM, libc::EINVAL, libc::EBUSY, libc::ENOENT] {
        let mut answer = Answer::new(2, PORT, FAMILY);
        assert_eq!(
            answer.take(0, &error(2, -errno, FAMILY)).unwrap(),
            Received::Refused(errno)
        );
    }
    // With the request's payload echoed after its header, as the kernel
    // does for an error unless NETLINK_CAP_ACK is set.
    let request = connect_request(FAMILY, 2, &connect());
    let mut payload = (-libc::EBUSY).to_ne_bytes().to_vec();
    payload.extend_from_slice(&request);
    let mut answer = Answer::new(2, PORT, FAMILY);
    assert_eq!(
        answer
            .take(0, &message(NLMSG_ERROR, 0, 2, PORT, &payload))
            .unwrap(),
        Received::Refused(libc::EBUSY)
    );
}

#[test]
fn an_answer_the_kernel_does_not_send_is_an_error() {
    let reply = genl(
        NBD_CMD_CONNECT,
        1,
        &[attribute(NBD_ATTR_INDEX, &3u32.to_ne_bytes())],
    );
    let ack = error(2, 0, FAMILY);
    let truncated_error = {
        let mut cut = message(NLMSG_ERROR, 0, 2, PORT, &0i32.to_ne_bytes());
        cut.truncate(NLMSG_HDRLEN + 4);
        cut
    };
    for (sender, datagram, what) in [
        (0, error(2, 1, FAMILY), "a positive errno"),
        (0, error(3, 0, FAMILY), "another sequence number"),
        (
            0,
            message(FAMILY, 0, 1, PORT, &reply),
            "a reply to another request",
        ),
        (
            0,
            message(FAMILY, 0, 2, PORT + 1, &reply),
            "another socket's port",
        ),
        (1234, ack.clone(), "a message not from the kernel"),
        (
            0,
            message(GENL_ID_CTRL, 0, 2, PORT, &reply),
            "a reply of another family",
        ),
        (
            0,
            message(NLMSG_DONE, 0, 2, PORT, &0i32.to_ne_bytes()),
            "NLMSG_DONE",
        ),
        (0, message(NLMSG_NOOP, 0, 2, PORT, &[]), "NLMSG_NOOP"),
        (
            0,
            message(FAMILY, 0, 2, PORT, &[1, 1]),
            "a reply without its generic header",
        ),
        (0, truncated_error, "an error without the request's header"),
        (
            0,
            ack[..NLMSG_HDRLEN - 1].to_vec(),
            "a cut-off message header",
        ),
        (0, Vec::new(), "an empty datagram"),
        (
            0,
            {
                let mut long = ack.clone();
                long[0] = 200; // nlmsg_len beyond the datagram
                long
            },
            "a message longer than its datagram",
        ),
        (
            0,
            {
                let mut short = ack.clone();
                short[..4].copy_from_slice(&8u32.to_ne_bytes()); // below the header
                short
            },
            "a message shorter than its header",
        ),
        (
            0,
            [ack.clone(), message(FAMILY, 0, 2, PORT, &reply)].concat(),
            "a message after the acknowledgement",
        ),
    ] {
        let mut answer = Answer::new(2, PORT, FAMILY);
        assert!(answer.take(sender, &datagram).is_err(), "accepted {what}");
    }
}
