//! Generic netlink for the kernel's `nbd` family: the three requests the
//! helper sends (`CTRL_CMD_GETFAMILY`, `NBD_CMD_CONNECT`,
//! `NBD_CMD_DISCONNECT`), how the kernel's answers are read, and the socket
//! that carries them.
//!
//! Messages are built in host byte order, as netlink requires, with every
//! attribute padded to four bytes. Nested attributes carry `NLA_F_NESTED`,
//! as libnl's `nla_nest_start` has set it since 3.5 (what nbd-client 3.27
//! sent): the `nbd` family parses its requests with the kernel's liberal
//! validation (`GENL_DONT_VALIDATE_STRICT`), which accepts the flag and
//! masks it out of the type, and a strict parser would require it.
//!
//! An answer is accepted only from the kernel (netlink port 0), only for
//! this request's sequence number and this socket's port, and only in the
//! shapes the kernel sends: replies of the expected family, then one
//! `NLMSG_ERROR` that acknowledges (0) or refuses (a negative errno).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Instant;

pub(crate) const NETLINK_GENERIC: i32 = 16;
pub(crate) const NLMSG_HDRLEN: usize = 16;
pub(crate) const GENL_HDRLEN: usize = 4;
pub(crate) const NLA_HDRLEN: usize = 4;
pub(crate) const NLM_F_REQUEST: u16 = 0x1;
pub(crate) const NLM_F_ACK: u16 = 0x4;
pub(crate) const NLMSG_NOOP: u16 = 0x1;
pub(crate) const NLMSG_ERROR: u16 = 0x2;
pub(crate) const NLMSG_DONE: u16 = 0x3;
pub(crate) const NLA_F_NESTED: u16 = 1 << 15;
pub(crate) const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
pub(crate) const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

pub(crate) const GENL_ID_CTRL: u16 = 0x10;
pub(crate) const CTRL_CMD_NEWFAMILY: u8 = 1;
pub(crate) const CTRL_CMD_GETFAMILY: u8 = 3;
/// The version libnl's `genl_ctrl_resolve` sends; the kernel ignores it.
pub(crate) const CTRL_VERSION: u8 = 1;
pub(crate) const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub(crate) const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub(crate) const CTRL_ATTR_MAXATTR: u16 = 5;

pub(crate) const NBD_GENL_FAMILY_NAME: &str = "nbd";
/// The family's version from `<linux/nbd-netlink.h>`; the kernel does not
/// check it (nbd-client 3.27 sends 0).
pub(crate) const NBD_GENL_VERSION: u8 = 1;
pub(crate) const NBD_CMD_CONNECT: u8 = 1;
pub(crate) const NBD_CMD_DISCONNECT: u8 = 2;
pub(crate) const NBD_ATTR_INDEX: u16 = 1;
pub(crate) const NBD_ATTR_SIZE_BYTES: u16 = 2;
pub(crate) const NBD_ATTR_BLOCK_SIZE_BYTES: u16 = 3;
pub(crate) const NBD_ATTR_TIMEOUT: u16 = 4;
pub(crate) const NBD_ATTR_SERVER_FLAGS: u16 = 5;
pub(crate) const NBD_ATTR_CLIENT_FLAGS: u16 = 6;
pub(crate) const NBD_ATTR_SOCKETS: u16 = 7;
pub(crate) const NBD_ATTR_DEAD_CONN_TIMEOUT: u16 = 8;
pub(crate) const NBD_ATTR_DEVICE_LIST: u16 = 9;
pub(crate) const NBD_ATTR_BACKEND_IDENTIFIER: u16 = 10;
pub(crate) const NBD_SOCK_ITEM: u16 = 1;
pub(crate) const NBD_SOCK_FD: u16 = 1;

/// The sequence numbers of a socket's two requests.
pub(crate) const FAMILY_SEQUENCE: u32 = 1;
pub(crate) const COMMAND_SEQUENCE: u32 = 2;

/// The largest answer datagram read; a longer one is refused.
pub(crate) const MAX_DATAGRAM: usize = 16 * 1024;
/// Datagrams read for one request; the kernel sends at most two.
pub(crate) const MAX_DATAGRAMS: usize = 8;

/// The attributes of one `NBD_CMD_CONNECT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Connect<'a> {
    pub index: u32,
    pub size: u64,
    pub block_size: u64,
    pub server_flags: u64,
    /// The negotiated socket's descriptor in this process.
    pub socket: u32,
    pub identifier: &'a str,
}

/// `CTRL_CMD_GETFAMILY` for the `nbd` family.
pub(crate) fn family_request(seq: u32) -> Vec<u8> {
    let _ = seq;
    todo!("family_request")
}

/// `NBD_CMD_CONNECT`, its attributes in nbd-client's order: index, size,
/// block size, server flags, backend identifier, then the socket list.
pub(crate) fn connect_request(family: u16, seq: u32, connect: &Connect<'_>) -> Vec<u8> {
    let _ = (family, seq, connect);
    todo!("connect_request")
}

/// `NBD_CMD_DISCONNECT` of one device.
pub(crate) fn disconnect_request(family: u16, seq: u32, index: u32) -> Vec<u8> {
    let _ = (family, seq, index);
    todo!("disconnect_request")
}

/// Where an answer stands after a datagram.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Received {
    /// More is expected.
    Pending,
    /// The kernel acknowledged the request; the replies it sent before,
    /// each a generic netlink message (its 4-byte header and attributes).
    Acknowledged(Vec<Vec<u8>>),
    /// The kernel refused the request with this errno.
    Refused(i32),
}

/// Collects the kernel's answer to one request.
pub(crate) struct Answer {
    seq: u32,
    port: u32,
    family: u16,
    replies: Vec<Vec<u8>>,
}

impl Answer {
    /// The answer to request `seq`, sent from the socket bound to `port`,
    /// whose replies are messages of `family`.
    pub(crate) fn new(seq: u32, port: u32, family: u16) -> Self {
        Self {
            seq,
            port,
            family,
            replies: Vec::new(),
        }
    }

    /// Take one datagram that the netlink port `sender` sent. An error is
    /// a datagram the kernel does not send in answer to this request.
    pub(crate) fn take(&mut self, sender: u32, datagram: &[u8]) -> Result<Received, String> {
        let _ = (
            sender,
            datagram,
            self.seq,
            self.port,
            self.family,
            &self.replies,
        );
        todo!("Answer::take")
    }
}

/// What `CTRL_CMD_GETFAMILY` says about a family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Family {
    pub id: u16,
    pub max_attr: u32,
}

/// Read the `nbd` family out of a `CTRL_CMD_NEWFAMILY` reply.
pub(crate) fn family(reply: &[u8]) -> Result<Family, String> {
    let _ = reply;
    todo!("family")
}

/// The device index of an `NBD_CMD_CONNECT` reply.
pub(crate) fn connected_index(reply: &[u8]) -> Result<u32, String> {
    let _ = reply;
    todo!("connected_index")
}

/// Why a request got no acknowledgement.
#[derive(Debug)]
pub(crate) enum Unacknowledged {
    /// The kernel refused it with this errno: nothing changed.
    Refused(i32),
    /// Its answer could not be read: the kernel may have applied it.
    Unanswered(io::Error),
}

/// A generic netlink socket, close-on-exec, bound to a port the kernel
/// chose.
pub(crate) struct Socket {
    fd: OwnedFd,
    port: u32,
}

impl Socket {
    pub(crate) fn open() -> io::Result<Self> {
        todo!("Socket::open")
    }

    /// The netlink port the kernel bound this socket to.
    pub(crate) fn port(&self) -> u32 {
        self.port
    }

    /// Send `request` (sequence number `seq`) and read the kernel's answer
    /// by `deadline`; replies must be messages of `family`.
    pub(crate) fn exchange(
        &self,
        request: &[u8],
        seq: u32,
        family: u16,
        deadline: Instant,
    ) -> Result<Vec<Vec<u8>>, Unacknowledged> {
        let _ = (&self.fd, request, seq, family, deadline);
        todo!("Socket::exchange")
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
thread_local! {
    static SOCKETS_REFUSED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Until the guard is dropped, this thread cannot open a netlink socket:
/// tests of the step runner reach the kernel's NBD devices never.
#[cfg(test)]
pub(crate) fn refuse_sockets() -> impl Drop {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            SOCKETS_REFUSED.set(self.0);
        }
    }
    Restore(SOCKETS_REFUSED.replace(true))
}
