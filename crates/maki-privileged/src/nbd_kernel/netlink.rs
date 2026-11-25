//! Generic netlink for the kernel's `nbd` family: the three requests the
//! helper sends (`CTRL_CMD_GETFAMILY`, `NBD_CMD_CONNECT`,
//! `NBD_CMD_DISCONNECT`), how the kernel's answers are read, and the socket
//! that carries them.
//!
//! Messages are built in host byte order, as netlink requires, with every
//! attribute padded to four bytes. Nested attributes carry `NLA_F_NESTED`,
//! as libnl's `nla_nest_start` sets it (3.6 and later; nbd-client 3.27
//! sends its requests through it): the `nbd` family parses requests with
//! the kernel's liberal validation (`GENL_DONT_VALIDATE_STRICT`), which
//! accepts the flag and masks it out of the type, and a strict parser
//! would require it.
//!
//! An answer is accepted only from the kernel (netlink port 0), only for
//! this request's sequence number and this socket's port, and only in the
//! shapes the kernel sends: replies of the expected family, then one
//! `NLMSG_ERROR` that acknowledges (0) or refuses (a negative errno).

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Instant;

use super::handshake::wait_for;

pub(crate) const NETLINK_GENERIC: i32 = 16;
pub(crate) const NLMSG_HDRLEN: usize = 16;
pub(crate) const GENL_HDRLEN: usize = 4;
pub(crate) const NLA_HDRLEN: usize = 4;
pub(crate) const NLM_F_REQUEST: u16 = 0x1;
pub(crate) const NLM_F_ACK: u16 = 0x4;
/// Neither is part of an answer to these requests.
#[allow(dead_code)]
pub(crate) const NLMSG_NOOP: u16 = 0x1;
pub(crate) const NLMSG_ERROR: u16 = 0x2;
#[allow(dead_code)]
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
/// Never sent, as nbd-client 3.27 sent none (the kernel's defaults apply).
#[allow(dead_code)]
pub(crate) const NBD_ATTR_TIMEOUT: u16 = 4;
pub(crate) const NBD_ATTR_SERVER_FLAGS: u16 = 5;
#[allow(dead_code)]
pub(crate) const NBD_ATTR_CLIENT_FLAGS: u16 = 6;
pub(crate) const NBD_ATTR_SOCKETS: u16 = 7;
#[allow(dead_code)]
pub(crate) const NBD_ATTR_DEAD_CONN_TIMEOUT: u16 = 8;
#[allow(dead_code)]
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

/// A request under construction: its header, its generic netlink header
/// and its attributes, each padded to four bytes.
struct Message(Vec<u8>);

impl Message {
    fn new(kind: u16, seq: u32, command: u8, version: u8) -> Self {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // the length, set by `finish`
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        bytes.extend_from_slice(&seq.to_ne_bytes());
        // The sender's port: the kernel knows it from the socket.
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&[command, version, 0, 0]);
        Self(bytes)
    }

    fn put(&mut self, kind: u16, value: &[u8]) {
        let length = u16::try_from(NLA_HDRLEN + value.len()).expect("a netlink attribute fits");
        self.0.extend_from_slice(&length.to_ne_bytes());
        self.0.extend_from_slice(&kind.to_ne_bytes());
        self.0.extend_from_slice(value);
        self.0.resize(self.0.len().next_multiple_of(4), 0);
    }

    /// A nested attribute holding what `inner` puts, as libnl's
    /// `nla_nest_start`/`nla_nest_end` encode it.
    fn nest(&mut self, kind: u16, inner: impl FnOnce(&mut Self)) {
        let start = self.0.len();
        self.0.extend_from_slice(&[0, 0]);
        self.0
            .extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        inner(self);
        let length = u16::try_from(self.0.len() - start).expect("a netlink attribute fits");
        self.0[start..start + 2].copy_from_slice(&length.to_ne_bytes());
    }

    fn finish(mut self) -> Vec<u8> {
        let length = u32::try_from(self.0.len()).expect("a netlink message fits");
        self.0[..4].copy_from_slice(&length.to_ne_bytes());
        self.0
    }
}

/// `CTRL_CMD_GETFAMILY` for the `nbd` family.
pub(crate) fn family_request(seq: u32) -> Vec<u8> {
    let mut message = Message::new(GENL_ID_CTRL, seq, CTRL_CMD_GETFAMILY, CTRL_VERSION);
    message.put(CTRL_ATTR_FAMILY_NAME, &nul_terminated(NBD_GENL_FAMILY_NAME));
    message.finish()
}

/// `NBD_CMD_CONNECT`, its attributes in nbd-client's order: index, size,
/// block size, server flags, backend identifier, then the socket list.
pub(crate) fn connect_request(family: u16, seq: u32, connect: &Connect<'_>) -> Vec<u8> {
    let mut message = Message::new(family, seq, NBD_CMD_CONNECT, NBD_GENL_VERSION);
    message.put(NBD_ATTR_INDEX, &connect.index.to_ne_bytes());
    message.put(NBD_ATTR_SIZE_BYTES, &connect.size.to_ne_bytes());
    message.put(NBD_ATTR_BLOCK_SIZE_BYTES, &connect.block_size.to_ne_bytes());
    message.put(NBD_ATTR_SERVER_FLAGS, &connect.server_flags.to_ne_bytes());
    message.put(
        NBD_ATTR_BACKEND_IDENTIFIER,
        &nul_terminated(connect.identifier),
    );
    message.nest(NBD_ATTR_SOCKETS, |sockets| {
        sockets.nest(NBD_SOCK_ITEM, |item| {
            item.put(NBD_SOCK_FD, &connect.socket.to_ne_bytes());
        });
    });
    message.finish()
}

/// `NBD_CMD_DISCONNECT` of one device.
pub(crate) fn disconnect_request(family: u16, seq: u32, index: u32) -> Vec<u8> {
    let mut message = Message::new(family, seq, NBD_CMD_DISCONNECT, NBD_GENL_VERSION);
    message.put(NBD_ATTR_INDEX, &index.to_ne_bytes());
    message.finish()
}

/// An `NLA_STRING` as libnl's `nla_put_string` sends it.
fn nul_terminated(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

/// One message of a datagram.
struct Incoming<'a> {
    kind: u16,
    seq: u32,
    port: u32,
    payload: &'a [u8],
}

/// The messages of one datagram, each within it.
fn messages(datagram: &[u8]) -> Result<Vec<Incoming<'_>>, String> {
    if datagram.is_empty() {
        return Err("an empty datagram".into());
    }
    let mut found = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        let Some(header) = rest.first_chunk::<NLMSG_HDRLEN>() else {
            return Err(format!("a message header cut to {} bytes", rest.len()));
        };
        let field = |at: usize| u32::from_ne_bytes(header[at..at + 4].try_into().unwrap());
        let length = usize::try_from(field(0)).unwrap_or(usize::MAX);
        if length < NLMSG_HDRLEN || length > rest.len() {
            return Err(format!(
                "a message of {length} bytes where {} remain",
                rest.len()
            ));
        }
        found.push(Incoming {
            kind: u16::from_ne_bytes([header[4], header[5]]),
            seq: field(8),
            port: field(12),
            payload: &rest[NLMSG_HDRLEN..length],
        });
        rest = &rest[length.next_multiple_of(4).min(rest.len())..];
    }
    Ok(found)
}

/// The attributes of a list, their types without flags, each within it.
fn attributes(mut rest: &[u8]) -> Result<Vec<(u16, &[u8])>, String> {
    let mut found = Vec::new();
    while !rest.is_empty() {
        let Some(header) = rest.first_chunk::<NLA_HDRLEN>() else {
            return Err(format!("an attribute header cut to {} bytes", rest.len()));
        };
        let length = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        if length < NLA_HDRLEN || length > rest.len() {
            return Err(format!(
                "an attribute of {length} bytes where {} remain",
                rest.len()
            ));
        }
        let kind = u16::from_ne_bytes([header[2], header[3]]) & NLA_TYPE_MASK;
        found.push((kind, &rest[NLA_HDRLEN..length]));
        rest = &rest[length.next_multiple_of(4).min(rest.len())..];
    }
    Ok(found)
}

/// The attributes of a generic netlink message of `command`.
fn generic(reply: &[u8], command: u8) -> Result<Vec<(u16, &[u8])>, String> {
    let Some((header, list)) = reply.split_first_chunk::<GENL_HDRLEN>() else {
        return Err("a reply without its generic netlink header".into());
    };
    if header[0] != command {
        return Err(format!("a reply of command {}, not {command}", header[0]));
    }
    attributes(list)
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
        if sender != 0 {
            return Err(format!(
                "a message from netlink port {sender}, not from the kernel"
            ));
        }
        let messages = messages(datagram)?;
        let last = messages.len() - 1;
        for (position, message) in messages.into_iter().enumerate() {
            if message.seq != self.seq {
                return Err(format!(
                    "a message for request {}, not {}",
                    message.seq, self.seq
                ));
            }
            if message.port != self.port {
                return Err(format!(
                    "a message for netlink port {}, not this socket's {}",
                    message.port, self.port
                ));
            }
            match message.kind {
                NLMSG_ERROR => {
                    if position != last {
                        return Err("messages after the acknowledgement".into());
                    }
                    // struct nlmsgerr: the errno, then the request's header.
                    if message.payload.len() < 4 + NLMSG_HDRLEN {
                        return Err("an error message without the request's header".into());
                    }
                    let errno = i32::from_ne_bytes(message.payload[..4].try_into().unwrap());
                    return match errno {
                        0 => Ok(Received::Acknowledged(std::mem::take(&mut self.replies))),
                        errno if errno < 0 && errno != i32::MIN => Ok(Received::Refused(-errno)),
                        errno => Err(format!("an error message with errno {errno}")),
                    };
                }
                kind if kind == self.family => {
                    if message.payload.len() < GENL_HDRLEN {
                        return Err("a reply without its generic netlink header".into());
                    }
                    if self.replies.len() >= MAX_DATAGRAMS {
                        return Err("more replies than the kernel sends".into());
                    }
                    self.replies.push(message.payload.to_vec());
                }
                kind => return Err(format!("a message of type {kind:#x}")),
            }
        }
        Ok(Received::Pending)
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
    let (mut id, mut name, mut max_attr) = (None, None, None);
    for (kind, value) in generic(reply, CTRL_CMD_NEWFAMILY)? {
        let repeated = match kind {
            CTRL_ATTR_FAMILY_ID => id
                .replace(
                    <[u8; 2]>::try_from(value)
                        .map(u16::from_ne_bytes)
                        .map_err(|_| format!("a {}-byte family id", value.len()))?,
                )
                .is_some(),
            CTRL_ATTR_FAMILY_NAME => name.replace(value).is_some(),
            CTRL_ATTR_MAXATTR => max_attr
                .replace(
                    <[u8; 4]>::try_from(value)
                        .map(u32::from_ne_bytes)
                        .map_err(|_| format!("a {}-byte highest attribute", value.len()))?,
                )
                .is_some(),
            _ => false,
        };
        if repeated {
            return Err(format!("attribute {kind} more than once"));
        }
    }
    if name != Some(&nul_terminated(NBD_GENL_FAMILY_NAME)[..]) {
        return Err("a reply about another family".into());
    }
    Ok(Family {
        id: id
            .filter(|id| *id != 0)
            .ok_or("a reply without a family id")?,
        max_attr: max_attr.ok_or("a reply without the family's highest attribute")?,
    })
}

/// The device index of an `NBD_CMD_CONNECT` reply.
pub(crate) fn connected_index(reply: &[u8]) -> Result<u32, String> {
    let index = generic(reply, NBD_CMD_CONNECT)?
        .into_iter()
        .find(|(kind, _)| *kind == NBD_ATTR_INDEX)
        .ok_or("a connect reply without the device index")?
        .1;
    <[u8; 4]>::try_from(index)
        .map(u32::from_ne_bytes)
        .map_err(|_| format!("a {}-byte device index", index.len()))
}

/// Why a request got no acknowledgement.
#[derive(Debug)]
pub(crate) enum Unacknowledged {
    /// The kernel refused it with this errno: nothing changed.
    Refused(i32),
    /// Its answer could not be read: the kernel may have applied it.
    Unanswered(io::Error),
}

/// Read the answer to one request into `answer`, a datagram at a time, from
/// `receive`: it fills the buffer it is given with one datagram and returns
/// the datagram's length and its sender's netlink port, a length above the
/// buffer's being a datagram that did not fit (`MSG_TRUNC`). Anything but an
/// acknowledgement or a refusal leaves the outcome unknown.
pub(crate) fn collect(
    mut answer: Answer,
    mut receive: impl FnMut(&mut [u8]) -> io::Result<(usize, u32)>,
) -> Result<Vec<Vec<u8>>, Unacknowledged> {
    let unanswered = |error: io::Error| Unacknowledged::Unanswered(error);
    let malformed =
        |message: String| unanswered(io::Error::new(io::ErrorKind::InvalidData, message));
    let mut buffer = vec![0; MAX_DATAGRAM];
    for _ in 0..MAX_DATAGRAMS {
        let (length, sender) = receive(&mut buffer).map_err(unanswered)?;
        if length > buffer.len() {
            return Err(malformed(format!(
                "the kernel's {length}-byte answer exceeds the {MAX_DATAGRAM}-byte limit"
            )));
        }
        match answer.take(sender, &buffer[..length]) {
            Ok(Received::Pending) => {}
            Ok(Received::Acknowledged(replies)) => return Ok(replies),
            Ok(Received::Refused(errno)) => return Err(Unacknowledged::Refused(errno)),
            Err(message) => return Err(malformed(format!("the answer holds {message}"))),
        }
    }
    Err(malformed(
        "the kernel sent more datagrams than it answers a request with".into(),
    ))
}

/// A generic netlink socket, close-on-exec, bound to a port the kernel
/// chose.
pub(crate) struct Socket {
    fd: OwnedFd,
    port: u32,
}

fn kernel_address() -> libc::sockaddr_nl {
    // SAFETY: sockaddr_nl is plain data; all zeroes is port 0, no groups.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address
}

impl Socket {
    pub(crate) fn open() -> io::Result<Self> {
        #[cfg(test)]
        if SOCKETS_REFUSED.get() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "this test refuses netlink sockets",
            ));
        }
        // SAFETY: socket(2) with constant arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Port 0: the kernel chooses this socket's port.
        let mut address = kernel_address();
        let mut length = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: address is a sockaddr_nl and length its size.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above, writable.
        if unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                (&mut address as *mut libc::sockaddr_nl).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            port: address.nl_pid,
        })
    }

    /// The netlink port the kernel bound this socket to.
    #[cfg(test)]
    pub(crate) fn port(&self) -> u32 {
        self.port
    }

    /// Send `request` (sequence number `seq`) and read the kernel's answer
    /// by `deadline`; replies must be messages of `family`. Anything but an
    /// acknowledgement or a refusal leaves the outcome unknown.
    pub(crate) fn exchange(
        &self,
        request: &[u8],
        seq: u32,
        family: u16,
        deadline: Instant,
    ) -> Result<Vec<Vec<u8>>, Unacknowledged> {
        let unanswered = |error: io::Error| Unacknowledged::Unanswered(error);
        let malformed =
            |message: String| unanswered(io::Error::new(io::ErrorKind::InvalidData, message));
        let address = kernel_address();
        // SAFETY: the request's bytes and the kernel's address, both valid
        // for the call. The kernel handles the request before this returns.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        match usize::try_from(sent) {
            Ok(count) if count == request.len() => {}
            Ok(count) => {
                return Err(malformed(format!(
                    "only {count} of the request's {} bytes were sent",
                    request.len()
                )))
            }
            Err(_) => return Err(unanswered(io::Error::last_os_error())),
        }
        collect(Answer::new(seq, self.port, family), |buffer| {
            self.receive(buffer, deadline)
        })
    }

    /// One datagram and its sender's port; a length above the buffer's is
    /// a datagram that did not fit (`MSG_TRUNC`).
    fn receive(&self, buffer: &mut [u8], deadline: Instant) -> io::Result<(usize, u32)> {
        loop {
            wait_for(
                self.fd.as_raw_fd(),
                libc::POLLIN,
                deadline,
                "the kernel's netlink answer",
            )?;
            let mut address = kernel_address();
            let mut length = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // SAFETY: buffer and address are writable for their lengths.
            let received = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                    (&mut address as *mut libc::sockaddr_nl).cast(),
                    &mut length,
                )
            };
            match usize::try_from(received) {
                Ok(count) => return Ok((count, address.nl_pid)),
                Err(_) => {
                    let error = io::Error::last_os_error();
                    if !matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) {
                        return Err(error);
                    }
                }
            }
        }
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
