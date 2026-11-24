//! The kernel NBD connection, made by the helper itself (SPEC §6): the
//! NBD handshake on the volume daemon's socket ([`handshake`]) and one
//! generic netlink request to the kernel's `nbd` family. No external
//! program runs.
//!
//! A connect resolves the `nbd` family first, then connects to the
//! daemon's socket, negotiates, and hands that socket to the kernel with
//! the export's size and transmission flags, the plan's block size and the
//! attach record's connection identifier as the backend identifier. The
//! helper's own descriptor is closed in every outcome; after a connect the
//! kernel holds its own reference. A disconnect sends
//! `NBD_CMD_DISCONNECT` for the device's index.
//!
//! Each step ends by the limit of an external step command, or by the
//! thread's `finish_by` deadline when that comes first (the failed-start
//! hook bounds all of its commands that way).

use std::fmt;
use std::io;
use std::mem::{offset_of, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use netlink::{Unacknowledged, COMMAND_SEQUENCE, FAMILY_SEQUENCE};

pub mod handshake;
pub(crate) mod netlink;

/// Why a connect or a disconnect did not succeed.
#[derive(Debug)]
pub enum NbdError {
    /// The device was not changed: a check, the family lookup or the
    /// handshake failed before the request, or the kernel refused it.
    Failed(String),
    /// The request was sent but its answer could not be read (a timeout, a
    /// lost or malformed reply): the kernel may have applied it, and only
    /// the backend identifier it shows decides what is connected.
    Unknown(io::Error),
}

impl fmt::Display for NbdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NbdError::Failed(message) => f.write_str(message),
            NbdError::Unknown(error) => write!(
                f,
                "{error}; the kernel may have applied the request, so the device's backend \
                 identifier decides what is connected"
            ),
        }
    }
}

impl std::error::Error for NbdError {}

/// The longest backend identifier the helper sends; the record's are 41
/// bytes.
const MAX_IDENTIFIER_BYTES: usize = 255;

/// Connect `/dev/nbd<index>` to the export behind `socket`, with
/// `block_size` as its logical block size and `identifier` as its kernel
/// backend identifier.
pub fn connect(
    socket: &str,
    index: u32,
    block_size: u32,
    identifier: &str,
) -> Result<(), NbdError> {
    let deadline = step_deadline()?;
    if identifier.is_empty()
        || identifier.len() > MAX_IDENTIFIER_BYTES
        || !identifier.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(NbdError::Failed(format!(
            "refusing backend identifier {identifier:?}: it must be 1 to \
             {MAX_IDENTIFIER_BYTES} printable ASCII characters"
        )));
    }
    if !block_size.is_power_of_two() || !(512..=65536).contains(&block_size) {
        return Err(NbdError::Failed(format!(
            "refusing block size {block_size}: the kernel takes a power of two from 512 bytes"
        )));
    }
    let netlink = open_netlink()?;
    let family = resolve(&netlink, deadline)?;
    // An older kernel would ignore the identifier and connect a device
    // that no identity check could ever claim.
    if family.max_attr < u32::from(netlink::NBD_ATTR_BACKEND_IDENTIFIER) {
        return Err(NbdError::Failed(format!(
            "the kernel's nbd netlink family takes no backend identifier (its highest \
             attribute is {})",
            family.max_attr
        )));
    }
    let (stream, export) = open_export(socket, deadline)?;
    let descriptor = u32::try_from(stream.as_raw_fd()).expect("an open descriptor");
    let request = netlink::connect_request(
        family.id,
        COMMAND_SEQUENCE,
        &connect_attributes(index, block_size, identifier, export, descriptor),
    );
    let answer = netlink.exchange(&request, COMMAND_SEQUENCE, family.id, deadline);
    // Whatever the answer: a connected kernel holds its own reference.
    drop(stream);
    match answer {
        Ok(replies) => connected(index, &replies),
        Err(Unacknowledged::Refused(errno)) => Err(NbdError::Failed(format!(
            "the kernel refused NBD_CMD_CONNECT for nbd{index}: {}",
            io::Error::from_raw_os_error(errno)
        ))),
        Err(Unacknowledged::Unanswered(error)) => Err(unknown("NBD_CMD_CONNECT", index, error)),
    }
}

/// Disconnect `/dev/nbd<index>`.
pub fn disconnect(index: u32) -> Result<(), NbdError> {
    let deadline = step_deadline()?;
    let netlink = open_netlink()?;
    let family = resolve(&netlink, deadline)?;
    let request = netlink::disconnect_request(family.id, COMMAND_SEQUENCE, index);
    match netlink.exchange(&request, COMMAND_SEQUENCE, family.id, deadline) {
        Ok(replies) if replies.is_empty() => Ok(()),
        Ok(_) => Err(unknown(
            "NBD_CMD_DISCONNECT",
            index,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the kernel answered with a reply it does not send",
            ),
        )),
        Err(Unacknowledged::Refused(errno)) => Err(NbdError::Failed(format!(
            "the kernel refused NBD_CMD_DISCONNECT for nbd{index}: {}",
            io::Error::from_raw_os_error(errno)
        ))),
        Err(Unacknowledged::Unanswered(error)) => Err(unknown("NBD_CMD_DISCONNECT", index, error)),
    }
}

/// Connect to the NBD socket at `path` and negotiate the default export by
/// `deadline`. The stream returned is blocking, close-on-exec and has no
/// socket timeouts: it is ready to be handed to the kernel.
pub fn open_export(
    path: &str,
    deadline: Instant,
) -> Result<(UnixStream, handshake::Export), NbdError> {
    let stream = connect_socket(path, deadline).map_err(|error| {
        NbdError::Failed(format!("cannot connect to the NBD socket {path}: {error}"))
    })?;
    log_peer(&stream, path);
    let export = handshake::negotiate(&stream, deadline).map_err(|error| {
        NbdError::Failed(format!("the NBD handshake on {path} failed: {error}"))
    })?;
    tracing::info!(
        "maki-attach: {path} exports {} bytes with transmission flags {:#06x}",
        export.size,
        export.transmission_flags
    );
    Ok((stream, export))
}

/// The `NBD_CMD_CONNECT` attributes for `export` on `socket`: the export's
/// size and transmission flags exactly as negotiated.
pub(crate) fn connect_attributes<'a>(
    index: u32,
    block_size: u32,
    identifier: &'a str,
    export: handshake::Export,
    socket: u32,
) -> netlink::Connect<'a> {
    netlink::Connect {
        index,
        size: export.size,
        block_size: block_size.into(),
        server_flags: export.transmission_flags.into(),
        socket,
        identifier,
    }
}

fn step_deadline() -> Result<Instant, NbdError> {
    crate::exec::command::step_deadline().map_err(|error| NbdError::Failed(error.to_string()))
}

fn unknown(request: &str, index: u32, error: io::Error) -> NbdError {
    NbdError::Unknown(io::Error::new(
        error.kind(),
        format!("{request} for nbd{index}: {error}"),
    ))
}

/// The acknowledgement decides; a reply, which the kernel sends unless it
/// runs out of memory, must name the device that was asked for.
fn connected(index: u32, replies: &[Vec<u8>]) -> Result<(), NbdError> {
    let invalid = |message: String| {
        unknown(
            "NBD_CMD_CONNECT",
            index,
            io::Error::new(io::ErrorKind::InvalidData, message),
        )
    };
    if replies.len() > 1 {
        return Err(invalid(format!(
            "the kernel sent {} replies",
            replies.len()
        )));
    }
    for reply in replies {
        match netlink::connected_index(reply) {
            Ok(reported) if reported == index => {}
            Ok(reported) => {
                return Err(invalid(format!(
                    "the kernel acknowledged the request but reported nbd{reported}"
                )))
            }
            Err(message) => return Err(invalid(format!("the kernel's reply holds {message}"))),
        }
    }
    Ok(())
}

fn open_netlink() -> Result<netlink::Socket, NbdError> {
    netlink::Socket::open()
        .map_err(|error| NbdError::Failed(format!("cannot open a generic netlink socket: {error}")))
}

/// Look up the `nbd` family. The lookup changes nothing: every failure is
/// a plain one.
fn resolve(netlink: &netlink::Socket, deadline: Instant) -> Result<netlink::Family, NbdError> {
    let failed = |what: String| {
        NbdError::Failed(format!(
            "cannot look up the kernel's nbd netlink family: {what}"
        ))
    };
    let request = netlink::family_request(FAMILY_SEQUENCE);
    match netlink.exchange(&request, FAMILY_SEQUENCE, netlink::GENL_ID_CTRL, deadline) {
        Ok(replies) => match replies.as_slice() {
            [reply] => netlink::family(reply).map_err(failed),
            _ => Err(failed(format!("{} replies instead of one", replies.len()))),
        },
        Err(Unacknowledged::Refused(libc::ENOENT)) => Err(failed(
            "the nbd module is not loaded or has no netlink interface".into(),
        )),
        Err(Unacknowledged::Refused(errno)) => {
            Err(failed(io::Error::from_raw_os_error(errno).to_string()))
        }
        Err(Unacknowledged::Unanswered(error)) => Err(failed(error.to_string())),
    }
}

/// A blocking, close-on-exec stream connected to `path` by `deadline`, and
/// without a send or receive timeout of its own.
fn connect_socket(path: &str, deadline: Instant) -> io::Result<UnixStream> {
    // SAFETY: sockaddr_un is plain data.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path does not fit a Unix socket address",
        ));
    }
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let length = (offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // A full listen backlog makes connect(2) wait; the send timeout bounds
    // that wait and is cleared again before the kernel sees the socket.
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no time left to connect",
        ));
    }
    set_send_timeout(&fd, left)?;
    loop {
        // SAFETY: address is a sockaddr_un holding `length` bytes.
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        };
        if rc == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN | libc::EINPROGRESS) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the daemon did not accept the connection by the deadline",
                ))
            }
            _ => return Err(error),
        }
    }
    set_send_timeout(&fd, Duration::ZERO)?;
    Ok(UnixStream::from(fd))
}

/// `SO_SNDTIMEO`; zero is no timeout, and anything else at least 1 µs.
fn set_send_timeout(fd: &OwnedFd, timeout: Duration) -> io::Result<()> {
    let mut value = libc::timeval {
        tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_usec: libc::suseconds_t::from(timeout.subsec_micros()),
    };
    if !timeout.is_zero() && value.tv_sec == 0 && value.tv_usec == 0 {
        value.tv_usec = 1;
    }
    // SAFETY: value is a timeval of the given size.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&value as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Who serves the socket, for the log only: the documented flows may run
/// nbdkit outside the volume's unit, so nothing is enforced.
fn log_peer(stream: &UnixStream, path: &str) {
    // SAFETY: ucred is plain data.
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: peer is a writable ucred of the given size.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if rc == 0 {
        tracing::info!(
            "maki-attach: NBD socket {path} is served by pid {} (uid {})",
            peer.pid,
            peer.uid
        );
    } else {
        tracing::info!(
            "maki-attach: the peer of NBD socket {path} is unknown: {}",
            io::Error::last_os_error()
        );
    }
}

/// How long a connect keeps retrying a device the kernel reports busy, and
/// how often. The kernel refuses `NBD_CMD_CONNECT` with `EBUSY` while
/// anything holds the unconnected device open: udev probes a device after a
/// disconnect, and opening one allocates its configuration.
pub(crate) const BUSY_RETRY_WINDOW: Duration = Duration::from_secs(5);
pub(crate) const BUSY_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// What the connect retries need, so that they are tested without a kernel.
pub(crate) trait Attempts {
    /// Negotiate a fresh connection to the daemon and send one
    /// `NBD_CMD_CONNECT` with sequence number `seq`. An error is a failure
    /// before the request (the handshake): final, nothing changed.
    fn connect(&mut self, seq: u32) -> Result<Result<Vec<Vec<u8>>, Unacknowledged>, NbdError>;
    /// Whether the device shows a connection now.
    fn shows_connection(&mut self) -> Result<bool, NbdError>;
    fn now(&self) -> Instant;
    fn sleep(&mut self, duration: Duration);
}

/// Connect `nbd<index>` by `deadline`, retrying an `EBUSY` refusal every
/// [`BUSY_RETRY_INTERVAL`] for up to [`BUSY_RETRY_WINDOW`] while the device
/// still shows no connection. Every other answer is final.
pub(crate) fn connect_retrying(
    index: u32,
    deadline: Instant,
    attempts: &mut impl Attempts,
) -> Result<(), NbdError> {
    let _ = (index, deadline, attempts);
    todo!("connect_retrying")
}

/// Refuse a family that does not take a backend identifier: an older kernel
/// would ignore the attribute and connect a device that no identity check
/// could ever claim.
pub(crate) fn check_family(family: &netlink::Family) -> Result<(), NbdError> {
    let _ = family;
    todo!("check_family")
}

/// Whether `nbd<index>` under `sysfs` (`/sys/block`) shows a connection: a
/// `pid` attribute or a non-empty backend identifier.
pub(crate) fn device_shows_connection(sysfs: &std::path::Path, index: u32) -> io::Result<bool> {
    let _ = (sysfs, index);
    todo!("device_shows_connection")
}

#[cfg(test)]
mod handshake_tests;

#[cfg(test)]
mod retry_tests;

#[cfg(test)]
mod netlink_tests;

#[cfg(test)]
mod header_tests;

#[cfg(test)]
mod tests;
