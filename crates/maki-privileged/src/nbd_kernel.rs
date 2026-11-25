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
//! Two answers are "busy" and are retried, every 100 ms for up to 5 s from
//! the first of them and only while the device still shows no connection;
//! every other answer is final.
//!
//! - The kernel refuses a connect with `EBUSY` while anything holds the
//!   unconnected device open (udev probes a device after a disconnect, and
//!   an open allocates the device's configuration). It answers so before it
//!   takes the socket, so the next request goes out on the connection that
//!   is already negotiated, as long as that is still open with nothing to
//!   read on it. A refusal after the kernel took the socket shuts it down,
//!   and only then is a fresh connection negotiated.
//! - The daemon refuses `NBD_OPT_GO` with `NBD_REP_ERR_UNKNOWN` while its
//!   export is not available. Maki's plugin serves one connection at a time,
//!   and nbdkit closes a connection a moment after its peer did: a handshake
//!   that follows a disconnect, or the helper's own closed connection, can
//!   arrive before that. A server without a default export answers the
//!   same, and is refused once the time is over.
//!
//! A device that stayed busy to the end is reported as such
//! ([`NbdError::DeviceBusy`]): nothing was changed, and an attach that
//! allocated the device itself may take another.
//!
//! What is bounded, and what is not. The helper's own waits end by the limit
//! of an external step command, or by the thread's `finish_by` deadline when
//! that comes first (the failed-start hook bounds all of its commands that
//! way): connecting to the daemon's socket, the handshake, the retries of a
//! busy device or export, and the wait for the kernel's answer. The kernel's work on a
//! request is not: it runs inside the `sendto(2)` that sends it, and its
//! mutex waits are uninterruptible, so neither a deadline nor a signal ends
//! them. The `nbd` family sets no `parallel_ops`, so the kernel runs each of
//! its requests under the global generic-netlink mutex (`genl_mutex`), which
//! every family without `parallel_ops` shares, the control family that
//! answers family lookups (`CTRL_CMD_GETFAMILY`) among them.
//! `NBD_CMD_DISCONNECT` takes the device's configuration lock and each
//! connection's transmit lock and writes `NBD_CMD_DISC` to the daemon's
//! socket, which has no send timeout (none is set, and the kernel sets one
//! only with `NBD_ATTR_TIMEOUT`). If the daemon has stopped reading and the
//! socket's send buffer is full, a request in flight holds the transmit lock
//! indefinitely, and the helper waits, holding the attach lock and that
//! mutex, so that no other `nbd` request runs, nor a request to any other
//! such family or a family lookup, anywhere on the host (a client that has
//! yet to resolve its family's ID waits whichever family it wants), until
//! the daemon reads again or its socket closes (the daemon exits). In the
//! helper's flows the unmount and the VG
//! deactivation come first when they are needed; both need the daemon to
//! serve I/O and are bounded external commands, so they fail first when it
//! has stopped. A detach retry whose earlier attempt completed them goes
//! straight to the disconnect. The outer bound is the unit's start or stop
//! timeout, after which systemd kills the helper; a task in an
//! uninterruptible wait ends only when the wait does. With `nbd-client`
//! the helper could abandon a child stuck in the same request after the step
//! limit and release the attach lock, with the same kernel state left
//! behind.

use std::fmt;
use std::io;
use std::mem::{offset_of, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use netlink::{Unacknowledged, COMMAND_SEQUENCE, FAMILY_SEQUENCE};

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
pub mod handshake;
pub(crate) mod netlink;

/// Why a connect or a disconnect did not succeed.
#[derive(Debug)]
pub enum NbdError {
    /// The device was not changed: a check, the family lookup or the
    /// handshake failed before the request, or the kernel refused it.
    Failed(String),
    /// The device was not changed: the kernel answered every connect in the
    /// busy window with `EBUSY`. Something has the unconnected device open.
    DeviceBusy(String),
    /// The request was sent but its answer could not be read (a timeout, a
    /// lost or malformed reply): the kernel may have applied it, and only
    /// the backend identifier it shows decides what is connected.
    Unknown(io::Error),
}

impl fmt::Display for NbdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NbdError::Failed(message) | NbdError::DeviceBusy(message) => f.write_str(message),
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
    check_family(&family)?;
    connect_retrying(
        index,
        deadline,
        &mut KernelAttempts {
            netlink: &netlink,
            family: family.id,
            socket,
            index,
            block_size,
            identifier,
            deadline,
            negotiated: None,
        },
    )
}

/// The real daemon and kernel behind [`Attempts`]. The negotiated
/// connection is the helper's own descriptor: it is closed when this is
/// dropped, in every outcome, and a connected kernel holds its own
/// reference.
pub(crate) struct KernelAttempts<'a> {
    pub(crate) netlink: &'a netlink::Socket,
    pub(crate) family: u16,
    pub(crate) socket: &'a str,
    pub(crate) index: u32,
    pub(crate) block_size: u32,
    pub(crate) identifier: &'a str,
    pub(crate) deadline: Instant,
    pub(crate) negotiated: Option<(UnixStream, handshake::Export)>,
}

impl Attempts for KernelAttempts<'_> {
    fn negotiate(&mut self) -> Result<Negotiation, NbdError> {
        // The daemon serves one connection: close the earlier one first.
        self.negotiated = None;
        match try_open_export(self.socket, self.deadline) {
            Ok(negotiated) => {
                self.negotiated = Some(negotiated);
                Ok(Negotiation::Ready)
            }
            Err(Refusal::ExportUnavailable(refusal)) => Ok(Negotiation::ExportUnavailable(refusal)),
            Err(Refusal::Final(message)) => Err(NbdError::Failed(message)),
        }
    }

    fn reusable(&mut self) -> bool {
        self.negotiated
            .as_ref()
            .is_some_and(|(stream, _)| idle(stream))
    }

    fn request(&mut self, seq: u32) -> Result<Vec<Vec<u8>>, Unacknowledged> {
        let (stream, export) = self
            .negotiated
            .as_ref()
            .expect("a request follows a negotiation");
        let descriptor = u32::try_from(stream.as_raw_fd()).expect("an open descriptor");
        let request = netlink::connect_request(
            self.family,
            seq,
            &connect_attributes(
                self.index,
                self.block_size,
                self.identifier,
                *export,
                descriptor,
            ),
        );
        self.netlink
            .exchange(&request, seq, self.family, self.deadline)
    }

    fn shows_connection(&mut self) -> Result<bool, NbdError> {
        device_shows_connection(std::path::Path::new("/sys/block"), self.index).map_err(|error| {
            NbdError::Failed(format!(
                "cannot tell whether nbd{} shows a connection: {error}",
                self.index
            ))
        })
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Disconnect `/dev/nbd<index>`.
pub fn disconnect(index: u32) -> Result<(), NbdError> {
    let deadline = step_deadline()?;
    let netlink = open_netlink()?;
    let family = resolve(&netlink, deadline)?;
    let request = netlink::disconnect_request(family.id, COMMAND_SEQUENCE, index);
    disconnected(
        index,
        netlink.exchange(&request, COMMAND_SEQUENCE, family.id, deadline),
    )
}

/// What the kernel's answer to `NBD_CMD_DISCONNECT` for `nbd<index>` says:
/// an acknowledgement without a reply, or why not.
fn disconnected(index: u32, answer: Result<Vec<Vec<u8>>, Unacknowledged>) -> Result<(), NbdError> {
    match answer {
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
    try_open_export(path, deadline).map_err(|refusal| match refusal {
        Refusal::ExportUnavailable(message) | Refusal::Final(message) => NbdError::Failed(message),
    })
}

/// Why [`try_open_export`] returned no export.
enum Refusal {
    /// The server answered that the export is not available
    /// ([`handshake::ExportUnavailable`]): it may be once the daemon has
    /// closed its previous connection.
    ExportUnavailable(String),
    /// Anything else: waiting does not help.
    Final(String),
}

/// [`open_export`], telling the one refusal that can end by itself apart.
fn try_open_export(
    path: &str,
    deadline: Instant,
) -> Result<(UnixStream, handshake::Export), Refusal> {
    let stream = connect_socket(path, deadline).map_err(|error| {
        Refusal::Final(format!("cannot connect to the NBD socket {path}: {error}"))
    })?;
    log_peer(&stream, path);
    let export = handshake::negotiate(&stream, deadline).map_err(|error| {
        let message = format!("the NBD handshake on {path} failed: {error}");
        if handshake::export_unavailable(&error) {
            Refusal::ExportUnavailable(message)
        } else {
            Refusal::Final(message)
        }
    })?;
    tracing::info!(
        "maki-attach: {path} exports {} bytes with transmission flags {:#06x}",
        export.size,
        export.transmission_flags
    );
    Ok((stream, export))
}

/// Whether a negotiated stream is still what the handshake left: open, with
/// nothing to read. A peer that closed, a socket the kernel shut down when
/// it cleaned up a refused connect, and bytes that no server sends before a
/// request all make it unfit for the kernel. `MSG_PEEK` consumes nothing.
pub(crate) fn idle(stream: &UnixStream) -> bool {
    let mut byte = 0u8;
    loop {
        // SAFETY: one writable byte; MSG_DONTWAIT never blocks.
        let received = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if received >= 0 {
            // End of stream, or a byte nobody asked for.
            return false;
        }
        match io::Error::last_os_error().kind() {
            io::ErrorKind::WouldBlock => return true,
            io::ErrorKind::Interrupted => {}
            _ => return false,
        }
    }
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
    let request = netlink::family_request(FAMILY_SEQUENCE);
    resolved(netlink.exchange(&request, FAMILY_SEQUENCE, netlink::GENL_ID_CTRL, deadline))
}

/// The `nbd` family in the kernel's answer to the family lookup: one reply
/// that describes it.
fn resolved(answer: Result<Vec<Vec<u8>>, Unacknowledged>) -> Result<netlink::Family, NbdError> {
    let failed = |what: String| {
        NbdError::Failed(format!(
            "cannot look up the kernel's nbd netlink family: {what}"
        ))
    };
    match answer {
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

/// How long a connect keeps retrying after its first busy answer, and how
/// often. The kernel refuses `NBD_CMD_CONNECT` with `EBUSY` while anything
/// holds the unconnected device open: udev probes a device after a
/// disconnect, and opening one allocates its configuration. The daemon
/// answers that its export is not available until it has closed its
/// previous connection.
pub(crate) const BUSY_RETRY_WINDOW: Duration = Duration::from_secs(5);
pub(crate) const BUSY_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// What a negotiation with the daemon gave.
#[derive(Debug)]
pub(crate) enum Negotiation {
    /// A connection in the transmission phase, ready for the kernel.
    Ready,
    /// The server answered that the export is not available, in these
    /// words; no connection is kept.
    ExportUnavailable(String),
}

/// What the connect retries need, so that they are tested without a daemon
/// or a kernel.
pub(crate) trait Attempts {
    /// Close the connection of an earlier negotiation, connect to the
    /// daemon and negotiate. An error is final: nothing changed.
    fn negotiate(&mut self) -> Result<Negotiation, NbdError>;
    /// Whether the negotiated connection can still be handed to the kernel:
    /// open, with nothing to read on it.
    fn reusable(&mut self) -> bool;
    /// Send one `NBD_CMD_CONNECT` with sequence number `seq` for the
    /// negotiated connection.
    fn request(&mut self, seq: u32) -> Result<Vec<Vec<u8>>, Unacknowledged>;
    /// Whether the device shows a connection now.
    fn shows_connection(&mut self) -> Result<bool, NbdError>;
    fn now(&self) -> Instant;
    fn sleep(&mut self, duration: Duration);
}

/// Which side answered busy.
enum Busy {
    /// The kernel: `EBUSY` for the device.
    Device,
    /// The daemon: the export is not available.
    Export(String),
}

/// Connect `nbd<index>` by `deadline`. A busy answer, the kernel's `EBUSY`
/// or the daemon's unavailable export, is retried every
/// [`BUSY_RETRY_INTERVAL`] for up to [`BUSY_RETRY_WINDOW`] from the first
/// one, while the device still shows no connection. A request after the
/// kernel's `EBUSY` reuses the negotiated connection when it is still
/// usable. Every other answer is final.
pub(crate) fn connect_retrying(
    index: u32,
    deadline: Instant,
    attempts: &mut impl Attempts,
) -> Result<(), NbdError> {
    let mut busy_until = None;
    let mut seq = COMMAND_SEQUENCE;
    let mut negotiated = false;
    loop {
        let mut unavailable = None;
        if !(negotiated && attempts.reusable()) {
            match attempts.negotiate()? {
                Negotiation::Ready => negotiated = true,
                Negotiation::ExportUnavailable(refusal) => {
                    negotiated = false;
                    unavailable = Some(refusal);
                }
            }
        }
        let busy = match unavailable {
            Some(refusal) => Busy::Export(refusal),
            None => {
                let answer = attempts.request(seq);
                seq = seq.wrapping_add(1);
                match answer {
                    Ok(replies) => return connected(index, &replies),
                    Err(Unacknowledged::Refused(libc::EBUSY)) => Busy::Device,
                    Err(Unacknowledged::Refused(errno)) => {
                        return Err(NbdError::Failed(format!(
                            "the kernel refused NBD_CMD_CONNECT for nbd{index}: {}",
                            io::Error::from_raw_os_error(errno)
                        )))
                    }
                    Err(Unacknowledged::Unanswered(error)) => {
                        return Err(unknown("NBD_CMD_CONNECT", index, error))
                    }
                }
            }
        };
        let now = attempts.now();
        let until = *busy_until.get_or_insert(deadline.min(now + BUSY_RETRY_WINDOW));
        if now + BUSY_RETRY_INTERVAL >= until {
            return Err(gave_up(index, busy));
        }
        match &busy {
            Busy::Device => tracing::info!(
                "maki-attach: nbd{index} is busy (something has it open); retrying the connect"
            ),
            Busy::Export(_) => tracing::info!(
                "maki-attach: the daemon's export is not available yet (it serves one \
                 connection at a time); retrying the handshake"
            ),
        }
        attempts.sleep(BUSY_RETRY_INTERVAL);
        if attempts.shows_connection()? {
            return Err(NbdError::Failed(match busy {
                Busy::Device => format!(
                    "nbd{index} was busy and now shows a connection; refusing to connect it"
                ),
                Busy::Export(_) => format!(
                    "nbd{index} shows a connection now, after the daemon's export was not \
                     available; refusing to connect it"
                ),
            }));
        }
    }
}

/// The final answer of a connect whose busy answers did not end in time.
fn gave_up(index: u32, busy: Busy) -> NbdError {
    match busy {
        Busy::Device => NbdError::DeviceBusy(format!(
            "the kernel refused NBD_CMD_CONNECT for nbd{index}: {}; something has kept the \
             unconnected device open",
            io::Error::from_raw_os_error(libc::EBUSY)
        )),
        Busy::Export(refusal) => NbdError::Failed(format!(
            "{refusal}. The export stayed unavailable: it is busy with another connection (the \
             daemon serves one at a time, and a kernel NBD device or another client still holds \
             it), or the server has no default export"
        )),
    }
}

/// Refuse a family that does not take a backend identifier: an older kernel
/// would ignore the attribute and connect a device that no identity check
/// could ever claim.
pub(crate) fn check_family(family: &netlink::Family) -> Result<(), NbdError> {
    if family.max_attr < u32::from(netlink::NBD_ATTR_BACKEND_IDENTIFIER) {
        return Err(NbdError::Failed(format!(
            "the kernel's nbd netlink family takes no backend identifier (its highest \
             attribute is {})",
            family.max_attr
        )));
    }
    Ok(())
}

/// Whether `nbd<index>` under `sysfs` (`/sys/block`) shows a connection: a
/// `pid` attribute or a non-empty backend identifier. What cannot be read
/// is an error, never "no connection".
pub(crate) fn device_shows_connection(sysfs: &std::path::Path, index: u32) -> io::Result<bool> {
    let device = sysfs.join(format!("nbd{index}"));
    match std::fs::symlink_metadata(device.join("pid")) {
        Ok(_) => return Ok(true),
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        Err(_) => {}
    }
    match std::fs::read_to_string(device.join("backend")) {
        Ok(backend) => Ok(!backend.trim().is_empty()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
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
mod property_tests;

#[cfg(test)]
mod tests;
