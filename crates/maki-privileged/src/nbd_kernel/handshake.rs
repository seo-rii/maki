//! The client side of the NBD fixed-newstyle handshake, as the helper runs
//! it on the volume daemon's socket before handing that socket to the
//! kernel (SPEC §6).
//!
//! The daemon runs as an unprivileged user, so every byte read here is
//! untrusted input to a root process: a reply's length is checked before
//! any of it is read, the whole handshake reads at most
//! [`MAX_HANDSHAKE_BYTES`], and every wait ends at the caller's deadline.
//! The client sends one option, `NBD_OPT_GO` for the default export with no
//! information requests, and nothing else: no structured replies, extended
//! headers, metadata contexts or TLS, none of which the kernel's client
//! implements, and no `NBD_OPT_EXPORT_NAME` fallback (Maki's server is
//! always nbdkit, which answers `NBD_OPT_GO`).
//!
//! The socket is waited on with `poll(2)` and read and written with
//! per-call flags, never with socket timeouts or `O_NONBLOCK`: the kernel
//! keeps using the socket after the handshake, and a receive timeout left
//! on it would fail its reads once the device is idle that long.
//!
//! This file uses only `std` and `libc`: maki-nbdkit's native tests compile
//! it by path to run it against Maki's own plugin.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

/// The greeting's first eight bytes, `NBDMAGIC`.
pub const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
/// The newstyle greeting's second eight bytes and every option's magic,
/// `IHAVEOPT`.
pub const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
/// The second eight bytes of an oldstyle greeting.
pub const OLDSTYLE_MAGIC: u64 = 0x0000_4202_8186_1253;
/// The magic of every option reply.
pub const REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;

/// Handshake flags (server to client).
pub const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
pub const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;
/// Client flags: only bits the server offered are ever set.
pub const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1 << 0;
pub const NBD_FLAG_C_NO_ZEROES: u32 = 1 << 1;

pub const NBD_OPT_GO: u32 = 7;

pub const NBD_REP_ACK: u32 = 1;
pub const NBD_REP_SERVER: u32 = 2;
pub const NBD_REP_INFO: u32 = 3;
pub const NBD_REP_FLAG_ERROR: u32 = 1 << 31;
pub const NBD_REP_ERR_UNSUP: u32 = NBD_REP_FLAG_ERROR | 1;
pub const NBD_REP_ERR_POLICY: u32 = NBD_REP_FLAG_ERROR | 2;
pub const NBD_REP_ERR_INVALID: u32 = NBD_REP_FLAG_ERROR | 3;
pub const NBD_REP_ERR_PLATFORM: u32 = NBD_REP_FLAG_ERROR | 4;
pub const NBD_REP_ERR_TLS_REQD: u32 = NBD_REP_FLAG_ERROR | 5;
pub const NBD_REP_ERR_UNKNOWN: u32 = NBD_REP_FLAG_ERROR | 6;
pub const NBD_REP_ERR_SHUTDOWN: u32 = NBD_REP_FLAG_ERROR | 7;
pub const NBD_REP_ERR_BLOCK_SIZE_REQD: u32 = NBD_REP_FLAG_ERROR | 8;
pub const NBD_REP_ERR_TOO_BIG: u32 = NBD_REP_FLAG_ERROR | 9;
pub const NBD_REP_ERR_EXT_HEADER_REQD: u32 = NBD_REP_FLAG_ERROR | 10;

pub const NBD_INFO_EXPORT: u16 = 0;
pub const NBD_INFO_NAME: u16 = 1;
pub const NBD_INFO_DESCRIPTION: u16 = 2;
pub const NBD_INFO_BLOCK_SIZE: u16 = 3;

/// Transmission flags, as `<linux/nbd.h>` names them.
pub const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
pub const NBD_FLAG_READ_ONLY: u16 = 1 << 1;
pub const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
pub const NBD_FLAG_SEND_FUA: u16 = 1 << 3;
pub const NBD_FLAG_ROTATIONAL: u16 = 1 << 4;
pub const NBD_FLAG_SEND_TRIM: u16 = 1 << 5;
pub const NBD_FLAG_SEND_WRITE_ZEROES: u16 = 1 << 6;
pub const NBD_FLAG_CAN_MULTI_CONN: u16 = 1 << 8;

/// What an export must advertise before the kernel may use it.
/// `SEND_FLUSH` is needed for durability: without it the kernel gives the
/// device no write cache, so a FLUSH completes without reaching the server
/// and a FUA write goes out as a plain write, and the filesystem's barriers
/// would never reach the journal. `SEND_FUA` is required by policy: without
/// it the block layer emulates every FUA write with a full flush, which does
/// reach the server. `HAS_FLAGS` is required by the NBD protocol, without
/// which the other bits mean nothing; the kernel itself ignores it.
pub const REQUIRED_TRANSMISSION_FLAGS: u16 =
    NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA;

/// The longest option reply read: a string of the protocol's 4096-byte
/// limit (a name, a description, an error message) and a 2-byte info type.
pub const MAX_REPLY_LENGTH: u32 = 4096 + 2;
/// Every byte the handshake reads, the greeting included.
pub const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;
/// The largest size the kernel accepts (its `loff_t`).
pub const MAX_EXPORT_SIZE: u64 = i64::MAX as u64;

/// What the server said about the default export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Export {
    /// Bytes; never 0 and at most [`MAX_EXPORT_SIZE`].
    pub size: u64,
    /// The export's transmission flags exactly as the server sent them;
    /// they always include [`REQUIRED_TRANSMISSION_FLAGS`].
    pub transmission_flags: u16,
}

/// The refusal `NBD_REP_ERR_UNKNOWN` of `NBD_OPT_GO`: the export is not
/// available. It is the one refusal that can end by itself. nbdkit answers
/// it whenever its plugin cannot open the export, with no message and
/// whatever the plugin's reason (checked in 1.32.5, 1.36.3 and 1.38.5), and
/// Maki's plugin serves one connection at a time: until nbdkit has closed
/// the previous connection, the next one is answered this way. A server
/// without a default export answers the same, so a caller that waits for
/// the export bounds its wait.
#[derive(Debug)]
pub struct ExportUnavailable(String);

impl std::fmt::Display for ExportUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExportUnavailable {}

/// Whether `error`, from [`negotiate`], is the server's answer that the
/// export is not available ([`ExportUnavailable`]).
pub fn export_unavailable(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<ExportUnavailable>())
}

/// Everything the client sends after a greeting that carried
/// `server_flags`: its own flags, then `NBD_OPT_GO` for the default export.
pub fn client_request(server_flags: u16) -> Vec<u8> {
    let mut client_flags = NBD_FLAG_C_FIXED_NEWSTYLE;
    // A flag the server did not offer makes nbdkit drop the connection.
    if server_flags & NBD_FLAG_NO_ZEROES != 0 {
        client_flags |= NBD_FLAG_C_NO_ZEROES;
    }
    let mut bytes = Vec::with_capacity(26);
    bytes.extend_from_slice(&client_flags.to_be_bytes());
    bytes.extend_from_slice(&IHAVEOPT.to_be_bytes());
    bytes.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
    // The option's data: an empty name (the default export), then no
    // information requests.
    bytes.extend_from_slice(&6u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes
}

/// Run the handshake on `stream`, which has just connected to the server,
/// and return the export once the server acknowledged `NBD_OPT_GO`: the
/// stream is then in the transmission phase. Every failure is final: the
/// caller drops the stream.
///
/// A protocol violation or refusal is `InvalidData`, a deadline that
/// passed `TimedOut` and a stream that ended early `UnexpectedEof`. The
/// refusal of an export that is not available is told apart by
/// [`export_unavailable`].
pub fn negotiate(stream: &UnixStream, deadline: Instant) -> io::Result<Export> {
    let mut session = Session {
        fd: stream.as_raw_fd(),
        deadline,
        read: 0,
    };
    let mut greeting = [0; 8];
    session.read(&mut greeting)?;
    if u64::from_be_bytes(greeting) != NBDMAGIC {
        return Err(invalid(
            "the server's greeting does not start with the NBD magic",
        ));
    }
    session.read(&mut greeting)?;
    match u64::from_be_bytes(greeting) {
        IHAVEOPT => {}
        OLDSTYLE_MAGIC => {
            return Err(invalid(
                "the server speaks the oldstyle protocol; fixed-newstyle negotiation is required",
            ))
        }
        _ => {
            return Err(invalid(
                "the server's greeting carries an unknown second magic",
            ))
        }
    }
    let mut flags = [0; 2];
    session.read(&mut flags)?;
    let server_flags = u16::from_be_bytes(flags);
    if server_flags & NBD_FLAG_FIXED_NEWSTYLE == 0 {
        return Err(invalid(
            "the server does not offer fixed-newstyle negotiation, which NBD_OPT_GO requires",
        ));
    }
    session.write(&client_request(server_flags))?;

    let mut export = None;
    loop {
        let mut header = [0; 20];
        session.read(&mut header)?;
        let word = |at: usize| u32::from_be_bytes(header[at..at + 4].try_into().unwrap());
        let (option, kind, length) = (word(8), word(12), word(16));
        if u64::from_be_bytes(header[..8].try_into().unwrap()) != REPLY_MAGIC {
            return Err(invalid("an option reply carries the wrong magic"));
        }
        if option != NBD_OPT_GO {
            return Err(invalid(format!(
                "the server replied to option {option}, which the client did not send"
            )));
        }
        // Checked before anything of the reply is read.
        if length > MAX_REPLY_LENGTH {
            return Err(invalid(format!(
                "the server announced a {length}-byte option reply, longer than the \
                 {MAX_REPLY_LENGTH}-byte limit"
            )));
        }
        let mut data = vec![0; length as usize];
        session.read(&mut data)?;
        match kind {
            NBD_REP_ACK if !data.is_empty() => {
                return Err(invalid(
                    "the server's acknowledgement of NBD_OPT_GO carries data",
                ))
            }
            NBD_REP_ACK => {
                return export.ok_or_else(|| {
                    invalid("the server acknowledged NBD_OPT_GO without NBD_INFO_EXPORT")
                })
            }
            NBD_REP_INFO => {
                let Some((info, value)) = data.split_first_chunk::<2>() else {
                    return Err(invalid(
                        "the server sent an information reply shorter than its type",
                    ));
                };
                // Information the client did not ask for is skipped.
                if u16::from_be_bytes(*info) != NBD_INFO_EXPORT {
                    continue;
                }
                let Ok(value) = <[u8; 10]>::try_from(value) else {
                    return Err(invalid(format!(
                        "the server sent a {}-byte NBD_INFO_EXPORT; it has 12 bytes",
                        data.len()
                    )));
                };
                if export.is_some() {
                    return Err(invalid("the server sent NBD_INFO_EXPORT more than once"));
                }
                let (size, flags) = value.split_at(8);
                export = Some(checked_export(
                    u64::from_be_bytes(size.try_into().unwrap()),
                    u16::from_be_bytes(flags.try_into().unwrap()),
                )?);
            }
            kind if kind & NBD_REP_FLAG_ERROR != 0 => {
                // The message is the daemon's text: not shown to root's log.
                let refusal = format!(
                    "the server refused NBD_OPT_GO with {} (its {}-byte message is not \
                     shown); NBD_OPT_EXPORT_NAME is not tried",
                    error_name(kind),
                    data.len()
                );
                return Err(if kind == NBD_REP_ERR_UNKNOWN {
                    io::Error::new(io::ErrorKind::InvalidData, ExportUnavailable(refusal))
                } else {
                    invalid(refusal)
                });
            }
            kind => {
                return Err(invalid(format!(
                    "the server sent reply type {kind} to NBD_OPT_GO"
                )))
            }
        }
    }
}

/// The export, if the kernel may use it.
fn checked_export(size: u64, flags: u16) -> io::Result<Export> {
    if size == 0 {
        return Err(invalid("the export's size is 0"));
    }
    if size > MAX_EXPORT_SIZE {
        return Err(invalid(format!(
            "the export's size {size} exceeds the kernel's limit of {MAX_EXPORT_SIZE} bytes"
        )));
    }
    let missing: Vec<&str> = [
        (NBD_FLAG_HAS_FLAGS, "NBD_FLAG_HAS_FLAGS"),
        (NBD_FLAG_SEND_FLUSH, "NBD_FLAG_SEND_FLUSH"),
        (NBD_FLAG_SEND_FUA, "NBD_FLAG_SEND_FUA"),
    ]
    .into_iter()
    .filter(|(flag, _)| flags & flag == 0)
    .map(|(_, name)| name)
    .collect();
    if !missing.is_empty() {
        return Err(invalid(format!(
            "the export does not advertise {} (transmission flags {flags:#06x}): Maki requires \
             SEND_FLUSH for durability, SEND_FUA by policy and HAS_FLAGS by the NBD protocol",
            missing.join(", ")
        )));
    }
    Ok(Export {
        size,
        transmission_flags: flags,
    })
}

fn error_name(kind: u32) -> String {
    let name = match kind {
        NBD_REP_ERR_UNSUP => "NBD_REP_ERR_UNSUP",
        NBD_REP_ERR_POLICY => "NBD_REP_ERR_POLICY",
        NBD_REP_ERR_INVALID => "NBD_REP_ERR_INVALID",
        NBD_REP_ERR_PLATFORM => "NBD_REP_ERR_PLATFORM",
        NBD_REP_ERR_TLS_REQD => "NBD_REP_ERR_TLS_REQD (TLS, which the kernel client cannot use)",
        NBD_REP_ERR_UNKNOWN => {
            "NBD_REP_ERR_UNKNOWN (the export is not available: busy with another connection, \
             or no default export)"
        }
        NBD_REP_ERR_SHUTDOWN => "NBD_REP_ERR_SHUTDOWN",
        NBD_REP_ERR_BLOCK_SIZE_REQD => "NBD_REP_ERR_BLOCK_SIZE_REQD",
        NBD_REP_ERR_TOO_BIG => "NBD_REP_ERR_TOO_BIG",
        NBD_REP_ERR_EXT_HEADER_REQD => {
            "NBD_REP_ERR_EXT_HEADER_REQD (extended headers, which the kernel client cannot use)"
        }
        _ => return format!("error {kind:#010x}"),
    };
    name.to_string()
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// One handshake's socket, its deadline and the bytes read so far.
struct Session {
    fd: RawFd,
    deadline: Instant,
    read: usize,
}

/// Wait until `events` is ready on `fd`, or fail with `TimedOut` once
/// `deadline` has passed; `what` names what did not finish.
pub(crate) fn wait_for(
    fd: RawFd,
    events: libc::c_short,
    deadline: Instant,
    what: &str,
) -> io::Result<()> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{what} did not finish by its deadline"),
            ));
        }
        // Rounded up: a wait never ends before the deadline.
        let milliseconds = i32::try_from(left.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX);
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the duration of the call.
        let ready = unsafe { libc::poll(&mut poll, 1, milliseconds) };
        if ready > 0 {
            return Ok(());
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

impl Session {
    fn wait(&self, events: libc::c_short) -> io::Result<()> {
        wait_for(self.fd, events, self.deadline, "the NBD handshake")
    }

    /// Fill `buffer`, within the deadline and the handshake's byte limit.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        if buffer.len() > MAX_HANDSHAKE_BYTES - self.read {
            return Err(invalid(format!(
                "the server's handshake exceeds the byte limit of {MAX_HANDSHAKE_BYTES} bytes"
            )));
        }
        let mut filled = 0;
        while filled < buffer.len() {
            self.wait(libc::POLLIN)?;
            let rest = &mut buffer[filled..];
            // SAFETY: the pointer and length describe the unfilled part of
            // `buffer`; MSG_DONTWAIT never blocks, whatever poll reported.
            let received = unsafe {
                libc::recv(
                    self.fd,
                    rest.as_mut_ptr().cast(),
                    rest.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            match usize::try_from(received) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the server closed the connection during the NBD handshake",
                    ))
                }
                Ok(count) => filled += count,
                Err(_) => retry_or_fail(io::Error::last_os_error())?,
            }
        }
        self.read += buffer.len();
        Ok(())
    }

    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let mut sent = 0;
        while sent < bytes.len() {
            self.wait(libc::POLLOUT)?;
            let rest = &bytes[sent..];
            // SAFETY: the pointer and length describe the unsent part of
            // `bytes`. MSG_NOSIGNAL: a closed peer is an error, not SIGPIPE.
            let written = unsafe {
                libc::send(
                    self.fd,
                    rest.as_ptr().cast(),
                    rest.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            match usize::try_from(written) {
                Ok(count) => sent += count,
                Err(_) => retry_or_fail(io::Error::last_os_error())?,
            }
        }
        Ok(())
    }
}

/// Waiting again is the answer to a socket that was not ready after all.
fn retry_or_fail(error: io::Error) -> io::Result<()> {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(()),
        _ => Err(error),
    }
}
