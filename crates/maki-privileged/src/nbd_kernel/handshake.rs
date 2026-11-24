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

/// What an export must advertise before the kernel may use it. Without
/// `SEND_FLUSH` the kernel completes a FLUSH without sending it, and
/// without `SEND_FUA` it completes a FUA write's durability promise the
/// same way: the filesystem's barriers would never reach the journal.
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

/// Everything the client sends after a greeting that carried
/// `server_flags`: its own flags, then `NBD_OPT_GO` for the default export.
pub fn client_request(server_flags: u16) -> Vec<u8> {
    let _ = server_flags;
    todo!("client_request")
}

/// Run the handshake on `stream`, which has just connected to the server,
/// and return the export once the server acknowledged `NBD_OPT_GO`: the
/// stream is then in the transmission phase. Every failure is final: the
/// caller drops the stream.
///
/// A protocol violation or refusal is `InvalidData`, a deadline that
/// passed `TimedOut` and a stream that ended early `UnexpectedEof`.
pub fn negotiate(stream: &UnixStream, deadline: Instant) -> io::Result<Export> {
    let _ = (stream, deadline);
    todo!("negotiate")
}
