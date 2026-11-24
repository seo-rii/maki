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
use std::os::unix::net::UnixStream;
use std::time::Instant;

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

/// Connect `/dev/nbd<index>` to the export behind `socket`, with
/// `block_size` as its logical block size and `identifier` as its kernel
/// backend identifier.
pub fn connect(
    socket: &str,
    index: u32,
    block_size: u32,
    identifier: &str,
) -> Result<(), NbdError> {
    let _ = (socket, index, block_size, identifier);
    todo!("connect")
}

/// Disconnect `/dev/nbd<index>`.
pub fn disconnect(index: u32) -> Result<(), NbdError> {
    let _ = index;
    todo!("disconnect")
}

/// Connect to the NBD socket at `path` and negotiate the default export by
/// `deadline`. The stream returned is blocking, close-on-exec and has no
/// socket timeouts: it is ready to be handed to the kernel.
pub fn open_export(
    path: &str,
    deadline: Instant,
) -> Result<(UnixStream, handshake::Export), NbdError> {
    let _ = (path, deadline);
    todo!("open_export")
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
    let _ = (index, block_size, identifier, export, socket);
    todo!("connect_attributes")
}

#[cfg(test)]
mod handshake_tests;

#[cfg(test)]
mod netlink_tests;

#[cfg(test)]
mod header_tests;

#[cfg(test)]
mod tests;
