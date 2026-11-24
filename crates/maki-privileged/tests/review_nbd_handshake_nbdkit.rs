//! The helper's NBD handshake against a real nbdkit, unprivileged: the
//! socket connect, fixed-newstyle negotiation and `NBD_OPT_GO` that
//! `maki-attach` runs before it hands the socket to the kernel. Exports
//! that do not advertise FLUSH and FUA are refused here, before any kernel
//! could see them (SPEC §6).
#![cfg(target_os = "linux")]

#[path = "support/nbdkit.rs"]
mod nbdkit;

use std::time::{Duration, Instant};

use maki_privileged::nbd_kernel::handshake::{
    NBD_FLAG_READ_ONLY, NBD_FLAG_SEND_FLUSH, NBD_FLAG_SEND_FUA, REQUIRED_TRANSMISSION_FLAGS,
};
use maki_privileged::nbd_kernel::{open_export, NbdError};

const DEADLINE: Duration = Duration::from_secs(20);

/// An eval-plugin export whose FLUSH and FUA support the arguments decide.
fn eval_export<'a>(flush: &'a str, fua: &'a str) -> Vec<&'a str> {
    vec![
        "eval",
        "get_size=echo 1048576",
        "pread=dd if=/dev/zero count=$3 iflag=count_bytes status=none",
        "pwrite=cat >/dev/null",
        "can_write=exit 0",
        flush,
        "flush=exit 0",
        fua,
    ]
}

#[test]
fn the_helper_negotiates_an_nbdkit_memory_export() {
    if !nbdkit::available("the_helper_negotiates_an_nbdkit_memory_export") {
        return;
    }
    let server = nbdkit::Server::start(&["memory", "1M"]);
    let (stream, export) = open_export(server.socket(), Instant::now() + DEADLINE)
        .unwrap_or_else(|error| panic!("{error}: {}", server.log()));
    assert_eq!(export.size, 1 << 20);
    assert_eq!(
        export.transmission_flags & REQUIRED_TRANSMISSION_FLAGS,
        REQUIRED_TRANSMISSION_FLAGS,
        "{:#06x}",
        export.transmission_flags
    );
    assert_eq!(export.transmission_flags & NBD_FLAG_READ_ONLY, 0);
    drop(stream);
}

#[test]
fn a_real_export_without_flush_or_fua_is_refused() {
    if !nbdkit::available("a_real_export_without_flush_or_fua_is_refused") {
        return;
    }
    for (arguments, missing) in [
        (
            eval_export("can_flush=exit 3", "can_fua=echo native"),
            "NBD_FLAG_SEND_FLUSH",
        ),
        (
            eval_export("can_flush=exit 0", "can_fua=echo none"),
            "NBD_FLAG_SEND_FUA",
        ),
    ] {
        let server = nbdkit::Server::start(&arguments);
        match open_export(server.socket(), Instant::now() + DEADLINE) {
            Err(NbdError::Failed(message)) => {
                assert!(message.contains(missing), "{message}");
            }
            Err(error) => panic!("{error}: {}", server.log()),
            Ok((_, export)) => panic!(
                "accepted an export with flags {:#06x}",
                export.transmission_flags
            ),
        }
    }
    // The same plugin with both is accepted: the refusals were the flags'.
    let server = nbdkit::Server::start(&eval_export("can_flush=exit 0", "can_fua=echo native"));
    let (_, export) = open_export(server.socket(), Instant::now() + DEADLINE)
        .unwrap_or_else(|error| panic!("{error}: {}", server.log()));
    assert_ne!(export.transmission_flags & NBD_FLAG_SEND_FLUSH, 0);
    assert_ne!(export.transmission_flags & NBD_FLAG_SEND_FUA, 0);
}
