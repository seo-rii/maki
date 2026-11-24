//! A WRITE_ZEROES request with `NBD_CMD_FLAG_FAST_ZERO` against Maki's
//! plugin in a real nbdkit: the request is refused with `NBD_ENOTSUP`, the
//! export is unchanged, and the server keeps serving.
//!
//! nbdkit does not check that a client's FAST_ZERO flag was advertised:
//! `validate_request` (server/protocol.c) accepts it on every WRITE_ZEROES
//! request, and `backend_zero` (server/backend.c) then asserts that the
//! plugin answered `can_fast_zero` with 1. A plugin that answers 0 therefore
//! lets one request abort the whole server (the code is the same in 1.32.5,
//! 1.36.3 and 1.38.5). The plugin advertises fast zero for that reason only
//! and refuses every such request itself, which the NBD protocol allows
//! ("a fast failure of `NBD_ENOTSUP` still counts as a fast response").
//!
//! The handshake is the privileged helper's own source, compiled here by
//! path, as in `review_helper_nbd_handshake.rs`. Without nbdkit the tests
//! are skipped with a notice; `MAKI_TEST_REQUIRE_NBDKIT=1` makes that a
//! failure.
#![cfg(target_os = "linux")]

#[path = "support/native_plugin.rs"]
mod native_plugin;

#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/short_dir.rs"]
mod short_dir;

#[allow(dead_code)]
#[path = "../../maki-privileged/src/nbd_kernel/handshake.rs"]
mod handshake;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use handshake::{
    NBD_FLAG_HAS_FLAGS, NBD_FLAG_SEND_FLUSH, NBD_FLAG_SEND_FUA, NBD_FLAG_SEND_TRIM,
    NBD_FLAG_SEND_WRITE_ZEROES,
};

const REQUIRE: &str = "MAKI_TEST_REQUIRE_NBDKIT";
const DEADLINE: Duration = Duration::from_secs(30);

/// Bit 11 of the transmission flags (NBD protocol, "Transmission flags").
const NBD_FLAG_SEND_FAST_ZERO: u16 = 1 << 11;

const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_WRITE_ZEROES: u16 = 6;
const NBD_CMD_FLAG_FUA: u16 = 1 << 0;
const NBD_CMD_FLAG_NO_HOLE: u16 = 1 << 1;
const NBD_CMD_FLAG_FAST_ZERO: u16 = 1 << 4;
const NBD_ENOTSUP: u32 = 95;

const UNIT: usize = 4096;
const EXPORT_SIZE: u64 = 2 << 20;

fn nbdkit_available(test: &str) -> bool {
    let reason = match Command::new("nbdkit").arg("--version").output() {
        Ok(output) if output.status.success() => return true,
        Ok(output) => format!("`nbdkit --version` exited with {}", output.status),
        Err(error) => format!("nbdkit cannot run ({error})"),
    };
    assert!(
        std::env::var_os(REQUIRE).is_none_or(|value| value != "1"),
        "{REQUIRE}=1, but {reason}"
    );
    eprintln!("{test}: skipped: {reason} (set {REQUIRE}=1 to fail instead)");
    false
}

fn config(root: &Path, control: &Path) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "fast-zero"
max_virtual_size = "2MiB"
device_block_size = 4096
crypto_unit_size = 4096
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = {}
journal_emergency_reserve_bytes = "0B"
[control]
socket = {}
"#,
        serde_json::to_string(root.to_str().unwrap()).unwrap(),
        serde_json::to_string(control.to_str().unwrap()).unwrap()
    )
}

/// Maki's plugin serving a new fake-provider volume, with or without
/// discard, on a private socket.
struct Daemon {
    directory: tempfile::TempDir,
    child: Child,
    socket: PathBuf,
}

impl Daemon {
    fn start(discard: bool) -> Self {
        let directory = short_dir::tempdir().unwrap();
        let raw = config(
            &directory.path().join("volume"),
            &directory.path().join("control.sock"),
        );
        let config_path = directory.path().join("volume.toml");
        volume_config::write(&config_path, &raw).unwrap();
        if discard {
            maki_nbdkit::daemon::create_volume_with_discard_from_config_str(&raw).unwrap();
        } else {
            maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        }
        let socket = directory.path().join("nbd.sock");
        let pid_file = directory.path().join("nbdkit.pid");
        let log = std::fs::File::create(directory.path().join("nbdkit.log")).unwrap();
        let child = Command::new("nbdkit")
            .args(["--foreground", "--exit-with-parent", "-U"])
            .arg(&socket)
            .arg("-P")
            .arg(&pid_file)
            .arg(native_plugin::path())
            .arg(format!("config={}", config_path.display()))
            .env_remove("NOTIFY_SOCKET")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("start nbdkit");
        let mut daemon = Self {
            directory,
            child,
            socket,
        };
        // nbdkit writes its PID file once its socket is bound, before the
        // plugin starts up; a connection made from then on waits in the
        // listen backlog until the plugin is ready.
        let started = Instant::now();
        while !std::fs::read_to_string(&pid_file).is_ok_and(|pid| pid.ends_with('\n')) {
            if let Some(status) = daemon.child.try_wait().unwrap() {
                panic!("nbdkit exited with {status}: {}", daemon.log());
            }
            assert!(
                started.elapsed() < DEADLINE,
                "nbdkit did not start: {}",
                daemon.log()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        daemon
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.path().join("nbdkit.log")).unwrap_or_default()
    }

    /// A connection in the transmission phase, and the export it serves.
    fn connect(&self) -> (UnixStream, handshake::Export) {
        let stream = UnixStream::connect(&self.socket).unwrap();
        let export = handshake::negotiate(&stream, Instant::now() + DEADLINE)
            .unwrap_or_else(|error| panic!("{error}: {}", self.log()));
        stream.set_read_timeout(Some(DEADLINE)).unwrap();
        stream.set_write_timeout(Some(DEADLINE)).unwrap();
        (stream, export)
    }

    /// How the server ended, if it did.
    fn ended(&mut self) -> Option<String> {
        // A server that aborts does so right after the request.
        std::thread::sleep(Duration::from_millis(200));
        self.child
            .try_wait()
            .unwrap()
            .map(|status| format!("{status}; log: {}", self.log()))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Send one request; `payload` is empty for everything but a write.
fn send(
    stream: &mut UnixStream,
    command: u16,
    flags: u16,
    offset: u64,
    length: u32,
    payload: &[u8],
) {
    let mut bytes = Vec::with_capacity(28 + payload.len());
    bytes.extend_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&command.to_be_bytes());
    bytes.extend_from_slice(&0x6d61_6b69u64.to_be_bytes());
    bytes.extend_from_slice(&offset.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
    stream.write_all(&bytes).unwrap();
}

/// The error number of the simple reply to the last request, or why there
/// is no reply.
fn reply(stream: &mut UnixStream) -> Result<u32, String> {
    let mut header = [0u8; 16];
    stream
        .read_exact(&mut header)
        .map_err(|error| format!("no reply: {error}"))?;
    let magic = u32::from_be_bytes(header[..4].try_into().unwrap());
    if magic != NBD_SIMPLE_REPLY_MAGIC {
        return Err(format!("reply magic {magic:#010x}"));
    }
    Ok(u32::from_be_bytes(header[4..8].try_into().unwrap()))
}

fn write(stream: &mut UnixStream, offset: u64, data: &[u8]) {
    send(
        stream,
        NBD_CMD_WRITE,
        NBD_CMD_FLAG_FUA,
        offset,
        data.len() as u32,
        data,
    );
    assert_eq!(reply(stream), Ok(0), "write at {offset}");
}

fn read(stream: &mut UnixStream, offset: u64, length: usize) -> Vec<u8> {
    send(stream, NBD_CMD_READ, 0, offset, length as u32, &[]);
    assert_eq!(reply(stream), Ok(0), "read at {offset}");
    let mut data = vec![0u8; length];
    stream.read_exact(&mut data).unwrap();
    data
}

#[test]
fn a_fast_zero_request_is_refused_with_enotsup_and_changes_nothing() {
    if !nbdkit_available("a_fast_zero_request_is_refused_with_enotsup_and_changes_nothing") {
        return;
    }
    for discard in [false, true] {
        let mut daemon = Daemon::start(discard);
        let (mut stream, _) = daemon.connect();
        let written: Vec<u8> = (0..4 * UNIT).map(|index| (index % 251) as u8 + 1).collect();
        write(&mut stream, 0, &written);

        // Whole units, a range that ends inside the data, and the whole
        // export: a refusal does not depend on the length.
        for (offset, length) in [
            (UNIT as u64, 2 * UNIT as u32),
            (0, UNIT as u32),
            (0, EXPORT_SIZE as u32),
        ] {
            for extra in [0, NBD_CMD_FLAG_NO_HOLE, NBD_CMD_FLAG_FUA] {
                let flags = NBD_CMD_FLAG_FAST_ZERO | extra;
                send(
                    &mut stream,
                    NBD_CMD_WRITE_ZEROES,
                    flags,
                    offset,
                    length,
                    &[],
                );
                let answer = reply(&mut stream);
                if let Some(end) = answer.is_err().then(|| daemon.ended()).flatten() {
                    panic!(
                        "discard {discard}: a fast zero request (flags {flags:#x}, {offset}+{length}) \
                         ended the server: {end}"
                    );
                }
                assert_eq!(
                    answer,
                    Ok(NBD_ENOTSUP),
                    "discard {discard}: fast zero (flags {flags:#x}, {offset}+{length}) must fail \
                     with NBD_ENOTSUP"
                );
            }
        }
        assert!(
            read(&mut stream, 0, written.len()) == written,
            "discard {discard}: a refused fast zero changed the export"
        );

        // The same request without the flag is served.
        send(
            &mut stream,
            NBD_CMD_WRITE_ZEROES,
            NBD_CMD_FLAG_FUA,
            UNIT as u64,
            2 * UNIT as u32,
            &[],
        );
        assert_eq!(reply(&mut stream), Ok(0), "discard {discard}: plain zero");
        let mut expected = written.clone();
        expected[UNIT..3 * UNIT].fill(0);
        assert!(
            read(&mut stream, 0, expected.len()) == expected,
            "discard {discard}: a zero without the flag must zero exactly its range"
        );
        assert_eq!(
            daemon.ended(),
            None,
            "discard {discard}: the server must still be running"
        );
    }
}

/// The helper forwards these flags to the kernel unchanged (SPEC §6), so
/// the exact word is pinned: fast zero is the one bit beyond what the Linux
/// NBD driver reads.
#[test]
fn the_export_advertises_fast_zero_next_to_its_other_flags() {
    if !nbdkit_available("the_export_advertises_fast_zero_next_to_its_other_flags") {
        return;
    }
    for discard in [false, true] {
        let daemon = Daemon::start(discard);
        let (_stream, export) = daemon.connect();
        let mut expected = NBD_FLAG_HAS_FLAGS
            | NBD_FLAG_SEND_FLUSH
            | NBD_FLAG_SEND_FUA
            | NBD_FLAG_SEND_WRITE_ZEROES
            | NBD_FLAG_SEND_FAST_ZERO;
        if discard {
            expected |= NBD_FLAG_SEND_TRIM;
        }
        assert_eq!(
            export.transmission_flags, expected,
            "discard {discard}: {:#06x} != {expected:#06x}",
            export.transmission_flags
        );
        assert_eq!(export.size, EXPORT_SIZE);
    }
}
