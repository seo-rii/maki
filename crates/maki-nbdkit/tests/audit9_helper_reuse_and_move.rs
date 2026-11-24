//! Round-9 audit (slug `r8-privileged`): the daemon's side of what #383 made
//! the helper do on a busy device, against Maki's own plugin in a real
//! nbdkit. No kernel NBD device is involved: the test stands where the
//! kernel would and speaks the transmission phase itself.
//!
//! - While the kernel answers `EBUSY`, the helper keeps the connection it
//!   negotiated and looks at it before every request (`nbd_kernel::idle`,
//!   copied below: the function is crate-private). The daemon must leave an
//!   idle negotiated connection alone for the whole five-second window, and
//!   must serve it afterwards as if nothing had happened.
//! - When a device stays busy, the helper drops that connection without an
//!   `NBD_CMD_DISC` and negotiates again for the next device. The plugin
//!   serves one connection and nbdkit closes one a moment after its peer
//!   did, so the next handshake can be refused (`NBD_REP_ERR_UNKNOWN`); the
//!   helper retries that every 100 ms for up to five seconds.
//!
//! The support code is a copy of `review_helper_nbd_handshake.rs`'s; the
//! handshake is the helper's own source, compiled by path.
//! Run with `MAKI_TEST_REQUIRE_NBDKIT=1 cargo test -p maki-nbdkit --locked
//! --test audit9_helper_reuse_and_move -- --test-threads=2 --nocapture`.
#![cfg(target_os = "linux")]
#![allow(dead_code)]

#[path = "support/native_plugin.rs"]
mod native_plugin;

#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/short_dir.rs"]
mod short_dir;

#[allow(dead_code)]
#[path = "../../maki-privileged/src/nbd_kernel/handshake.rs"]
mod handshake;

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};


const REQUIRE: &str = "MAKI_TEST_REQUIRE_NBDKIT";
const DEADLINE: Duration = Duration::from_secs(30);

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
name = "audit9-reuse"
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
        // nbdkit writes its PID file once it accepts connections.
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

    fn negotiate(&self) -> handshake::Export {
        let stream = UnixStream::connect(&self.socket).unwrap();
        handshake::negotiate(&stream, Instant::now() + DEADLINE)
            .unwrap_or_else(|error| panic!("{error}: {}", self.log()))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}


use std::io::{Read, Write};
use std::os::fd::AsRawFd;

/// `maki_privileged::nbd_kernel::idle`, verbatim: open, with nothing to read.
fn idle(stream: &UnixStream) -> bool {
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
            return false;
        }
        match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::WouldBlock => return true,
            std::io::ErrorKind::Interrupted => {}
            _ => return false,
        }
    }
}

const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;

/// One request as the kernel's client sends it, and its simple reply.
fn request(
    stream: &mut UnixStream,
    command: u16,
    cookie: u64,
    offset: u64,
    length: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&command.to_be_bytes());
    bytes.extend_from_slice(&cookie.to_be_bytes());
    bytes.extend_from_slice(&offset.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
    stream.write_all(&bytes).unwrap();
    let mut reply = [0u8; 16];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(
        u32::from_be_bytes(reply[..4].try_into().unwrap()),
        NBD_SIMPLE_REPLY_MAGIC,
        "the first bytes after the handshake are not a reply: {reply:02x?}"
    );
    assert_eq!(u32::from_be_bytes(reply[4..8].try_into().unwrap()), 0, "error");
    assert_eq!(u64::from_be_bytes(reply[8..].try_into().unwrap()), cookie);
    let mut data = vec![0u8; if command == NBD_CMD_READ { length as usize } else { 0 }];
    stream.read_exact(&mut data).unwrap();
    data
}

fn open(daemon: &Daemon) -> std::io::Result<(UnixStream, handshake::Export)> {
    let stream = UnixStream::connect(&daemon.socket)?;
    handshake::negotiate(&stream, Instant::now() + DEADLINE).map(|export| (stream, export))
}

/// The helper's wait for an export that is not available: every 100 ms for
/// up to five seconds. Returns the connection and how often it was refused.
fn open_retrying(daemon: &Daemon) -> (UnixStream, handshake::Export, u32) {
    let started = Instant::now();
    let mut refused = 0;
    loop {
        match open(daemon) {
            Ok((stream, export)) => return (stream, export, refused),
            Err(error) => {
                assert!(
                    handshake::export_unavailable(&error),
                    "a refusal the helper takes for final: {error}: {}",
                    daemon.log()
                );
                refused += 1;
                assert!(
                    started.elapsed() + Duration::from_millis(100) < Duration::from_secs(5),
                    "the export stayed unavailable for the helper's whole window: {}",
                    daemon.log()
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// A connection the helper negotiated and then held through the kernel's
/// busy answers: the daemon sends nothing and does not close it for the
/// whole window, and then serves it.
#[test]
fn audit9_an_idle_negotiated_connection_survives_the_busy_window() {
    if !nbdkit_available("audit9_an_idle_negotiated_connection_survives_the_busy_window") {
        return;
    }
    let daemon = Daemon::start(false);
    let (mut stream, export) = open(&daemon).unwrap_or_else(|error| panic!("{error}: {}", daemon.log()));
    let held = Instant::now();
    let mut looks = 0;
    while held.elapsed() < Duration::from_millis(5200) {
        assert!(
            idle(&stream),
            "after {:?} the negotiated connection is no longer what the handshake left: {}",
            held.elapsed(),
            daemon.log()
        );
        looks += 1;
        std::thread::sleep(Duration::from_millis(100));
    }
    // The peek consumed nothing: the next bytes are the reply to the first
    // request, as the kernel would read them.
    let block = vec![0xA5u8; 4096];
    request(&mut stream, NBD_CMD_WRITE, 1, 0, 4096, &block);
    request(&mut stream, NBD_CMD_FLUSH, 2, 0, 0, &[]);
    assert_eq!(request(&mut stream, NBD_CMD_READ, 3, 0, 4096, &[]), block);
    assert!(idle(&stream));
    println!("held {:?}, {looks} looks, export {} bytes", held.elapsed(), export.size);
}

/// The move: the helper drops the connection it negotiated for the busy
/// device, without a disconnect request, and negotiates again for the next
/// one. The next handshake is served within the helper's wait, however
/// often; the connection it gets is served; and a connection the kernel
/// shut down without `NBD_CMD_DISC` frees the export the same way.
#[test]
fn audit9_a_dropped_connection_frees_the_export_for_the_next_device() {
    if !nbdkit_available("audit9_a_dropped_connection_frees_the_export_for_the_next_device") {
        return;
    }
    let daemon = Daemon::start(false);
    let (mut refusals, mut most) = (0, 0);
    let mut cookie = 10;
    for round in 0..40u64 {
        // The connection for the device that stays busy.
        let (first, _, refused) = open_retrying(&daemon);
        refusals += refused;
        most = most.max(refused);
        if round % 2 == 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(idle(&first), "round {round}: {}", daemon.log());
        // Given up: closed, and the next negotiation follows at once.
        drop(first);
        let (mut second, _, refused) = open_retrying(&daemon);
        refusals += refused;
        most = most.max(refused);
        let block = vec![round as u8 + 1; 4096];
        cookie += 1;
        request(&mut second, NBD_CMD_WRITE, cookie, 4096 * (round % 8), 4096, &block);
        cookie += 1;
        assert_eq!(
            request(&mut second, NBD_CMD_READ, cookie, 4096 * (round % 8), 4096, &[]),
            block,
            "round {round}"
        );
        if round % 3 == 0 {
            // A clean disconnect, as NBD_CMD_DISCONNECT makes the kernel send.
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
            bytes.extend_from_slice(&0u16.to_be_bytes());
            bytes.extend_from_slice(&NBD_CMD_DISC.to_be_bytes());
            bytes.extend_from_slice(&0u64.to_be_bytes());
            bytes.extend_from_slice(&0u64.to_be_bytes());
            bytes.extend_from_slice(&0u32.to_be_bytes());
            second.write_all(&bytes).unwrap();
        } else {
            // A socket shut down in both directions, as the kernel does to a
            // connection it gives up.
            second.shutdown(std::net::Shutdown::Both).unwrap();
        }
    }
    println!("80 handshakes: {refusals} refused as unavailable and retried, at most {most} in a row");
    assert!(most < 10, "{most} refusals in a row");
}
