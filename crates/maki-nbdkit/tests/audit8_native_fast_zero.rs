//! Round-8 audit (native-nbdkit): a WRITE_ZEROES request that carries
//! NBD_CMD_FLAG_FAST_ZERO must be answered with an error (SPEC §48 "no fast
//! zero"; `docs/review-remediation.md` R5-036: "a FAST_ZERO request fails
//! with ENOTSUP"), and the daemon must keep serving.
//!
//! The plugin answers `can_fast_zero` with 0 and guards `zero_v2` with an
//! ENOTSUP return. nbdkit's `validate_request` does not look at the
//! advertised flag, and `backend_zero` asserts `c->can_fast_zero == 1`
//! (server/backend.c:752 in 1.36.3 and 1.38.5), so on an nbdkit built with
//! assertions the guard is never reached: the whole server aborts.
//!
//! Run: python3 -B scripts/run_cargo_tests.py --locked -p maki-nbdkit \
//!        --test audit8_native_fast_zero -- --nocapture
#![cfg(target_os = "linux")]

#[path = "support/native_plugin.rs"]
mod native_plugin;

#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/short_dir.rs"]
mod short_dir;

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(20);
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_WRITE_ZEROES: u16 = 6;
const NBD_CMD_FLAG_FAST_ZERO: u16 = 1 << 4;
const NBD_FLAG_SEND_FAST_ZERO: u16 = 1 << 11;

fn nbdkit_available() -> bool {
    match Command::new("nbdkit").arg("--version").output() {
        Ok(output) => output.status.success(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            assert!(
                std::env::var_os("MAKI_TEST_REQUIRE_NBDKIT").is_none(),
                "nbdkit is required"
            );
            eprintln!("nbdkit unavailable; skipping");
            false
        }
        Err(error) => panic!("nbdkit probe failed: {error}"),
    }
}

/// Newstyle handshake with NBD_OPT_GO on the default export; returns the
/// transmission flags.
fn handshake(stream: &mut UnixStream) -> u16 {
    let mut hello = [0u8; 18];
    stream.read_exact(&mut hello).unwrap();
    assert_eq!(&hello[..16], b"NBDMAGICIHAVEOPT");
    stream.write_all(&3u32.to_be_bytes()).unwrap(); // FIXED_NEWSTYLE | NO_ZEROES
    let mut option = Vec::new();
    option.extend_from_slice(b"IHAVEOPT");
    option.extend_from_slice(&7u32.to_be_bytes()); // NBD_OPT_GO
    option.extend_from_slice(&6u32.to_be_bytes());
    option.extend_from_slice(&0u32.to_be_bytes()); // export name length
    option.extend_from_slice(&0u16.to_be_bytes()); // no information requests
    stream.write_all(&option).unwrap();
    let mut flags = None;
    loop {
        let mut header = [0u8; 20];
        stream.read_exact(&mut header).unwrap();
        let kind = u32::from_be_bytes(header[12..16].try_into().unwrap());
        let length = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).unwrap();
        match kind {
            1 => return flags.expect("NBD_INFO_EXPORT before the acknowledgement"),
            3 if body.len() >= 12 && body[..2] == [0, 0] => {
                flags = Some(u16::from_be_bytes(body[10..12].try_into().unwrap()));
            }
            3 => {}
            other => panic!("option refused: {other:#x}"),
        }
    }
}

fn request(stream: &mut UnixStream, flags: u16, kind: u16, cookie: u64, offset: u64, payload: &[u8], length: u32) {
    let mut bytes = Vec::with_capacity(28 + payload.len());
    bytes.extend_from_slice(&0x2560_9513u32.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&cookie.to_be_bytes());
    bytes.extend_from_slice(&offset.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
    stream.write_all(&bytes).unwrap();
}

/// A simple reply's error number, or `None` when the server went away.
fn reply(stream: &mut UnixStream) -> Option<u32> {
    let mut bytes = [0u8; 16];
    match stream.read_exact(&mut bytes) {
        Ok(()) => {
            assert_eq!(u32::from_be_bytes(bytes[..4].try_into().unwrap()), 0x6744_6698);
            Some(u32::from_be_bytes(bytes[4..8].try_into().unwrap()))
        }
        Err(_) => None,
    }
}

#[test]
fn an_unadvertised_fast_zero_request_is_refused_and_the_daemon_keeps_serving() {
    if !nbdkit_available() {
        return;
    }
    let directory = short_dir::tempdir().unwrap();
    let root = directory.path().join("volume");
    let config = directory.path().join("volume.toml");
    let socket = directory.path().join("nbd.sock");
    let control = directory.path().join("control.sock");
    let raw = format!(
        r#"
config_schema_version = 1
[volume]
name = "audit8-fast-zero"
max_virtual_size = "2MiB"
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = {root:?}
[control]
socket = {control:?}
"#
    );
    volume_config::write(&config, &raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();

    let notify_path = directory.path().join("notify.sock");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    notify.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let log = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
    let mut server = Command::new("nbdkit")
        .args(["--foreground", "--exit-with-parent", "-U"])
        .arg(&socket)
        .arg(native_plugin::path())
        .arg(format!("config={}", config.display()))
        .env("NOTIFY_SOCKET", &notify_path)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(log.reopen().unwrap())
        .stderr(log.reopen().unwrap())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        let mut bytes = [0u8; 256];
        if let Ok(count) = notify.recv(&mut bytes) {
            if bytes[..count].split(|b| *b == b'\n').any(|line| line == b"READY=1") {
                break;
            }
        }
        assert!(server.try_wait().unwrap().is_none(), "nbdkit exited before READY");
        assert!(started.elapsed() < DEADLINE, "READY deadline");
    }

    let mut stream = UnixStream::connect(&socket).unwrap();
    stream.set_read_timeout(Some(DEADLINE)).unwrap();
    let flags = handshake(&mut stream);
    assert_eq!(flags & NBD_FLAG_SEND_FAST_ZERO, 0, "fast zero is not advertised");

    // An ordinary FUA write first: the connection works.
    request(&mut stream, 1, NBD_CMD_WRITE, 1, 0, &[0xA5; 4096], 4096);
    assert_eq!(reply(&mut stream), Some(0));

    // The request under test.
    request(&mut stream, NBD_CMD_FLAG_FAST_ZERO, NBD_CMD_WRITE_ZEROES, 2, 0, &[], 4096);
    let answer = reply(&mut stream);
    std::thread::sleep(Duration::from_millis(300));
    let exited = server.try_wait().unwrap();
    let mut text = String::new();
    log.reopen().unwrap().read_to_string(&mut text).unwrap();
    unsafe { libc::kill(-(server.id() as i32), libc::SIGKILL) };
    let _ = server.wait();
    assert!(
        exited.is_none(),
        "one FAST_ZERO request terminated the daemon (signal {:?}); client saw {answer:?}; nbdkit log: {text}",
        exited.and_then(|status| status.signal()),
    );
    // NBD_ENOTSUP is 95; EINVAL (22) would also be a refusal.
    assert!(
        matches!(answer, Some(95 | 22)),
        "FAST_ZERO must be refused with an error reply, got {answer:?}"
    );
}
