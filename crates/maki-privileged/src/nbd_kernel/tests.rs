//! Connect and disconnect around the handshake and netlink: what reaches
//! the kernel, the socket it is handed, and the time limits. Nothing here
//! sends a request to the kernel's `nbd` family.

use super::handshake::{
    Export, NBD_FLAG_FIXED_NEWSTYLE, NBD_FLAG_HAS_FLAGS, NBD_FLAG_SEND_FLUSH, NBD_FLAG_SEND_FUA,
    NBD_FLAG_SEND_TRIM, NBD_FLAG_SEND_WRITE_ZEROES, NBD_INFO_EXPORT, NBD_OPT_GO, NBD_REP_ACK,
    NBD_REP_ERR_POLICY, NBD_REP_ERR_UNKNOWN, NBD_REP_INFO, REPLY_MAGIC,
};
use super::*;

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

const IDENTIFIER: &str = "maki-0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";
const FLAGS: u16 =
    NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA | NBD_FLAG_SEND_WRITE_ZEROES;
const PATIENCE: Duration = Duration::from_secs(10);

static DIRECTORIES: AtomicU64 = AtomicU64::new(0);

/// A private directory for one listener, removed when dropped.
struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        // A Unix socket path holds at most 107 bytes.
        let temp = std::env::temp_dir();
        let parent = if temp.as_os_str().len() <= 60 {
            temp
        } else {
            PathBuf::from("/tmp")
        };
        let path = parent.join(format!(
            "maki-nbdk-{}-{}",
            std::process::id(),
            DIRECTORIES.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn socket(&self) -> String {
        self.0.join("nbd.sock").to_str().unwrap().to_string()
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn reply(kind: u32, data: &[u8]) -> Vec<u8> {
    let mut bytes = REPLY_MAGIC.to_be_bytes().to_vec();
    bytes.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

fn greeting() -> Vec<u8> {
    let mut bytes = b"NBDMAGICIHAVEOPT".to_vec();
    bytes.extend_from_slice(&NBD_FLAG_FIXED_NEWSTYLE.to_be_bytes());
    bytes
}

fn export_script(size: u64, flags: u16) -> Vec<u8> {
    let mut data = NBD_INFO_EXPORT.to_be_bytes().to_vec();
    data.extend_from_slice(&size.to_be_bytes());
    data.extend_from_slice(&flags.to_be_bytes());
    [
        greeting(),
        reply(NBD_REP_INFO, &data),
        reply(NBD_REP_ACK, &[]),
    ]
    .concat()
}

/// Accept one connection on `socket`, write `script` and return whether
/// the client closed its end within [`PATIENCE`]: the read ends, or is
/// reset because the client left some of the script unread.
fn serve_once(socket: &str, script: Vec<u8>) -> thread::JoinHandle<bool> {
    let listener = UnixListener::bind(socket).unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.write_all(&script);
        stream.set_read_timeout(Some(PATIENCE)).unwrap();
        let mut rest = Vec::new();
        match stream.read_to_end(&mut rest) {
            Ok(_) => true,
            Err(error) => error.kind() == std::io::ErrorKind::ConnectionReset,
        }
    })
}

fn descriptor_flags(fd: i32) -> (bool, bool) {
    // SAFETY: F_GETFD and F_GETFL on an open descriptor.
    let (fd_flags, status) = unsafe {
        (
            libc::fcntl(fd, libc::F_GETFD),
            libc::fcntl(fd, libc::F_GETFL),
        )
    };
    assert!(fd_flags >= 0 && status >= 0);
    (
        fd_flags & libc::FD_CLOEXEC != 0,
        status & libc::O_NONBLOCK != 0,
    )
}

fn socket_timeout(fd: i32, option: i32) -> (libc::time_t, libc::suseconds_t) {
    let mut value = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut length = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: value and length describe a writable timeval.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::timeval).cast(),
            &mut length,
        )
    };
    assert_eq!(rc, 0);
    (value.tv_sec, value.tv_usec)
}

#[test]
fn the_kernel_gets_the_negotiated_size_and_flags_unchanged() {
    for flags in [FLAGS, FLAGS | NBD_FLAG_SEND_TRIM, 0xffff] {
        let export = Export {
            size: 3 << 30,
            transmission_flags: flags,
        };
        assert_eq!(
            connect_attributes(5, 512, IDENTIFIER, export, 9),
            netlink::Connect {
                index: 5,
                size: 3 << 30,
                block_size: 512,
                server_flags: u64::from(flags),
                socket: 9,
                identifier: IDENTIFIER,
            }
        );
    }
}

#[test]
fn an_export_is_opened_on_a_blocking_close_on_exec_socket_without_timeouts() {
    let directory = Directory::new();
    let socket = directory.socket();
    let server = serve_once(&socket, export_script(1 << 20, FLAGS));
    let (stream, export) = open_export(&socket, Instant::now() + PATIENCE).unwrap();
    assert_eq!(
        export,
        Export {
            size: 1 << 20,
            transmission_flags: FLAGS,
        }
    );
    let fd = stream.as_raw_fd();
    assert_eq!(
        descriptor_flags(fd),
        (true, false),
        "(FD_CLOEXEC, O_NONBLOCK)"
    );
    // The kernel's I/O on this socket must never time out by itself.
    assert_eq!(socket_timeout(fd, libc::SO_RCVTIMEO), (0, 0), "SO_RCVTIMEO");
    assert_eq!(socket_timeout(fd, libc::SO_SNDTIMEO), (0, 0), "SO_SNDTIMEO");
    drop(stream);
    assert!(server.join().unwrap());
}

#[test]
fn a_refused_handshake_closes_the_socket_and_names_the_reason() {
    let directory = Directory::new();
    let socket = directory.socket();
    for script in [
        [greeting(), reply(NBD_REP_ERR_POLICY, b"no")].concat(),
        export_script(1 << 20, FLAGS & !NBD_FLAG_SEND_FUA),
    ] {
        let _ = std::fs::remove_file(&socket);
        let server = serve_once(&socket, script);
        match open_export(&socket, Instant::now() + PATIENCE) {
            Err(NbdError::Failed(message)) => assert!(message.contains(&socket), "{message}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(server.join().unwrap(), "the helper kept its socket open");
    }
}

/// A negotiated connection is handed to the kernel again only while it is
/// what the handshake left: open, with nothing to read. Looking consumes
/// nothing.
#[test]
fn a_negotiated_connection_is_reusable_only_while_open_and_silent() {
    use std::os::unix::net::UnixStream;

    let (client, server) = UnixStream::pair().unwrap();
    assert!(idle(&client), "an open, silent connection");
    assert!(idle(&client), "looking changed it");

    // The daemon closed its end.
    drop(server);
    assert!(!idle(&client));

    // The kernel's cleanup of a refused connect shut the socket down.
    let (client, _server) = UnixStream::pair().unwrap();
    client.shutdown(std::net::Shutdown::Both).unwrap();
    assert!(!idle(&client));

    // A byte no server sends before a request; it stays unread.
    let (client, mut server) = UnixStream::pair().unwrap();
    server.write_all(&[0x67]).unwrap();
    assert!(!idle(&client));
    assert!(!idle(&client));
    let mut byte = [0];
    (&client).read_exact(&mut byte).unwrap();
    assert_eq!(byte, [0x67]);
    assert!(idle(&client));
}

/// The daemon serves one connection at a time, so a new negotiation closes
/// the helper's earlier connection before it opens the next one, and what
/// the daemon then answers is passed on: an export, or that the export is
/// not available.
#[test]
fn a_new_negotiation_closes_the_earlier_connection_first() {
    let directory = Directory::new();
    let socket = directory.socket();
    let listener = UnixListener::bind(&socket).unwrap();
    let serving = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        first.write_all(&export_script(1 << 20, FLAGS)).unwrap();
        let (mut second, _) = listener.accept().unwrap();
        // The second connection exists: the first must be closed already.
        // What is left on it is the client's request, then the end.
        first.set_nonblocking(true).unwrap();
        let mut rest = Vec::new();
        let closed_first = first.read_to_end(&mut rest).is_ok();
        second
            .write_all(&[greeting(), reply(NBD_REP_ERR_UNKNOWN, b"")].concat())
            .unwrap();
        second.set_read_timeout(Some(PATIENCE)).unwrap();
        let _ = second.read_to_end(&mut rest);
        closed_first
    });
    let netlink = netlink::Socket::open().unwrap();
    let mut attempts = KernelAttempts {
        netlink: &netlink,
        family: 0x1e,
        socket: &socket,
        index: 3,
        block_size: 4096,
        identifier: IDENTIFIER,
        deadline: Instant::now() + PATIENCE,
        negotiated: None,
    };
    assert!(!attempts.reusable(), "nothing is negotiated yet");
    assert!(matches!(attempts.negotiate(), Ok(Negotiation::Ready)));
    assert!(attempts.reusable());
    match attempts.negotiate() {
        Ok(Negotiation::ExportUnavailable(refusal)) => {
            assert!(refusal.contains(&socket), "{refusal}");
            assert!(refusal.contains("NBD_REP_ERR_UNKNOWN"), "{refusal}");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        !attempts.reusable(),
        "a refused negotiation left a connection"
    );
    drop(attempts);
    assert!(
        serving.join().unwrap(),
        "the first connection was still open when the second arrived"
    );
}

#[test]
fn a_daemon_that_never_answers_is_left_at_the_deadline() {
    let directory = Directory::new();
    let socket = directory.socket();
    let listener = UnixListener::bind(&socket).unwrap();
    let silent = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(PATIENCE)).unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
    });
    let started = Instant::now();
    let deadline = Duration::from_millis(200);
    match open_export(&socket, started + deadline) {
        Err(NbdError::Failed(message)) => assert!(message.contains("deadline"), "{message}"),
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert!(started.elapsed() < deadline + Duration::from_secs(2));
    silent.join().unwrap();
}

#[test]
fn a_socket_that_cannot_be_reached_is_a_plain_failure() {
    let directory = Directory::new();
    let missing = directory.socket();
    match open_export(&missing, Instant::now() + PATIENCE) {
        Err(NbdError::Failed(message)) => assert!(message.contains(&missing), "{message}"),
        other => panic!("{other:?}"),
    }
    let long = format!("/{}", "x".repeat(120));
    assert!(matches!(
        open_export(&long, Instant::now() + PATIENCE),
        Err(NbdError::Failed(_))
    ));
}

#[test]
fn no_time_left_means_nothing_is_attempted() {
    let directory = Directory::new();
    let socket = directory.socket();
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let _netlink = netlink::refuse_sockets();
    let _bounded = crate::exec::command::finish_by(Instant::now());
    for result in [connect(&socket, 3, 4096, IDENTIFIER), disconnect(3)] {
        match result {
            Err(NbdError::Failed(message)) => {
                assert!(message.contains("no time left"), "{message}")
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "the daemon's socket was connected"
    );
}

#[test]
fn a_malformed_identifier_or_block_size_is_refused_before_the_socket() {
    let directory = Directory::new();
    let socket = directory.socket();
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let _netlink = netlink::refuse_sockets();
    let long = "m".repeat(300);
    for identifier in ["", "maki-\0x", "maki x", "maki-\u{e9}", long.as_str()] {
        match connect(&socket, 3, 4096, identifier) {
            Err(NbdError::Failed(message)) => assert!(message.contains("identifier"), "{message}"),
            other => panic!("{identifier:?}: {other:?}"),
        }
    }
    for block_size in [0, 256, 1000, 4097] {
        match connect(&socket, 3, block_size, IDENTIFIER) {
            Err(NbdError::Failed(message)) => assert!(message.contains("block size"), "{message}"),
            other => panic!("{block_size}: {other:?}"),
        }
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn the_netlink_socket_is_close_on_exec() {
    let socket = netlink::Socket::open().unwrap();
    assert!(socket.port() != 0, "the kernel binds the socket to a port");
    assert!(descriptor_flags(socket.as_raw_fd()).0, "FD_CLOEXEC");
}
