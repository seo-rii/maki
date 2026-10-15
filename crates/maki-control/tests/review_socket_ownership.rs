//! BUG-055: publishing and removing a control address must respect its owner.

#![cfg(unix)]

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Barrier;

use maki_control::uds::bind_control_socket;

#[tokio::test]
async fn a_live_control_socket_is_not_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control.sock");
    let first = bind_control_socket(&socket, None).unwrap();
    let second = bind_control_socket(&socket, None);
    assert!(
        second.is_err(),
        "a second bind replaced a live control socket"
    );
    assert_eq!(second.unwrap_err().kind(), io::ErrorKind::AddrInUse);
    assert!(UnixStream::connect(&socket).is_ok());
    drop(first);
    assert!(!socket.exists());
}

#[tokio::test]
async fn old_listener_drop_preserves_a_successor_inode() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control.sock");
    let old = bind_control_socket(&socket, None).unwrap();
    std::fs::remove_file(&socket).unwrap();
    let successor = bind_control_socket(&socket, None).unwrap();
    drop(old);
    assert!(
        UnixStream::connect(&socket).is_ok(),
        "old listener removed its successor"
    );
    drop(successor);
    assert!(!socket.exists());
}

#[tokio::test]
async fn a_stale_socket_is_reclaimed() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control.sock");
    drop(UnixListener::bind(&socket).unwrap());
    assert!(socket.exists());
    let listener = bind_control_socket(&socket, None).unwrap();
    assert!(UnixStream::connect(&socket).is_ok());
    drop(listener);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn concurrent_binders_publish_exactly_one_live_listener() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control.sock");
    let start = Barrier::new(2);
    let listeners = std::thread::scope(|scope| {
        let bind = || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap();
            let _entered = runtime.enter();
            start.wait();
            bind_control_socket(&socket, None)
        };
        let first = scope.spawn(bind);
        let second = scope.spawn(bind);
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(
        usize::from(listeners.0.is_ok()) + usize::from(listeners.1.is_ok()),
        1,
        "both concurrent binders claimed the same address"
    );
    assert!(UnixStream::connect(&socket).is_ok());
    drop(listeners);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn old_listener_drop_preserves_a_replacement_regular_file() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control.sock");
    let old = bind_control_socket(&socket, None).unwrap();
    std::fs::remove_file(&socket).unwrap();
    std::fs::write(&socket, b"replacement").unwrap();
    drop(old);
    assert_eq!(std::fs::read(&socket).unwrap(), b"replacement");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_full_listener_backlog_is_still_a_live_address() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    // SAFETY: this listening socket is live; a short backlog keeps the
    // fixture bounded without relying on a machine's default backlog.
    assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
    // SAFETY: sockaddr_un is a plain C record, valid when zero initialized.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = socket.as_os_str().as_bytes();
    for (destination, byte) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *byte as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    let mut clients = Vec::new();
    let mut backlog_full = false;
    for _ in 0..8 {
        // SAFETY: socket returns a new descriptor or -1, checked below.
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        assert!(raw >= 0);
        // SAFETY: this transfers the newly created descriptor's sole owner.
        let client = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: address contains the fixture's short, valid pathname.
        let connected = unsafe {
            libc::connect(
                client.as_raw_fd(),
                std::ptr::from_ref(&address).cast(),
                length as libc::socklen_t,
            )
        };
        if connected == 0 {
            clients.push(client);
        } else {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN)
            );
            backlog_full = true;
            break;
        }
    }
    assert!(
        backlog_full,
        "the fixture did not fill the listener backlog"
    );
    let error = bind_control_socket(&socket, None).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    assert!(socket.exists());
    drop(clients);
    drop(listener);
    // Once the listener is gone, the same pathname really is stale.
    drop(bind_control_socket(&socket, None).unwrap());
    assert!(!socket.exists());
}

/// BUG-099: the address is configurable, and binding renamed the socket over
/// whatever file was there. A mistyped `control.socket` naming a volume file
/// (`superblock.a`, a shard) destroyed it. Only a dead socket is reclaimed.
#[tokio::test]
async fn a_regular_file_at_the_address_is_not_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("superblock.a");
    std::fs::write(&path, b"volume metadata").unwrap();

    let error = bind_control_socket(&path, None).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
    assert_eq!(std::fs::read(&path).unwrap(), b"volume metadata");
    assert_eq!(
        std::fs::read_dir(directory.path()).unwrap().count(),
        1,
        "a refused bind leaves no staging directory behind"
    );
}

#[tokio::test]
async fn a_symlink_at_the_address_is_not_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    std::fs::write(&target, b"kept").unwrap();
    let path = directory.path().join("control.sock");
    std::os::unix::fs::symlink(&target, &path).unwrap();

    let error = bind_control_socket(&path, None).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
    assert!(std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read(&target).unwrap(), b"kept");
}
