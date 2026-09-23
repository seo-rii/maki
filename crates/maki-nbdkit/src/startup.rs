//! One-shot initialization and Linux systemd readiness notification. This is
//! called after nbdkit forks; no runtime or thread exists in the parent.

use std::ffi::OsStr;
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

#[derive(Default)]
pub(super) struct Startup {
    result: OnceLock<Result<(), String>>,
}

impl Startup {
    pub(super) const fn new() -> Self {
        Self {
            result: OnceLock::new(),
        }
    }

    /// Failures and panics are sticky too. A later open/callback must never
    /// retry recovery, create a second adapter, or repeat a notification.
    pub(super) fn run(&self, initialize: impl FnOnce() -> Result<(), String>) -> i32 {
        catch_unwind(AssertUnwindSafe(|| {
            let result = self.result.get_or_init(|| {
                catch_unwind(AssertUnwindSafe(initialize))
                    .unwrap_or_else(|_| Err("panic during startup".into()))
            });
            match result {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("maki-nbdkit: startup failed: {error}");
                    -1
                }
            }
        }))
        .unwrap_or(-1)
    }

    pub(super) fn ready(&self) -> bool {
        matches!(self.result.get(), Some(Ok(())))
    }
}

/// Absence permits manual/rootless operation. A configured destination is a
/// startup contract: malformed addresses, permission errors, missing receivers
/// and full queues are failures rather than an apparent successful start.
pub(super) fn notify_ready(destination: Option<&OsStr>) -> io::Result<()> {
    let Some(destination) = destination else {
        return Ok(());
    };
    let bytes = destination.as_bytes();
    if bytes.len() < 2 || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid NOTIFY_SOCKET address",
        ));
    }
    let address = match bytes[0] {
        // The standard constructors enforce each representation's own limit:
        // pathname needs a trailing NUL; abstract uses the leading NUL and
        // allows 107 name bytes (108 bytes including the environment's '@').
        b'/' => SocketAddr::from_pathname(destination)?,
        b'@' => SocketAddr::from_abstract_name(&bytes[1..])?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NOTIFY_SOCKET must be absolute or abstract",
            ))
        }
    };
    let socket = UnixDatagram::unbound()?;
    // A stuck/overfull notification receiver must not hang startup forever.
    socket.set_nonblocking(true)?;
    let count = socket.send_to_addr(b"READY=1", &address)?;
    if count != b"READY=1".len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete readiness notification",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn concurrent_callbacks_initialize_and_notify_only_once() {
        let startup = std::sync::Arc::new(Startup::new());
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let startup = startup.clone();
                let calls = calls.clone();
                std::thread::spawn(move || {
                    startup.run(|| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), 0);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(startup.ready());
    }

    #[test]
    fn errors_and_panics_stay_failed_without_unwinding_across_the_callback_boundary() {
        for panic in [false, true] {
            let startup = Startup::new();
            assert!(!startup.ready());
            assert_eq!(
                startup.run(|| {
                    assert!(!panic, "fixture startup panic");
                    Err("fixture startup error".into())
                }),
                -1
            );
            assert_eq!(startup.run(|| panic!("failed startup must not retry")), -1);
            assert!(!startup.ready());
        }
    }

    #[test]
    fn notification_addresses_fail_closed_and_absence_is_optional() {
        assert!(notify_ready(None).is_ok());
        for bad in ["", "@", "/", "relative", "@has\0nul"] {
            assert!(notify_ready(Some(OsStr::new(bad))).is_err());
        }
        assert!(notify_ready(Some(OsStr::new(&format!("@{}", "x".repeat(108))))).is_err());
        let dir = tempfile::tempdir().unwrap();
        assert!(notify_ready(Some(dir.path().join("missing.sock").as_os_str())).is_err());
    }

    #[test]
    fn notification_uses_path_and_abstract_unix_datagram_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let pathname = UnixDatagram::bind(&path).unwrap();
        notify_ready(Some(path.as_os_str())).unwrap();
        let abstract_name = format!(
            "maki-ready-{}-{}",
            std::process::id(),
            dir.path().file_name().unwrap().to_str().unwrap()
        );
        let abstract_socket = UnixDatagram::bind_addr(
            &SocketAddr::from_abstract_name(abstract_name.as_bytes()).unwrap(),
        )
        .unwrap();
        notify_ready(Some(OsStr::new(&format!("@{abstract_name}")))).unwrap();
        for socket in [pathname, abstract_socket] {
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            let mut bytes = [0; 64];
            let count = socket.recv(&mut bytes).unwrap();
            assert_eq!(&bytes[..count], b"READY=1");
        }
    }

    #[test]
    fn maximum_length_abstract_address_is_supported() {
        let prefix = format!("maki-ready-max-{}-", std::process::id());
        let name = format!("{prefix}{}", "x".repeat(107 - prefix.len()));
        let receiver =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap())
                .unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        notify_ready(Some(OsStr::new(&format!("@{name}")))).unwrap();
        let mut bytes = [0; 16];
        assert_eq!(receiver.recv(&mut bytes).unwrap(), 7);
        assert_eq!(&bytes[..7], b"READY=1");
    }
}
