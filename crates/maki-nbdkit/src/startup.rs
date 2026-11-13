//! One-shot initialization and Linux systemd readiness notification. This is
//! called after nbdkit forks; no runtime or thread exists in the parent.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

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

// The packaged initial timeout is 180s. Refresh that finite window at most
// once per 30s, and only when the recovery worker completes more work. A
// blocked operation, provider outage or dead worker has no heartbeat thread.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(30);
const PROGRESS_NOTIFICATION: &[u8] =
    b"EXTEND_TIMEOUT_USEC=180000000\nSTATUS=Recovering volume data";

pub(super) struct RecoveryNotifier {
    destination: Option<OsString>,
    started: Instant,
    state: Mutex<(Duration, Option<io::ErrorKind>)>,
}

impl RecoveryNotifier {
    pub(super) fn new(destination: Option<OsString>) -> Self {
        Self {
            destination,
            started: Instant::now(),
            state: Mutex::new((Duration::ZERO, None)),
        }
    }

    pub(super) fn progress(&self) {
        self.progress_at(self.started.elapsed());
    }

    fn progress_at(&self, elapsed: Duration) {
        if self.destination.is_none() {
            return;
        }
        let mut state = self.state.lock();
        if state.1.is_some() || elapsed.saturating_sub(state.0) < PROGRESS_INTERVAL {
            return;
        }
        match notify(self.destination.as_deref(), PROGRESS_NOTIFICATION) {
            Ok(()) => state.0 = elapsed,
            Err(error) => state.1 = Some(error.kind()),
        }
    }

    pub(super) fn ready(&self) -> io::Result<()> {
        if let Some(kind) = self.state.lock().1 {
            return Err(io::Error::new(
                kind,
                "recovery progress notification failed",
            ));
        }
        notify_ready(self.destination.as_deref())
    }
}

/// Absence permits manual/rootless operation. A configured destination is a
/// startup contract: malformed addresses, permission errors, missing receivers
/// and full queues are failures rather than an apparent successful start.
pub(super) fn notify_ready(destination: Option<&OsStr>) -> io::Result<()> {
    // STATUS persists in systemd after readiness, so replace recovery status
    // in the same datagram that announces successful initialization.
    notify(destination, b"READY=1\nSTATUS=Ready")
}

fn notify(destination: Option<&OsStr>, message: &[u8]) -> io::Result<()> {
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
    let count = socket.send_to_addr(message, &address)?;
    if count != message.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete startup notification",
        ));
    }
    Ok(())
}

/// nbdkit binds its listener before after_fork. Inspect owned listening FDs,
/// rather than treating a pathname's existence as evidence of this listener.
/// See https://github.com/libguestfs/nbdkit/blob/master/server/main.c
pub(super) fn effective_nbd_socket(configured: Option<&str>) -> io::Result<Option<String>> {
    use std::mem::{size_of, zeroed};
    use std::path::Path;

    let mut listeners = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let mut accepting: libc::c_int = 0;
        let mut option_len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: both output pointers refer to initialized, correctly sized
        // storage. ENOTSOCK/EBADF also covers the iterator's own closed FD.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut accepting as *mut libc::c_int).cast(),
                &mut option_len,
            )
        } != 0
            || accepting != 1
        {
            continue;
        }
        // SAFETY: a sockaddr_un is large enough for all supported listener
        // addresses; inspect its family and returned length before sun_path.
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        let mut address_len = size_of::<libc::sockaddr_un>() as libc::socklen_t;
        if unsafe {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_un).cast(),
                &mut address_len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if address.sun_family != libc::AF_UNIX as libc::sa_family_t {
            continue;
        }
        let path_len = (address_len as usize)
            .saturating_sub(std::mem::offset_of!(libc::sockaddr_un, sun_path))
            .min(address.sun_path.len());
        let bytes: Vec<u8> = address.sun_path[..path_len]
            .iter()
            .map(|byte| *byte as u8)
            .take_while(|byte| *byte != 0)
            .collect();
        // Abstract/unnamed sockets cannot satisfy a pathname used by helper.
        if bytes.is_empty() {
            continue;
        }
        let path = String::from_utf8(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "native NBD listener is not a UTF-8 pathname",
            )
        })?;
        listeners.push(path);
    }
    let actual = if listeners.len() == 1 {
        listeners.pop()
    } else {
        None
    };
    if let Some(configured) = configured {
        if actual
            .as_deref()
            .is_none_or(|actual| Path::new(actual) != Path::new(configured))
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                format!("nbd.socket {configured:?} does not match the unique native pathname listener {actual:?}; set nbdkit -U and nbd.socket to the same path")));
        }
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn recovery_notifications_require_progress_and_are_rate_limited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("progress.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let notifier = RecoveryNotifier::new(Some(path.into_os_string()));
        let mut message = [0; 128];
        // Creating the observer does not start a timer or send a heartbeat.
        assert_eq!(
            receiver.recv(&mut message).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        notifier.progress_at(Duration::from_secs(29));
        assert_eq!(
            receiver.recv(&mut message).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        for elapsed in [30, 60, 240] {
            notifier.progress_at(Duration::from_secs(elapsed));
            let len = receiver.recv(&mut message).unwrap();
            assert_eq!(&message[..len], PROGRESS_NOTIFICATION);
            notifier.progress_at(Duration::from_secs(elapsed + 1));
            assert_eq!(
                receiver.recv(&mut message).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
        // Once work stops, there is no background sender to renew the lease.
        assert_eq!(
            receiver.recv(&mut message).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn a_failed_extension_permanently_prevents_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.sock");
        let notifier = RecoveryNotifier::new(Some(path.clone().into_os_string()));
        notifier.progress_at(PROGRESS_INTERVAL);
        // Restoring the destination cannot erase the failed startup contract.
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver.set_nonblocking(true).unwrap();
        notifier.progress_at(PROGRESS_INTERVAL * 2);
        let startup = Startup::new();
        assert_eq!(
            startup.run(|| notifier.ready().map_err(|error| error.to_string())),
            -1
        );
        assert!(!startup.ready());
        assert_eq!(startup.run(|| panic!("failed startup must not retry")), -1);
        let mut message = [0; 128];
        assert_eq!(
            receiver.recv(&mut message).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn advancing_recovery_outlives_the_initial_deadline_before_ready() {
        use maki_core::volume::{Volume, VolumeOptions};
        use maki_format::{geometry::Geometry, init, superblock::Superblock};
        use std::sync::atomic::AtomicU64;

        let backing = std::sync::Arc::new(maki_backing::MemBacking::new());
        init::create_volume(
            backing.as_ref(),
            Superblock {
                generation: 0,
                volume_uuid: uuid::Uuid::from_u128(0xDEAD11),
                provider_type: "fake".into(),
                crypto_compatibility_id: "test-profile-v1".into(),
                key_identity: "fixture".into(),
                geometry: Geometry::compute(512, 512, 512, 512, 512 * 64, 512 * 64).unwrap(),
                format_version: 1,
                created_unix: 0,
            },
        )
        .unwrap();
        let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
        for unit in 0..16 {
            volume.write_ct(unit, &[unit as u8; 512], false).unwrap();
        }
        volume.flush().unwrap();
        drop(volume);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("progress.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let notifier = RecoveryNotifier::new(Some(path.into_os_string()));
        let elapsed = AtomicU64::new(0);
        let deadline = AtomicU64::new(180);
        let startup = Startup::new();
        assert_eq!(
            startup.run(|| {
                let volume = Volume::recover_with_progress(
                    backing.clone(),
                    VolumeOptions::default(),
                    &|| {
                        // Logical time makes every completed work item take 30s.
                        // No wall-clock sleep or background keepalive is involved.
                        let now = elapsed.fetch_add(30, Ordering::SeqCst) + 30;
                        assert!(now < deadline.load(Ordering::SeqCst));
                        notifier.progress_at(Duration::from_secs(now));
                        let mut message = [0; 128];
                        let len = receiver.recv(&mut message).unwrap();
                        assert_eq!(&message[..len], PROGRESS_NOTIFICATION);
                        deadline.store(now + 180, Ordering::SeqCst);
                    },
                )
                .map_err(|error| error.to_string())?;
                assert_eq!(volume.checkpoint_sequence(), 16);
                assert_eq!(volume.read_ct(15).unwrap().unwrap().1, vec![15; 512]);
                notifier.ready().map_err(|error| error.to_string())
            }),
            0
        );
        assert!(elapsed.load(Ordering::SeqCst) > 180);
        assert!(startup.ready());
        assert_eq!(
            startup.run(|| panic!("ready startup must not initialize twice")),
            0
        );
        let mut message = [0; 128];
        let len = receiver.recv(&mut message).unwrap();
        assert_eq!(&message[..len], b"READY=1\nSTATUS=Ready");
        assert_eq!(
            receiver.recv(&mut message).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

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
            assert_eq!(&bytes[..count], b"READY=1\nSTATUS=Ready");
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
        let mut bytes = [0; 64];
        let count = receiver.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..count], b"READY=1\nSTATUS=Ready");
    }
}
