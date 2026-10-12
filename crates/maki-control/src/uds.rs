//! Unix-domain-socket listener with SPEC §7 ownership/mode
//! (`owner maki, group maki-admin, mode 0660`). Unix only.
//!
//! Binding is separated from serving so the daemon can fail attach when
//! the socket cannot be created (review M-005: a daemon without its control
//! socket is not operable) and so ownership is applied *before* any client
//! can connect (review M-017: the group named in `control.group` is applied
//! with `chown`, which the unprivileged daemon may do for any group it is a
//! member of — `packaging/sysusers.d` adds `maki` to `maki-admin`).

use std::future::Future;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use tokio::net::UnixListener;
use tokio::sync::Semaphore;

use crate::server::{serve_connection, ControlBackend, ControlLimits, SerializedBackend};

/// A bound control socket: accepts connections until dropped, and removes
/// its own socket inode when dropped.
pub struct ControlListener {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}

impl ControlListener {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for ControlListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlListener")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Drop for ControlListener {
    fn drop(&mut self) {
        // BUG-055: an address can have been unlinked and reused while this
        // listener was alive. Serialize with publication, and only remove
        // the filesystem inode this listener originally published.
        if let Ok(_directory) = lock_socket_directory(&self.path) {
            if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
                if metadata.file_type().is_socket()
                    && (metadata.dev(), metadata.ino()) == self.identity
                {
                    let _ = std::fs::remove_file(&self.path);
                }
            }
        }
    }
}

/// A directory lock serializes socket publication and ownership checks
/// across processes without leaving another persistent filesystem entry.
fn lock_socket_directory(path: &Path) -> io::Result<std::fs::File> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = std::fs::File::open(parent)?;
    loop {
        // SAFETY: the descriptor stays open in the returned File. Closing
        // it releases this advisory lock after the synchronous operation.
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(directory);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// A full listener backlog must not make attach block while holding the
/// directory lock. Only connection refusal proves an existing socket stale.
fn socket_is_live(path: &Path) -> io::Result<bool> {
    // A single poll starts Tokio's nonblocking connect. Pending, including
    // an unfinished connection, cannot prove this address safe to replace.
    // Dropping the future closes the probe; no asynchronous wait or stale
    // reactor registration remains while the directory lock is held.
    let mut connect = std::pin::pin!(tokio::net::UnixStream::connect(path));
    let mut context = Context::from_waker(Waker::noop());
    match connect.as_mut().poll(&mut context) {
        Poll::Ready(Ok(_)) | Poll::Pending => Ok(true),
        Poll::Ready(Err(error)) => match error.raw_os_error() {
            Some(libc::ECONNREFUSED | libc::ENOENT) => Ok(false),
            Some(libc::EAGAIN | libc::EINPROGRESS | libc::EALREADY) => Ok(true),
            _ => Err(error),
        },
    }
}

/// Resolve a group name to its gid.
pub fn resolve_gid(name: &str) -> io::Result<u32> {
    resolve_gid_with_capacity(name, 16 * 1024)
}

/// Largest group record buffer [`resolve_gid`] grows to.
const MAX_GROUP_BUFFER: usize = 16 << 20;

/// [`resolve_gid`] starting from an `initial` record buffer. `getgrnam_r`
/// reports `ERANGE` when the record (a directory group's member list can
/// be large) does not fit; the buffer is doubled and the lookup retried, up
/// to [`MAX_GROUP_BUFFER`].
pub fn resolve_gid_with_capacity(name: &str, initial: usize) -> io::Result<u32> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "group name contains NUL"))?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; initial.clamp(1, MAX_GROUP_BUFFER)];
    let mut result: *mut libc::group = std::ptr::null_mut();
    loop {
        // SAFETY: all pointers reference live, correctly sized buffers for
        // the duration of the call; getgrnam_r writes only within them.
        let rc = unsafe {
            libc::getgrnam_r(
                cname.as_ptr(),
                &mut grp,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < MAX_GROUP_BUFFER {
            buf = vec![0u8; (buf.len() * 2).min(MAX_GROUP_BUFFER)];
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        break;
    }
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("group {name:?} not found"),
        ));
    }
    Ok(grp.gr_gid)
}

/// Bind the control socket (replacing a stale file, refusing live sockets), apply `group` if
/// given, and restrict the mode to 0660 before publishing its path. Must
/// be called inside a tokio runtime.
pub fn bind_control_socket(path: &Path, group: Option<&str>) -> io::Result<ControlListener> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "control socket directory {} does not exist",
                parent.display()
            ),
        ));
    }
    // Validate the public address even when the private bind uses a shorter
    // path: clients still need to connect through the requested address.
    std::os::unix::net::SocketAddr::from_pathname(path)?;
    let gid = group.map(resolve_gid).transpose()?;

    // BUG-014: umask is shared by every thread (and inherited by children).
    // A temporary override could strip directory traversal from unrelated
    // file creation. Hide the socket in a private directory instead, then
    // publish it atomically only after its group and permissions are ready.
    let staging = tempfile::Builder::new()
        .prefix(".maki-control-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    // Creation honors the inherited umask; restore owner traversal without
    // ever allowing another user to enter the private directory.
    std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o700))?;
    let staged_path = staging.path().join("socket");
    let listener = UnixListener::bind(&staged_path);
    #[cfg(target_os = "linux")]
    let listener = listener.or_else(|error| {
        use std::os::fd::AsRawFd;

        if std::os::unix::net::SocketAddr::from_pathname(&staged_path).is_ok() {
            return Err(error);
        }
        // Staging must not reduce Linux's valid public socket path length.
        // An open directory supplies a short address for the same inode;
        // the ordinary path above keeps short binds independent of procfs.
        let directory = std::fs::File::open(staging.path())?;
        UnixListener::bind(format!("/proc/self/fd/{}/socket", directory.as_raw_fd()))
    });
    let listener = listener?;
    let metadata = std::fs::symlink_metadata(&staged_path)?;
    let mut bound = ControlListener {
        listener,
        path: staged_path.clone(),
        identity: (metadata.dev(), metadata.ino()),
    };
    if let Some(gid) = gid {
        std::os::unix::fs::chown(&staged_path, None, Some(gid)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("chgrp {group:?} on {}: {e}", path.display()),
            )
        })?;
    }
    std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(0o660))?;
    // Both binders and dropping predecessors take this lock, so checking
    // an existing address and publishing the prepared socket is one step.
    let _directory = lock_socket_directory(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && socket_is_live(path)? => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "control socket {} already has a live listener",
                    path.display()
                ),
            ));
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    std::fs::rename(&staged_path, path)?;
    bound.path = path.to_path_buf();
    Ok(bound)
}

use std::time::Duration;

use crate::protocol::ProtocolError;

/// Serve connections on a bound socket until the future is dropped, with
/// the default [`ControlLimits`].
pub async fn serve(listener: ControlListener, backend: Arc<dyn ControlBackend>) -> io::Result<()> {
    serve_with_limits(listener, backend, ControlLimits::default()).await
}

/// Serve connections on a bound socket until the future is dropped.
pub async fn serve_with_limits(
    listener: ControlListener,
    backend: Arc<dyn ControlBackend>,
    limits: ControlLimits,
) -> io::Result<()> {
    // No external shutdown signal: hold a sender for the whole call so the
    // receiver never fires. The loop then ends only when this future is
    // dropped (its task aborted), which drops the session `JoinSet` and
    // aborts every live session — the historical behaviour for callers that
    // stop the server by aborting its task.
    let (_tx, rx) = tokio::sync::watch::channel(false);
    serve_with_shutdown(listener, backend, limits, rx).await
}

/// Serve connections until `shutdown` fires (its value changes or its
/// sender drops), then stop accepting and drain every live session.
///
/// An `accept` error is never fatal: EMFILE/ENFILE/ENOBUFS during a client
/// burst or a transiently short descriptor table used to end this loop,
/// unlink the socket, and leave the daemon without a control plane for the
/// rest of its life (O-04). Log, pause briefly, and keep accepting.
///
/// At most `limits.max_sessions` sessions are served at once: the session
/// slot is taken *before* `accept`, so excess clients wait in the kernel
/// backlog instead of each getting a task and a descriptor (F10). Mutating
/// verbs are serialized through [`SerializedBackend`].
///
/// Sessions run in a [`JoinSet`](tokio::task::JoinSet); on shutdown the set
/// is aborted *and awaited*, so every `Engine` reference a session held is
/// dropped before this returns. A clean detach relies on that to release
/// the volume lock (BUG-015): a session still holding the engine would keep
/// the lock even after `shutdown` reported success.
pub async fn serve_with_shutdown(
    listener: ControlListener,
    backend: Arc<dyn ControlBackend>,
    limits: ControlLimits,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let backend: Arc<dyn ControlBackend> = Arc::new(SerializedBackend::new(backend));
    let sessions = Arc::new(Semaphore::new(limits.max_sessions.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        // Race the shutdown signal against the slot wait: when every session
        // slot is held by a live session, `acquire_owned` would otherwise
        // park here and never observe shutdown, so the drain below would
        // never run and a clean detach could hang (a control session that
        // keeps its connection open holds its slot indefinitely).
        let slot = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            slot = sessions.clone().acquire_owned() => {
                slot.expect("session semaphore is never closed")
            }
        };
        let stream = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            accepted = listener.listener.accept() => match accepted {
                Ok((stream, _addr)) => stream,
                Err(e) => {
                    tracing::warn!("control socket accept failed (retrying): {e}");
                    drop(slot);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let backend = backend.clone();
        tasks.spawn(async move {
            let _slot = slot;
            match serve_connection(stream, backend, limits).await {
                Ok(()) => {}
                Err(ProtocolError::IdleTimeout) => {
                    tracing::debug!("control session closed: idle timeout")
                }
                Err(e) => tracing::warn!("control session ended with error: {e}"),
            }
        });
        // Reap finished sessions so the set stays bounded over a long life.
        while tasks.try_join_next().is_some() {}
    }
    tasks.shutdown().await;
    Ok(())
}

/// Bind with restrictive permissions and serve forever.
pub async fn serve_uds(
    path: &Path,
    backend: Arc<dyn ControlBackend>,
    group: Option<&str>,
) -> io::Result<()> {
    let listener = bind_control_socket(path, group)?;
    serve(listener, backend).await
}
