//! Unix-domain-socket listener with SPEC §7 ownership/mode
//! (`owner maki, group maki-admin, mode 0660`). Unix only.
//!
//! Binding is separated from serving so the daemon can fail attach when
//! the socket cannot be created (review M-005: a daemon without its control
//! socket is not operable) and so ownership is applied *before* any client
//! can connect (review M-017: the group named in `control.group` is applied
//! with `chown`, which the unprivileged daemon may do for any group it is a
//! member of — `packaging/sysusers.d` adds `maki` to `maki-admin`).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::Semaphore;

use crate::server::{serve_connection, ControlBackend, ControlLimits, SerializedBackend};

/// A bound control socket: accepts connections until dropped, and removes
/// its path when dropped.
pub struct ControlListener {
    listener: UnixListener,
    path: PathBuf,
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
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Resolve a group name to its gid.
pub fn resolve_gid(name: &str) -> io::Result<u32> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "group name contains NUL"))?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers reference live, correctly sized buffers for the
    // duration of the call; getgrnam_r writes only within them.
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("group {name:?} not found"),
        ));
    }
    Ok(grp.gr_gid)
}

/// Bind the control socket (replacing a stale file), apply `group` if
/// given, and restrict the mode to 0660 — all before returning, so no
/// client can observe a wider mode. Must be called inside a tokio runtime.
pub fn bind_control_socket(path: &Path, group: Option<&str>) -> io::Result<ControlListener> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "control socket directory {} does not exist",
                    parent.display()
                ),
            ));
        }
    }
    let _ = std::fs::remove_file(path);
    // Bind under a restrictive umask so the socket never exists world- or
    // group-connectable before chgrp/chmod run (O-11); connections made in
    // that window would sit in the backlog and be served.
    let listener = {
        let _umask = UmaskGuard::set(0o117);
        UnixListener::bind(path)?
    };
    let bound = ControlListener {
        listener,
        path: path.to_path_buf(),
    };
    if let Some(group) = group {
        let gid = resolve_gid(group)?;
        std::os::unix::fs::chown(path, None, Some(gid)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("chgrp {group:?} on {}: {e}", path.display()),
            )
        })?;
        // A 0660 socket is unreachable when its directory cannot be
        // traversed: systemd creates the runtime directory maki:maki, so an
        // administrator in `control.group` could not connect at all (fifth
        // pass, N-11). Give the group search access to the socket's own
        // directory when we own it; anything else is the operator's layout.
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            grant_group_search(parent, gid, group);
        }
    }
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    Ok(bound)
}

use std::time::Duration;

use crate::protocol::ProtocolError;

/// chgrp `dir` to `gid` and add group read+search, when the directory is
/// ours to change. Failures are logged, not fatal: the socket itself is
/// correct, only its reachability for the group depends on the directory.
fn grant_group_search(dir: &Path, gid: u32, group: &str) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(meta) = std::fs::metadata(dir) else {
        return;
    };
    // SAFETY: plain getuid.
    let ours = meta.uid() == unsafe { libc::getuid() };
    if !ours {
        tracing::warn!(
            "control socket directory {} is not owned by the daemon; make sure group \
             {group:?} can traverse it",
            dir.display()
        );
        return;
    }
    if meta.gid() != gid {
        if let Err(e) = std::os::unix::fs::chown(dir, None, Some(gid)) {
            tracing::warn!("chgrp {group:?} on {}: {e}", dir.display());
            return;
        }
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o050 != 0o050 {
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode | 0o050))
        {
            tracing::warn!("chmod g+rx on {}: {e}", dir.display());
        }
    }
}

/// Process umask override, restored on drop.
struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn set(mask: libc::mode_t) -> Self {
        // SAFETY: umask is a plain process-wide syscall wrapper.
        Self(unsafe { libc::umask(mask) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: restores the value returned by the earlier call.
        unsafe {
            libc::umask(self.0);
        }
    }
}

/// Serve connections on a bound socket until the future is dropped, with
/// the default [`ControlLimits`].
pub async fn serve(listener: ControlListener, backend: Arc<dyn ControlBackend>) -> io::Result<()> {
    serve_with_limits(listener, backend, ControlLimits::default()).await
}

/// Serve connections on a bound socket until the future is dropped.
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
pub async fn serve_with_limits(
    listener: ControlListener,
    backend: Arc<dyn ControlBackend>,
    limits: ControlLimits,
) -> io::Result<()> {
    let backend: Arc<dyn ControlBackend> = Arc::new(SerializedBackend::new(backend));
    let sessions = Arc::new(Semaphore::new(limits.max_sessions.max(1)));
    loop {
        let slot = sessions
            .clone()
            .acquire_owned()
            .await
            .expect("session semaphore is never closed");
        let stream = match listener.listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                tracing::warn!("control socket accept failed (retrying): {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let backend = backend.clone();
        tokio::spawn(async move {
            let _slot = slot;
            match serve_connection(stream, backend, limits).await {
                Ok(()) => {}
                Err(ProtocolError::IdleTimeout) => {
                    tracing::debug!("control session closed: idle timeout")
                }
                Err(e) => tracing::warn!("control session ended with error: {e}"),
            }
        });
    }
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
