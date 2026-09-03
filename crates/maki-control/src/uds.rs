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

use crate::server::{serve_connection, ControlBackend};

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
    let listener = UnixListener::bind(path)?;
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
    }
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    Ok(bound)
}

/// Serve connections on a bound socket until the future is dropped.
pub async fn serve(listener: ControlListener, backend: Arc<dyn ControlBackend>) -> io::Result<()> {
    loop {
        let (stream, _addr) = listener.listener.accept().await?;
        let backend = backend.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, backend).await {
                tracing::warn!("control session ended with error: {e}");
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
