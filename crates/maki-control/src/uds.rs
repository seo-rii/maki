//! Unix-domain-socket listener with SPEC §7 ownership/mode
//! (`owner maki, group maki-admin, mode 0660`). Unix only.

use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;

use crate::server::{serve_connection, ControlBackend};

/// Bind the control socket with restrictive permissions and serve forever.
pub async fn serve_uds(
    path: &Path,
    backend: Arc<dyn ControlBackend>,
) -> Result<(), std::io::Error> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    // 0660: owner (maki) + group (maki-admin) only. Group ownership is
    // arranged by the runtime directory (tmpfiles.d) / systemd.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    loop {
        let (stream, _addr) = listener.accept().await?;
        let backend = backend.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, backend).await {
                tracing::warn!("control session ended with error: {e}");
            }
        });
    }
}
