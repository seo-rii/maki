//! Blocking NBD adapter over the async engine (SPEC §48).
//!
//! - Every entry point catches panics: nothing ever unwinds across the FFI
//!   boundary; a panic maps to EIO and the adapter stays usable.
//! - Capability surface per SPEC §48: FLUSH + FUA supported; trim, write-
//!   zeroes, and multi-connection disabled (nbdkit emulates zeroes via
//!   pwrite).
//! - `open_config` also binds and serves the per-volume control socket
//!   (SPEC §7, review M-005) on the adapter's runtime; a socket that cannot
//!   be bound fails attach. `shutdown` is the clean-detach path: FLUSH
//!   barrier, checkpoint, control socket removal, then release of the
//!   volume lock.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use maki_core::engine::Engine;
use maki_core::CoreError;
use maki_crypto::SecretBuffer;

use crate::daemon;

pub const EIO: i32 = 5;
pub const EINVAL: i32 = 22;
pub const ENOSPC: i32 = 28;
pub const ESHUTDOWN: i32 = 108;

#[derive(Debug, thiserror::Error)]
#[error("adapter error (errno {errno}): {message}")]
pub struct AdapterError {
    pub errno: i32,
    pub message: String,
}

impl AdapterError {
    fn new(errno: i32, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
        }
    }
}

fn map_core_error(e: &CoreError) -> AdapterError {
    let errno = match e {
        CoreError::Invalid(_) => EINVAL,
        CoreError::Io(io) if io.kind() == std::io::ErrorKind::StorageFull => ENOSPC,
        _ => EIO,
    };
    AdapterError::new(errno, e.to_string())
}

struct AdapterState {
    engine: Engine,
    /// (minimum, preferred, maximum) I/O sizes advertised to NBD.
    block_sizes: (u32, u32, u32),
}

/// The running control-socket server (Unix only).
#[cfg(unix)]
struct ControlServer {
    task: tokio::task::JoinHandle<()>,
    path: std::path::PathBuf,
}

pub struct NbdAdapter {
    runtime: tokio::runtime::Runtime,
    state: parking_lot::RwLock<Option<Arc<AdapterState>>>,
    #[cfg(unix)]
    control: parking_lot::Mutex<Option<ControlServer>>,
}

impl NbdAdapter {
    pub fn from_engine(engine: Engine, runtime: tokio::runtime::Runtime) -> Self {
        let g = engine.geometry();
        let block_sizes = (g.device_block_size, g.crypto_unit_size, 1 << 20);
        Self {
            runtime,
            state: parking_lot::RwLock::new(Some(Arc::new(AdapterState {
                engine,
                block_sizes,
            }))),
            #[cfg(unix)]
            control: parking_lot::Mutex::new(None),
        }
    }

    /// Full daemon path: parse + validate config, build backing/provider,
    /// run recovery + self-test, start the control socket, return a serving
    /// adapter.
    pub fn open_config(path: &str) -> Result<Self, AdapterError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| AdapterError::new(EINVAL, format!("config {path}: {e}")))?;
        let config = daemon::parse_and_validate(&raw)
            .map_err(|e| AdapterError::new(EINVAL, e.to_string()))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.nbd.threads.clamp(1, 256) as usize)
            .enable_all()
            .build()
            .map_err(|e| AdapterError::new(EIO, e.to_string()))?;
        let (engine, crypto_stats) = runtime
            .block_on(daemon::attach_from_config_with_stats(&config))
            .map_err(|e| AdapterError::new(EIO, e.to_string()))?;
        #[cfg(not(unix))]
        let _ = &crypto_stats; // only the Unix control socket reports them
        let block_sizes = (
            config.nbd.minimum_io,
            config.nbd.preferred_io,
            config.nbd.maximum_io.0 as u32, // validated as a wire-sized value
        );

        #[cfg(unix)]
        let control = {
            let socket = daemon::control_socket_path(&config);
            let backend: Arc<dyn maki_control::server::ControlBackend> = Arc::new(
                crate::control::EngineControlBackend::new(
                    engine.clone(),
                    config.volume.name.clone(),
                )
                .with_crypto_stats(crypto_stats.clone()),
            );
            let group = config.control.group.clone();
            let listener = runtime
                .block_on(async {
                    maki_control::uds::bind_control_socket(
                        std::path::Path::new(&socket),
                        group.as_deref(),
                    )
                })
                .map_err(|e| AdapterError::new(EIO, format!("control socket {socket}: {e}")))?;
            let task = runtime.spawn(async move {
                if let Err(e) = maki_control::uds::serve(listener, backend).await {
                    tracing::error!("control socket server stopped: {e}");
                }
            });
            Some(ControlServer {
                task,
                path: std::path::PathBuf::from(socket),
            })
        };

        Ok(Self {
            runtime,
            state: parking_lot::RwLock::new(Some(Arc::new(AdapterState {
                engine,
                block_sizes,
            }))),
            #[cfg(unix)]
            control: parking_lot::Mutex::new(control),
        })
    }

    /// Path of the served control socket, if one is running.
    #[cfg(unix)]
    pub fn control_socket_path(&self) -> Option<std::path::PathBuf> {
        self.control.lock().as_ref().map(|c| c.path.clone())
    }

    fn state(&self) -> Result<Arc<AdapterState>, AdapterError> {
        self.state
            .read()
            .clone()
            .ok_or_else(|| AdapterError::new(ESHUTDOWN, "volume detached"))
    }

    /// Run a blocking engine operation with a panic boundary.
    fn run<T>(&self, op: impl FnOnce(Engine) -> BoxCoreFuture<T>) -> Result<T, AdapterError> {
        let state = self.state()?;
        let engine = state.engine.clone();
        let outcome =
            std::panic::catch_unwind(AssertUnwindSafe(|| self.runtime.block_on(op(engine))));
        match outcome {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(map_core_error(&e)),
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panic in engine".to_string());
                tracing::error!("panic caught at NBD boundary: {msg}");
                Err(AdapterError::new(EIO, format!("internal panic: {msg}")))
            }
        }
    }

    pub fn get_size(&self) -> u64 {
        self.state().map(|s| s.engine.size()).unwrap_or(0)
    }

    pub fn block_sizes(&self) -> (u32, u32, u32) {
        self.state()
            .map(|s| s.block_sizes)
            .unwrap_or((512, 4096, 1 << 20))
    }

    pub fn can_trim(&self) -> bool {
        false
    }

    pub fn can_write_zeroes(&self) -> bool {
        false
    }

    pub fn can_multi_conn(&self) -> bool {
        false
    }

    pub fn can_flush(&self) -> bool {
        true
    }

    pub fn can_fua(&self) -> bool {
        true
    }

    /// Negotiation is advisory: clients may still send requests outside
    /// these limits. Refuse them before copying plaintext or entering the
    /// engine, whose journal headroom is sized for the configured maximum.
    fn validate_request(&self, offset: u64, length: usize) -> Result<(), AdapterError> {
        let state = self.state()?;
        let (minimum, _, maximum) = state.block_sizes;
        if length == 0
            || length as u64 > maximum as u64
            || !(length as u64).is_multiple_of(minimum as u64)
            || !offset.is_multiple_of(minimum as u64)
            || offset
                .checked_add(length as u64)
                .is_none_or(|end| end > state.engine.size())
        {
            return Err(AdapterError::new(
                EINVAL,
                "request exceeds NBD size or alignment constraints",
            ));
        }
        Ok(())
    }

    pub fn pread(&self, buf: &mut [u8], offset: u64) -> Result<(), AdapterError> {
        self.validate_request(offset, buf.len())?;
        let len = buf.len();
        // Plaintext stays in zeroizing buffers until it is copied into the
        // caller's (nbdkit's) buffer (SPEC §36).
        let data =
            self.run(move |engine| Box::pin(async move { engine.read_secret(offset, len).await }))?;
        buf.copy_from_slice(data.expose());
        Ok(())
    }

    pub fn pwrite(&self, data: &[u8], offset: u64, fua: bool) -> Result<(), AdapterError> {
        self.validate_request(offset, data.len())?;
        let owned = SecretBuffer::from_slice(data);
        self.run(move |engine| {
            Box::pin(async move { engine.write(offset, owned.expose(), fua).await })
        })
    }

    pub fn flush(&self) -> Result<(), AdapterError> {
        self.run(move |engine| Box::pin(async move { engine.flush().await }))
    }

    pub fn checkpoint(&self) -> Result<u64, AdapterError> {
        self.run(move |engine| Box::pin(async move { engine.checkpoint().await }))
    }

    /// Stop serving the control socket and remove its path.
    fn stop_control(&self) {
        #[cfg(unix)]
        if let Some(control) = self.control.lock().take() {
            control.task.abort();
            let _ = std::fs::remove_file(&control.path);
        }
    }

    /// Clean detach: FLUSH, checkpoint, stop the control socket, release
    /// the volume lock.
    pub fn shutdown(&self) -> Result<(), AdapterError> {
        self.flush()?;
        self.checkpoint()?;
        self.stop_control();
        *self.state.write() = None; // drops Engine → volume lock released
        Ok(())
    }
}

type BoxCoreFuture<T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, CoreError>> + Send>>;
