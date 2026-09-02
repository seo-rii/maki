//! Blocking NBD adapter over the async engine (SPEC §48).
//!
//! - Every entry point catches panics: nothing ever unwinds across the FFI
//!   boundary; a panic maps to EIO and the adapter stays usable.
//! - Capability surface per SPEC §48: FLUSH + FUA supported; trim, write-
//!   zeroes, and multi-connection disabled (nbdkit emulates zeroes via
//!   pwrite).
//! - `shutdown` is the clean-detach path: FLUSH barrier, checkpoint, then
//!   release of the volume lock.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use maki_core::engine::Engine;
use maki_core::CoreError;

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

pub struct NbdAdapter {
    runtime: tokio::runtime::Runtime,
    state: parking_lot::RwLock<Option<Arc<AdapterState>>>,
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
        }
    }

    /// Full daemon path: parse + validate config, build backing/provider,
    /// run recovery + self-test, return a serving adapter.
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
        let engine = runtime
            .block_on(daemon::attach_from_config(&config))
            .map_err(|e| AdapterError::new(EIO, e.to_string()))?;
        let block_sizes = (
            config.nbd.minimum_io,
            config.nbd.preferred_io,
            config.nbd.maximum_io.0.min(u32::MAX as u64) as u32,
        );
        Ok(Self {
            runtime,
            state: parking_lot::RwLock::new(Some(Arc::new(AdapterState {
                engine,
                block_sizes,
            }))),
        })
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

    pub fn pread(&self, buf: &mut [u8], offset: u64) -> Result<(), AdapterError> {
        let len = buf.len();
        let data =
            self.run(move |engine| Box::pin(async move { engine.read(offset, len).await }))?;
        buf.copy_from_slice(&data);
        Ok(())
    }

    pub fn pwrite(&self, data: &[u8], offset: u64, fua: bool) -> Result<(), AdapterError> {
        let owned = data.to_vec();
        self.run(move |engine| Box::pin(async move { engine.write(offset, &owned, fua).await }))
    }

    pub fn flush(&self) -> Result<(), AdapterError> {
        self.run(move |engine| Box::pin(async move { engine.flush().await }))
    }

    pub fn checkpoint(&self) -> Result<u64, AdapterError> {
        self.run(move |engine| Box::pin(async move { engine.checkpoint().await }))
    }

    /// Clean detach: FLUSH, checkpoint, release the volume lock.
    pub fn shutdown(&self) -> Result<(), AdapterError> {
        self.flush()?;
        self.checkpoint()?;
        *self.state.write() = None; // drops Engine → volume lock released
        Ok(())
    }
}

type BoxCoreFuture<T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, CoreError>> + Send>>;
