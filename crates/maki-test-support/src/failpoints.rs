//! Named failpoints for persistence boundaries (SPEC §42, §45).
//!
//! Production code calls `failpoints::hit("journal.append.pre_sync")?` behind
//! a `failpoints` cargo feature; with no action registered this is a no-op.
//! Tests register actions via [`set`], scoped by the returned guard.
//!
//! Failpoint names are global; tests that register actions must serialize via
//! [`test_lock`].

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, OnceLock};

use parking_lot::{Mutex, MutexGuard};

#[derive(Clone)]
pub enum FailpointAction {
    /// Panic with the given message (tests the panic boundary).
    Panic(String),
    /// Fail the operation with an io::Error.
    IoError(io::ErrorKind, String),
    /// Arbitrary callback; return Some(err) to fail the operation.
    Callback(Arc<dyn Fn() -> Option<io::Error> + Send + Sync>),
}

fn registry() -> &'static Mutex<HashMap<String, FailpointAction>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, FailpointAction>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Serialize tests that use (global) failpoints.
pub fn test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock()
}

/// Register an action; it is removed when the guard drops.
#[must_use = "the failpoint is cleared when the guard drops"]
pub fn set(name: &str, action: FailpointAction) -> FailpointGuard {
    registry().lock().insert(name.to_string(), action);
    FailpointGuard {
        name: name.to_string(),
    }
}

/// Register an action that fails the first `n` hits with an io::Error, then
/// becomes a no-op.
#[must_use = "the failpoint is cleared when the guard drops"]
pub fn fail_n_times(name: &str, n: usize, kind: io::ErrorKind, msg: &str) -> FailpointGuard {
    let remaining = Arc::new(Mutex::new(n));
    let msg = msg.to_string();
    set(
        name,
        FailpointAction::Callback(Arc::new(move || {
            let mut r = remaining.lock();
            if *r > 0 {
                *r -= 1;
                Some(io::Error::new(kind, msg.clone()))
            } else {
                None
            }
        })),
    )
}

pub fn clear_all() {
    registry().lock().clear();
}

/// Evaluate the failpoint `name`. No-op unless an action is registered.
pub fn hit(name: &str) -> io::Result<()> {
    let action = registry().lock().get(name).cloned();
    match action {
        None => Ok(()),
        Some(FailpointAction::Panic(msg)) => panic!("failpoint {name}: {msg}"),
        Some(FailpointAction::IoError(kind, msg)) => Err(io::Error::new(kind, msg)),
        Some(FailpointAction::Callback(cb)) => match cb() {
            Some(err) => Err(err),
            None => Ok(()),
        },
    }
}

pub fn is_active(name: &str) -> bool {
    registry().lock().contains_key(name)
}

pub struct FailpointGuard {
    name: String,
}

impl Drop for FailpointGuard {
    fn drop(&mut self) {
        registry().lock().remove(&self.name);
    }
}
