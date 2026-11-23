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
use std::sync::{Arc, OnceLock, Weak};

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

fn registry() -> &'static Mutex<HashMap<String, Arc<FailpointAction>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<FailpointAction>>>> = OnceLock::new();
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
    let action = Arc::new(action);
    let registration = Arc::downgrade(&action);
    let previous = registry().lock().insert(name.to_string(), action);
    drop(previous); // A callback may own another guard.
    FailpointGuard {
        name: name.to_string(),
        registration,
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
    let actions = std::mem::take(&mut *registry().lock());
    drop(actions);
}

/// Evaluate the failpoint `name`. No-op unless an action is registered.
pub fn hit(name: &str) -> io::Result<()> {
    let action = registry().lock().get(name).cloned();
    match action.as_deref() {
        None => Ok(()),
        Some(FailpointAction::Panic(msg)) => panic!("failpoint {name}: {msg}"),
        Some(FailpointAction::IoError(kind, msg)) => Err(io::Error::new(*kind, msg.clone())),
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
    registration: Weak<FailpointAction>,
}

impl Drop for FailpointGuard {
    fn drop(&mut self) {
        let mut actions = registry().lock();
        if actions
            .get(&self.name)
            .is_some_and(|current| self.registration.ptr_eq(&Arc::downgrade(current)))
        {
            let removed = actions.remove(&self.name);
            drop(actions);
            drop(removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callbacks_are_destroyed_after_unlocking_the_registry() {
        struct CheckDrop;
        impl Drop for CheckDrop {
            fn drop(&mut self) {
                assert!(
                    registry().try_lock().is_some(),
                    "action dropped under registry lock"
                );
            }
        }
        let _lock = test_lock();
        for operation in ["remove", "replace", "clear"] {
            let owned = CheckDrop;
            let guard = set(
                "owned",
                FailpointAction::Callback(Arc::new(move || {
                    let _reference = &owned;
                    None
                })),
            );
            match operation {
                "replace" => drop(set("owned", FailpointAction::Panic(String::new()))),
                "clear" => clear_all(),
                _ => (),
            }
            drop(guard);
        }
    }

    #[test]
    fn stale_guard_preserves_current_registration() {
        let _lock = test_lock();
        for clear_first in [false, true] {
            let old = fail_n_times("replacement", 1, io::ErrorKind::BrokenPipe, "old");
            if clear_first {
                clear_all();
            }
            let current = fail_n_times("replacement", 1, io::ErrorKind::Interrupted, "new");
            drop(old);
            assert_eq!(
                hit("replacement").unwrap_err().kind(),
                io::ErrorKind::Interrupted
            );
            drop(current);
            assert!(!is_active("replacement"));
        }
    }
}
