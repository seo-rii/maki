//! Shared admission and acknowledged drain for NBD callbacks and administration.

use std::sync::Arc;

use maki_core::engine::Engine;
use parking_lot::Mutex;
use tokio::sync::Notify;

#[derive(Default)]
enum Phase {
    #[default]
    Running,
    Draining,
    Failed(String),
    Drained(u64),
}

#[derive(Default)]
struct State {
    phase: Phase,
    active: usize,
}

#[derive(Default)]
pub(crate) struct DrainGate {
    state: Mutex<State>,
    idle: Notify,
    drain: tokio::sync::Mutex<()>,
}

impl DrainGate {
    pub(crate) fn enter(self: &Arc<Self>) -> Result<Callback, &'static str> {
        let mut state = self.state.lock();
        if !matches!(state.phase, Phase::Running) {
            return Err("volume admission is closed for drain");
        }
        state.active += 1;
        Ok(Callback(self.clone()))
    }

    pub(crate) fn status(&self) -> (&'static str, Option<String>) {
        match &self.state.lock().phase {
            Phase::Running => ("running", None),
            Phase::Draining => ("draining", None),
            Phase::Failed(error) => ("failed", Some(error.clone())),
            Phase::Drained(_) => ("drained", None),
        }
    }

    /// Cancellation leaves admission closed; a later caller retries the barrier.
    pub(crate) async fn drain(&self, engine: &Engine) -> Result<u64, String> {
        let _drain = self.drain.lock().await;
        {
            let mut state = self.state.lock();
            if let Phase::Drained(sequence) = state.phase {
                return Ok(sequence);
            }
            state.phase = Phase::Draining;
        }
        loop {
            // Register before inspecting active callbacks to avoid losing the
            // final callback's notification between the check and the await.
            let idle = self.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            if self.state.lock().active == 0 {
                break;
            }
            idle.await;
        }
        let result = async {
            engine.flush().await?;
            engine.checkpoint().await
        }
        .await
        .map_err(|e: maki_core::CoreError| e.to_string());
        self.state.lock().phase = match &result {
            Ok(sequence) => Phase::Drained(*sequence),
            Err(error) => Phase::Failed(error.clone()),
        };
        result
    }
}

pub(crate) struct Callback(Arc<DrainGate>);

impl Drop for Callback {
    fn drop(&mut self) {
        let mut state = self.0.state.lock();
        state.active -= 1;
        if state.active == 0 {
            self.0.idle.notify_one();
        }
    }
}
