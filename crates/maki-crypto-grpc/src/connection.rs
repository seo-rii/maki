//! An established channel can remain TCP-open while no longer making RPC
//! progress. Retire it on retryable failure, timeout or caller cancellation.
//! Preserve unfinished connection attempts: their separate TLS/connect bound
//! allows a slow successful handshake to outlive one RPC deadline. A channel
//! with no completed RPC is still retired after that initial progress window,
//! covering a completed handshake followed by a silent first RPC.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

use hyper_util::client::legacy::connect::HttpConnector;
use tonic::transport::{Channel, Endpoint};

struct CachedChannel {
    inner: Channel,
    established: AtomicBool,
    started: Instant,
}

impl CachedChannel {
    fn new(endpoint: &Endpoint, connector: &HttpConnector) -> Arc<Self> {
        Arc::new(Self {
            inner: endpoint
                .clone()
                .connect_with_connector_lazy(connector.clone()),
            established: AtomicBool::new(false),
            started: Instant::now(),
        })
    }
}

pub(super) struct ConnectionCache {
    endpoint: Endpoint,
    connector: HttpConnector,
    current: Mutex<Option<Arc<CachedChannel>>>,
    initial_progress_timeout: Duration,
}

impl ConnectionCache {
    pub(super) fn new(
        endpoint: Endpoint,
        connector: HttpConnector,
        initial_progress_timeout: Duration,
    ) -> Self {
        Self {
            endpoint,
            connector,
            // Start the connection/progress clock when the first RPC starts,
            // not when a possibly long-idle provider is constructed.
            current: Mutex::new(None),
            initial_progress_timeout,
        }
    }

    pub(super) fn exchange(&self) -> Exchange<'_> {
        let mut current = self.current.lock().expect("gRPC connection mutex poisoned");
        let channel = current
            .get_or_insert_with(|| CachedChannel::new(&self.endpoint, &self.connector))
            .clone();
        Exchange {
            cache: self,
            channel,
            finished: false,
        }
    }
}

pub(super) struct Exchange<'a> {
    cache: &'a ConnectionCache,
    channel: Arc<CachedChannel>,
    finished: bool,
}

impl Exchange<'_> {
    pub(super) fn channel(&self) -> Channel {
        self.channel.inner.clone()
    }

    pub(super) fn succeeded(&mut self) {
        self.channel.established.store(true, Ordering::Release);
        self.finished = true;
    }

    /// A completed nonretryable/throttled response needs no reconnect.
    pub(super) fn preserve(&mut self) {
        // An application error still proves the transport connected. Future
        // failures must not receive the unfinished-handshake grace period.
        self.succeeded();
    }
}

impl Drop for Exchange<'_> {
    fn drop(&mut self) {
        if self.finished
            || (!self.channel.established.load(Ordering::Acquire)
                && self.channel.started.elapsed() < self.cache.initial_progress_timeout)
        {
            return;
        }
        let mut current = self
            .cache
            .current
            .lock()
            .expect("gRPC connection mutex poisoned");
        // Concurrent RPCs may still reference an older channel. A late error
        // or cancellation must never evict a replacement another RPC opened.
        if current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.channel))
        {
            *current = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> ConnectionCache {
        ConnectionCache::new(
            Endpoint::from_static("http://127.0.0.1:1"),
            HttpConnector::new(),
            Duration::from_secs(4),
        )
    }

    #[tokio::test]
    async fn cancelling_unestablished_exchange_preserves_connection_attempt() {
        let cache = cache();
        let pending = cache.exchange();
        let original = pending.channel.clone();
        drop(pending);
        assert!(Arc::ptr_eq(&cache.exchange().channel, &original));
    }

    #[tokio::test(start_paused = true)]
    async fn no_successful_rpc_cannot_preserve_a_channel_forever() {
        let cache = cache();
        let first = cache.exchange();
        let old = first.channel.clone();
        tokio::time::advance(Duration::from_secs(4)).await;
        drop(first);
        assert!(!Arc::ptr_eq(&cache.exchange().channel, &old));
    }

    #[tokio::test]
    async fn late_cancelled_exchange_cannot_evict_a_healthy_replacement() {
        let cache = cache();
        let mut completed = cache.exchange();
        completed.succeeded();
        let old_request = cache.exchange();
        let failed_request = cache.exchange();
        drop(failed_request);
        let mut replacement = cache.exchange();
        replacement.succeeded();
        let new_channel = replacement.channel.clone();
        assert!(!Arc::ptr_eq(&old_request.channel, &new_channel));
        drop(old_request);
        assert!(Arc::ptr_eq(&cache.exchange().channel, &new_channel));
    }
}
