//! Cross-request batch scheduler (SPEC §30 "bounded queue → batch
//! scheduler"; config `[crypto.batch]` and `[limits]`
//! `max_pending_crypto_*` / `max_ciphertext_bytes`).
//!
//! `BatchScheduler` wraps a provider and coalesces concurrent requests into
//! fewer, larger provider calls: a batch is flushed as soon as
//! `target_items` / `target_bytes` are reached, and at the latest
//! `max_wait` after its first item arrived; it never exceeds `max_items` /
//! `max_bytes`. Requests are whole groups: a request's items are never
//! split across batches and their order is preserved, so per-position
//! validation in `CheckedProvider` keeps working. Encrypt and decrypt run
//! on separate lanes, each bounded (count + bytes) so pending crypto work
//! can never grow without limit (SPEC §12).
//!
//! Costs: a request pays at most `max_wait` of extra latency when it is
//! alone, and plaintext is copied once into the lane (the provider trait
//! takes slices). Local providers gain nothing from coalescing, so the
//! daemon only wraps remote ones.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::clock::Clock;
use crate::error::CryptoError;
use crate::flow::{DualPermit, DualSemaphore};
use crate::provider::CryptoProvider;
use crate::types::{CiphertextUnit, CryptoCapabilities, CryptoContext, PlaintextUnit};

#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub target_items: usize,
    pub target_bytes: u64,
    pub max_items: usize,
    pub max_bytes: u64,
    pub max_wait: Duration,
    /// Bound on queued (not yet dispatched) items per lane.
    pub max_pending_items: u32,
    /// Bound on queued plaintext bytes (encrypt lane).
    pub max_pending_plaintext_bytes: u64,
    /// Bound on queued ciphertext bytes (decrypt lane).
    pub max_pending_ciphertext_bytes: u64,
    /// Batches a lane keeps in flight at once. One would serialize every
    /// request behind a single provider round trip (C-04); the dispatcher's
    /// own inflight limits bound what actually reaches the endpoints.
    pub max_inflight_batches: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            target_items: 64,
            target_bytes: 256 << 10,
            max_items: 128,
            max_bytes: 1 << 20,
            max_wait: Duration::from_micros(150),
            max_pending_items: 4096,
            max_pending_plaintext_bytes: 128 << 20,
            max_pending_ciphertext_bytes: 160 << 20,
            max_inflight_batches: 8,
        }
    }
}

/// Observability (SPEC §40 `maki_crypto_pending_*`).
#[derive(Default)]
pub struct SchedulerStats {
    pending_items: AtomicU64,
    pending_bytes: AtomicU64,
    batches: AtomicU64,
    batched_items: AtomicU64,
    coalesced_batches: AtomicU64,
}

impl SchedulerStats {
    pub fn pending_items(&self) -> u64 {
        self.pending_items.load(Ordering::SeqCst)
    }

    pub fn pending_bytes(&self) -> u64 {
        self.pending_bytes.load(Ordering::SeqCst)
    }

    /// Provider calls made.
    pub fn batches_total(&self) -> u64 {
        self.batches.load(Ordering::SeqCst)
    }

    /// Items carried by those calls.
    pub fn batched_items_total(&self) -> u64 {
        self.batched_items.load(Ordering::SeqCst)
    }

    /// Provider calls that carried more than one request.
    pub fn coalesced_batches_total(&self) -> u64 {
        self.coalesced_batches.load(Ordering::SeqCst)
    }
}

struct Group<I, O> {
    context: CryptoContext,
    items: Vec<I>,
    bytes: u64,
    reply: oneshot::Sender<Result<Vec<O>, CryptoError>>,
    /// Queue capacity, released when the group is dispatched.
    _permit: DualPermit,
}

type CallFuture<O> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<O>, CryptoError>> + Send>>;
type LaneCall<I, O> = Arc<dyn Fn(CryptoContext, Vec<I>) -> CallFuture<O> + Send + Sync>;

struct Lane<I, O> {
    tx: mpsc::Sender<Group<I, O>>,
    admission: DualSemaphore,
}

impl<I: Send + 'static, O: Send + 'static> Lane<I, O> {
    fn spawn(
        config: SchedulerConfig,
        max_pending_bytes: u64,
        clock: Arc<dyn Clock>,
        stats: Arc<SchedulerStats>,
        call: LaneCall<I, O>,
    ) -> Self {
        let max_pending_items = config.max_pending_items.max(1);
        let (tx, rx) = mpsc::channel::<Group<I, O>>(max_pending_items as usize);
        let inflight = Arc::new(tokio::sync::Semaphore::new(
            config.max_inflight_batches.max(1) as usize,
        ));
        tokio::spawn(run_lane(rx, config, clock, stats, call, inflight));
        Self {
            tx,
            admission: DualSemaphore::new(max_pending_items, max_pending_bytes),
        }
    }

    async fn submit(
        &self,
        context: &CryptoContext,
        items: Vec<I>,
        bytes: u64,
        stats: &SchedulerStats,
    ) -> Result<Vec<O>, CryptoError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        // One item permit per *item* (C-10): the pending bound is stated in
        // items, and a request of many items must count as many.
        let permit = self
            .admission
            .acquire_n(u32::try_from(items.len()).unwrap_or(u32::MAX), bytes)
            .await;
        let (reply_tx, reply_rx) = oneshot::channel();
        let count = items.len() as u64;
        stats.pending_items.fetch_add(count, Ordering::SeqCst);
        stats.pending_bytes.fetch_add(bytes, Ordering::SeqCst);
        let group = Group {
            context: context.clone(),
            items,
            bytes,
            reply: reply_tx,
            _permit: permit,
        };
        if self.tx.send(group).await.is_err() {
            stats.pending_items.fetch_sub(count, Ordering::SeqCst);
            stats.pending_bytes.fetch_sub(bytes, Ordering::SeqCst);
            return Err(CryptoError::ProviderFatal(
                "crypto batch scheduler has stopped".to_string(),
            ));
        }
        reply_rx.await.unwrap_or_else(|_| {
            Err(CryptoError::Retryable(
                "crypto batch scheduler dropped the request".to_string(),
            ))
        })
    }
}

/// One lane's aggregation loop: form batches of whole groups, dispatch,
/// route results back. Exits when every sender is gone.
async fn run_lane<I: Send + 'static, O: Send + 'static>(
    mut rx: mpsc::Receiver<Group<I, O>>,
    config: SchedulerConfig,
    clock: Arc<dyn Clock>,
    stats: Arc<SchedulerStats>,
    call: LaneCall<I, O>,
    inflight: Arc<tokio::sync::Semaphore>,
) {
    let mut carry: Option<Group<I, O>> = None;
    loop {
        let first = match carry.take() {
            Some(g) => g,
            None => match rx.recv().await {
                Some(g) => g,
                None => return,
            },
        };
        let deadline = clock.now().saturating_add(config.max_wait);
        let mut batch: Vec<Group<I, O>> = vec![first];
        let mut items: usize = batch[0].items.len();
        let mut bytes: u64 = batch[0].bytes;

        while items < config.target_items && bytes < config.target_bytes {
            let remaining = deadline.saturating_sub(clock.now());
            if remaining.is_zero() {
                break;
            }
            let next = tokio::select! {
                g = rx.recv() => g,
                _ = clock.sleep(remaining) => None,
            };
            let Some(group) = next else {
                break;
            };
            let fits = items + group.items.len() <= config.max_items
                && bytes + group.bytes <= config.max_bytes
                && group.context == batch[0].context;
            if !fits {
                carry = Some(group);
                break;
            }
            items += group.items.len();
            bytes += group.bytes;
            batch.push(group);
        }

        for g in &batch {
            stats
                .pending_items
                .fetch_sub(g.items.len() as u64, Ordering::SeqCst);
            stats.pending_bytes.fetch_sub(g.bytes, Ordering::SeqCst);
        }
        stats.batches.fetch_add(1, Ordering::SeqCst);
        stats
            .batched_items
            .fetch_add(items as u64, Ordering::SeqCst);
        if batch.len() > 1 {
            stats.coalesced_batches.fetch_add(1, Ordering::SeqCst);
        }

        let context = batch[0].context.clone();
        let mut lengths = Vec::with_capacity(batch.len());
        let mut replies = Vec::with_capacity(batch.len());
        let mut all_items = Vec::with_capacity(items);
        for g in batch {
            lengths.push(g.items.len());
            replies.push(g.reply);
            all_items.extend(g.items);
            // `_permit` drops here: the group left the queue.
        }
        // Dispatch off the lane task so the next batch forms while this one
        // is in flight (C-04); the inflight semaphore bounds the overlap.
        let slot = inflight
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");
        let call = call.clone();
        tokio::spawn(async move {
            let _slot = slot;
            deliver(call(context, all_items).await, items, lengths, replies);
        });
    }
}

/// Split one provider result back into the groups that formed the batch;
/// a provider error (or a wrong result count) reaches every waiter.
fn deliver<O>(
    result: Result<Vec<O>, CryptoError>,
    items: usize,
    lengths: Vec<usize>,
    replies: Vec<oneshot::Sender<Result<Vec<O>, CryptoError>>>,
) {
    match result {
        Ok(mut out) if out.len() == items => {
            for (len, reply) in lengths.into_iter().zip(replies) {
                let part: Vec<O> = out.drain(..len).collect();
                let _ = reply.send(Ok(part));
            }
        }
        Ok(out) => {
            let err = CryptoError::Contract(format!(
                "provider returned {} results for {items} items",
                out.len()
            ));
            for reply in replies {
                let _ = reply.send(Err(err.duplicate()));
            }
        }
        Err(err) => {
            for reply in replies {
                let _ = reply.send(Err(err.duplicate()));
            }
        }
    }
}

/// A provider that coalesces concurrent requests into batched calls to an
/// inner provider.
pub struct BatchScheduler {
    inner: Arc<dyn CryptoProvider>,
    encrypt: Lane<PlaintextUnit, CiphertextUnit>,
    decrypt: Lane<CiphertextUnit, PlaintextUnit>,
    stats: Arc<SchedulerStats>,
}

impl BatchScheduler {
    /// Spawns the two lane tasks on the current tokio runtime.
    pub fn new(
        inner: Arc<dyn CryptoProvider>,
        config: SchedulerConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let stats = Arc::new(SchedulerStats::default());
        let enc_inner = inner.clone();
        let encrypt = Lane::spawn(
            config.clone(),
            config.max_pending_plaintext_bytes,
            clock.clone(),
            stats.clone(),
            Arc::new(move |context, items: Vec<PlaintextUnit>| {
                let inner = enc_inner.clone();
                Box::pin(async move { inner.encrypt_batch(&context, &items).await })
            }),
        );
        let dec_inner = inner.clone();
        let decrypt = Lane::spawn(
            config.clone(),
            config.max_pending_ciphertext_bytes,
            clock,
            stats.clone(),
            Arc::new(move |context, items: Vec<CiphertextUnit>| {
                let inner = dec_inner.clone();
                Box::pin(async move { inner.decrypt_batch(&context, &items).await })
            }),
        );
        Self {
            inner,
            encrypt,
            decrypt,
            stats,
        }
    }

    pub fn stats(&self) -> Arc<SchedulerStats> {
        self.stats.clone()
    }
}

#[async_trait]
impl CryptoProvider for BatchScheduler {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let bytes: u64 = items.iter().map(|i| i.data.len() as u64).sum();
        let owned: Vec<PlaintextUnit> = items
            .iter()
            .map(|i| PlaintextUnit {
                unit_index: i.unit_index,
                data: i.data.duplicate(),
            })
            .collect();
        self.encrypt
            .submit(context, owned, bytes, &self.stats)
            .await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let bytes: u64 = items.iter().map(|i| i.data.len() as u64).sum();
        self.decrypt
            .submit(context, items.to_vec(), bytes, &self.stats)
            .await
    }
}
