//! Generic batch aggregator (SPEC §30 "batch scheduler", config §57
//! `[crypto.batch]`): collects submitted items into batches bounded by
//! target/max item and byte counts, flushing early when a target is met and
//! at the latest after `max_wait`.

use std::time::Duration;

use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub target_items: usize,
    pub target_bytes: u64,
    pub max_items: usize,
    pub max_bytes: u64,
    pub max_wait: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            target_items: 64,
            target_bytes: 256 << 10,
            max_items: 128,
            max_bytes: 1 << 20,
            max_wait: Duration::from_micros(150),
        }
    }
}

pub struct Batcher<T: Send + 'static> {
    tx: mpsc::Sender<(T, u64)>,
}

impl<T: Send + 'static> Batcher<T> {
    /// Spawn the aggregation task. `flush` is called with each formed batch
    /// (serially, preserving submission order).
    pub fn spawn<F, Fut>(config: BatchConfig, mut flush: F) -> Self
    where
        F: FnMut(Vec<T>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        // Bounded submission channel: backpressure at 2× max_items.
        let (tx, mut rx) = mpsc::channel::<(T, u64)>(config.max_items.max(1) * 2);
        tokio::spawn(async move {
            loop {
                // Wait for the first item of the next batch.
                let Some((first, first_bytes)) = rx.recv().await else {
                    return;
                };
                let mut batch = vec![first];
                let mut bytes = first_bytes;
                let deadline = tokio::time::Instant::now() + config.max_wait;

                loop {
                    if batch.len() >= config.target_items || bytes >= config.target_bytes {
                        break;
                    }
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some((item, item_bytes))) => {
                            if batch.len() + 1 > config.max_items
                                || bytes + item_bytes > config.max_bytes
                            {
                                // Would overflow the hard cap: flush what we
                                // have, start the next batch with this item.
                                flush(std::mem::take(&mut batch)).await;
                                bytes = 0;
                            }
                            batch.push(item);
                            bytes += item_bytes;
                        }
                        Ok(None) => break, // channel closed: flush remainder
                        Err(_) => break,   // max_wait elapsed
                    }
                }
                if !batch.is_empty() {
                    flush(batch).await;
                }
            }
        });
        Self { tx }
    }

    /// Submit one item (applies backpressure when the channel is full).
    pub async fn submit(&self, item: T, bytes: u64) {
        let _ = self.tx.send((item, bytes)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    type ObservedBatches = Arc<Mutex<Vec<Vec<u32>>>>;
    type FlushFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
    type FlushFn = Box<dyn FnMut(Vec<u32>) -> FlushFuture + Send>;

    fn collector() -> (ObservedBatches, FlushFn) {
        let seen: ObservedBatches = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let flush = move |batch: Vec<u32>| {
            let seen = seen2.clone();
            Box::pin(async move {
                seen.lock().await.push(batch);
            }) as FlushFuture
        };
        (seen, Box::new(flush))
    }

    #[tokio::test(start_paused = true)]
    async fn flushes_when_target_items_reached() {
        let (seen, flush) = collector();
        let batcher = Batcher::spawn(
            BatchConfig {
                target_items: 3,
                max_wait: Duration::from_secs(60),
                ..Default::default()
            },
            flush,
        );
        for i in 0..6u32 {
            batcher.submit(i, 10).await;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
        let seen = seen.lock().await;
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], vec![0, 1, 2]);
        assert_eq!(seen[1], vec![3, 4, 5]);
    }

    #[tokio::test(start_paused = true)]
    async fn flushes_on_max_wait() {
        let (seen, flush) = collector();
        let batcher = Batcher::spawn(
            BatchConfig {
                target_items: 100,
                max_wait: Duration::from_millis(5),
                ..Default::default()
            },
            flush,
        );
        batcher.submit(1, 10).await;
        batcher.submit(2, 10).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let seen = seen.lock().await;
        assert_eq!(seen.len(), 1, "partial batch must flush after max_wait");
        assert_eq!(seen[0], vec![1, 2]);
    }
}
