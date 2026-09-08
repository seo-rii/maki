//! Flow-control primitives (SPEC §30): dual count+byte semaphores and
//! bounded queues with byte limits. All internal queues are bounded; all
//! major queues also have byte limits (SPEC §12).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::error::CryptoError;

/// A semaphore bounding both item count and total bytes.
pub struct DualSemaphore {
    items: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    max_items: usize,
    max_bytes: u64,
}

/// Held capacity; released on drop (permit leak = 0 by construction).
pub struct DualPermit {
    _items: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
}

impl DualSemaphore {
    pub fn new(max_items: u32, max_bytes: u64) -> Self {
        // tokio permits are u32-sized per acquire; cap byte budgets.
        let capped = max_bytes.min(u32::MAX as u64 >> 1) as usize;
        Self {
            items: Arc::new(Semaphore::new(max_items as usize)),
            bytes: Arc::new(Semaphore::new(capped)),
            max_items: max_items as usize,
            max_bytes: capped as u64,
        }
    }

    fn check_request(&self, items: u32, bytes: u64) -> Result<(), CryptoError> {
        if items == 0 || items as usize > self.max_items || bytes > self.max_bytes {
            return Err(CryptoError::NonRetryableRequest(format!(
                "admission request of {items} item(s) / {bytes} byte(s) exceeds \
                 capacity of {} item(s) / {} byte(s), or has no items",
                self.max_items, self.max_bytes
            )));
        }
        Ok(())
    }

    /// Acquire one item slot plus `bytes` of byte budget.
    /// Returns a non-retryable request error if it cannot fit the total budget.
    pub async fn acquire(&self, bytes: u64) -> Result<DualPermit, CryptoError> {
        self.acquire_n(1, bytes).await
    }

    /// Acquire `items` item slots plus `bytes` of byte budget. Oversized or
    /// zero-item requests fail before acquiring any capacity.
    pub async fn acquire_n(&self, items: u32, bytes: u64) -> Result<DualPermit, CryptoError> {
        self.check_request(items, bytes)?;
        let items = self
            .items
            .clone()
            .acquire_many_owned(items)
            .await
            .expect("semaphore closed");
        let bytes = self
            .bytes
            .clone()
            .acquire_many_owned(bytes as u32)
            .await
            .expect("semaphore closed");
        Ok(DualPermit {
            _items: items,
            _bytes: bytes,
        })
    }

    /// Non-blocking acquire. Returns `None` when capacity is unavailable or
    /// the request exceeds the total byte budget.
    pub fn try_acquire(&self, bytes: u64) -> Option<DualPermit> {
        if self.check_request(1, bytes).is_err() {
            return None;
        }
        let items = self.items.clone().try_acquire_owned().ok()?;
        let bytes = self
            .bytes
            .clone()
            .try_acquire_many_owned(bytes as u32)
            .ok()?;
        Some(DualPermit {
            _items: items,
            _bytes: bytes,
        })
    }

    pub fn available_items(&self) -> usize {
        self.items.available_permits()
    }

    pub fn available_bytes(&self) -> u64 {
        self.bytes.available_permits() as u64
    }

    pub fn max_items(&self) -> usize {
        self.max_items
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

/// FIFO queue bounded by item count and bytes; `push` applies backpressure.
pub struct BoundedQueue<T> {
    capacity: DualSemaphore,
    inner: parking_lot::Mutex<VecDeque<(T, DualPermit)>>,
    notify: Notify,
    len: AtomicUsize,
}

impl<T> BoundedQueue<T> {
    pub fn new(max_items: u32, max_bytes: u64) -> Self {
        Self {
            capacity: DualSemaphore::new(max_items, max_bytes),
            inner: parking_lot::Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            len: AtomicUsize::new(0),
        }
    }

    /// Enqueue, waiting for capacity (count and bytes).
    pub async fn push(&self, item: T, bytes: u64) -> Result<(), CryptoError> {
        let permit = self.capacity.acquire(bytes).await?;
        self.inner.lock().push_back((item, permit));
        self.len.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
        Ok(())
    }

    fn try_pop(&self) -> Option<T> {
        let mut inner = self.inner.lock();
        let (item, permit) = inner.pop_front()?;
        self.len.fetch_sub(1, Ordering::SeqCst);
        drop(inner);
        drop(permit); // capacity released only once the item leaves the queue
        Some(item)
    }

    /// Dequeue, waiting for an item.
    pub async fn pop(&self) -> T {
        loop {
            let notified = self.notify.notified();
            if let Some(item) = self.try_pop() {
                // Wake the next waiter in case multiple pops raced.
                self.notify.notify_one();
                return item;
            }
            notified.await;
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::SeqCst)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
