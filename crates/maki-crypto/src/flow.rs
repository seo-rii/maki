//! Flow-control primitives (SPEC §30): dual count+byte semaphores and
//! bounded queues with byte limits. All internal queues are bounded; all
//! major queues also have byte limits (SPEC §12).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

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

    fn byte_permits(&self, bytes: u64) -> u32 {
        // An oversized request is capped to the whole budget (it serializes
        // against everything else rather than deadlocking forever).
        bytes.min(self.max_bytes) as u32
    }

    /// Acquire one item slot plus `bytes` of byte budget.
    pub async fn acquire(&self, bytes: u64) -> DualPermit {
        let items = self
            .items
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");
        let bytes = self
            .bytes
            .clone()
            .acquire_many_owned(self.byte_permits(bytes))
            .await
            .expect("semaphore closed");
        DualPermit {
            _items: items,
            _bytes: bytes,
        }
    }

    /// Acquire `items` item slots plus `bytes` of byte budget. An oversized
    /// request is capped to the whole budget, like bytes.
    pub async fn acquire_n(&self, items: u32, bytes: u64) -> DualPermit {
        let count = (items as usize).clamp(1, self.max_items) as u32;
        let items = self
            .items
            .clone()
            .acquire_many_owned(count)
            .await
            .expect("semaphore closed");
        let bytes = self
            .bytes
            .clone()
            .acquire_many_owned(self.byte_permits(bytes))
            .await
            .expect("semaphore closed");
        DualPermit {
            _items: items,
            _bytes: bytes,
        }
    }

    /// Non-blocking acquire. Returns `None` when capacity is unavailable or
    /// the request exceeds the total byte budget.
    pub fn try_acquire(&self, bytes: u64) -> Option<DualPermit> {
        if bytes > self.max_bytes {
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
    pub async fn push(&self, item: T, bytes: u64) {
        let permit = self.capacity.acquire(bytes).await;
        self.inner.lock().push_back((item, permit));
        self.len.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
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
