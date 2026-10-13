//! BUG-079: queue occupancy remains within capacity during concurrent publication.

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

use maki_crypto::flow::BoundedQueue;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_queue_publication_keeps_length_within_capacity() {
    const CAPACITY: usize = 8;
    const ITEMS: usize = 500_000;
    let queue = Arc::new(BoundedQueue::<usize>::new(CAPACITY as u32, 1024));
    let largest = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let observer = {
        let (queue, largest, done) = (queue.clone(), largest.clone(), done.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                largest.fetch_max(queue.len(), Ordering::Relaxed);
                std::hint::spin_loop();
            }
        })
    };
    let writer = {
        let queue = queue.clone();
        tokio::spawn(async move {
            for item in 0..ITEMS {
                queue.push(item, 1).await.unwrap();
            }
        })
    };
    for expected in 0..ITEMS {
        assert_eq!(
            queue.pop().await,
            expected,
            "FIFO ordering must be preserved"
        );
        largest.fetch_max(queue.len(), Ordering::Relaxed);
    }
    writer.await.unwrap();
    done.store(true, Ordering::Release);
    observer.join().unwrap();
    assert!(queue.is_empty());
    let observed = largest.load(Ordering::Relaxed);
    assert!(
        observed <= CAPACITY,
        "queue capacity {CAPACITY}, largest reported length {observed}"
    );
    // All permits must also be reusable after this many publication races.
    for item in 0..CAPACITY {
        queue.push(item, 128).await.unwrap();
    }
    assert_eq!(queue.len(), CAPACITY);
    for item in 0..CAPACITY {
        assert_eq!(queue.pop().await, item);
    }
    assert!(queue.is_empty());
}

#[tokio::test]
async fn serial_queue_length_tracks_each_operation() {
    let queue = BoundedQueue::<usize>::new(8, 1024);
    for item in 0..8 {
        queue.push(item, 1).await.unwrap();
        assert_eq!(queue.len(), item + 1);
    }
    for item in 0..8 {
        assert_eq!(queue.pop().await, item);
        assert_eq!(queue.len(), 7 - item);
    }
    assert!(queue.is_empty());
}
