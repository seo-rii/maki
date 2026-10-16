use super::*;
use std::sync::atomic::AtomicUsize;
use tokio_tungstenite::tungstenite::Bytes;

struct ObservedFrame {
    bytes: Vec<u8>,
    drops: Arc<AtomicUsize>,
}

impl AsRef<[u8]> for ObservedFrame {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ObservedFrame {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cancelled_queued_frame_drops_while_a_live_sibling_keeps_its_connection() {
    let task = tokio::spawn(std::future::pending::<()>());
    let pending = Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let cancellation = ConnectionCancellation {
        task: task.abort_handle(),
        pending: pending.clone(),
        dead_generation: Arc::new(AtomicU64::new(0)),
        generation: 1,
        owners: Arc::new(parking_lot::Mutex::new(RequestOwners {
            accepting: true,
            active: 0,
        })),
    };
    let (sender, mut receiver) = mpsc::channel(2);
    let drops = Arc::new(AtomicUsize::new(0));
    let queued = Arc::new(parking_lot::Mutex::new(Some(Message::Binary(
        Bytes::from_owner(ObservedFrame {
            bytes: vec![0x51; 128],
            drops: drops.clone(),
        }),
    ))));
    assert!(cancellation.register());
    let cancelled = PendingRequest {
        id: 1,
        pending: pending.clone(),
        cancellation: cancellation.clone(),
        queued: queued.clone(),
        _sender: sender.clone(),
        completed: false,
    };
    assert!(cancellation.register());
    let sibling = PendingRequest {
        id: 2,
        pending,
        cancellation: cancellation.clone(),
        queued: Arc::new(parking_lot::Mutex::new(None)),
        _sender: sender.clone(),
        completed: true,
    };
    sender.try_send(queued).unwrap();
    drop(cancelled);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "queue retained cancelled payload"
    );
    assert!(receiver.try_recv().unwrap().lock().is_none());
    assert!(
        !cancellation.register(),
        "new callers joined a draining connection"
    );
    assert!(!task.is_finished(), "live sibling lost its connection task");
    drop(sibling);
    assert!(task.await.unwrap_err().is_cancelled());
}
