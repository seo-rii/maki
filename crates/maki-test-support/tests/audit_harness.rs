//! Audit: harness pieces (scheduler, manual clock, fake provider) that are
//! more permissive than the runtime or provider contract they stand in for.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use maki_crypto::clock::Clock;
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::{DeterministicScheduler, FakeCryptoProvider, ManualClock};

/// Returns `Pending` once *without* arranging a wake-up, then `Ready`.
/// This violates the `Future` contract: a real executor never polls it
/// again and the task hangs.
struct LostWakeup {
    polled: bool,
}

impl Future for LostWakeup {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.polled {
            Poll::Ready(())
        } else {
            self.polled = true;
            Poll::Pending
        }
    }
}

struct CountingWaker(AtomicUsize);
impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A real executor re-polls a task only after its waker fires. The
/// deterministic scheduler polls every unfinished task with a no-op waker,
/// so a lost wakeup (the classic bug in a hand-written semaphore, queue or
/// notify) still completes there.
#[test]
fn deterministic_scheduler_reports_a_task_that_was_never_woken() {
    // What a real executor sees: Pending, and no wake ever arrives.
    let counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut future = LostWakeup { polled: false };
    assert!(Pin::new(&mut future)
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        0,
        "nobody will re-poll it"
    );

    let mut sched = DeterministicScheduler::new(7);
    sched.spawn(async {
        LostWakeup { polled: false }.await;
    });
    assert!(
        !sched.run_bounded(1_000),
        "the scheduler completed a task whose only wake-up was lost"
    );
}

/// Sleepers sharing a deadline are woken from a `HashMap`, whose iteration
/// order is seeded per map. Under tokio the wake order is the run order, so
/// two runs of the same test schedule woken tasks differently.
#[test]
fn manual_clock_wakes_equal_deadlines_in_a_reproducible_order() {
    struct Recorder {
        id: usize,
        log: Arc<Mutex<Vec<usize>>>,
    }
    impl Wake for Recorder {
        fn wake(self: Arc<Self>) {
            self.log.lock().unwrap().push(self.id);
        }
    }

    let mut orders = Vec::new();
    for _ in 0..16 {
        let clock = ManualClock::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut sleeps: Vec<_> = (0..8)
            .map(|_| clock.sleep(Duration::from_secs(1)))
            .collect();
        for (id, sleep) in sleeps.iter_mut().enumerate() {
            let waker = Waker::from(Arc::new(Recorder {
                id,
                log: log.clone(),
            }));
            assert!(sleep
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending());
        }
        clock.advance(Duration::from_secs(1));
        orders.push(log.lock().unwrap().clone());
    }
    assert!(
        orders.windows(2).all(|pair| pair[0] == pair[1]),
        "wake order differs between identical clocks: {:?} vs {:?}",
        orders[0],
        orders.iter().find(|order| **order != orders[0]).unwrap()
    );
}

/// With integrity disabled the fake claims to behave like an unauthenticated
/// cipher (XTS): every well-sized ciphertext decrypts to *some* plaintext.
/// It still refuses a ciphertext whose first four bytes are not its magic,
/// so an engine that decrypts a zeroed or overwritten slot (instead of
/// refusing it through its own slot CRC) gets an integrity error from the
/// fake, where `local-aes-xts` would return garbage plaintext.
#[test]
fn fake_provider_without_integrity_decrypts_any_well_sized_ciphertext() {
    const UNIT: u32 = 4096;
    let provider = FakeCryptoProvider::new(UNIT).with_integrity_check(false);
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let caps = runtime.block_on(provider.capabilities()).unwrap();
    assert_eq!(caps.integrity, maki_crypto::Capability::Absent);
    let zeroed = maki_crypto::CiphertextUnit {
        unit_index: 0,
        data: vec![0; caps.max_ciphertext_size as usize],
    };
    let result = runtime.block_on(provider.decrypt_batch(&context, &[zeroed]));
    assert!(
        result.is_ok(),
        "an integrity-Absent fake refused a zeroed ciphertext: {:?}",
        result.err()
    );
}

/// The fake advertises `batch.max_bytes` but only enforces `max_items`, so a
/// scheduler that over-packs a batch by bytes passes every fake-backed test
/// while a vendor endpoint would refuse it.
#[test]
fn fake_provider_refuses_a_batch_over_its_declared_byte_limit() {
    const UNIT: u32 = 4096;
    let provider = FakeCryptoProvider::new(UNIT).with_max_batch(128, UNIT as u64);
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    };
    let items: Vec<_> = (0..4)
        .map(|unit_index| PlaintextUnit {
            unit_index,
            data: SecretBuffer::from_vec(vec![unit_index as u8; UNIT as usize]),
        })
        .collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let caps = runtime.block_on(provider.capabilities()).unwrap();
    assert_eq!(caps.batch.max_bytes, UNIT as u64);
    let result = runtime.block_on(provider.encrypt_batch(&context, &items));
    assert!(
        result.is_err(),
        "a {}-byte batch was accepted under a declared {}-byte limit",
        4 * UNIT,
        caps.batch.max_bytes
    );
}
