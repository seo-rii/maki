//! Randomized concurrency stress for the crypto data path: the batch
//! scheduler and the endpoint dispatcher under random request shapes and
//! random provider/endpoint faults, on a real multi-threaded runtime.
//!
//! Properties checked:
//! * results keep request order and unit identity, and round-trip;
//! * every failure is classified retryable (never a silent wrong answer);
//! * no request hangs (the whole run is under a deadline);
//! * counters return to zero: no leaked pending items, bytes, or permits;
//! * once faults stop, the set recovers and serves again.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::clock::SystemClock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{Clock, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: usize = 256;
const TASKS: u64 = 48;
const ROUNDS: u64 = 60;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x57),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    let mut data = vec![0u8; UNIT];
    for (k, b) in data.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(k as u8);
    }
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&data),
    }
}

fn random_error(rng: &mut StdRng) -> CryptoError {
    match rng.random_range(0..3u32) {
        0 => CryptoError::Retryable("chaos".into()),
        1 => CryptoError::Throttled("chaos".into()),
        _ => CryptoError::EndpointFatal("chaos".into()),
    }
}

/// Transient failure classes: retryable/throttled, or an endpoint failure
/// (which the dispatcher handles by failover). Never a data error.
fn transient(e: &CryptoError) -> bool {
    matches!(
        e,
        CryptoError::Retryable(_) | CryptoError::Throttled(_) | CryptoError::EndpointFatal(_)
    )
}

/// Decrypt through the raw provider, retrying past injected faults.
async fn decrypt_direct(
    provider: &FakeCryptoProvider,
    cts: &[maki_crypto::CiphertextUnit],
) -> Vec<PlaintextUnit> {
    for _ in 0..1000 {
        match provider.decrypt_batch(&ctx(), cts).await {
            Ok(v) => return v,
            Err(e) if transient(&e) => tokio::task::yield_now().await,
            Err(e) => panic!("non-retryable decrypt failure: {e}"),
        }
    }
    panic!("decrypt never succeeded");
}

fn scheduler_cfg() -> SchedulerConfig {
    SchedulerConfig {
        target_items: 6,
        target_bytes: 4 * UNIT as u64,
        max_items: 10,
        max_bytes: 16 * UNIT as u64,
        max_wait: Duration::from_micros(500),
        max_pending_items: 512,
        max_pending_plaintext_bytes: 1 << 20,
        max_pending_ciphertext_bytes: 1 << 20,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scheduler_keeps_identity_under_random_load_and_faults() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        scheduler_cfg(),
        clock,
    ));

    let stop = Arc::new(AtomicBool::new(false));
    let chaos = {
        let provider = provider.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0xC0A5);
            while !stop.load(Ordering::SeqCst) {
                if provider.queued_failures() < 4 {
                    provider.fail_next([random_error(&mut rng)]);
                }
                tokio::time::sleep(Duration::from_micros(300)).await;
            }
        })
    };

    let mut tasks = Vec::new();
    for t in 0..TASKS {
        let scheduler = scheduler.clone();
        let provider = provider.clone();
        tasks.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(t);
            let (mut ok, mut failed) = (0u64, 0u64);
            for round in 0..ROUNDS {
                let n = rng.random_range(1..=7u64);
                let base = t * 100_000 + round * 100;
                let units: Vec<PlaintextUnit> = (0..n).map(|i| pt(base + i)).collect();
                match scheduler.encrypt_batch(&ctx(), &units).await {
                    Ok(cts) => {
                        assert_eq!(cts.len(), units.len(), "result count");
                        for (c, p) in cts.iter().zip(&units) {
                            assert_eq!(c.unit_index, p.unit_index, "unit identity");
                        }
                        let back = decrypt_direct(&provider, &cts).await;
                        for (b, p) in back.iter().zip(&units) {
                            assert_eq!(b.unit_index, p.unit_index);
                            assert_eq!(b.data.expose(), p.data.expose(), "round trip");
                        }
                        ok += 1;
                    }
                    Err(e) => {
                        assert!(transient(&e), "unexpected failure class: {e}");
                        failed += 1;
                    }
                }
                if rng.random_bool(0.2) {
                    tokio::task::yield_now().await;
                }
            }
            (ok, failed)
        }));
    }

    let mut total_ok = 0;
    let mut total_failed = 0;
    for task in tasks {
        let (ok, failed) = tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("task hung")
            .unwrap();
        total_ok += ok;
        total_failed += failed;
    }
    stop.store(true, Ordering::SeqCst);
    chaos.await.unwrap();

    assert!(total_ok > 0, "nothing ever succeeded");
    assert!(
        total_failed > 0,
        "fault injection never fired; test is vacuous"
    );
    let stats = scheduler.stats();
    assert_eq!(stats.pending_items(), 0, "pending items leaked");
    assert_eq!(stats.pending_bytes(), 0, "pending bytes leaked");

    // With faults gone every request succeeds again.
    provider.fail_next([]);
    for _ in 0..50 {
        let _ = provider.encrypt_batch(&ctx(), &[pt(1)]).await;
        if provider.queued_failures() == 0 {
            break;
        }
    }
    let cts = scheduler
        .encrypt_batch(&ctx(), &[pt(7), pt(8)])
        .await
        .unwrap();
    assert_eq!(cts[0].unit_index, 7);
    assert_eq!(cts[1].unit_index, 8);
}

fn dispatch_cfg() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 0.5,
            burst: 8,
            min_probe_per_sec: 10.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 3,
            open_initial: Duration::from_millis(5),
            open_max: Duration::from_millis(20),
            half_open_max_requests: 2,
            success_threshold: 1,
        },
        global_max_inflight_batches: 16,
        global_max_inflight_bytes: 4 << 20,
        per_endpoint_max_inflight: 4,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: Some(Duration::from_millis(500)),
        retry_safe: true,
        validation_interval: Duration::from_millis(10),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dispatcher_survives_random_endpoint_faults_and_leaks_nothing() {
    let endpoints: Vec<Arc<FakeCryptoProvider>> = (0..3)
        .map(|_| Arc::new(FakeCryptoProvider::new(UNIT as u32)))
        .collect();
    let set = Arc::new(EndpointSet::new(
        endpoints
            .iter()
            .enumerate()
            .map(|(i, p)| (format!("ep{i}"), p.clone() as Arc<dyn CryptoProvider>))
            .collect(),
        dispatch_cfg(),
        Arc::new(SystemClock::new()),
    ));

    let stop = Arc::new(AtomicBool::new(false));
    let chaos = {
        let endpoints = endpoints.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0xD15);
            while !stop.load(Ordering::SeqCst) {
                let ep = &endpoints[rng.random_range(0..endpoints.len())];
                if ep.queued_failures() < 3 {
                    ep.fail_next([random_error(&mut rng)]);
                }
                tokio::time::sleep(Duration::from_micros(200)).await;
            }
        })
    };

    let mut tasks = Vec::new();
    for t in 0..TASKS {
        let set = set.clone();
        let endpoints = endpoints.clone();
        tasks.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0x1000 + t);
            let (mut ok, mut failed) = (0u64, 0u64);
            for round in 0..ROUNDS {
                let n = rng.random_range(1..=4u64);
                let base = t * 100_000 + round * 100;
                let units: Vec<PlaintextUnit> = (0..n).map(|i| pt(base + i)).collect();
                match set.encrypt_batch(&ctx(), &units).await {
                    Ok(cts) => {
                        assert_eq!(cts.len(), units.len());
                        for (c, p) in cts.iter().zip(&units) {
                            assert_eq!(c.unit_index, p.unit_index);
                        }
                        // Every endpoint shares the key: any of them decrypts.
                        let back = decrypt_direct(&endpoints[0], &cts).await;
                        for (b, p) in back.iter().zip(&units) {
                            assert_eq!(b.data.expose(), p.data.expose());
                        }
                        ok += 1;
                    }
                    Err(e) => {
                        assert!(transient(&e), "unexpected failure class: {e}");
                        failed += 1;
                    }
                }
            }
            (ok, failed)
        }));
    }

    let mut total_ok = 0;
    let mut total_failed = 0;
    for task in tasks {
        let (ok, failed) = tokio::time::timeout(Duration::from_secs(120), task)
            .await
            .expect("task hung")
            .unwrap();
        total_ok += ok;
        total_failed += failed;
    }
    stop.store(true, Ordering::SeqCst);
    chaos.await.unwrap();

    assert!(total_ok > 0, "nothing ever succeeded");
    let _ = total_failed;
    for status in set.endpoint_status() {
        assert_eq!(status.inflight, 0, "permit leaked on {}", status.name);
    }

    // Drain leftover injected faults and prove recovery.
    for ep in &endpoints {
        for _ in 0..20 {
            if ep.queued_failures() == 0 {
                break;
            }
            let _ = ep.encrypt_batch(&ctx(), &[pt(1)]).await;
        }
    }
    let mut recovered = false;
    for _ in 0..200 {
        if set.encrypt_batch(&ctx(), &[pt(3)]).await.is_ok() {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        recovered,
        "endpoint set never recovered after faults stopped"
    );
    for status in set.endpoint_status() {
        assert_eq!(status.inflight, 0, "permit leaked on {}", status.name);
    }
}
