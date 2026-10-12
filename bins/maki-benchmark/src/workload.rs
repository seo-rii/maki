use crate::{latency::Latencies, Options};
use maki_core::engine::Engine;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

#[derive(Serialize)]
pub struct Description {
    pub mode: &'static str,
    pub access: &'static str,
    pub read_percent: Option<u64>,
    pub working_set_bytes: u64,
    pub flush_every_operations: Option<u64>,
    pub seed: u64,
}
#[derive(Serialize)]
pub struct SetupReport {
    pub writes: u64,
    pub flushes: u64,
    pub elapsed_seconds: f64,
}
#[derive(Default, Serialize)]
pub struct ResourceReport {
    pub peak_pending_operations: u64,
    pub pending_operations_at_exit: u64,
    pub observed_peak_active_callbacks: u64,
    pub observed_peak_plaintext_bytes: u64,
    pub observed_peak_overlay_bytes: u64,
    pub observed_peak_journal_pending_bytes: u64,
    pub monitor_samples: u64,
    pub monitor_interval_ms: u64,
    pub process_peak_rss_bytes: Option<u64>,
    pub rss_source: Option<&'static str>,
}
pub struct Measurements {
    pub writes: Latencies,
    pub reads: Latencies,
    pub flushes: Latencies,
    pub elapsed: Duration,
    pub write_elapsed: Duration,
    pub read_elapsed: Duration,
    pub final_flush_us: f64,
    pub setup: SetupReport,
    pub resources: ResourceReport,
}
#[derive(Default)]
struct Pending {
    current: AtomicU64,
    peak: AtomicU64,
}
struct PendingGuard(Arc<Pending>);
impl PendingGuard {
    fn new(pending: Arc<Pending>) -> Self {
        let count = pending.current.fetch_add(1, Ordering::SeqCst) + 1;
        pending.peak.fetch_max(count, Ordering::SeqCst);
        Self(pending)
    }
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.current.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Samples {
    writes: Latencies,
    reads: Latencies,
    flushes: Latencies,
}
#[derive(Clone, Copy)]
enum Kind {
    Write,
    Read,
    Mixed,
}
fn random_slot(index: u64, seed: u64, slots: u64) -> u64 {
    // SplitMix64: reproducible independent address draws, without an address
    // vector proportional to the operation count or working-set size.
    let mut value = index.wrapping_add(seed).wrapping_add(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    (value ^ (value >> 31)) % slots
}
fn data_for(offset: u64, size: usize) -> Vec<u8> {
    let mut bytes = vec![0xa5; size];
    bytes[..8].copy_from_slice(&offset.to_le_bytes());
    bytes
}

/// At most `concurrency` jobs/results exist. Completion order drives refill,
/// so a slow request does not retain later results or block new submissions.
async fn phase(
    engine: &Engine,
    options: &Options,
    slots: u64,
    kind: Kind,
    pending: &Arc<Pending>,
    samples: &mut Samples,
) -> Result<f64, String> {
    let mut first = 0;
    let mut final_flush_us = 0.0;
    let flush = !matches!(kind, Kind::Read);
    let group = if flush {
        options.flush_every.unwrap_or(options.ops)
    } else {
        options.ops
    };
    while first < options.ops {
        let end = first.saturating_add(group).min(options.ops);
        let mut jobs = JoinSet::new();
        let mut next = first;
        while next < end || !jobs.is_empty() {
            while next < end && jobs.len() < options.concurrency {
                let index = next;
                next += 1;
                let read = match kind {
                    Kind::Read => true,
                    Kind::Write => false,
                    Kind::Mixed => {
                        let percent = options.read_percent.expect("mixed has a ratio");
                        (index + 1) * percent / 100 > index * percent / 100
                    }
                };
                let slot = if options.random {
                    random_slot(index, options.seed, slots)
                } else {
                    index % slots
                };
                let offset = slot * options.io_size as u64;
                let size = options.io_size;
                let fua = options.fua;
                let engine = engine.clone();
                let guard = PendingGuard::new(pending.clone());
                jobs.spawn(async move {
                    let _guard = guard;
                    let expected = data_for(offset, size);
                    let began = Instant::now();
                    let elapsed;
                    if read {
                        let actual = engine
                            .read(offset, size)
                            .await
                            .map_err(|error| format!("read at offset {offset} failed: {error}"))?;
                        elapsed = began.elapsed();
                        if actual != expected {
                            return Err(format!("read verification failed at offset {offset}"));
                        }
                    } else {
                        engine
                            .write(offset, &expected, fua)
                            .await
                            .map_err(|error| format!("write at offset {offset} failed: {error}"))?;
                        elapsed = began.elapsed();
                    }
                    Ok::<_, String>((read, elapsed))
                });
            }
            let (read, elapsed) = jobs
                .join_next()
                .await
                .expect("one pending job")
                .map_err(|error| format!("I/O worker failed: {error}"))??;
            if read {
                samples.reads.record(elapsed);
            } else {
                samples.writes.record(elapsed);
            }
        }
        if flush {
            // A periodic FLUSH follows a drained cohort, so its watermark is
            // defined independently of request completion/reordering.
            let began = Instant::now();
            engine
                .flush()
                .await
                .map_err(|error| format!("flush failed: {error}"))?;
            let elapsed = began.elapsed();
            samples.flushes.record(elapsed);
            final_flush_us = elapsed.as_secs_f64() * 1e6;
        }
        first = end;
    }
    Ok(final_flush_us)
}

fn observe(engine: &Engine, resources: &Mutex<ResourceReport>) {
    let stats = engine.monitoring_snapshot().stats;
    let mut report = resources.lock().unwrap();
    report.monitor_samples += 1;
    report.observed_peak_active_callbacks = report
        .observed_peak_active_callbacks
        .max(stats.active_callbacks);
    report.observed_peak_plaintext_bytes = report
        .observed_peak_plaintext_bytes
        .max(stats.plaintext_bytes_in_flight);
    report.observed_peak_overlay_bytes =
        report.observed_peak_overlay_bytes.max(stats.overlay_bytes);
    report.observed_peak_journal_pending_bytes = report
        .observed_peak_journal_pending_bytes
        .max(stats.journal_pending_bytes);
}
fn peak_rss() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()?
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmHWM:")
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse::<u64>().ok())
                    .and_then(|value| value.checked_mul(1024))
            })
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub async fn run(
    engine: Engine,
    options: &Options,
    working_set_bytes: u64,
) -> Result<Measurements, String> {
    let slots = working_set_bytes / options.io_size as u64;
    let began = Instant::now();
    let mut setup = SetupReport {
        writes: 0,
        flushes: 0,
        elapsed_seconds: 0.0,
    };
    if options.read_percent.is_some() {
        // Reads may be scheduled before any measured write. Initialize the
        // complete working set with the same address-dependent payload.
        for slot in 0..slots {
            let offset = slot * options.io_size as u64;
            engine
                .write(offset, &data_for(offset, options.io_size), false)
                .await
                .map_err(|error| format!("setup write at offset {offset} failed: {error}"))?;
            setup.writes += 1;
        }
        engine
            .flush()
            .await
            .map_err(|error| format!("setup flush failed: {error}"))?;
        setup.flushes = 1;
    }
    setup.elapsed_seconds = began.elapsed().as_secs_f64();
    let pending = Arc::new(Pending::default());
    let observations = Arc::new(Mutex::new(ResourceReport::default()));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let monitored_engine = engine.clone();
    let monitored = observations.clone();
    let monitor = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(1));
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                _ = interval.tick() => observe(&monitored_engine,&monitored),
                _ = &mut stopped => break,
            }
        }
        observe(&monitored_engine, &monitored);
    });
    let mut samples = Samples {
        writes: Latencies::new(),
        reads: Latencies::new(),
        flushes: Latencies::new(),
    };
    let began = Instant::now();
    let result = async {
        if options.read_percent.is_some() {
            let final_flush_us =
                phase(&engine, options, slots, Kind::Mixed, &pending, &mut samples).await?;
            let elapsed = began.elapsed();
            Ok::<_, String>((elapsed, elapsed, final_flush_us))
        } else {
            let final_flush_us =
                phase(&engine, options, slots, Kind::Write, &pending, &mut samples).await?;
            let write_elapsed = began.elapsed();
            let reading = Instant::now();
            phase(&engine, options, slots, Kind::Read, &pending, &mut samples).await?;
            Ok((write_elapsed, reading.elapsed(), final_flush_us))
        }
    }
    .await;
    let elapsed = began.elapsed();
    let _ = stop.send(());
    monitor
        .await
        .map_err(|error| format!("resource monitor failed: {error}"))?;
    let (write_elapsed, read_elapsed, final_flush_us) = result?;
    let mut resources = Arc::try_unwrap(observations)
        .map_err(|_| "resource monitor retained state")?
        .into_inner()
        .map_err(|_| "resource monitor state poisoned")?;
    resources.peak_pending_operations = pending.peak.load(Ordering::SeqCst);
    resources.pending_operations_at_exit = pending.current.load(Ordering::SeqCst);
    resources.monitor_interval_ms = 1;
    resources.process_peak_rss_bytes = peak_rss();
    resources.rss_source =
        if cfg!(target_os = "linux") && resources.process_peak_rss_bytes.is_some() {
            Some("linux-proc-self-status-VmHWM")
        } else {
            None
        };
    let Samples {
        writes,
        reads,
        flushes,
    } = samples;
    Ok(Measurements {
        writes,
        reads,
        flushes,
        elapsed,
        write_elapsed,
        read_elapsed,
        final_flush_us,
        setup,
        resources,
    })
}
