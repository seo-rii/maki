//! Round 9 (r8-storage): verbatim copy of round 8's `audit8_create_attach_chain.rs` from the dev branch,
//! re-run on the merged tree (1d4c7ea). Only this header was added.
//!
//! Audit round 8 (long-seeds): chains of interrupted `volume create` and
//! interrupted first attaches under the executable crash model.
//!
//! The committed sweeps start from three hand-built interrupted creations
//! (`review_superblock_durability.rs`) or kill a creation and lose
//! everything volatile (`review_init_crash.rs`). Here the creation itself
//! runs under a random fault (one failed backing operation, or the process
//! dying at an operation), followed by nothing, a sampled power loss with
//! torn writes or a worst-case power loss; then up to three attaches, each
//! under its own random fault and followed by the same choice. Oracles, from
//! docs/operations.md ("Once a copy is readable ... the root is a complete
//! volume ... The first attach makes both superblock copies durable before
//! it accepts writes") and SPEC section 12:
//!
//! - whenever a superblock copy is readable, a fault-free attach succeeds;
//! - once an attach has succeeded, the volume never stops being attachable
//!   and every FUA-acknowledged unit keeps its value, whatever fails or
//!   loses power afterwards;
//! - nothing panics.
//!
//! Seeds: `AUDIT8_SEED_START` / `AUDIT8_SEED_COUNT` (default 0 / 300).
//! Not part of the maintained suite.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::{load_volume_superblock, Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const UNITS: u64 = 12;

/// Round 8: a crash generator for `CrashableBacking::crash`, whose own
/// sampling keeps every volatile operation with probability one half and
/// tears a kept write with probability three tenths, independently. With
/// dozens of operations pending that never produces the states next to
/// "everything reached the disk" or "nothing did". `crash` decides with
/// `random_bool(0.5)` (keep) and `random_bool(0.3)` (tear), i.e. by
/// comparing one `u64` draw with 2^63 and with 0.3 * 2^64, so a draw from
/// [0, 0.3 * 2^64) says "keep, torn", one from [0.3 * 2^64, 2^63) "keep,
/// whole" and one above 2^63 "lost". This generator picks the range with
/// the given probabilities and a uniform value inside it.
struct Biased {
    inner: StdRng,
    keep_torn: f64,
    keep_whole: f64,
}

impl Biased {
    /// One of four biased crash kinds: nearly everything kept, nearly
    /// everything lost, nearly everything kept but half of it torn, and
    /// everything kept untorn.
    fn pick(rng: &mut StdRng) -> (Self, &'static str) {
        let (keep_torn, keep_whole, name) = match rng.random_range(0..4u32) {
            0 => (0.05, 0.90, "mostly kept"),
            1 => (0.02, 0.05, "mostly lost"),
            2 => (0.50, 0.45, "mostly kept, half torn"),
            _ => (0.0, 1.0, "everything kept"),
        };
        (
            Self {
                inner: StdRng::seed_from_u64(rng.random()),
                keep_torn,
                keep_whole,
            },
            name,
        )
    }
}

impl rand::RngCore for Biased {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        const TEAR: f64 = 0.3 * 18_446_744_073_709_551_616.0;
        const HALF: f64 = 0.5 * 18_446_744_073_709_551_616.0;
        let pick: f64 = self.inner.random();
        let frac: f64 = self.inner.random();
        let (lo, hi) = if pick < self.keep_torn {
            (0.0, TEAR)
        } else if pick < self.keep_torn + self.keep_whole {
            (TEAR + 2048.0, HALF - 2048.0)
        } else {
            (HALF + 2048.0, 18_446_744_073_709_547_520.0)
        };
        (lo + frac * (hi - lo)) as u64
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::RngCore::fill_bytes(&mut self.inner, dest)
    }
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xA8C4_0006),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(UNIT, UNIT, 512, UNIT + 8, UNITS * UNIT as u64, 4 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> EngineOptions {
    EngineOptions {
        volume: VolumeOptions {
            journal_segment_size: 48 + 2 * (32 + UNIT as u64 + 8),
        },
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: u64::MAX,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: Duration::from_secs(3600),
            ..Default::default()
        },
        ..EngineOptions::default()
    }
}

fn image(unit: u64, stamp: u32) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (stamp as usize * 131 + unit as usize * 17 + i) as u8 | 1;
    }
    v
}

/// Arm one fault for the next command: `None`, one failed operation, or the
/// process dying at an operation. Returns the "a fault fired" flag.
fn arm(machine: &CrashableBacking, rng: &mut StdRng, range: usize) -> (Arc<AtomicBool>, &'static str, usize) {
    let fired = Arc::new(AtomicBool::new(false));
    let mode = rng.random_range(0..10u32);
    let cut = rng.random_range(0..range);
    let kind = match mode {
        0..=3 => "none",
        4..=5 => "single",
        _ => "death",
    };
    if kind != "none" {
        let single = kind == "single";
        let count = AtomicUsize::new(0);
        let seen = fired.clone();
        machine.set_fault_hook(Some(Arc::new(move |_op: &FaultOp<'_>| {
            let index = count.fetch_add(1, Ordering::SeqCst);
            let fail = if single { index == cut } else { index >= cut };
            if fail {
                seen.store(true, Ordering::SeqCst);
            }
            fail.then(|| io::Error::other("injected"))
        })));
    }
    (fired, kind, cut)
}

fn lose_power(machine: &CrashableBacking, rng: &mut StdRng, history: &mut String) {
    match rng.random_range(0..10u32) {
        0..=3 => history.push_str("\n  (process restart)"),
        4..=5 => {
            machine.crash(rng);
            history.push_str("\n  power loss (sampled)");
        }
        6 => {
            let (mut biased, name) = Biased::pick(rng);
            machine.crash(&mut biased);
            history.push_str(&format!("\n  power loss ({name})"));
        }
        _ => {
            machine.crash_all_lost();
            history.push_str("\n  power loss (everything volatile lost)");
        }
    }
}

async fn attach(machine: &Arc<CrashableBacking>) -> Result<Engine, String> {
    Engine::attach(
        machine.process(),
        Arc::new(FakeCryptoProvider::new(UNIT)),
        options(),
    )
    .await
    .map_err(|e| e.to_string())
}

#[derive(Default)]
struct Stats {
    creations_failed: u64,
    volumes: u64,
    attaches_ok: u64,
    attaches_failed: u64,
    acknowledged: u64,
    final_checks: u64,
    not_a_volume: u64,
}

async fn chain(seed: u64, stats: &mut Stats) {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xA8C4_0006);
    let tear = [1usize, 64, 512, 4096][rng.random_range(0..4)];
    let machine = Arc::new(CrashableBacking::new().with_tearing(tear));
    let discard = rng.random_bool(0.5);
    let mut history = format!("seed {seed} tear {tear} discard {discard}");
    // Units a live process was told are durable.
    let mut acknowledged: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    // An attach returned to a live process: the root is a volume for good.
    let mut attached_once = false;
    let mut stamp = 0u32;

    // ---- `volume create`, under a fault
    let (fired, kind, cut) = arm(&machine, &mut rng, 70);
    let created = {
        let process = machine.process();
        if discard {
            init::create_volume_with_discard(process.as_ref(), superblock())
        } else {
            init::create_volume(process.as_ref(), superblock())
        }
    };
    machine.set_fault_hook(None);
    history += &format!(
        "\n  create ({kind} at {cut}, fired {}) -> {}",
        fired.load(Ordering::SeqCst),
        created.as_ref().map(|_| "ok".to_string()).unwrap_or_else(|e| e.to_string())
    );
    if created.is_err() {
        stats.creations_failed += 1;
    }
    lose_power(&machine, &mut rng, &mut history);

    // ---- attaches, each under a fault
    for _ in 0..rng.random_range(1..=3) {
        let readable = load_volume_superblock(machine.process().as_ref()).is_ok();
        if !readable {
            assert!(
                !attached_once,
                "SUPERBLOCK-LOST: no superblock copy is readable after an attach had succeeded\n{history}"
            );
            break;
        }
        let (fired, kind, cut) = arm(&machine, &mut rng, 90);
        let result = attach(&machine).await;
        let disturbed_death = kind == "death" && fired.load(Ordering::SeqCst);
        history += &format!(
            "\n  attach ({kind} at {cut}, fired {}) -> {}",
            fired.load(Ordering::SeqCst),
            result.as_ref().map(|_| "ok".to_string()).unwrap_or_else(|e| e.clone())
        );
        match result {
            Ok(engine) if !disturbed_death => {
                stats.attaches_ok += 1;
                attached_once = true;
                // Still under the armed fault (a single failure may come
                // later): FUA writes; an acknowledged one is durable.
                for _ in 0..rng.random_range(1..=3) {
                    let unit = rng.random_range(0..UNITS);
                    stamp += 1;
                    let data = image(unit, stamp);
                    let written = engine.write(unit * UNIT as u64, &data, true).await;
                    let dead = kind == "death" && fired.load(Ordering::SeqCst);
                    history += &format!(
                        "\n    write unit {unit} stamp {stamp} fua -> {}",
                        written.as_ref().map(|_| "ok".to_string()).unwrap_or_else(|e| e.to_string())
                    );
                    if written.is_ok() && !dead {
                        acknowledged.insert(unit, data);
                        stats.acknowledged += 1;
                    } else {
                        // Unknown outcome: the unit may hold either value.
                        acknowledged.remove(&unit);
                    }
                }
                machine.set_fault_hook(None);
                engine.stop_checkpoint_worker().await;
                drop(engine);
            }
            Ok(engine) => {
                // The process is dead: nothing it returned was reported.
                machine.set_fault_hook(None);
                engine.stop_checkpoint_worker().await;
                drop(engine);
                stats.attaches_failed += 1;
            }
            Err(_) => {
                machine.set_fault_hook(None);
                stats.attaches_failed += 1;
            }
        }
        lose_power(&machine, &mut rng, &mut history);
    }
    machine.set_fault_hook(None);

    // ---- the healthy device: a readable superblock is a volume
    if load_volume_superblock(machine.process().as_ref()).is_err() {
        assert!(
            !attached_once,
            "SUPERBLOCK-LOST: no superblock copy is readable after an attach had succeeded\n{history}"
        );
        stats.not_a_volume += 1;
        return;
    }
    stats.volumes += 1;
    for round in 0..2 {
        let engine = attach(&machine).await.unwrap_or_else(|e| {
            panic!(
                "ATTACH-REFUSED: a superblock is readable but a fault-free attach (round {round}) \
                 refuses the volume: {e}\n{history}"
            )
        });
        for (unit, data) in &acknowledged {
            let actual = engine
                .read(unit * UNIT as u64, UNIT as usize)
                .await
                .unwrap_or_else(|e| panic!("READ: unit {unit}: {e}\n{history}"));
            assert!(
                &actual == data,
                "ACKNOWLEDGED-LOST: unit {unit} does not hold its FUA-acknowledged value (round \
                 {round})\n{history}"
            );
        }
        if round == 0 {
            // One more acknowledged write, then the worst case: the first
            // successful attach must have made the volume durable.
            stamp += 1;
            let unit = rng.random_range(0..UNITS);
            let data = image(unit, stamp);
            engine
                .write(unit * UNIT as u64, &data, true)
                .await
                .unwrap_or_else(|e| panic!("WRITE: healthy volume refuses a write: {e}\n{history}"));
            acknowledged.insert(unit, data);
            history += &format!("\n  healthy attach, write unit {unit} stamp {stamp} fua, power loss");
            engine.stop_checkpoint_worker().await;
            drop(engine);
            machine.crash_all_lost();
            assert!(
                load_volume_superblock(machine.process().as_ref()).is_ok(),
                "SUPERBLOCK-LOST: the superblock did not survive a power loss after a successful \
                 attach and an acknowledged write\n{history}"
            );
        } else {
            engine.stop_checkpoint_worker().await;
        }
        stats.final_checks += 1;
    }
}

#[tokio::test]
async fn audit8_interrupted_create_and_attach_chains() {
    let get = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let start = get("AUDIT8_SEED_START", 0);
    let count = get("AUDIT8_SEED_COUNT", 300);
    let mut stats = Stats::default();
    for seed in start..start + count {
        chain(seed, &mut stats).await;
    }
    println!(
        "AUDIT8 create/attach chains: seeds {start}..{} creations failed {} volumes {} not-a-volume \
         {} attaches ok {} failed {} acknowledged writes {} final checks {}",
        start + count,
        stats.creations_failed,
        stats.volumes,
        stats.not_a_volume,
        stats.attaches_ok,
        stats.attaches_failed,
        stats.acknowledged,
        stats.final_checks
    );
}
