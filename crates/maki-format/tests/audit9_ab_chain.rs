//! Round 9 (r8-storage): verbatim copy of round 8's `audit8_ab_chain.rs` from the dev branch,
//! re-run on the merged tree (1d4c7ea). Only this header was added.
//!
//! Audit round 8 (long-seeds): model-based chain sweep of `AbStore`.
//!
//! The committed A/B tests (`review_ab_retry.rs`, `review_ab_length_retry.rs`)
//! pin single scenarios: one failed sync, then a retry. Here a record is
//! stored again and again by a fresh "process" each time, every store under
//! its own random fault (none, one failed backing operation, or the process
//! dying at an operation), each optionally followed by a restart, a sampled
//! power loss with torn writes, or a worst-case power loss. The oracle is
//! the BUG-001 preserve-first contract:
//!
//! - once a store (and the caller's directory sync) returned to a live
//!   process, a load never yields an older value, nothing, or an error —
//!   whatever fails or loses power afterwards;
//! - a load only ever yields the last acknowledged value or one attempted
//!   after it.
//!
//! Seeds: `AUDIT8_SEED_START` / `AUDIT8_SEED_COUNT` (default 0 / 400).
//! Not part of the maintained suite.

use std::collections::BTreeSet;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_format::ab::{AbRecord, AbStore};
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

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

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A record type whose payload carries a value id.
trait Valued: AbRecord {
    /// An empty record of the type.
    fn fresh() -> Self;
    /// Replace the payload by one that encodes `value`; `extra` varies the
    /// encoded length where the type allows it.
    fn set_value(&mut self, value: u64, extra: u64);
    fn value(&self) -> u64;
}

impl Valued for CheckpointState {
    fn fresh() -> Self {
        Self::default()
    }
    fn set_value(&mut self, value: u64, _extra: u64) {
        self.checkpoint_sequence = value;
    }
    fn value(&self) -> u64 {
        self.checkpoint_sequence
    }
}

/// A fixed-length record of 2080 bytes (five 512-byte sectors), shaped like
/// a large shard's allocation map between two checkpoints: the generation
/// sits in the first sector, what changes sits near the end (units
/// 16000..16064, fourth sector) and the CRC in the last one.
const MAP_UNITS: u64 = 16384;
const MAP_VALUE_AT: u64 = 16000;

impl Valued for AllocationMap {
    fn fresh() -> Self {
        AllocationMap::new(MAP_UNITS)
    }
    fn set_value(&mut self, value: u64, _extra: u64) {
        for bit in 0..64 {
            self.set(MAP_VALUE_AT + bit, value >> bit & 1 == 1);
        }
    }
    fn value(&self) -> u64 {
        (0..64).fold(0, |v, bit| v | (u64::from(self.get(MAP_VALUE_AT + bit)) << bit))
    }
}

impl Valued for ShardCatalog {
    fn fresh() -> Self {
        ShardCatalog::new()
    }
    // The value is the smallest shard index; `extra` further shards make the
    // record longer or shorter than its predecessor (BUG-066 length paths).
    fn set_value(&mut self, value: u64, extra: u64) {
        let generation = self.generation();
        *self = ShardCatalog::new();
        self.set_generation(generation);
        for shard in value..=value + extra {
            self.insert(shard);
        }
    }
    fn value(&self) -> u64 {
        self.shard_indices().next().unwrap_or(u64::MAX)
    }
}

#[derive(Default)]
struct Stats {
    stores: u64,
    acknowledged: u64,
    failed: u64,
    died: u64,
    restarts: u64,
    power_losses: u64,
    all_lost: u64,
    newer_unacknowledged_seen: u64,
    /// L3: a load showed an attempt that an earlier power loss had already
    /// been seen to lose (seeds are listed).
    resurrected: Vec<u64>,
}

fn chain<T: Valued>(seed: u64, stats: &mut Stats) {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xA8AB_C4A1);
    let drawn = [1usize, 7, 64, 512, 4096][rng.random_range(0..5)];
    let always = rng.random_bool(0.8);
    // `AUDIT8_TEAR=<bytes>` forces the torn-write unit (and tearing on).
    let forced = std::env::var("AUDIT8_TEAR").ok().and_then(|v| v.parse::<usize>().ok());
    let tear = forced.unwrap_or(drawn);
    let machine = if always || forced.is_some() {
        CrashableBacking::new().with_tearing(tear)
    } else {
        CrashableBacking::new()
    };
    let ab = || AbStore::new("m.a", "m.b");
    let mut history = format!("seed {seed} tear {tear}");

    // Initialisation as `create_volume` does it: two stores, directory sync.
    {
        let process = machine.process();
        let mut record = T::fresh();
        record.set_value(1, 0);
        ab().store(process.as_ref(), &mut record).unwrap();
        ab().store(process.as_ref(), &mut record).unwrap();
        process.sync_dir("").unwrap();
    }
    let mut acknowledged: u64 = 1;
    // Values attempted since the acknowledgement: a load may show them.
    let mut attempted: BTreeSet<u64> = BTreeSet::new();
    // Attempts a power loss was seen to lose: gone for good, one would think.
    let mut discarded: BTreeSet<u64> = BTreeSet::new();
    let mut next_value: u64 = 2;

    for _ in 0..rng.random_range(4..40) {
        // One process: load, change the payload, store, sync the directory.
        let value = next_value;
        next_value += rng.random_range(1..4u64);
        let extra = rng.random_range(0..40u64);
        let mode = rng.random_range(0..10u32); // 0..=4 none, 5..=6 single, 7..=9 death
        let cut = rng.random_range(0..14usize);
        let injected = Arc::new(AtomicBool::new(false));
        if mode >= 5 {
            let single = mode <= 6;
            let count = AtomicUsize::new(0);
            let seen = injected.clone();
            machine.set_fault_hook(Some(Arc::new(move |_| {
                let index = count.fetch_add(1, Ordering::SeqCst);
                let fail = if single { index == cut } else { index >= cut };
                if fail {
                    seen.store(true, Ordering::SeqCst);
                }
                fail.then(|| io::Error::other("injected"))
            })));
        }
        let outcome = (|| -> Result<(), String> {
            let process = machine.process();
            let mut record = ab()
                .load::<T>(process.as_ref())
                .map_err(|e| format!("load: {e}"))?
                .ok_or("load: no valid copy")?;
            record.set_value(value, extra);
            ab().store(process.as_ref(), &mut record)
                .map_err(|e| format!("store: {e}"))?;
            process.sync_dir("").map_err(|e| format!("sync_dir: {e}"))?;
            Ok(())
        })();
        machine.set_fault_hook(None);
        stats.stores += 1;
        let disturbed = injected.load(Ordering::SeqCst);
        let death = mode >= 7 && disturbed;
        history += &format!(
            "\n  store {value}(+{extra}) mode {} cut {cut} -> {outcome:?}{}",
            ["none", "single", "death"][match mode {
                0..=4 => 0,
                5..=6 => 1,
                _ => 2,
            }],
            if death { " [process died]" } else { "" }
        );
        if outcome.is_ok() && !death {
            acknowledged = value;
            attempted.clear();
            stats.acknowledged += 1;
        } else {
            attempted.insert(value);
            if death {
                stats.died += 1;
            } else {
                stats.failed += 1;
            }
        }

        // Restart, sampled power loss, or worst-case power loss.
        let event = rng.random_range(0..10u32);
        let power_lost = match event {
            0..=3 => {
                stats.restarts += 1;
                history += "\n  restart";
                false
            }
            4..=5 => {
                machine.crash(&mut rng);
                stats.power_losses += 1;
                history += "\n  power loss (sampled)";
                true
            }
            6..=7 => {
                let (mut biased, name) = Biased::pick(&mut rng);
                machine.crash(&mut biased);
                stats.power_losses += 1;
                history += &format!("\n  power loss ({name})");
                true
            }
            _ => {
                machine.crash_all_lost();
                stats.all_lost += 1;
                history += "\n  power loss (everything volatile lost)";
                true
            }
        };

        let process = machine.process();
        let loaded = ab().load::<T>(process.as_ref());
        let sides = ab().side_generations::<T>(process.as_ref());
        let seen = match loaded {
            Ok(Some(record)) => record.value(),
            other => panic!(
                "LOST: after acknowledging {acknowledged} the store loads {:?} (sides {sides:?})\n{history}",
                other.map(|r| r.map(|r| r.value())).map_err(|e| e.to_string())
            ),
        };
        if seen != acknowledged && !attempted.contains(&seen) {
            assert!(
                seen > acknowledged,
                "STALE: loaded {seen}, older than the acknowledged {acknowledged} (sides \
                 {sides:?})\n{history}"
            );
            assert!(
                discarded.contains(&seen),
                "FOREIGN: loaded {seen}, acknowledged {acknowledged}, attempted since \
                 {attempted:?} (sides {sides:?})\n{history}"
            );
            // L3: an attempt that earlier power losses had lost is back.
            if std::env::var_os("AUDIT8_STRICT").is_some() {
                panic!(
                    "RESURRECTED: loaded {seen}, which a power loss had already lost; \
                     acknowledged {acknowledged}, attempted since {attempted:?} (sides \
                     {sides:?})\n{history}"
                );
            }
            if !stats.resurrected.contains(&seed) {
                stats.resurrected.push(seed);
            }
            history += " [RESURRECTED]";
        }
        if seen != acknowledged {
            stats.newer_unacknowledged_seen += 1;
        }
        history += &format!(" -> loads {seen}");
        if power_lost {
            // What survived the power loss is the durable state now; the
            // newer attempts it lost are remembered.
            discarded.extend(attempted.iter().copied().filter(|v| *v > seen));
            discarded.retain(|v| *v > seen);
            acknowledged = seen;
            attempted.clear();
        }
    }
}

fn sweep<T: Valued>(name: &str) {
    let start = env("AUDIT8_SEED_START", 0);
    let count = env("AUDIT8_SEED_COUNT", 400);
    let mut stats = Stats::default();
    // Seeds are isolated: (class, tear granularity) -> seeds.
    let mut failures: std::collections::BTreeMap<(String, String), Vec<u64>> = Default::default();
    let mut first: Option<String> = None;
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for seed in start..start + count {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut local = Stats::default();
            chain::<T>(seed, &mut local);
            local
        }));
        match outcome {
            Ok(local) => {
                stats.stores += local.stores;
                stats.acknowledged += local.acknowledged;
                stats.failed += local.failed;
                stats.died += local.died;
                stats.restarts += local.restarts;
                stats.power_losses += local.power_losses;
                stats.all_lost += local.all_lost;
                stats.newer_unacknowledged_seen += local.newer_unacknowledged_seen;
                stats.resurrected.extend(local.resurrected);
            }
            Err(payload) => {
                let text = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                let class = text.split(':').next().unwrap_or("?").to_string();
                let tear = text
                    .split("tear ")
                    .nth(1)
                    .and_then(|rest| rest.split_whitespace().next())
                    .unwrap_or("?")
                    .to_string();
                failures.entry((class, tear)).or_default().push(seed);
                first.get_or_insert(text);
            }
        }
    }
    std::panic::set_hook(previous);
    println!(
        "AUDIT8 ab chain {name}: seeds {start}..{} stores {} acknowledged {} failed {} died {} \
         restarts {} power losses {} worst-case {} newer-unacknowledged-seen {} resurrected (L3) \
         seeds {} {:?}",
        start + count,
        stats.stores,
        stats.acknowledged,
        stats.failed,
        stats.died,
        stats.restarts,
        stats.power_losses,
        stats.all_lost,
        stats.newer_unacknowledged_seen,
        stats.resurrected.len(),
        &stats.resurrected[..stats.resurrected.len().min(10)]
    );
    for ((class, tear), seeds) in &failures {
        println!(
            "AUDIT8 ab chain {name}: FAIL class {class} tear {tear}: {} seed(s), first {:?}",
            seeds.len(),
            &seeds[..seeds.len().min(8)]
        );
    }
    if let Some(text) = first {
        panic!(
            "{} failing seed(s); first:\n{}",
            failures.values().map(Vec::len).sum::<usize>(),
            text.chars().take(5000).collect::<String>()
        );
    }
}

#[test]
fn audit8_ab_chain_checkpoint_state() {
    sweep::<CheckpointState>("checkpoint-state");
}

#[test]
fn audit8_ab_chain_shard_catalog() {
    sweep::<ShardCatalog>("shard-catalog");
}

/// A multi-sector fixed-length record: with `AUDIT8_TEAR=512` this is the
/// variant that answers whether L3 needs sub-sector tearing.
#[test]
fn audit8_ab_chain_allocation_map() {
    sweep::<AllocationMap>("allocation-map");
}

/// The process dies when it reaches the data sync of `path`: that sync and
/// everything after it never run (lenient model: the writes stay dirty).
fn die_at_sync_of(machine: &CrashableBacking, path: &'static str) {
    let dead = AtomicBool::new(false);
    machine.set_lenient_sync_failures(true);
    machine.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
        if matches!(op, FaultOp::SyncData { path: p } if *p == path) {
            dead.store(true, Ordering::SeqCst);
        }
        dead.load(Ordering::SeqCst)
            .then(|| io::Error::other("process died"))
    })));
}

fn alive(machine: &CrashableBacking) {
    machine.set_fault_hook(None);
    machine.set_lenient_sync_failures(false);
}

/// L3 with a 512-byte torn-write unit, deterministic (FAILS on 956e354).
///
/// A 2080-byte record (five sectors). Value 34 is acknowledged on side A.
/// 1. A store of value 37 to side B dies before B's sync; the power loss
///    persists every sector of that write except the first (the model's
///    "hole" tear: `crash` with a seed found by the loop below). B is
///    invalid, the store loads 34.
/// 2. The next store (value 43) targets B again, with the same generation
///    number; it dies before B's sync too, and the power loss persists only
///    the first 512-byte sector of its write.
/// B now holds 37's last four sectors and a first sector that is identical
/// in both attempts: a complete, CRC-valid copy of 37.
#[test]
fn audit8_ab_resurrection_with_512_byte_sectors() {
    let ab = || AbStore::new("m.a", "m.b");
    let attempt = |machine: &CrashableBacking, value: u64| {
        let process = machine.process();
        let mut record = ab().load::<AllocationMap>(process.as_ref()).unwrap().unwrap();
        record.set_value(value, 0);
        let stored = ab().store(process.as_ref(), &mut record);
        if stored.is_ok() {
            process.sync_dir("").unwrap();
        }
        stored.is_ok()
    };
    let mut found = None;
    for crash_seed in 0..5000u64 {
        let machine = CrashableBacking::new().with_tearing(512);
        {
            let process = machine.process();
            let mut record = AllocationMap::fresh();
            record.set_value(1, 0);
            ab().store(process.as_ref(), &mut record).unwrap(); // A, generation 1
            ab().store(process.as_ref(), &mut record).unwrap(); // B, generation 2
            process.sync_dir("").unwrap();
        }
        assert!(attempt(&machine, 34)); // A, generation 3: acknowledged
        die_at_sync_of(&machine, "m.b");
        assert!(!attempt(&machine, 37)); // B, generation 4: never synced
        alive(&machine);
        machine.crash(&mut StdRng::seed_from_u64(crash_seed));

        let process = machine.process();
        let loaded = ab().load::<AllocationMap>(process.as_ref()).unwrap().unwrap();
        let sides = ab().side_generations::<AllocationMap>(process.as_ref()).unwrap();
        let file = process.open("m.b", false).unwrap();
        let mut bytes = vec![0u8; file.len().unwrap() as usize];
        file.read_at(0, &mut bytes).unwrap();
        let mut want = AllocationMap::fresh();
        want.set_value(37, 0);
        want.set_generation(4);
        let want = AbRecord::encode(&want);
        // Every sector of the write but the first reached the disk.
        if loaded.value() == 34
            && sides == (Some(3), None)
            && bytes.len() == want.len()
            && bytes[512..] == want[512..]
            && bytes[..512] != want[..512]
        {
            found = Some((machine, crash_seed));
            break;
        }
    }
    let (machine, crash_seed) = found.expect("no crash seed leaves only the first sector stale");

    die_at_sync_of(&machine, "m.b");
    assert!(!attempt(&machine, 43)); // B again, generation 4 again
    alive(&machine);
    // Only the first 512 bytes of that write reach the disk.
    machine.crash_keep_torn_prefix("m.b", 512);

    let process = machine.process();
    let loaded = ab().load::<AllocationMap>(process.as_ref()).unwrap().unwrap();
    let sides = ab().side_generations::<AllocationMap>(process.as_ref()).unwrap();
    println!(
        "AUDIT8 512-byte sectors (first power loss: crash seed {crash_seed}): acknowledged 34, \
         store of 37 lost at the first power loss, store of 43 cut by the second; the pair now \
         loads value {} at generation {} (sides {sides:?})",
        loaded.value(),
        loaded.generation()
    );
    assert!(
        loaded.value() == 34 || loaded.value() == 43,
        "RESURRECTED with 512-byte sectors: the pair loads {}, the attempt the first power loss \
         had already been seen to lose",
        loaded.value()
    );
}
