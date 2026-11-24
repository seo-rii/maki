//! A torn A/B copy must stay invalid for good.
//!
//! `AbStore::store` rewrites the stale side in place. When that side does
//! not decode, the next generation is one above the *other* side's, which is
//! also what the store that tore this side used. A second cut store can then
//! complete the first: the sectors the first power loss dropped are the ones
//! both attempts share (magic, version, the same generation, unchanged
//! payload), and once they reach the disk the side holds a whole, CRC-valid
//! copy of the *older* attempt. `load` selects it, although every recovery
//! in between had fallen back to the other side and the writer had moved on.
//!
//! A side that does not decode is therefore emptied, and the emptying made
//! durable, before a new record is written into it. A side that decodes is
//! never emptied: the preserve-first rule (a readable newer generation is
//! kept and made durable by the next store) is unchanged.

use std::collections::BTreeSet;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::Backing;
use maki_format::ab::{AbRecord, AbStore};
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const A: &str = "m.a";
const B: &str = "m.b";

fn ab() -> AbStore {
    AbStore::new(A, B)
}

/// A record whose payload carries a value, so a test can tell which store
/// produced the copy that `load` selects.
trait Valued: AbRecord {
    fn fresh() -> Self;
    /// `extra` varies the encoded length where the type allows it.
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

impl Valued for ShardCatalog {
    fn fresh() -> Self {
        ShardCatalog::new()
    }
    // The value is the smallest shard index; `extra` further shards make the
    // record longer or shorter than the one it replaces.
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

/// A 2080-byte allocation map: five 512-byte sectors. The generation is in
/// the first sector; what a store changes (units 16000..16064) is in the
/// fourth and the CRC in the fifth, as when a checkpoint allocates slots
/// near the end of a large shard.
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
        (0..64).fold(0, |v, bit| {
            v | (u64::from(self.get(MAP_VALUE_AT + bit)) << bit)
        })
    }
}

/// One process: load, change the payload, store, sync the directory.
fn store_value<T: Valued>(machine: &CrashableBacking, value: u64, extra: u64) -> bool {
    let process = machine.process();
    let Ok(Some(mut record)) = ab().load::<T>(process.as_ref()) else {
        return false;
    };
    record.set_value(value, extra);
    ab().store(process.as_ref(), &mut record).is_ok() && process.sync_dir("").is_ok()
}

fn loaded<T: Valued>(machine: &CrashableBacking) -> T {
    ab().load::<T>(machine.process().as_ref())
        .unwrap()
        .expect("a valid copy")
}

fn sides<T: Valued>(machine: &CrashableBacking) -> (Option<u64>, Option<u64>) {
    ab().side_generations::<T>(machine.process().as_ref())
        .unwrap()
}

fn bytes_of(machine: &CrashableBacking, path: &str) -> Vec<u8> {
    let file = machine.process().open(path, false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

/// Where a store is cut.
#[derive(Clone, Copy)]
enum Cut {
    /// The process dies at the `n`-th data sync that follows a write to the
    /// same file (1 = the preserved side's rewrite, 2 = the new record):
    /// that sync and everything after it never run, the writes stay dirty.
    DiesAtRecordSync(usize),
    /// The data sync that follows a truncation of `path` to zero fails once
    /// with EIO; the process lives. As on Linux, the truncation is then
    /// neither dirty nor known to be durable.
    TruncationSyncFails(&'static str),
    /// The process dies at backing operation `n` of the store.
    DiesAtOperation(usize),
}

/// Arm one cut for the next store; the flag says whether the process died.
fn arm(machine: &CrashableBacking, cut: Cut) -> Arc<AtomicBool> {
    let dead = Arc::new(AtomicBool::new(false));
    let died = dead.clone();
    let fired = AtomicBool::new(false);
    let count = AtomicUsize::new(0);
    let previous: Mutex<Option<(String, bool)>> = Mutex::new(None);
    machine.set_lenient_sync_failures(!matches!(cut, Cut::TruncationSyncFails(_)));
    machine.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
        let mut previous = previous.lock().unwrap();
        let synced = match op {
            FaultOp::SyncData { path } => Some(*path),
            _ => None,
        };
        // Whether this is the data sync that follows a write (`true`) or a
        // truncation to zero (`false`) of the same file.
        let follows = |write: bool| {
            synced.is_some_and(|path| previous.as_ref() == Some(&(path.to_string(), write)))
        };
        let dies = match cut {
            Cut::DiesAtRecordSync(n) => {
                follows(true) && count.fetch_add(1, Ordering::SeqCst) + 1 == n
            }
            Cut::DiesAtOperation(n) => count.fetch_add(1, Ordering::SeqCst) == n,
            Cut::TruncationSyncFails(_) => false,
        };
        let fails = match cut {
            Cut::TruncationSyncFails(target) => {
                synced == Some(target) && follows(false) && !fired.swap(true, Ordering::SeqCst)
            }
            _ => false,
        };
        if dies {
            dead.store(true, Ordering::SeqCst);
        }
        // Remember, per step, whether the last change of a file was a write
        // (`true`) or a truncation to zero (`false`).
        match op {
            FaultOp::WriteAt { path, .. } => *previous = Some((path.to_string(), true)),
            FaultOp::SetLen { path, len: 0 } => *previous = Some((path.to_string(), false)),
            FaultOp::SetLen { .. } => {}
            _ => *previous = None,
        }
        if dead.load(Ordering::SeqCst) {
            Some(io::Error::other("process died"))
        } else if fails {
            Some(io::Error::from_raw_os_error(5))
        } else {
            None
        }
    })));
    died
}

fn disarm(machine: &CrashableBacking) {
    machine.set_fault_hook(None);
    machine.set_lenient_sync_failures(false);
}

/// Side A holds the acknowledged value 34 (generation 3). A store of 37 to
/// side B (generation 4) died before B's sync, and the power loss persisted
/// every 512-byte sector of that write except the first: B is invalid, the
/// pair loads 34.
fn first_sector_of_an_attempt_lost() -> CrashableBacking {
    for crash_seed in 0..5000u64 {
        let machine = CrashableBacking::new().with_tearing(512);
        {
            let process = machine.process();
            let mut record = AllocationMap::fresh();
            record.set_value(1, 0);
            ab().store(process.as_ref(), &mut record).unwrap();
            ab().store(process.as_ref(), &mut record).unwrap();
            process.sync_dir("").unwrap();
        }
        assert!(store_value::<AllocationMap>(&machine, 34, 0));
        let _ = arm(&machine, Cut::DiesAtRecordSync(2));
        assert!(!store_value::<AllocationMap>(&machine, 37, 0));
        disarm(&machine);
        machine.crash(&mut StdRng::seed_from_u64(crash_seed));

        let mut attempt = AllocationMap::fresh();
        attempt.set_value(37, 0);
        attempt.set_generation(4);
        let attempt = AbRecord::encode(&attempt);
        let on_disk = bytes_of(&machine, B);
        if loaded::<AllocationMap>(&machine).value() == 34
            && sides::<AllocationMap>(&machine) == (Some(3), None)
            && on_disk.len() == attempt.len()
            && on_disk[512..] == attempt[512..]
            && on_disk[..512] != attempt[..512]
        {
            return machine;
        }
    }
    panic!("no power loss left only the first sector of the attempt stale");
}

/// The next store is cut too, and only the first sector of its write reaches
/// the disk: the sector both attempts share. The earlier attempt must not
/// come back.
#[test]
fn a_second_cut_store_does_not_complete_the_first() {
    let machine = first_sector_of_an_attempt_lost();
    let _ = arm(&machine, Cut::DiesAtRecordSync(2));
    assert!(!store_value::<AllocationMap>(&machine, 43, 0));
    disarm(&machine);
    machine.crash_keep_torn_prefix(B, 512);

    let value = loaded::<AllocationMap>(&machine).value();
    assert!(
        value == 34 || value == 43,
        "the pair loads {value} at generations {:?}: the store that an earlier power loss had \
         already been seen to lose",
        sides::<AllocationMap>(&machine)
    );
}

/// A truncation whose sync failed is not known to be durable, and a file
/// that reads as empty proves nothing about the disk. The retry empties the
/// side again and syncs that before it writes.
#[test]
fn a_truncation_whose_sync_failed_is_repeated_before_the_side_is_written() {
    let machine = first_sector_of_an_attempt_lost();
    let _ = arm(&machine, Cut::TruncationSyncFails(B));
    assert!(
        !store_value::<AllocationMap>(&machine, 43, 0),
        "the store succeeded although emptying the invalid side could not be made durable"
    );
    disarm(&machine);
    assert_eq!(loaded::<AllocationMap>(&machine).value(), 34);

    let _ = arm(&machine, Cut::DiesAtRecordSync(2));
    assert!(!store_value::<AllocationMap>(&machine, 44, 0));
    disarm(&machine);
    // The failed sync's truncation is lost with everything else that was
    // not synced; the first sector of the new write is kept.
    machine.crash_keep_torn_prefix(B, 512);

    let value = loaded::<AllocationMap>(&machine).value();
    assert!(
        value == 34 || value == 44,
        "the pair loads {value} at generations {:?}",
        sides::<AllocationMap>(&machine)
    );
}

/// The operations one store performs on each side, in order.
fn operations_of_a_store(machine: &CrashableBacking, value: u64) -> Vec<String> {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let seen = trace.clone();
    machine.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
        let entry = match op {
            FaultOp::SetLen { path, len: 0 } => Some(format!("{path}:truncate")),
            FaultOp::WriteAt { path, .. } => Some(format!("{path}:write")),
            FaultOp::SyncData { path } => Some(format!("{path}:sync")),
            _ => None,
        };
        seen.lock().unwrap().extend(entry);
        None
    })));
    assert!(store_value::<AllocationMap>(machine, value, 0));
    machine.set_fault_hook(None);
    let trace = trace.lock().unwrap();
    trace.clone()
}

/// Emptying costs one more data sync. It is paid only for a side that
/// exists and does not decode; a decodable side is overwritten in place as
/// before and never emptied, and a side that does not exist is created.
#[test]
fn only_a_side_that_does_not_decode_is_emptied_first() {
    // Both sides valid: the stale side (B, generation 2) is the target.
    let healthy = CrashableBacking::new();
    {
        let process = healthy.process();
        let mut record = AllocationMap::fresh();
        ab().store(process.as_ref(), &mut record).unwrap();
        // B does not exist yet: it is created, not emptied.
        let created = {
            let trace = Arc::new(Mutex::new(Vec::new()));
            let seen = trace.clone();
            healthy.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
                if let FaultOp::SetLen { path, len: 0 } = op {
                    seen.lock().unwrap().push(path.to_string());
                }
                None
            })));
            ab().store(process.as_ref(), &mut record).unwrap();
            healthy.set_fault_hook(None);
            let truncated = trace.lock().unwrap();
            truncated.clone()
        };
        assert_eq!(created, Vec::<String>::new(), "an absent side was emptied");
        process.sync_dir("").unwrap();
    }
    assert_eq!(
        operations_of_a_store(&healthy, 5),
        ["m.b:write", "m.b:sync", "m.a:write", "m.a:sync"],
        "a decodable target: the preserved side, then the record, one sync each"
    );

    // B invalid: preserve A, empty B durably, then write the record.
    let torn = first_sector_of_an_attempt_lost();
    assert_eq!(
        operations_of_a_store(&torn, 43),
        [
            "m.a:write",
            "m.a:sync",
            "m.b:truncate",
            "m.b:sync",
            "m.b:write",
            "m.b:sync"
        ]
    );
    assert_eq!(loaded::<AllocationMap>(&torn).value(), 43);
    // Both sides decode again: the next store pays nothing extra.
    assert_eq!(
        operations_of_a_store(&torn, 44),
        ["m.b:write", "m.b:sync", "m.a:write", "m.a:sync"]
    );
}

/// How a chain of stores is disturbed.
#[derive(Clone, Copy)]
struct Profile {
    /// Percent of stores cut exactly between the new record's write and its
    /// sync; the rest of the disturbed stores die at a random operation or
    /// have one operation fail.
    cut_at_record_sync: u32,
    /// Percent of stores left undisturbed.
    clean: u32,
    /// Percent of failed stores followed by a sampled power loss.
    power_loss_after_failure: u32,
    /// Stores per chain: at least `.0`, fewer than `.1`.
    steps: (usize, usize),
}

/// A chain of stores, each by a new process, each possibly cut, each
/// followed by a restart or a power loss. After every step the pair must
/// load the acknowledged value or one attempted since: never nothing
/// (`LOST`), never an older value (`STALE`), never a value that a power loss
/// had already been seen to lose (`REVIVED`), never anything else
/// (`FOREIGN`).
fn chain<T: Valued>(seed: u64, tear: usize, profile: Profile) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let machine = CrashableBacking::new().with_tearing(tear);
    {
        let process = machine.process();
        let mut record = T::fresh();
        record.set_value(1, 0);
        ab().store(process.as_ref(), &mut record).unwrap();
        ab().store(process.as_ref(), &mut record).unwrap();
        process.sync_dir("").unwrap();
    }
    let mut history = format!("seed {seed}, torn-write unit {tear}");
    let mut acknowledged = 1u64;
    let mut attempted = BTreeSet::new();
    // Attempts a power loss was seen to lose.
    let mut lost = BTreeSet::new();
    let mut next = 2u64;

    for _ in 0..rng.random_range(profile.steps.0..profile.steps.1) {
        let value = next;
        next += rng.random_range(1..4u64);
        let extra = rng.random_range(0..40u64);
        let roll = rng.random_range(0..100u32);
        let (stored, died) = if roll < profile.clean {
            (store_value::<T>(&machine, value, extra), false)
        } else if roll < profile.clean + profile.cut_at_record_sync {
            let dead = arm(&machine, Cut::DiesAtRecordSync(2));
            let stored = store_value::<T>(&machine, value, extra);
            (stored, dead.load(Ordering::SeqCst))
        } else if rng.random_bool(0.5) {
            let dead = arm(&machine, Cut::DiesAtOperation(rng.random_range(0..16)));
            let stored = store_value::<T>(&machine, value, extra);
            (stored, dead.load(Ordering::SeqCst))
        } else {
            // One failed operation, the process lives: writeback-error
            // semantics for a failed sync.
            let at = rng.random_range(0..16usize);
            let count = AtomicUsize::new(0);
            machine.set_fault_hook(Some(Arc::new(move |_op: &FaultOp<'_>| {
                (count.fetch_add(1, Ordering::SeqCst) == at).then(|| io::Error::other("failed"))
            })));
            (store_value::<T>(&machine, value, extra), false)
        };
        disarm(&machine);
        // A store that returned to a live process is acknowledged (a cut
        // that never fired leaves a clean store); a dead one reports nothing.
        if stored && !died {
            acknowledged = value;
            attempted.clear();
        } else {
            attempted.insert(value);
        }
        history += &format!("\n  store {value} -> {}", if stored { "ok" } else { "cut" });

        let event = rng.random_range(0..100u32);
        let power_lost =
            if (!stored && event < profile.power_loss_after_failure) || (stored && event < 25) {
                machine.crash(&mut rng);
                history += ", power loss";
                true
            } else if event >= 95 {
                machine.crash_all_lost();
                history += ", power loss (everything volatile lost)";
                true
            } else {
                history += ", restart";
                false
            };

        let seen = match ab().load::<T>(machine.process().as_ref()) {
            Ok(Some(record)) => record.value(),
            other => {
                return Err(format!(
                    "LOST: after acknowledging {acknowledged} the pair loads {:?}\n{history}",
                    other
                        .map(|r| r.map(|r| r.value()))
                        .map_err(|e| e.to_string())
                ))
            }
        };
        if seen != acknowledged && !attempted.contains(&seen) {
            let class = if seen < acknowledged {
                "STALE"
            } else if lost.contains(&seen) {
                "REVIVED"
            } else {
                "FOREIGN"
            };
            return Err(format!(
                "{class}: the pair loads {seen}; acknowledged {acknowledged}, attempted since \
                 {attempted:?}, generations {:?}\n{history}",
                sides::<T>(&machine)
            ));
        }
        history += &format!(" -> {seen}");
        if power_lost {
            // What survived the power loss is the durable state.
            lost.extend(attempted.iter().copied().filter(|v| *v > seen));
            lost.retain(|v| *v > seen);
            acknowledged = seen;
            attempted.clear();
        }
    }
    Ok(())
}

/// The seeds whose chain fails, each with its report.
fn failures<T: Valued>(
    seeds: std::ops::Range<u64>,
    tear: usize,
    profile: Profile,
) -> Vec<(u64, String)> {
    seeds
        .filter_map(|seed| Some((seed, chain::<T>(seed, tear, profile).err()?)))
        .collect()
}

fn assert_none(failed: &[(u64, String)]) {
    assert!(
        failed.is_empty(),
        "{} failing chain(s), seeds {:?}; first:\n{}",
        failed.len(),
        failed.iter().map(|(seed, _)| *seed).collect::<Vec<_>>(),
        failed[0].1
    );
}

/// Stores cut between the record's write and its sync, most of them
/// followed by a power loss, on a five-sector record with 512-byte sectors.
#[test]
fn chains_of_cut_stores_never_revive_an_attempt_a_power_loss_lost() {
    let profile = Profile {
        cut_at_record_sync: 60,
        clean: 25,
        power_loss_after_failure: 85,
        steps: (30, 50),
    };
    assert_none(&failures::<AllocationMap>(0..CUT_CHAIN_SEEDS, 512, profile));
}

const CUT_CHAIN_SEEDS: u64 = 500;

/// Mixed disturbances on a one-sector record, a record whose length changes
/// and the five-sector record, at torn-write units from one byte to a page:
/// the preserve-first contract (nothing acknowledged is lost or regresses)
/// together with the rule above.
#[test]
fn seeded_chains_never_lose_regress_or_revive_a_record() {
    let profile = Profile {
        cut_at_record_sync: 20,
        clean: 45,
        power_loss_after_failure: 55,
        steps: (8, 40),
    };
    let mut failed = Vec::new();
    for tear in [1, 7, 64, 512, 4096] {
        failed.extend(failures::<CheckpointState>(0..120, tear, profile));
        failed.extend(failures::<ShardCatalog>(0..120, tear, profile));
        failed.extend(failures::<AllocationMap>(0..120, tear, profile));
    }
    assert_none(&failed);
}
