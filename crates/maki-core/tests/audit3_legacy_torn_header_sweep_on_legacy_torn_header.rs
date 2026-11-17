//! Audit round 3 (PR #177 `fix/legacy-torn-header-20261117`): try to make
//! the new header-only-final-segment discard lose an acknowledged write, or
//! make the deep check and recovery disagree.
//!
//! Randomized: FUA / plain writes, FLUSH, checkpoints, rolls every three
//! records, random journal/metadata faults (failed writes, syncs, removes,
//! directory syncs), then a process restart or a power loss with fine-grained
//! tearing (so the current writer's header write can persist as a 48-byte
//! file with a hole), optional in-place damage of a header-only final
//! segment, recovery interrupted by a fault and re-run after another restart
//! or power loss. Oracle: each unit reads its last acknowledged value or a
//! value written after it; recovery and the deep check agree.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::journal::SEGMENT_HEADER_SIZE;
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{failpoints, CrashableBacking};

const CT: usize = 1024;
const UNITS: u64 = 8;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

fn new_backing(seed: u64) -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new().with_tearing(8));
    let sb = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0x2026_1117_a3a3 + seed as u128),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, CT as u32, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    init::create_volume(backing.as_ref(), sb).unwrap();
    backing
}

/// Per unit: values in write order and the index of the last acknowledged.
#[derive(Clone, Default)]
struct Unit {
    values: Vec<Vec<u8>>,
    acked: Option<usize>,
}

struct Model {
    units: Vec<Unit>,
    /// Units written (not yet acknowledged) since the last barrier.
    pending: Vec<(usize, usize)>,
}

impl Model {
    fn new() -> Self {
        Self {
            units: vec![Unit::default(); UNITS as usize],
            pending: Vec::new(),
        }
    }
    fn wrote(&mut self, unit: usize, value: Vec<u8>) -> usize {
        self.units[unit].values.push(value);
        self.units[unit].values.len() - 1
    }
    fn ack(&mut self, unit: usize, index: usize) {
        let u = &mut self.units[unit];
        if u.acked.is_none_or(|a| a < index) {
            u.acked = Some(index);
        }
    }
    fn ack_all_pending(&mut self) {
        for (unit, index) in std::mem::take(&mut self.pending) {
            self.ack(unit, index);
        }
    }
    /// After recovery everything it accepted is durable: rebase on it.
    fn check_and_rebase(&mut self, volume: &Volume, case: &str) -> Result<(), String> {
        for unit in 0..UNITS as usize {
            let got = volume
                .read_ct(unit as u64)
                .map_err(|e| format!("{case}: unit {unit} read error {e}"))?
                .map(|(_, data)| data);
            let u = &self.units[unit];
            let allowed_from = u.acked.unwrap_or(0);
            let ok = match &got {
                None => u.acked.is_none(),
                Some(data) => u.values[allowed_from..].iter().any(|v| v == data),
            };
            if !ok {
                return Err(format!(
                    "{case}: unit {unit} lost an acknowledged write: got {:?}, acked {:?} \
                     (values {})",
                    got.as_ref().map(|d| d[0]),
                    u.acked.map(|a| u.values[a][0]),
                    u.values.len()
                ));
            }
            let u = &mut self.units[unit];
            match got {
                None => *u = Unit::default(),
                Some(data) => {
                    u.values = vec![data];
                    u.acked = Some(0);
                }
            }
        }
        self.pending.clear();
        Ok(())
    }
}

fn is_journal(path: &str) -> bool {
    path.starts_with("journal/")
}

/// Fail `1/odds` of the matching operations (all when odds == 1).
fn install_faults(backing: &CrashableBacking, seed: u64, odds: u32) {
    let counter = Arc::new(AtomicU32::new(0));
    backing.set_fault_hook(Some(Arc::new(move |op| {
        let n = counter.fetch_add(1, Ordering::SeqCst) as u64;
        let roll = (n.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ seed).rotate_left(17) % odds as u64;
        let target = match op {
            FaultOp::WriteAt { path, .. } => is_journal(path),
            FaultOp::SyncData { path } => is_journal(path) || path.starts_with("data/"),
            FaultOp::SetLen { path, .. } => is_journal(path),
            FaultOp::Remove { path } => is_journal(path),
            FaultOp::SyncDir { dir } => *dir == layout::JOURNAL_DIR,
            FaultOp::Open { path, create } => *create && is_journal(path),
            FaultOp::Rename { .. } => false,
        };
        (target && roll == 0).then(|| io::Error::other("injected fault"))
    })));
}

fn final_segment(backing: &CrashableBacking) -> Option<String> {
    let mut names: Vec<(u64, String)> = backing
        .list(layout::JOURNAL_DIR)
        .ok()?
        .into_iter()
        .filter_map(|n| layout::parse_journal_segment(&n).map(|i| (i, n)))
        .collect();
    names.sort();
    names
        .pop()
        .map(|(_, n)| format!("{}/{}", layout::JOURNAL_DIR, n))
}

fn recover(backing: &Arc<CrashableBacking>) -> Result<Volume, String> {
    Volume::recover(backing.clone() as Arc<dyn Backing>, options()).map_err(|e| e.to_string())
}

#[derive(Default, Debug)]
struct Tally {
    runs: u64,
    restarts: u64,
    power_losses: u64,
    header_only_final: u64,
    damaged: u64,
    damaged_refused: u64,
    interrupted_recoveries: u64,
    refusals_without_damage: Vec<String>,
    disagreements: Vec<String>,
    losses: Vec<String>,
}

fn run(seed: u64, tally: &mut Tally) {
    let mut log: Vec<String> = Vec::new();
    let mut rng = StdRng::seed_from_u64(seed);
    let backing = new_backing(seed);
    let mut model = Model::new();
    let mut volume = recover(&backing).unwrap();
    let mut counter = 1u8;
    for round in 0..6 {
        // Workload, with faults part of the time.
        let faulty = rng.random_bool(0.6);
        if faulty {
            install_faults(&backing, rng.random(), rng.random_range(2..8));
        }
        log.push(format!("round {round} faulty={faulty}"));
        for _ in 0..rng.random_range(2..14) {
            let unit = rng.random_range(0..UNITS) as usize;
            match rng.random_range(0..10) {
                0..=4 => {
                    counter = counter.wrapping_add(1).max(1);
                    let value = vec![counter; CT];
                    let fua = rng.random_bool(0.5);
                    let index = model.wrote(unit, value.clone());
                    let r = volume.write_ct(unit as u64, &value, fua);
                    log.push(format!(
                        "  write unit {unit} value {counter} fua={fua} -> {:?} (seg {:?})",
                        r.as_ref().map_err(|e| e.to_string()),
                        volume.journal_active_segment_path()
                    ));
                    match r {
                        Ok(_) if fua => model.ack(unit, index),
                        Ok(_) => model.pending.push((unit, index)),
                        // A failed write is not completed: no later
                        // barrier acknowledges it (it stays a candidate).
                        Err(_) => {}
                    }
                }
                5..=7 => {
                    let r = volume.flush();
                    log.push(format!("  flush -> {:?}", r.as_ref().map_err(|e| e.to_string())));
                    if r.is_ok() {
                        model.ack_all_pending();
                    }
                }
                _ => {
                    let r = volume.checkpoint();
                    log.push(format!("  checkpoint -> {:?}", r.map_err(|e| e.to_string())));
                }
            }
        }
        backing.set_fault_hook(None);
        drop(volume);

        // Restart or power loss.
        let power_loss = rng.random_bool(0.6);
        log.push(format!("  stop power_loss={power_loss} journal={:?}", backing.list(layout::JOURNAL_DIR)));
        if power_loss {
            tally.power_losses += 1;
            backing.crash(&mut rng);
        } else {
            tally.restarts += 1;
        }

        // Media damage on a header-only final segment.
        let mut damaged = false;
        if let Some(path) = final_segment(&backing) {
            let file = backing.open(&path, false).unwrap();
            if file.len().unwrap() == SEGMENT_HEADER_SIZE as u64 {
                tally.header_only_final += 1;
                if rng.random_bool(0.4) {
                    let mut header = [0u8; SEGMENT_HEADER_SIZE];
                    file.read_at(0, &mut header).unwrap();
                    let at = rng.random_range(0..SEGMENT_HEADER_SIZE);
                    header[at] ^= 1 << rng.random_range(0..8);
                    file.write_at(0, &header).unwrap();
                    file.sync_data().unwrap();
                    damaged = true;
                    tally.damaged += 1;
                    log.push(format!("  damaged {path}"));
                }
            }
        }

        // Recovery interrupted part-way, then a restart or power loss.
        if rng.random_bool(0.3) {
            tally.interrupted_recoveries += 1;
            install_faults(&backing, rng.random(), rng.random_range(1..4));
            let r = recover(&backing);
            log.push(format!("  interrupted recovery -> {:?}", r.as_ref().err()));
            drop(r);
            backing.set_fault_hook(None);
            if rng.random_bool(0.5) {
                backing.crash(&mut rng);
                log.push("  crash after interrupted recovery".into());
            }
        }

        let case = format!("seed {seed} round {round}");
        let check = maki_core::check::deep_check(backing.clone() as Arc<dyn Backing>, 4096);
        let check_journal_ok = match &check {
            Ok(report) => !report.errors.iter().any(|e| e.starts_with("journal")),
            Err(_) => true,
        };
        volume = match recover(&backing) {
            Ok(v) => {
                if !check_journal_ok {
                    tally.disagreements.push(format!(
                        "{case}: recovery attached but the deep check reported journal \
                         damage: {:?}",
                        check.as_ref().map(|r| &r.errors)
                    ));
                }
                v
            }
            Err(e) => {
                if check_journal_ok && check.as_ref().is_ok_and(|r| r.ok()) {
                    tally.disagreements.push(format!(
                        "{case}: deep check passed but recovery refused: {e}"
                    ));
                }
                if damaged {
                    tally.damaged_refused += 1;
                } else {
                    tally.refusals_without_damage.push(format!("{case}: {e}"));
                }
                return;
            }
        };
        log.push(format!("  recovered journal={:?}", backing.list(layout::JOURNAL_DIR)));
        if let Err(loss) = model.check_and_rebase(&volume, &case) {
            if std::env::var("AUDIT3_LOG").is_ok() {
                eprintln!("{loss}\n{}", log.join("\n"));
            }
            tally.losses.push(loss);
            return;
        }
    }
    tally.runs += 1;
}

#[test]
fn legacy_torn_header_discard_never_loses_acknowledged_writes() {
    let _serial = failpoints::test_lock();
    let seeds: u64 = std::env::var("AUDIT3_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(400);
    let mut tally = Tally::default();
    let only: Option<u64> = std::env::var("AUDIT3_SEED").ok().and_then(|s| s.parse().ok());
    for seed in 0..seeds {
        if only.is_some_and(|o| o != seed) {
            continue;
        }
        run(seed, &mut tally);
    }
    eprintln!(
        "runs {} restarts {} power_losses {} header_only_final {} damaged {} damaged_refused {} \
         interrupted_recoveries {} refusals_without_damage {} disagreements {} losses {}",
        tally.runs,
        tally.restarts,
        tally.power_losses,
        tally.header_only_final,
        tally.damaged,
        tally.damaged_refused,
        tally.interrupted_recoveries,
        tally.refusals_without_damage.len(),
        tally.disagreements.len(),
        tally.losses.len()
    );
    for line in tally.refusals_without_damage.iter().take(10) {
        eprintln!("refused: {line}");
    }
    for line in tally.disagreements.iter().take(10) {
        eprintln!("disagree: {line}");
    }
    assert!(tally.losses.is_empty(), "{:#?}", tally.losses);
    assert!(tally.disagreements.is_empty(), "{:#?}", tally.disagreements);
    assert!(
        tally.refusals_without_damage.is_empty(),
        "{:#?}",
        tally.refusals_without_damage
    );
}
