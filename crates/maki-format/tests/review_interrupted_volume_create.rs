//! `maki volume create` on a local rollback-protected backing enrolls the
//! backing with its witness and then initializes the volume inside it. The
//! whole command, not only its enrollment, must leave a pair that one
//! command continues: `create` run again until the volume's superblock is
//! committed, `open` from then on. A creation that stopped after the
//! witness anchor and before the superblock used to leave a pair that
//! `create` refused ("rollback enrollment requires empty backing and
//! witness directories") and that held no volume to open.
//!
//! What `create` may continue is only a creation that acknowledged
//! nothing. The evidence is the state the witness authenticates: the pair
//! opens (the manifest and every page match the witness anchor, which
//! damage cannot arrange) and holds nothing but what a creation writes
//! before its superblock (which no volume that was ever attached holds).
//! Whatever else is there is refused and left as it is.
//!
//! The executable crash model hosts both directories, each on its own
//! machine, and ends the command before each of their backing operations as
//! a process death, as a power loss of both, and as a single failed
//! operation.
#![cfg(target_os = "linux")]

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::{Backing, RollbackBacking};
use maki_format::checker::check_volume;
use maki_format::geometry::Geometry;
use maki_format::init::{create_in_rollback_backing, RollbackCreateError};
use maki_format::layout;
use maki_format::superblock::{load_volume_superblock, Superblock};
use maki_test_support::CrashableBacking;
use rand::{rngs::StdRng, SeedableRng};

const PAGE: u64 = 4096;
const CAPACITY: u64 = 64 * PAGE;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::new_v4(),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "fixture".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

struct Machines {
    root: CrashableBacking,
    witness: CrashableBacking,
}

fn machines() -> Machines {
    Machines {
        root: CrashableBacking::new().with_tearing(512),
        witness: CrashableBacking::new().with_tearing(512),
    }
}

impl Machines {
    /// Fail the backing operations of either machine whose index `fails`
    /// selects, as ENOSPC.
    fn inject(&self, fails: impl Fn(usize) -> bool + Send + Sync + 'static) {
        let count = Arc::new(AtomicUsize::new(0));
        let fails = Arc::new(fails);
        for machine in [&self.root, &self.witness] {
            let (count, fails) = (count.clone(), fails.clone());
            machine.set_fault_hook(Some(Arc::new(move |_| {
                fails(count.fetch_add(1, Ordering::SeqCst))
                    .then(|| io::Error::new(io::ErrorKind::StorageFull, "injected"))
            })));
        }
    }

    fn heal(&self) {
        self.root.set_fault_hook(None);
        self.witness.set_fault_hook(None);
    }

    /// `maki volume create`, in its own process, for `capacity`.
    fn create_for(&self, capacity: u64) -> Result<Superblock, RollbackCreateError> {
        let (root, witness) = (self.root.process(), self.witness.process());
        let (same_root, same_witness) = (root.clone(), witness.clone());
        create_in_rollback_backing(
            || RollbackBacking::create_on(root, witness, capacity),
            || RollbackBacking::open_on(same_root, same_witness),
            capacity,
            superblock(),
            false,
        )
        .map(|(_, superblock)| superblock)
    }

    fn create(&self) -> Result<Superblock, RollbackCreateError> {
        self.create_for(CAPACITY)
    }

    /// The pair as the daemon, `maki check` and `maki volume inspect` open
    /// it, in a process of their own.
    fn open(&self) -> io::Result<RollbackBacking> {
        RollbackBacking::open_on(self.root.process(), self.witness.process())
    }

    /// The volume those commands need: the pair opens, holds a superblock
    /// and passes the format check (nothing of its layout is missing).
    fn volume(&self) -> Result<(RollbackBacking, Superblock), String> {
        let backing = self.open().map_err(|error| format!("open: {error}"))?;
        let superblock = load_volume_superblock(&backing)
            .map_err(|error| format!("superblock: {error}"))?
            .superblock;
        let report = check_volume(&backing).map_err(|error| format!("check: {error}"))?;
        if !report.ok() {
            return Err(format!("check: {:?}", report.errors));
        }
        Ok((backing, superblock))
    }

    fn power_loss(&self, seed: u64) {
        if seed == 0 {
            self.root.crash_all_lost();
            self.witness.crash_all_lost();
        } else {
            let mut rng = StdRng::seed_from_u64(seed);
            self.root.crash(&mut rng);
            self.witness.crash(&mut rng);
        }
    }

    fn lists(&self) -> (Vec<String>, Vec<String>) {
        (
            self.root.process().list("").unwrap(),
            self.witness.process().list("").unwrap(),
        )
    }
}

/// How many backing operations an undisturbed command performs.
fn operations() -> usize {
    let machines = machines();
    let count = Arc::new(AtomicUsize::new(0));
    for machine in [&machines.root, &machines.witness] {
        let seen = count.clone();
        machine.set_fault_hook(Some(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            None
        })));
    }
    machines.create().unwrap();
    count.load(Ordering::SeqCst)
}

/// An acknowledged write, as the first attach makes one.
fn commit(backing: &RollbackBacking) {
    backing.create_dir_all(layout::JOURNAL_DIR).unwrap();
    let file = backing.open("journal/payload", true).unwrap();
    file.write_at(0, b"kept").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
}

fn payload(backing: &RollbackBacking) -> io::Result<[u8; 4]> {
    let mut bytes = [0; 4];
    backing
        .open("journal/payload", false)?
        .read_at(0, &mut bytes)?;
    Ok(bytes)
}

/// Exactly one command continues the pair: `create` until the volume's
/// superblock is committed, `open` from then on. A creation that reports
/// success is durable as it returned.
fn continued(machines: &Machines, context: &str) -> RollbackBacking {
    match machines.volume() {
        Ok((backing, superblock)) => {
            drop(backing);
            if machines.create().is_ok() {
                panic!(
                    "{context}: create completed over a volume that opens: {:?}",
                    machines.lists()
                );
            }
            let (backing, again) = machines.volume().unwrap();
            assert_eq!(again.volume_uuid, superblock.volume_uuid, "{context}");
            backing
        }
        Err(opened) => {
            let created = machines.create().unwrap_or_else(|created| {
                panic!(
                    "{context}: stranded: {opened}; create: {created}; backing and witness: {:?}",
                    machines.lists()
                )
            });
            // A creation that reported success is durable as it returned.
            machines.power_loss(0);
            let (backing, superblock) = machines.volume().unwrap_or_else(|error| {
                panic!("{context}: the creation that succeeded did not survive: {error}")
            });
            assert_eq!(superblock.volume_uuid, created.volume_uuid, "{context}");
            backing
        }
    }
}

/// [`continued`], and then the volume is used: an acknowledged write
/// survives, and nothing creates over it.
fn complete(machines: &Machines, context: &str) {
    let volume = continued(machines, context);
    commit(&volume);
    drop(volume);
    machines.power_loss(0);
    let (reopened, _) = machines
        .volume()
        .unwrap_or_else(|error| panic!("{context}: the completed volume did not survive: {error}"));
    assert_eq!(&payload(&reopened).unwrap(), b"kept", "{context}");
    drop(reopened);
    assert!(
        machines.create().is_err(),
        "{context}: create succeeded over an acknowledged write"
    );
}

#[test]
fn an_undisturbed_creation_is_refused_by_a_second_one() {
    let machines = machines();
    machines.create().unwrap();
    assert!(machines.create().is_err());
    complete(&machines, "undisturbed");
}

/// The command stopped before operation `cut`, as a process death (`None`)
/// or followed by a power loss.
fn interrupted(cut: usize, power_loss: Option<u64>) -> Machines {
    let machines = machines();
    // The process dies before operation `cut`: nothing it does from there
    // on, cleanup included, reaches either directory.
    machines.inject(move |index| index >= cut);
    let _ = machines.create();
    machines.heal();
    if let Some(seed) = power_loss {
        machines.power_loss(seed);
    }
    machines
}

/// The command has several hundred operations, and each image costs a few
/// opens of two 8 MiB manifest slots in the crash model. The tests below
/// cut at every third, fifth or seventh operation, so together at most of
/// them; the release gate at the end of this group cuts at every one.
fn every(step: usize, operations: usize) -> impl Iterator<Item = usize> {
    (0..=operations).filter(move |cut| cut % step == 0 || *cut == operations)
}

#[test]
fn a_creation_killed_at_any_operation_can_be_continued() {
    for cut in every(3, operations()) {
        let machines = interrupted(cut, None);
        let context = format!("killed before operation {cut}");
        // Every state is continued; some are also used afterwards.
        if cut % 4 == 0 {
            complete(&machines, &context);
        } else {
            continued(&machines, &context);
        }
    }
}

#[test]
fn a_creation_cut_by_a_power_loss_at_any_operation_can_be_continued() {
    for cut in every(5, operations()) {
        // Seed 0 loses everything volatile; the other keeps a subset of it
        // that differs from cut to cut, with torn writes.
        for seed in [0, cut as u64 + 1] {
            let machines = interrupted(cut, Some(seed));
            continued(
                &machines,
                &format!("power loss before operation {cut}, seed {seed}"),
            );
        }
    }
}

#[test]
fn a_creation_whose_operation_failed_can_be_run_again() {
    for failed in every(7, operations() - 1) {
        let machines = machines();
        // One operation fails, as on a full disk, and the command returns.
        machines.inject(move |index| index == failed);
        let outcome = machines.create();
        machines.heal();
        let context = format!("operation {failed} failed");
        match outcome {
            // A failure the command survives leaves a complete volume.
            Ok(created) => {
                let (_, opened) = machines
                    .volume()
                    .unwrap_or_else(|e| panic!("{context}: {e}"));
                assert_eq!(opened.volume_uuid, created.volume_uuid, "{context}");
            }
            Err(_) => drop(continued(&machines, &context)),
        }
    }
}

/// How many backing operations the continuation of `stopped` performs.
fn continuation_operations(stopped: &Machines) -> usize {
    let count = Arc::new(AtomicUsize::new(0));
    for machine in [&stopped.root, &stopped.witness] {
        let seen = count.clone();
        machine.set_fault_hook(Some(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            None
        })));
    }
    stopped.create().unwrap();
    count.load(Ordering::SeqCst)
}

/// A continued creation is itself interrupted, at every operation: the
/// first run stopped in the middle of the volume's initialization.
#[test]
fn a_continued_creation_that_is_interrupted_again_can_be_continued() {
    let first = operations() * 2 / 3;
    let stopped = || {
        let machines = interrupted(first, None);
        assert!(
            machines.volume().is_err(),
            "the cut is before the superblock"
        );
        machines
    };
    for cut in every(5, continuation_operations(&stopped())) {
        let seed = (cut % 2 == 1).then_some(cut as u64);
        let machines = stopped();
        machines.inject(move |index| index >= cut);
        let _ = machines.create();
        machines.heal();
        if let Some(seed) = seed {
            machines.power_loss(seed);
        }
        continued(
            &machines,
            &format!("continuation cut before operation {cut}, power loss {seed:?}"),
        );
    }
}

/// The release gate: every operation of the command as a process death,
/// with five power losses and as the one operation that fails, and every
/// operation of a continuation of a run stopped at four places, as a
/// process death and with three power losses. Every volume that results is
/// used.
#[test]
#[ignore = "release gate: the whole creation at every operation with five power losses each"]
fn gate_a_creation_cut_anywhere_in_any_way_can_be_continued_and_used() {
    let total = operations();
    for cut in 0..=total {
        for power_loss in [None, Some(0), Some(1), Some(2), Some(3), Some(4)] {
            let machines = interrupted(cut, power_loss);
            complete(
                &machines,
                &format!("cut before operation {cut}, power loss {power_loss:?}"),
            );
        }
    }
    for failed in 0..total {
        let machines = machines();
        machines.inject(move |index| index == failed);
        let outcome = machines.create();
        machines.heal();
        if outcome.is_err() {
            complete(&machines, &format!("operation {failed} failed"));
        }
    }
    for first in [total / 3, total / 2, total * 2 / 3, total * 5 / 6] {
        for cut in 0..=continuation_operations(&interrupted(first, None)) {
            for power_loss in [None, Some(0), Some(1), Some(2)] {
                let machines = interrupted(first, None);
                machines.inject(move |index| index >= cut);
                let _ = machines.create();
                machines.heal();
                if let Some(seed) = power_loss {
                    machines.power_loss(seed);
                }
                complete(
                    &machines,
                    &format!(
                        "first run cut before {first}, continuation before {cut}, power loss \
                         {power_loss:?}"
                    ),
                );
            }
        }
    }
}

/// Once anything was acknowledged, `create` is refused whatever a crash
/// leaves of the volume's later commits.
#[test]
fn an_acknowledged_volume_is_never_created_over_whatever_cuts_its_commits() {
    let later = {
        let machines = machines();
        machines.create().unwrap();
        let (volume, _) = machines.volume().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        for machine in [&machines.root, &machines.witness] {
            let seen = count.clone();
            machine.set_fault_hook(Some(Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                None
            })));
        }
        commit(&volume);
        count.load(Ordering::SeqCst)
    };
    for cut in 0..=later {
        for seed in [None, Some(0), Some(cut as u64 + 1)] {
            let machines = machines();
            let created = machines.create().unwrap();
            let (volume, _) = machines.volume().unwrap();
            machines.inject(move |index| index >= cut);
            let file = volume
                .create_dir_all(layout::JOURNAL_DIR)
                .and_then(|()| volume.open("journal/payload", true));
            if let Ok(file) = file {
                let _ = file
                    .write_at(0, b"kept")
                    .and_then(|()| file.sync_data())
                    .and_then(|()| volume.sync_dir(layout::JOURNAL_DIR));
            }
            drop(volume);
            machines.heal();
            if let Some(seed) = seed {
                machines.power_loss(seed);
            }
            let context = format!("commit cut before operation {cut}, power loss {seed:?}");
            assert!(machines.create().is_err(), "{context}: created over");
            let (reopened, superblock) = machines
                .volume()
                .unwrap_or_else(|error| panic!("{context}: {error}"));
            assert_eq!(superblock.volume_uuid, created.volume_uuid, "{context}");
            if let Ok(bytes) = payload(&reopened) {
                assert_eq!(&bytes, b"kept", "{context}");
            }
        }
    }
}

/// A creation stopped right after the witness anchor, before the volume's
/// first commit.
fn stopped_after_the_anchor() -> Machines {
    let machines = machines();
    drop(
        RollbackBacking::create_on(
            machines.root.process(),
            machines.witness.process(),
            CAPACITY,
        )
        .unwrap(),
    );
    machines
}

/// A volume that was attached: it holds a superblock and an acknowledged
/// write.
fn used() -> (Machines, Superblock) {
    let machines = machines();
    let superblock = machines.create().unwrap();
    let (volume, _) = machines.volume().unwrap();
    commit(&volume);
    drop(volume);
    (machines, superblock)
}

/// `create` refuses the pair as an existing one and leaves it as it is
/// (opening a witness takes its lock, whose file may be new).
fn refused_unchanged(machines: &Machines, context: &str) {
    let state = || {
        let (root, mut witness) = machines.lists();
        witness.retain(|name| name != "witness.lock");
        let arena = machines
            .root
            .process()
            .open("rollback.arena", false)
            .unwrap();
        (root, witness, arena.len().unwrap())
    };
    let inside = || {
        machines.open().ok().map(|volume| {
            [
                "",
                layout::DATA_DIR,
                layout::JOURNAL_DIR,
                layout::CHECKPOINT_DIR,
            ]
            .map(|dir| volume.list(dir).unwrap_or_default())
        })
    };
    let before = (state(), inside());
    let error = machines.create().expect_err(context);
    assert!(
        matches!(&error, RollbackCreateError::Backing(error) if error.kind() == io::ErrorKind::AlreadyExists),
        "{context}: {error}"
    );
    assert_eq!(before, (state(), inside()), "{context}");
}

#[test]
fn a_creation_stopped_right_after_the_anchor_is_continued() {
    let machines = stopped_after_the_anchor();
    assert!(machines.volume().is_err());
    complete(&machines, "stopped after the anchor");
}

/// A creation stopped in the middle of the volume's initialization: the
/// backing holds what the interrupted run committed, and the continuation
/// starts the volume over inside it.
#[test]
fn a_creation_stopped_before_its_superblock_is_continued() {
    let machines = interrupted(operations() * 2 / 3, None);
    let volume = machines.open().unwrap();
    let left = (
        volume.list("").unwrap(),
        volume.list(layout::JOURNAL_DIR).unwrap(),
    );
    drop(volume);
    assert!(
        !left.1.is_empty() && !left.0.iter().any(|name| name == layout::SUPERBLOCK_A),
        "{left:?}"
    );
    complete(&machines, "stopped before the superblock");
}

/// The continuation keeps the capacity the interrupted creation reserved:
/// the witnessed manifest fixes it.
#[test]
fn a_continuation_with_another_capacity_is_refused_with_both_values() {
    let machines = stopped_after_the_anchor();
    let error = machines.create_for(CAPACITY * 2).unwrap_err().to_string();
    assert!(
        error.contains(&CAPACITY.to_string()) && error.contains(&(CAPACITY * 2).to_string()),
        "{error}"
    );
    assert!(machines.volume().is_err());
    complete(&machines, "after a refused capacity");
}

/// Media damage to a used volume never looks like an unfinished creation:
/// its pages and its manifest are authenticated against the witness before
/// anything is judged.
#[test]
fn a_used_volume_with_damaged_superblocks_is_never_created_over() {
    let (machines, _) = used();
    // Damage every committed page of the arena, both superblock copies
    // among them, in place.
    let arena = machines
        .root
        .process()
        .open("rollback.arena", false)
        .unwrap();
    let mut page = vec![0; PAGE as usize];
    let mut damaged = 0;
    for index in 0..arena.len().unwrap() / PAGE {
        arena.read_at(index * PAGE, &mut page).unwrap();
        if page.iter().any(|byte| *byte != 0) {
            page[100] ^= 0xFF;
            arena.write_at(index * PAGE, &page).unwrap();
            damaged += 1;
        }
    }
    arena.sync_data().unwrap();
    assert!(damaged >= 2);
    refused_unchanged(&machines, "damaged superblocks");
    assert!(machines.open().is_err(), "a pair with damaged pages opens");
}

#[test]
fn a_used_volume_with_damaged_manifest_slots_is_never_created_over() {
    for zeroed in [false, true] {
        let (machines, _) = used();
        for slot in ["rollback.manifest.0", "rollback.manifest.1"] {
            let file = machines.root.process().open(slot, false).unwrap();
            if zeroed {
                let size = file.len().unwrap();
                file.set_len(0).unwrap();
                file.set_len(size).unwrap();
            } else {
                file.write_at(20, &[0xFF; 8]).unwrap();
            }
            file.sync_data().unwrap();
        }
        refused_unchanged(&machines, &format!("manifest slots, zeroed {zeroed}"));
        assert!(
            machines.open().is_err(),
            "a pair without its manifest opens"
        );
    }
}

#[test]
fn a_used_volume_whose_anchor_is_missing_or_empty_is_never_created_over() {
    for empty in [false, true] {
        let (machines, _) = used();
        let witness = machines.witness.process();
        if empty {
            witness.open("anchor", false).unwrap().set_len(0).unwrap();
        } else {
            witness.remove("anchor").unwrap();
        }
        witness.sync_dir("").unwrap();
        refused_unchanged(&machines, &format!("anchor, empty {empty}"));
        assert!(machines.open().is_err(), "a pair without its anchor opens");
    }
}

/// A witness mount that is not mounted is an empty directory.
#[test]
fn a_used_volume_beside_an_unmounted_witness_is_never_created_over() {
    let (machines, _) = used();
    let unmounted = Machines {
        root: machines.root,
        witness: CrashableBacking::new(),
    };
    refused_unchanged(&unmounted, "unmounted witness");
}

/// A pair that `create` refuses and that does not open says why it does not
/// open: the refusal alone reads as "empty both directories", also where
/// the cause is one to repair (a witness that is not mounted).
#[test]
fn a_refused_pair_that_does_not_open_says_why() {
    let unmounted = |machines: Machines| Machines {
        root: machines.root,
        witness: CrashableBacking::new(),
    };
    for (what, machines) in [
        ("a used volume", unmounted(used().0)),
        (
            "an unfinished creation",
            unmounted(interrupted(operations() * 2 / 3, None)),
        ),
    ] {
        let error = machines.create().unwrap_err();
        assert!(
            matches!(&error, RollbackCreateError::Backing(error) if error.kind() == io::ErrorKind::AlreadyExists),
            "{what}: {error}"
        );
        let text = error.to_string();
        assert!(
            text.contains("requires empty backing and witness directories")
                && text.contains("no anchor"),
            "{what}: {text}"
        );
    }
}

/// A backing root without its format marker that holds what an interrupted
/// creation does not leave (the `lost+found` of a filesystem mounted
/// there) is refused by `create` every time it runs. Neither the refusal
/// nor the commands that open the pair may say that running `create` again
/// continues it; they name what stops it.
#[test]
fn a_root_without_a_marker_that_create_refuses_is_not_said_to_be_continued() {
    let machines = machines();
    machines
        .root
        .process()
        .create_dir_all("lost+found")
        .unwrap();
    for attempt in ["first", "second"] {
        let text = machines.create().unwrap_err().to_string();
        assert!(
            text.contains("requires empty backing and witness directories"),
            "{attempt}: {text}"
        );
        assert!(text.contains("\"lost+found\""), "{attempt}: {text}");
        assert!(
            !text.contains("running volume create again continues"),
            "{attempt}: {text}"
        );
    }
    let text = machines.open().err().expect("no marker").to_string();
    assert!(text.contains("\"lost+found\""), "{text}");
    assert!(
        !text.contains("running volume create again continues"),
        "{text}"
    );
}

/// What the witness authenticates must itself be nothing but an unfinished
/// creation. A volume whose superblock copies are gone, but which holds
/// anything a creation does not write before its superblock, is refused.
#[test]
fn an_authenticated_volume_without_superblocks_that_holds_more_is_never_created_over() {
    type Plant = fn(&RollbackBacking);
    let plants: [(&str, Plant); 6] = [
        ("a journal segment", |volume| {
            volume.open(&layout::journal_segment(1), true).unwrap();
        }),
        ("a shard", |volume| {
            volume.open(&layout::shard_data(0), true).unwrap();
        }),
        ("a key canary", |volume| {
            volume.open(layout::KEY_CANARY_A, true).unwrap();
        }),
        ("a checkpoint file", |volume| {
            volume.open("checkpoint/other", true).unwrap();
        }),
        ("an unknown root entry", |volume| {
            volume.open("unknown", true).unwrap();
        }),
        ("a journal durable mark that was written", |volume| {
            let mark = volume.open(layout::JOURNAL_DURABLE_MARK, true).unwrap();
            mark.write_at(0, &[1; 16]).unwrap();
        }),
    ];
    for (what, plant) in plants {
        let machines = machines();
        machines.create().unwrap();
        let (volume, _) = machines.volume().unwrap();
        plant(&volume);
        for copy in [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B] {
            volume.remove(copy).unwrap();
        }
        for dir in [
            layout::JOURNAL_DIR,
            layout::DATA_DIR,
            layout::CHECKPOINT_DIR,
            "",
        ] {
            volume.sync_dir(dir).unwrap();
        }
        drop(volume);
        // The pair opens and holds no superblock, like an unfinished
        // creation.
        assert!(machines.open().is_ok(), "{what}");
        assert!(machines.volume().is_err(), "{what}");
        refused_unchanged(&machines, what);
    }
}

/// A superblock copy that exists is a volume, even beside nothing else
/// (writable recovery completes the other copy): never an unfinished
/// creation.
#[test]
fn a_volume_with_one_superblock_copy_is_never_created_over() {
    let machines = machines();
    let created = machines.create().unwrap();
    let (volume, _) = machines.volume().unwrap();
    volume.remove(layout::SUPERBLOCK_B).unwrap();
    volume.sync_dir("").unwrap();
    drop(volume);
    refused_unchanged(&machines, "one superblock copy");
    assert_eq!(
        machines.volume().unwrap().1.volume_uuid,
        created.volume_uuid
    );
}
