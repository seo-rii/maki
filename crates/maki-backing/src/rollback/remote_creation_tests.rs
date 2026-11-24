//! The first thing a remote creation publishes in a backing root is its
//! format marker. A creation that is cut or fails anywhere in that step must
//! leave a root one of the documented commands continues: `volume create`
//! again while the marker is not published, enrollment recovery once it is.
//! A root that holds an unwritten or torn marker is neither, and nothing can
//! complete it. The executable crash model ends the step after each of its
//! backing operations as a process death, as a power loss and as a single
//! failed operation.
use super::*;
use crate::rollback::review_restore::crash_backing::CrashableBacking;
use rand::{rngs::StdRng, SeedableRng};
use std::sync::atomic::{AtomicUsize, Ordering};

fn machine() -> CrashableBacking {
    CrashableBacking::new().with_tearing(512)
}

/// Fail the backing operations whose index `fails` selects, as ENOSPC.
fn inject(machine: &CrashableBacking, fails: impl Fn(usize) -> bool + Send + Sync + 'static) {
    let count = AtomicUsize::new(0);
    machine.set_fault_hook(Some(Arc::new(move |_| {
        fails(count.fetch_add(1, Ordering::SeqCst))
            .then(|| io::Error::from_raw_os_error(libc::ENOSPC))
    })));
}

/// One creation attempt in its own process, as far as the marker: both root
/// locks, then the step under test.
fn attempt(machine: &CrashableBacking) -> io::Result<()> {
    let process = machine.process();
    let _operation = process.try_lock(OPERATION_LOCK)?;
    let _enrollment = process.try_lock(super::super::ENROLL_LOCK)?;
    initialize_remote_root(process.as_ref())
}

/// How many backing operations an undisturbed attempt performs.
fn operations() -> usize {
    operations_of(attempt)
}

fn operations_of(attempt: fn(&CrashableBacking) -> io::Result<()>) -> usize {
    let machine = machine();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    machine.set_fault_hook(Some(Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        None
    })));
    attempt(&machine).unwrap();
    count.load(Ordering::SeqCst)
}

/// Whether enrollment recovery accepts the root's marker.
fn published(machine: &CrashableBacking) -> bool {
    let process = machine.process();
    let Ok(marker) = process.open(MARKER, false) else {
        return false;
    };
    let mut bytes = vec![0; REMOTE_MAGIC.len()];
    marker.len().ok() == Some(bytes.len() as u64)
        && marker.read_at(0, &mut bytes).is_ok()
        && bytes == REMOTE_MAGIC
}

/// Exactly one documented command continues the root: enrollment recovery
/// when the marker is published, `volume create` when it is not.
fn one_command_continues(machine: &CrashableBacking, context: &str) {
    let create = require_empty_remote_root(machine.process().as_ref());
    assert_eq!(
        create.is_ok(),
        !published(machine),
        "{context}: marker published: {}, create: {create:?}, root: {:?}",
        published(machine),
        machine.process().list("").unwrap()
    );
}

/// Continue the root to a published marker and require it to be durable.
fn complete(machine: &CrashableBacking, context: &str) {
    one_command_continues(machine, context);
    if !published(machine) {
        attempt(machine).unwrap_or_else(|error| panic!("{context}: create again: {error}"));
        assert!(published(machine), "{context}");
        // What a successful creation published survives any power loss.
        machine.crash_all_lost();
        assert!(published(machine), "{context}: the marker was not durable");
    }
}

#[test]
fn an_undisturbed_creation_publishes_a_durable_marker() {
    let machine = machine();
    attempt(&machine).unwrap();
    assert!(published(&machine));
    assert_eq!(
        machine.process().list("").unwrap(),
        [super::super::ENROLL_LOCK, OPERATION_LOCK, MARKER]
    );
    machine.crash_all_lost();
    assert!(published(&machine));
    // Published: `create` refuses it from now on.
    assert!(attempt(&machine).is_err());
}

#[test]
fn a_creation_killed_at_any_operation_can_be_continued() {
    for cut in 0..=operations() {
        let machine = machine();
        // The process dies before operation `cut`: nothing it does from
        // there on, cleanup included, reaches the backing.
        inject(&machine, move |index| index >= cut);
        let _ = attempt(&machine);
        machine.set_fault_hook(None);
        complete(&machine, &format!("killed before operation {cut}"));
    }
}

#[test]
fn a_creation_cut_by_a_power_loss_at_any_operation_can_be_continued() {
    for cut in 0..=operations() {
        for seed in 0..=16 {
            let machine = machine();
            inject(&machine, move |index| index >= cut);
            let _ = attempt(&machine);
            machine.set_fault_hook(None);
            // Seed 0 loses everything volatile; the others keep any subset
            // of it, with torn writes.
            if seed == 0 {
                machine.crash_all_lost();
            } else {
                machine.crash(&mut StdRng::seed_from_u64(seed));
            }
            complete(
                &machine,
                &format!("power loss before operation {cut}, seed {seed}"),
            );
        }
    }
}

#[test]
fn a_creation_whose_operation_failed_can_be_retried() {
    for failed in 0..operations() {
        let machine = machine();
        // One operation fails, as on a full disk, and the command returns.
        inject(&machine, move |index| index == failed);
        assert!(attempt(&machine).is_err(), "operation {failed}");
        machine.set_fault_hook(None);
        complete(&machine, &format!("operation {failed} failed"));
    }
}

/// A sync that failed left bytes that are readable and not durable, and a
/// bare retry of the sync writes nothing. A later attempt that finds them
/// must write the marker again before it syncs and publishes it.
#[test]
fn a_marker_whose_sync_failed_is_written_again_before_it_is_published() {
    use crate::rollback::review_restore::crash_backing::FaultOp;
    let machine = machine();
    let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let died = dead.clone();
    // The process dies in the first data sync of the step: that sync fails
    // and nothing after it reaches the backing.
    machine.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(op, FaultOp::SyncData { .. }) {
            died.store(true, Ordering::SeqCst);
        }
        died.load(Ordering::SeqCst)
            .then(|| io::Error::from_raw_os_error(libc::EIO))
    })));
    assert!(attempt(&machine).is_err());
    assert!(dead.load(Ordering::SeqCst));
    machine.set_fault_hook(None);
    complete(&machine, "the marker's first sync failed");
    assert!(published(&machine));
}

const IDENTITY: [u8; 16] = [0x5a; 16];
const CAPACITY: u64 = 16 * PAGE;
/// The binding of the creation these tests run.
const CREATION: Enrollment = Enrollment {
    identity: IDENTITY,
    capacity: CAPACITY,
};

/// One creation attempt as far as the binding, the file after the marker.
/// The authority is claimed only once both are durable, so a creation cut
/// anywhere in here has claimed nothing.
fn attempt_binding(machine: &CrashableBacking) -> io::Result<()> {
    let process = machine.process();
    let _operation = process.try_lock(OPERATION_LOCK)?;
    let _enrollment = process.try_lock(super::super::ENROLL_LOCK)?;
    initialize_remote_root(process.as_ref())?;
    Enrollment::load_or_create(process.as_ref(), IDENTITY, CAPACITY).map(drop)
}

/// One enrollment recovery in its own process, as far as the binding: what
/// `recover_enrollment_remote` does in the root it has opened. It checks the
/// binding, and refuses one that is there and is not this identity's, then
/// publishes the marker again and writes the binding.
fn resume_binding(machine: &CrashableBacking) -> io::Result<()> {
    let process = machine.process();
    let _operation = process.try_lock(OPERATION_LOCK)?;
    let _enrollment = process.try_lock(super::super::ENROLL_LOCK)?;
    Enrollment::verify_if_present(process.as_ref(), IDENTITY, CAPACITY)?;
    republish_marker(process.as_ref())?;
    Enrollment::load_or_create(process.as_ref(), IDENTITY, CAPACITY).map(drop)
}

/// Continue the root to a durable binding with the documented command:
/// `volume create` again while the marker is not published, enrollment
/// recovery once it is. Recovery first checks the binding, and refuses one
/// that is there and is not this identity's: that must never be what a
/// creation that was cut leaves.
fn complete_binding(machine: &CrashableBacking, context: &str) {
    one_command_continues(machine, context);
    if published(machine) {
        resume_binding(machine).unwrap_or_else(|error| {
            panic!(
                "{context}: resume: {error}; root: {:?}",
                machine.process().list("").unwrap()
            )
        });
    } else {
        attempt_binding(machine).unwrap_or_else(|error| panic!("{context}: create again: {error}"));
    }
    // What the completing command published survives any power loss.
    machine.crash_all_lost();
    assert!(published(machine), "{context}: the marker was not durable");
    assert_eq!(
        Enrollment::load(machine.process().as_ref()).ok(),
        Some(Enrollment {
            identity: IDENTITY,
            capacity: CAPACITY
        }),
        "{context}: the binding was not durable"
    );
}

#[test]
fn a_creation_killed_at_any_operation_of_its_binding_can_be_continued() {
    for cut in 0..=operations_of(attempt_binding) {
        let machine = machine();
        inject(&machine, move |index| index >= cut);
        let _ = attempt_binding(&machine);
        machine.set_fault_hook(None);
        complete_binding(&machine, &format!("killed before operation {cut}"));
    }
}

#[test]
fn a_creation_cut_by_a_power_loss_at_any_operation_of_its_binding_can_be_continued() {
    for cut in 0..=operations_of(attempt_binding) {
        for seed in 0..=16 {
            let machine = machine();
            inject(&machine, move |index| index >= cut);
            let _ = attempt_binding(&machine);
            machine.set_fault_hook(None);
            if seed == 0 {
                machine.crash_all_lost();
            } else {
                machine.crash(&mut StdRng::seed_from_u64(seed));
            }
            complete_binding(
                &machine,
                &format!("power loss before operation {cut}, seed {seed}"),
            );
        }
    }
}

#[test]
fn a_creation_whose_binding_operation_failed_can_be_continued() {
    for failed in 0..operations_of(attempt_binding) {
        let machine = machine();
        inject(&machine, move |index| index == failed);
        assert!(attempt_binding(&machine).is_err(), "operation {failed}");
        machine.set_fault_hook(None);
        complete_binding(&machine, &format!("operation {failed} failed"));
    }
}

/// The process dies at the first operation `dies_at` selects: that operation
/// and everything after it fail.
fn die_at(
    machine: &CrashableBacking,
    dies_at: impl Fn(&crate::rollback::review_restore::crash_backing::FaultOp<'_>) -> bool
        + Send
        + Sync
        + 'static,
) {
    let dead = std::sync::atomic::AtomicBool::new(false);
    machine.set_fault_hook(Some(Arc::new(move |op| {
        if dies_at(op) {
            dead.store(true, Ordering::SeqCst);
        }
        dead.load(Ordering::SeqCst)
            .then(|| io::Error::from_raw_os_error(libc::EIO))
    })));
}

/// A creation whose marker is readable while its name is not durable (the
/// directory sync that publishes it failed) is continued by enrollment
/// recovery, and the next file recovery writes is the binding. Recovery must
/// make the marker's name durable before it stages the binding: a power
/// loss keeps directory entries in any order, and a root that kept the
/// staged binding and lost the marker is one neither command expects.
#[test]
fn enrollment_recovery_makes_the_marker_durable_before_it_stages_the_binding() {
    use crate::rollback::review_restore::crash_backing::FaultOp;
    let machine = machine();
    let failed = std::sync::atomic::AtomicBool::new(false);
    machine.set_fault_hook(Some(Arc::new(move |op| {
        (matches!(op, FaultOp::SyncDir { .. }) && !failed.swap(true, Ordering::SeqCst))
            .then(|| io::Error::from_raw_os_error(libc::EIO))
    })));
    assert!(attempt_binding(&machine).is_err());
    machine.set_fault_hook(None);
    assert!(published(&machine));
    one_command_continues(&machine, "the marker's directory sync failed");

    // Recovery dies at the rename that publishes the binding.
    die_at(&machine, |op| matches!(op, FaultOp::Rename { .. }));
    assert!(resume_binding(&machine).is_err());
    machine.set_fault_hook(None);
    // The power loss keeps the staged binding and nothing else that was
    // not synced.
    machine.crash_keep_torn_prefix(super::super::enrollment::FILE_NEXT, usize::MAX);
    assert!(
        published(&machine),
        "the staged binding outlived the marker; root: {:?}",
        machine.process().list("").unwrap()
    );
    complete_binding(&machine, "recovery died at the binding's rename");
}

/// A binding that recovery finds and accepts is readable, which does not
/// make its bytes durable: another process may just have written it. Until
/// recovery has written and synced those bytes again, it must not sync the
/// directory, or a power loss leaves the binding's name with nothing in it,
/// which recovery refuses from then on.
#[test]
fn enrollment_recovery_syncs_no_directory_before_a_binding_it_found_is_durable() {
    use crate::rollback::review_restore::crash_backing::FaultOp;
    let machine = machine();
    attempt(&machine).unwrap();
    let bytes = binding_bytes();
    let file = machine
        .process()
        .open(super::super::enrollment::FILE, true)
        .unwrap();
    file.write_at(0, &bytes).unwrap();
    drop(file);
    assert_eq!(
        Enrollment::load(machine.process().as_ref()).ok(),
        Some(CREATION)
    );

    // Recovery dies at the data sync of the binding it found.
    die_at(
        &machine,
        |op| matches!(op, FaultOp::SyncData { path } if *path == super::super::enrollment::FILE),
    );
    assert!(resume_binding(&machine).is_err());
    machine.set_fault_hook(None);
    machine.crash_all_lost();
    assert_eq!(
        machine.process().list("").unwrap(),
        [super::super::ENROLL_LOCK, OPERATION_LOCK, MARKER],
        "the binding's name outlived its bytes"
    );
    complete_binding(
        &machine,
        "recovery died before the binding it found was synced",
    );
}

/// A creation that continues a root in which its binding outlived the marker
/// accepts that binding as it reads. Publishing the marker syncs the
/// directory, and with it the binding's name: the binding's bytes must be
/// durable by then, even if another process has only just written them.
#[test]
fn creation_makes_a_binding_it_found_durable_before_it_publishes_the_marker() {
    use crate::rollback::review_restore::crash_backing::FaultOp;
    let machine = machine();
    let file = machine
        .process()
        .open(super::super::enrollment::FILE, true)
        .unwrap();
    file.write_at(0, &binding_bytes()).unwrap();
    drop(file);

    // The creation dies once the marker is published: at the first
    // operation after the directory sync that follows the marker's rename.
    let step = AtomicUsize::new(0);
    die_at(&machine, move |op| {
        match (step.load(Ordering::SeqCst), op) {
            (0, FaultOp::Rename { to, .. }) if *to == MARKER => {
                step.store(1, Ordering::SeqCst);
                false
            }
            (1, FaultOp::SyncDir { .. }) => {
                step.store(2, Ordering::SeqCst);
                false
            }
            (2, _) => true,
            _ => false,
        }
    });
    assert!(attempt_binding(&machine).is_err());
    machine.set_fault_hook(None);
    machine.crash_all_lost();
    assert!(published(&machine));
    complete_binding(&machine, "the creation died once its marker was published");
}

/// The bytes of this identity's binding, from a creation that completed.
fn binding_bytes() -> Vec<u8> {
    let machine = machine();
    attempt_binding(&machine).unwrap();
    let file = machine
        .process()
        .open(super::super::enrollment::FILE, false)
        .unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

/// A root a release without that directory sync can have left: the staged
/// marker, whose rename the power loss dropped, beside the binding under
/// `name`, staged or published. A published binding was renamed into place
/// after its bytes were synced, as that release did it. `durable` is the
/// root as the power loss left it; without it no name in it is on the disk
/// yet, which is what a later process finds when another has just written
/// the root.
fn binding_without_marker(name: &str, durable: bool) -> CrashableBacking {
    use super::super::enrollment::{FILE, FILE_NEXT};
    let machine = machine();
    let process = machine.process();
    let marker = process.open(super::super::MARKER_NEXT, true).unwrap();
    marker.write_at(0, REMOTE_MAGIC).unwrap();
    let binding = process.open(FILE_NEXT, true).unwrap();
    binding.write_at(0, &binding_bytes()).unwrap();
    if name == FILE {
        binding.sync_data().unwrap();
        process.rename(FILE_NEXT, FILE).unwrap();
    }
    if durable {
        marker.sync_data().unwrap();
        binding.sync_data().unwrap();
        process.sync_dir("").unwrap();
    }
    machine
}

const LEFT_WITHOUT_MARKER: [&str; 2] = [
    super::super::enrollment::FILE_NEXT,
    super::super::enrollment::FILE,
];

/// Such a root published nothing a creation may not write again and claimed
/// nothing: `volume create` continues it, wherever that creation is cut in
/// turn, and what it accepted of the root is durable when it returns.
#[test]
fn a_binding_left_without_a_marker_is_continued_by_creation_from_any_cut() {
    for name in LEFT_WITHOUT_MARKER {
        for durable in [true, false] {
            let machine = binding_without_marker(name, durable);
            complete_binding(
                &machine,
                &format!("{name} without a marker, durable: {durable}"),
            );
        }

        let operations = {
            let machine = binding_without_marker(name, true);
            let count = Arc::new(AtomicUsize::new(0));
            let seen = count.clone();
            machine.set_fault_hook(Some(Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                None
            })));
            attempt_binding(&machine).unwrap();
            count.load(Ordering::SeqCst)
        };
        for cut in 0..=operations {
            // Killed, then nothing, everything or any part of what was not
            // synced is lost.
            for seed in 0..=17 {
                let machine = binding_without_marker(name, true);
                inject(&machine, move |index| index >= cut);
                let _ = attempt_binding(&machine);
                machine.set_fault_hook(None);
                match seed {
                    0 => {}
                    1 => machine.crash_all_lost(),
                    _ => machine.crash(&mut StdRng::seed_from_u64(seed)),
                }
                complete_binding(
                    &machine,
                    &format!("{name} without a marker, cut at operation {cut}, seed {seed}"),
                );
            }
            if cut < operations {
                let machine = binding_without_marker(name, true);
                inject(&machine, move |index| index == cut);
                assert!(
                    attempt_binding(&machine).is_err(),
                    "{name}: operation {cut}"
                );
                machine.set_fault_hook(None);
                complete_binding(
                    &machine,
                    &format!("{name} without a marker, operation {cut} failed"),
                );
            }
        }
    }
}

/// One to four commands in a row are interrupted, each the documented one
/// for the root the last left (`volume create` while the marker is not
/// published, enrollment recovery once it is): at a random operation, as a
/// process death or as one failed operation, with or without a power loss
/// after it. Whatever that leaves, exactly one command continues it, to a
/// durable marker and binding. The chain starts from an empty root, or from
/// a binding `left` without its marker.
fn interrupted_chain(seed: u64, left: Option<&str>) -> Result<(), String> {
    use rand::Rng;
    let outcome = std::panic::catch_unwind(|| {
        let mut rng = StdRng::seed_from_u64(seed);
        let machine = match left {
            Some(name) => binding_without_marker(name, rng.random_bool(0.5)),
            None => machine(),
        };
        let operations = operations_of(attempt_binding);
        let mut context = format!("seed {seed}, left {left:?}");
        for _ in 0..rng.random_range(1..=4) {
            let cut = rng.random_range(0..=operations + 2);
            let single = rng.random_bool(0.5);
            let resumed = published(&machine);
            one_command_continues(&machine, &context);
            inject(
                &machine,
                move |index| {
                    if single {
                        index == cut
                    } else {
                        index >= cut
                    }
                },
            );
            let result = if resumed {
                resume_binding(&machine)
            } else {
                attempt_binding(&machine)
            };
            machine.set_fault_hook(None);
            let loss = rng.random_range(0..4u64);
            match loss {
                0 => {}
                1 => machine.crash_all_lost(),
                _ => machine.crash(&mut StdRng::seed_from_u64(rng.random())),
            }
            context += &format!(
                "; {} {} at operation {cut}: {}, power loss {loss}",
                if resumed { "resume" } else { "create" },
                if single { "fails" } else { "dies" },
                if result.is_ok() { "ok" } else { "error" },
            );
        }
        complete_binding(&machine, &context);
    });
    outcome.map_err(|panic| {
        panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|text| text.to_string()))
            .unwrap_or_default()
    })
}

/// Chains from an empty root, and from each root a binding was left in.
const CHAIN_SEEDS: [(Option<&str>, u64); 3] = [
    (None, 3000),
    (Some(super::super::enrollment::FILE_NEXT), 500),
    (Some(super::super::enrollment::FILE), 500),
];

#[test]
fn a_creation_interrupted_repeatedly_is_continued_by_exactly_one_command() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let failed: Vec<(Option<&str>, u64, String)> = CHAIN_SEEDS
        .iter()
        .flat_map(|&(left, seeds)| (0..seeds).map(move |seed| (left, seed)))
        .filter_map(|(left, seed)| {
            interrupted_chain(seed, left)
                .err()
                .map(|error| (left, seed, error))
        })
        .collect();
    std::panic::set_hook(previous);
    let from = |start: Option<&str>| -> Vec<u64> {
        failed
            .iter()
            .filter(|(left, ..)| *left == start)
            .map(|(_, seed, _)| *seed)
            .collect()
    };
    assert!(
        failed.is_empty(),
        "{} failing chain(s): from an empty root, seeds {:?}; from a staged binding, {} seeds; \
         from a published binding, {} seeds; first:\n{}",
        failed.len(),
        from(None),
        from(CHAIN_SEEDS[1].0).len(),
        from(CHAIN_SEEDS[2].0).len(),
        failed[0].2
    );
}
