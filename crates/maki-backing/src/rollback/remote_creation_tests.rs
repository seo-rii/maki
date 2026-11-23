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

/// Continue the root to a durable binding with the documented command:
/// `volume create` again while the marker is not published, enrollment
/// recovery once it is. Recovery first checks the binding, and refuses one
/// that is there and is not this identity's: that must never be what a
/// creation that was cut leaves.
fn complete_binding(machine: &CrashableBacking, context: &str) {
    one_command_continues(machine, context);
    if published(machine) {
        let process = machine.process();
        let _enrollment = process.try_lock(super::super::ENROLL_LOCK).unwrap();
        Enrollment::verify_if_present(process.as_ref(), IDENTITY, CAPACITY).unwrap_or_else(
            |error| {
                panic!(
                    "{context}: enrollment recovery refuses the binding ({error}); root: {:?}",
                    process.list("").unwrap()
                )
            },
        );
        Enrollment::load_or_create(process.as_ref(), IDENTITY, CAPACITY)
            .unwrap_or_else(|error| panic!("{context}: resume: {error}"));
    } else {
        attempt_binding(machine).unwrap_or_else(|error| panic!("{context}: create again: {error}"));
    }
    // What the completing command published survives any power loss.
    machine.crash_all_lost();
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
