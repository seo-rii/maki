//! A local creation publishes the witness anchor last. A creation that is
//! cut or fails anywhere before that must leave a backing and a witness
//! directory that running `create` again completes, and one cut after it a
//! volume that opens: never a pair that both refuse. The executable crash
//! model hosts both directories, each on its own machine, and ends the
//! creation after each of their backing operations as a process death, as
//! a power loss of both, and as a single failed operation.
use super::*;
use crate::rollback::review_restore::crash_backing::CrashableBacking;
use rand::{rngs::StdRng, SeedableRng};
use std::sync::atomic::{AtomicUsize, Ordering};

const CAPACITY: u64 = 16 * PAGE;

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
                    .then(|| io::Error::from_raw_os_error(libc::ENOSPC))
            })));
        }
    }

    fn heal(&self) {
        self.root.set_fault_hook(None);
        self.witness.set_fault_hook(None);
    }

    /// `volume create`, in its own process.
    fn create(&self) -> io::Result<RollbackBacking> {
        RollbackBacking::create_backing(self.root.process(), self.witness.process(), CAPACITY)
    }

    /// The daemon's start, in its own process.
    fn open(&self) -> io::Result<RollbackBacking> {
        let witness = self.witness.process();
        RollbackBacking::open_witnessed(self.root.process(), || FileWitness::open_backing(witness))
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
}

/// How many backing operations an undisturbed creation performs.
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
    drop(machines.create().unwrap());
    count.load(Ordering::SeqCst)
}

/// The witness anchor as `open` reads it, without taking the witness lock.
fn read_anchor_of(machines: &Machines) -> io::Result<crate::witness::Anchor> {
    let file = machines.witness.process().open("anchor", false)?;
    let mut bytes = vec![0; file.len()? as usize];
    file.read_at(0, &mut bytes)?;
    crate::witness::decode_anchor(&bytes)
}

fn commit(backing: &RollbackBacking) {
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, b"kept").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
}

/// Exactly one command continues the pair: `open` once the anchor is
/// published, `create` until then. Then the volume must be durable.
fn complete(machines: &Machines, context: &str) {
    // Neither published name ever holds an empty or torn file.
    let process = machines.root.process();
    if let Ok(marker) = process.open(MARKER, false) {
        let mut bytes = vec![0; marker.len().unwrap() as usize];
        marker.read_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, MAGIC, "{context}: published marker");
    }
    drop(process);
    if let Err(error) = read_anchor_of(machines) {
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{context}: {error}");
    }
    let lists = || {
        (
            machines.root.process().list("").unwrap(),
            machines.witness.process().list("").unwrap(),
        )
    };
    let volume = match machines.open() {
        Ok(volume) => {
            drop(volume);
            if let Ok(created) = machines.create() {
                drop(created);
                panic!(
                    "{context}: create completed a published volume: {:?}",
                    lists()
                );
            }
            machines.open().unwrap()
        }
        Err(opened) => {
            let created = machines.create().unwrap_or_else(|created| {
                panic!(
                    "{context}: open: {opened}; create: {created}; backing and witness: {:?}",
                    lists()
                )
            });
            drop(created);
            // A creation that reported success is durable as it returned.
            machines.power_loss(0);
            machines.open().unwrap_or_else(|error| {
                panic!("{context}: the creation that succeeded did not survive: {error}")
            })
        }
    };
    commit(&volume);
    drop(volume);
    machines.power_loss(0);
    let reopened = machines
        .open()
        .unwrap_or_else(|error| panic!("{context}: the completed volume did not survive: {error}"));
    let mut bytes = [0; 4];
    reopened
        .open("payload", false)
        .unwrap()
        .read_at(0, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"kept", "{context}");
}

#[test]
fn an_undisturbed_creation_is_refused_by_a_second_one() {
    let machines = machines();
    drop(machines.create().unwrap());
    assert!(machines.create().is_err());
    complete(&machines, "undisturbed");
}

#[test]
fn a_creation_killed_at_any_operation_can_be_continued() {
    for cut in 0..=operations() {
        let machines = machines();
        // The process dies before operation `cut`: nothing it does from
        // there on, cleanup included, reaches either directory.
        machines.inject(move |index| index >= cut);
        let _ = machines.create();
        machines.heal();
        complete(&machines, &format!("killed before operation {cut}"));
    }
}

#[test]
fn a_creation_cut_by_a_power_loss_at_any_operation_can_be_continued() {
    for cut in 0..=operations() {
        // Seed 0 loses everything volatile; the others keep any subset of
        // it, with torn writes. A creation has many more operations than
        // the remote marker step, so fewer subsets per cut keep this fast.
        for seed in 0..=2 {
            let machines = machines();
            machines.inject(move |index| index >= cut);
            let _ = machines.create();
            machines.heal();
            machines.power_loss(seed);
            complete(
                &machines,
                &format!("power loss before operation {cut}, seed {seed}"),
            );
        }
    }
}

#[test]
fn a_creation_whose_operation_failed_can_be_run_again() {
    for failed in 0..operations() {
        let machines = machines();
        // One operation fails, as on a full disk, and the command returns.
        machines.inject(move |index| index == failed);
        assert!(machines.create().is_err(), "operation {failed}");
        machines.heal();
        complete(&machines, &format!("operation {failed} failed"));
    }
}

/// A volume that committed anything is never created over, whatever the
/// witness holds: here a witness directory that lost everything.
#[test]
fn control_a_committed_volume_is_never_created_over() {
    let machines = machines();
    let volume = machines.create().unwrap();
    commit(&volume);
    drop(volume);
    let empty = CrashableBacking::new();
    assert!(
        RollbackBacking::create_backing(machines.root.process(), empty.process(), CAPACITY)
            .is_err()
    );
    assert!(empty.process().list("").unwrap().is_empty());
    let reopened = machines.open().unwrap();
    assert!(reopened.open("payload", false).is_ok());
}
