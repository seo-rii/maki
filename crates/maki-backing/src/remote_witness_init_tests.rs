//! Initializing a local authority publishes its first record. An
//! initialization that is cut or fails anywhere must leave a state
//! directory that one of the two commands an operator has continues:
//! initialize again while no record is published, serve once one is. A
//! directory holding an empty `remote.state` is neither, and it is also
//! what an enrolled authority whose state was truncated looks like, so
//! nothing may complete it automatically. An enrolled authority must never
//! be initialized again, whatever interrupts it later. The executable crash
//! model ends each step before each of its backing operations as a process
//! death, as a power loss and as a single failed operation.
use super::*;
use crate::rollback::review_restore::crash_backing::{CrashableBacking, FaultOp};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const ID: [u8; 16] = [7; 16];

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

/// How many backing operations `run` performs undisturbed.
fn operations(machine: &CrashableBacking, run: impl FnOnce()) -> usize {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    machine.set_fault_hook(Some(Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        None
    })));
    run();
    machine.set_fault_hook(None);
    count.load(Ordering::SeqCst)
}

/// `maki-witness init`, in its own process.
fn init(machine: &CrashableBacking) -> io::Result<StateStore> {
    StateStore::create_backing(machine.process(), ID)
}

/// `maki-witness serve` as far as its durable state open, in its own process.
fn serve(machine: &CrashableBacking) -> io::Result<StateStore> {
    StateStore::open_backing(machine.process())
}

fn inspect(store: &mut StateStore) -> Record {
    store
        .handle(
            Role::Admin,
            &Request {
                authorization: None,
                operation_id: [0; 16],
                expected: None,
                action: Action::Inspect,
            },
        )
        .unwrap()
}

fn claim(store: &mut StateStore) -> Request {
    Request {
        authorization: Some(SessionAuthorization::from_bytes([9; 32])),
        operation_id: [1; 16],
        expected: Some(inspect(store)),
        action: Action::Claim,
    }
}

fn power_loss(machine: &CrashableBacking, seed: u64) {
    // Seed 0 loses everything volatile; the others keep any subset of it,
    // with torn writes.
    if seed == 0 {
        machine.crash_all_lost();
    } else {
        machine.crash(&mut StdRng::seed_from_u64(seed));
    }
}

fn serves_the_initial_record(machine: &CrashableBacking, context: &str) {
    let mut store = serve(machine).unwrap_or_else(|error| {
        panic!(
            "{context}: neither init nor serve continues: {error}; state directory: {:?}",
            machine.process().list("").unwrap()
        )
    });
    let record = inspect(&mut store);
    assert_eq!(
        (record.identity, record.fence, record.phase),
        (ID, 0, Phase::Released),
        "{context}"
    );
    assert!(record.current.is_none(), "{context}");
}

/// After an initialization that did not report success, exactly one
/// command continues: `init` again, or, when the first record was already
/// published, `serve`. The authority then serves the initial record of this
/// identity and stays enrolled across a power loss.
fn continued(machine: &CrashableBacking, context: &str) {
    match init(machine) {
        // It reports success, so its record must already be durable.
        Ok(store) => {
            drop(store);
            machine.crash_all_lost();
        }
        Err(error) => assert_eq!(
            error.kind(),
            io::ErrorKind::AlreadyExists,
            "{context}: init again: {error}"
        ),
    }
    serves_the_initial_record(machine, context);
    machine.crash_all_lost();
    assert_eq!(
        init(machine).err().map(|error| error.kind()),
        Some(io::ErrorKind::AlreadyExists),
        "{context}: a served authority was initialized again"
    );
    serves_the_initial_record(machine, context);
}

/// The backing operations of one undisturbed initialization.
fn initial_operations() -> usize {
    let machine = machine();
    operations(&machine, || drop(init(&machine).unwrap()))
}

#[test]
fn an_undisturbed_init_enrolls_durably_and_only_once() {
    let machine = machine();
    drop(init(&machine).unwrap());
    machine.crash_all_lost();
    assert_eq!(
        init(&machine).err().unwrap().kind(),
        io::ErrorKind::AlreadyExists
    );
    serves_the_initial_record(&machine, "undisturbed");
}

#[test]
fn an_init_killed_at_any_operation_can_be_run_again_or_served() {
    for cut in 0..=initial_operations() {
        let machine = machine();
        // The process dies before operation `cut`: nothing it does from
        // there on reaches the backing.
        inject(&machine, move |index| index >= cut);
        let _ = init(&machine);
        machine.set_fault_hook(None);
        continued(&machine, &format!("killed before operation {cut}"));
    }
}

#[test]
fn an_init_cut_by_a_power_loss_at_any_operation_can_be_run_again_or_served() {
    for cut in 0..=initial_operations() {
        for seed in 0..=16 {
            let machine = machine();
            inject(&machine, move |index| index >= cut);
            let _ = init(&machine);
            machine.set_fault_hook(None);
            power_loss(&machine, seed);
            continued(
                &machine,
                &format!("power loss before operation {cut}, seed {seed}"),
            );
        }
    }
}

#[test]
fn an_init_whose_operation_failed_can_be_run_again_or_served() {
    for failed in 0..initial_operations() {
        let machine = machine();
        // One operation fails, as on a full disk, and the command returns.
        inject(&machine, move |index| index == failed);
        assert!(init(&machine).is_err(), "operation {failed}");
        machine.set_fault_hook(None);
        continued(&machine, &format!("operation {failed} failed"));
    }
}

/// A sync that failed left bytes that are readable and not durable, and a
/// bare retry of the sync writes nothing. The initialization that finds
/// them must write the record again before it syncs and publishes it.
#[test]
fn a_first_record_whose_sync_failed_is_written_again_before_it_is_published() {
    let machine = machine();
    let dead = Arc::new(AtomicBool::new(false));
    let died = dead.clone();
    // The process dies in the first data sync of `remote.next`.
    machine.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(op, FaultOp::SyncData { path } if *path == TEMP_FILE) {
            died.store(true, Ordering::SeqCst);
        }
        died.load(Ordering::SeqCst)
            .then(|| io::Error::from_raw_os_error(libc::EIO))
    })));
    assert!(init(&machine).is_err());
    assert!(dead.load(Ordering::SeqCst));
    machine.set_fault_hook(None);
    drop(init(&machine).unwrap());
    machine.crash_all_lost();
    assert_eq!(inspect(&mut serve(&machine).unwrap()).fence, 0);
}

/// Once an initialization has reported success, no later interruption makes
/// the directory look uninitialized: `init` refuses it after every cut of a
/// later publication, and what is served is never behind the last record
/// the authority acknowledged.
#[test]
fn an_enrolled_authority_is_never_initialized_again_whatever_interrupts_it() {
    let enrolled = || {
        let machine = machine();
        drop(init(&machine).unwrap());
        machine
    };
    let publication = {
        let machine = enrolled();
        let mut store = serve(&machine).unwrap();
        let request = claim(&mut store);
        operations(&machine, || {
            store.handle(Role::Writer, &request).unwrap();
        })
    };
    assert!(publication > 0);
    for cut in 0..=publication {
        for seed in 0..=8 {
            let machine = enrolled();
            let mut store = serve(&machine).unwrap();
            let request = claim(&mut store);
            inject(&machine, move |index| index >= cut);
            let acknowledged = store.handle(Role::Writer, &request).is_ok();
            machine.set_fault_hook(None);
            drop(store);
            power_loss(&machine, seed);
            let context = format!("claim cut before operation {cut}, seed {seed}");
            assert_eq!(
                init(&machine).err().map(|error| error.kind()),
                Some(io::ErrorKind::AlreadyExists),
                "{context}"
            );
            let record = inspect(&mut serve(&machine).unwrap());
            assert_eq!(record.identity, ID, "{context}");
            if acknowledged {
                assert_eq!(
                    (record.fence, record.phase),
                    (1, Phase::Claimed),
                    "{context}"
                );
            } else {
                assert!(record.fence <= 1, "{context}");
            }
        }
    }
}

/// An empty `remote.state` is what releases that created the file before
/// writing it left of an interrupted initialization, and also what an
/// enrolled authority whose state was truncated looks like. Neither command
/// replaces it; both say what it can mean and what the operator may do.
#[test]
fn an_empty_state_file_is_refused_by_init_and_serve_and_left_as_it_is() {
    let machine = machine();
    let view = machine.process();
    let state = view.open(STATE_FILE, true).unwrap();
    state.sync_data().unwrap();
    view.sync_dir("").unwrap();
    drop((state, view));
    for (command, kind) in [
        (
            init as fn(&CrashableBacking) -> io::Result<StateStore>,
            io::ErrorKind::AlreadyExists,
        ),
        (serve, io::ErrorKind::InvalidData),
    ] {
        let error = command(&machine).err().unwrap();
        assert_eq!(error.kind(), kind);
        let text = error.to_string();
        assert!(
            text.contains("remote.state is empty")
                && text.contains("did not complete")
                && text.contains("lost its state")
                && text.contains("never been served"),
            "{text}"
        );
    }
    let view = machine.process();
    assert!(view.open(STATE_FILE, false).unwrap().is_empty().unwrap());
    assert!(!view.exists(TEMP_FILE).unwrap());
}
