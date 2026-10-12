//! BUG-054: restored, readable bytes must be durable before local COW readiness.

use super::*;
use rand::{rngs::StdRng, SeedableRng};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// Use the same failed-writeback and torn-write semantics as core recovery
// regressions. A dev dependency on maki-test-support would form a cycle.
#[allow(dead_code)]
#[path = "../../../maki-test-support/src/crash_backing.rs"]
mod crash_backing;
use crash_backing::{CrashableBacking, FaultOp};

struct Restore {
    disk: Arc<CrashableBacking>,
    witness: tempfile::TempDir,
    snapshots: BTreeMap<String, Vec<u8>>,
    selected: String,
    original: Vec<u8>,
}

impl Restore {
    fn new(dirty: Option<&str>, dirty_length: bool) -> Self {
        let source = tempfile::tempdir().unwrap();
        let witness = tempfile::tempdir_in("/dev/shm").unwrap();
        let backing = RollbackBacking::create(source.path(), witness.path(), 3 * PAGE).unwrap();
        let file = backing.open("payload", true).unwrap();
        let original = vec![0x59; 2 * PAGE as usize];
        file.write_at(0, &original).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        let selected = MANIFESTS[backing.state.lock().manifest_slot].to_owned();
        drop((file, backing));

        let snapshots: BTreeMap<_, _> = std::fs::read_dir(source.path())
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
            .collect();
        let disk = Arc::new(CrashableBacking::new().with_tearing(512));
        let target = dirty.map(|name| if name == "selected" { &*selected } else { name });
        for (name, bytes) in &snapshots {
            let file = disk.open(name, true).unwrap();
            let is_dirty = target == Some(name.as_str());
            let durable_len = if is_dirty && dirty_length {
                0
            } else {
                bytes.len() as u64
            };
            file.set_len(durable_len).unwrap();
            file.sync_data().unwrap();
            file.set_len(bytes.len() as u64).unwrap();
            file.write_at(0, bytes).unwrap();
            if !is_dirty {
                file.sync_data().unwrap();
            }
        }
        disk.sync_dir("").unwrap();
        Self {
            disk,
            witness,
            snapshots,
            selected,
            original,
        }
    }

    fn open(&self) -> io::Result<RollbackBacking> {
        RollbackBacking::open_backing(self.disk.clone(), self.witness.path())
    }

    fn fail_syncs(&self, path: &str, failures: usize) {
        let path = path.to_owned();
        let remaining = Mutex::new(failures);
        self.disk.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { path: actual } if *actual == path => {
                let mut remaining = remaining.lock();
                if *remaining > 0 {
                    *remaining -= 1;
                    Some(io::Error::from_raw_os_error(libc::EIO))
                } else {
                    None
                }
            }
            _ => None,
        })));
    }

    fn read_original(&self, backing: &RollbackBacking) {
        let file = backing.open("payload", false).unwrap();
        let mut bytes = vec![0; self.original.len()];
        file.read_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, self.original);
    }

    fn acknowledge_later_write(&self, backing: &RollbackBacking) {
        self.read_original(backing);
        let file = backing.open("payload", false).unwrap();
        file.write_at(2 * PAGE, b"later acknowledged bytes")
            .unwrap();
        file.sync_data().unwrap();
    }

    fn verify_after_crash(&self, later_write: bool) {
        let backing = self
            .open()
            .expect("a ready COW session must preserve its authenticated restore after power loss");
        self.read_original(&backing);
        if later_write {
            let file = backing.open("payload", false).unwrap();
            let mut bytes = [0; 24];
            file.read_at(2 * PAGE, &mut bytes).unwrap();
            assert_eq!(&bytes, b"later acknowledged bytes");
        }
    }
}

#[test]
fn restored_arena_failed_open_then_plain_restart_and_sync_survives_power_loss() {
    let restore = Restore::new(Some(ARENA), false);
    let anchor = std::fs::read(restore.witness.path().join("anchor")).unwrap();
    restore.fail_syncs(ARENA, 1);
    assert_eq!(
        restore.open().err().unwrap().raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(
        std::fs::read(restore.witness.path().join("anchor")).unwrap(),
        anchor,
        "a failed readiness barrier must never advance the witness"
    );
    // A plain restart retains readable pages the failed sync marked clean.
    let resumed = restore.open().unwrap();
    restore.acknowledge_later_write(&resumed);
    drop(resumed);
    restore.disk.crash_all_lost();
    restore.verify_after_crash(true);
}

#[test]
fn healthy_restore_and_later_sync_survive_power_loss() {
    let restore = Restore::new(Some(ARENA), false);
    let backing = restore.open().unwrap();
    restore.acknowledge_later_write(&backing);
    drop(backing);
    restore.disk.crash_all_lost();
    restore.verify_after_crash(true);
}

#[test]
fn caller_rewrite_after_failed_sync_is_a_durability_control() {
    let restore = Restore::new(Some(ARENA), false);
    restore.fail_syncs(ARENA, 1);
    assert!(restore.open().is_err());
    restore
        .disk
        .open(ARENA, false)
        .unwrap()
        .write_at(0, &restore.snapshots[ARENA])
        .unwrap();
    let backing = restore.open().unwrap();
    restore.acknowledge_later_write(&backing);
    drop(backing);
    restore.disk.crash_all_lost();
    restore.verify_after_crash(true);
}

#[test]
fn selected_manifest_and_its_length_survive_prior_failed_restore_writeback() {
    let restore = Restore::new(Some("selected"), true);
    restore.fail_syncs(&restore.selected, 1);
    assert_eq!(
        restore
            .disk
            .open(&restore.selected, false)
            .unwrap()
            .sync_data()
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EIO)
    );
    let backing = restore.open().unwrap();
    restore.read_original(&backing);
    drop(backing);
    restore.disk.crash_all_lost();
    restore.verify_after_crash(false);
}

#[test]
fn arena_length_survives_failed_restore_writeback_before_ready() {
    let restore = Restore::new(Some(ARENA), true);
    restore.fail_syncs(ARENA, 1);
    assert!(restore.open().is_err());
    let backing = restore.open().unwrap();
    restore.read_original(&backing);
    drop(backing);
    restore.disk.crash_all_lost();
    restore.verify_after_crash(false);
}

#[test]
fn format_marker_and_its_length_survive_prior_failed_restore_writeback() {
    let restore = Restore::new(Some(MARKER), true);
    restore.fail_syncs(MARKER, 1);
    assert_eq!(
        restore
            .disk
            .open(MARKER, false)
            .unwrap()
            .sync_data()
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EIO)
    );
    drop(restore.open().unwrap());
    restore.disk.crash_all_lost();
    restore.verify_after_crash(false);
}

#[test]
fn repeated_readiness_sync_failures_refuse_then_preserve_restored_pages() {
    let restore = Restore::new(Some(ARENA), true);
    restore.fail_syncs(ARENA, 3);
    for _ in 0..3 {
        assert_eq!(
            restore.open().err().unwrap().raw_os_error(),
            Some(libc::EIO)
        );
    }
    let backing = restore.open().unwrap();
    restore.acknowledge_later_write(&backing);
    drop(backing);
    restore.disk.crash_all_lost();
    restore.verify_after_crash(true);
}

#[test]
fn partial_restore_rewrite_is_retryable_without_advancing_the_witness() {
    let restore = Restore::new(Some(ARENA), false);
    let anchor = std::fs::read(restore.witness.path().join("anchor")).unwrap();
    let first = AtomicBool::new(true);
    restore
        .disk
        .set_partial_write_hook(Some(Arc::new(move |op| {
            if matches!(op, FaultOp::WriteAt { path: ARENA, .. })
                && first.swap(false, Ordering::SeqCst)
            {
                Some((128, io::Error::from_raw_os_error(libc::EIO)))
            } else {
                None
            }
        })));
    assert_eq!(
        restore.open().err().unwrap().raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(
        std::fs::read(restore.witness.path().join("anchor")).unwrap(),
        anchor
    );
    let backing = restore.open().unwrap();
    restore.acknowledge_later_write(&backing);
    drop(backing);
    restore.disk.crash_all_lost();
    restore.verify_after_crash(true);
}

#[test]
fn all_pages_are_authenticated_before_any_restore_mutation() {
    let restore = Restore::new(None, false);
    let backing = restore.open().unwrap();
    let page = backing
        .state
        .lock()
        .committed
        .files
        .values()
        .next()
        .unwrap()
        .pages[&1]
        .slot;
    drop(backing);
    restore
        .disk
        .open(ARENA, false)
        .unwrap()
        .write_at(page * PAGE, &[0x12])
        .unwrap();
    let mutations = Arc::new(AtomicUsize::new(0));
    let count = mutations.clone();
    restore.disk.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(
            op,
            FaultOp::WriteAt { .. }
                | FaultOp::SetLen { .. }
                | FaultOp::SyncData { .. }
                | FaultOp::SyncDir { .. }
        ) {
            count.fetch_add(1, Ordering::SeqCst);
        }
        None
    })));
    assert_eq!(
        restore.open().err().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
}

#[test]
fn acknowledged_restore_survives_deterministic_torn_write_crash_sweep() {
    for seed in 0..8 {
        let restore = Restore::new(Some(ARENA), true);
        restore.fail_syncs(ARENA, 1);
        assert!(restore.open().is_err());
        let backing = restore.open().unwrap();
        restore.acknowledge_later_write(&backing);
        drop(backing);
        restore.disk.crash(&mut StdRng::seed_from_u64(seed));
        restore.verify_after_crash(true);
    }
}
