#![cfg(target_os = "linux")]
use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, RollbackBacking};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};

type PausedReply = (bool, Arc<Barrier>, Arc<Barrier>);

struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
    lose_advance_reply: AtomicBool,
    unavailable: AtomicBool,
    lose_transition: Mutex<Option<&'static str>>,
    lose_all_advance_replies: AtomicBool,
    pause: Mutex<Option<PausedReply>>,
}
impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(io::Error::other("unavailable"));
        }
        let result = self.store.lock().unwrap().handle(self.role, request)?;
        let pause = {
            let mut slot = self.pause.lock().unwrap();
            if slot.as_ref().is_some_and(|(advance, _, _)| {
                *advance == matches!(request.action, Action::Advance { .. })
                    && (*advance || matches!(request.action, Action::Inspect))
            }) {
                slot.take()
            } else {
                None
            }
        };
        if let Some((_, entered, resume)) = pause {
            entered.wait();
            resume.wait();
        }
        let name = match request.action {
            Action::Claim => "claim",
            Action::Activate { .. } => "activate",
            Action::Release => "release",
            _ => "other",
        };
        let lose = {
            let mut slot = self.lose_transition.lock().unwrap();
            if *slot == Some(name) {
                *slot = None;
                true
            } else {
                false
            }
        };
        if lose
            || (matches!(request.action, Action::Advance { .. })
                && (self.lose_all_advance_replies.load(Ordering::SeqCst)
                    || self.lose_advance_reply.swap(false, Ordering::SeqCst)))
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "reply lost after durable commit",
            ));
        }
        Ok(result)
    }
}
fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })
    .unwrap()
}
struct Fixture {
    root: tempfile::TempDir,
    _witness: tempfile::TempDir,
    writer: Arc<LocalRpc>,
    admin: Arc<LocalRpc>,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let witness = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            StateStore::create(witness.path(), [1; 16]).unwrap(),
        ));
        let rpc = |role| {
            Arc::new(LocalRpc {
                store: store.clone(),
                role,
                lose_advance_reply: AtomicBool::new(false),
                unavailable: AtomicBool::new(false),
                pause: Mutex::new(None),
                lose_transition: Mutex::new(None),
                lose_all_advance_replies: AtomicBool::new(false),
            })
        };
        Self {
            root,
            _witness: witness,
            writer: rpc(Role::Writer),
            admin: rpc(Role::Admin),
        }
    }
    fn create(&self) -> RollbackBacking {
        RollbackBacking::create_remote(self.root.path(), self.writer.clone(), 32 * 4096).unwrap()
    }
}
fn write(backing: &RollbackBacking, data: &[u8]) {
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, data).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
}
fn read(backing: &RollbackBacking) -> Vec<u8> {
    let file = backing.open("payload", false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

#[test]
fn normal_reattach_releases_session_but_refuses_active_writer() {
    let f = Fixture::new();
    let b = f.create();
    write(&b, b"durable");
    assert!(RollbackBacking::open_remote(f.root.path(), f.writer.clone()).is_err());
    assert_eq!(read(&b), b"durable");
    let first = inspect(f.writer.as_ref());
    drop(b);
    let b = RollbackBacking::open_remote(f.root.path(), f.writer.clone()).unwrap();
    assert_eq!(read(&b), b"durable");
    let next = inspect(f.writer.as_ref());
    assert!(next.fence > first.fence);
    assert_ne!(
        next.current.unwrap().namespace,
        first.current.unwrap().namespace
    );
}

#[test]
fn takeover_fences_old_handles_and_never_reuses_their_arena() {
    let f = Fixture::new();
    let old = f.create();
    write(&old, b"confirmed");
    let old_file = old.open("payload", false).unwrap();
    let expected = inspect(f.admin.as_ref());
    assert!(RollbackBacking::takeover_remote(f.root.path(), f.writer.clone(), &expected).is_err());
    let new = RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &expected).unwrap();
    assert_eq!(read(&new), b"confirmed");
    assert!(old_file.write_at(0, b"stale!!!!").is_err());
    assert!(old.check_freshness().is_err());
    assert!(old_file.sync_data().is_err());
    write(&new, b"new root!");
    drop(old_file);
    drop(old);
    assert_eq!(read(&new), b"new root!");
}

#[test]
fn lost_commit_reply_retries_the_identical_operation_without_losing_data() {
    let f = Fixture::new();
    let b = f.create();
    write(&b, b"before");
    let file = b.open("payload", false).unwrap();
    file.write_at(0, b"after!").unwrap();
    let before = inspect(f.writer.as_ref())
        .current
        .unwrap()
        .anchor
        .generation;
    f.writer.lose_advance_reply.store(true, Ordering::SeqCst);
    file.sync_data().unwrap();
    assert_eq!(
        inspect(f.writer.as_ref())
            .current
            .unwrap()
            .anchor
            .generation,
        before + 1
    );
    drop(file);
    drop(b);
    let b = RollbackBacking::open_remote(f.root.path(), f.writer.clone()).unwrap();
    assert_eq!(read(&b), b"after!");
}

#[test]
fn unavailable_witness_stops_existing_handles_and_never_falls_back() {
    let f = Fixture::new();
    let b = f.create();
    write(&b, b"confirmed");
    let file = b.open("payload", false).unwrap();
    f.writer.unavailable.store(true, Ordering::SeqCst);
    assert!(file.read_at(0, &mut [0; 9]).is_err());
    f.writer.unavailable.store(false, Ordering::SeqCst);
    assert!(b.check_freshness().is_err());
}

#[test]
fn explicit_restore_increments_epoch_and_generation_while_restoring_snapshot_data() {
    let f = Fixture::new();
    let old = f.create();
    write(&old, b"snapshot");
    let snapshot = tempfile::tempdir().unwrap();
    let source = old.snapshot_remote(snapshot.path()).unwrap();
    write(&old, b"latest!!");
    let expected = inspect(f.admin.as_ref());
    assert!(RollbackBacking::restore_remote(
        f.root.path(),
        snapshot.path(),
        &source,
        f.writer.clone(),
        &expected
    )
    .is_err());
    let restored = RollbackBacking::restore_remote(
        f.root.path(),
        snapshot.path(),
        &source,
        f.admin.clone(),
        &expected,
    )
    .unwrap();
    assert_eq!(read(&restored), b"snapshot");
    assert!(old.check_freshness().is_err());
    let current = inspect(f.admin.as_ref()).current.unwrap();
    let previous = expected.current.as_ref().unwrap();
    assert_eq!(current.epoch, previous.epoch + 1);
    assert_eq!(current.anchor.generation, previous.anchor.generation + 1);
    assert_eq!(current.anchor.identity, previous.anchor.identity);
    assert!(RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &expected).is_err());
}

#[test]
fn corrupted_snapshot_cannot_advance_the_committed_root() {
    use std::os::unix::fs::FileExt;
    let f = Fixture::new();
    let b = f.create();
    write(&b, b"snapshot");
    let snapshot = tempfile::tempdir().unwrap();
    let source = b.snapshot_remote(snapshot.path()).unwrap();
    write(&b, b"latest!!");
    let expected = inspect(f.admin.as_ref());
    let arena = std::fs::OpenOptions::new()
        .write(true)
        .open(
            snapshot
                .path()
                .join(&source.namespace)
                .join("rollback.arena"),
        )
        .unwrap();
    let size = arena.metadata().unwrap().len();
    arena.write_all_at(&vec![0x7f; size as usize], 0).unwrap();
    arena.sync_all().unwrap();
    assert!(RollbackBacking::restore_remote(
        f.root.path(),
        snapshot.path(),
        &source,
        f.admin.clone(),
        &expected
    )
    .is_err());
    assert_eq!(inspect(f.admin.as_ref()).current, expected.current);
}

#[test]
fn old_write_paused_after_freshness_check_cannot_overwrite_takeover_root() {
    let f = Fixture::new();
    let old = f.create();
    write(&old, b"committed");
    let file = old.open("payload", false).unwrap();
    let expected = inspect(f.admin.as_ref());
    let entered = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    *f.writer.pause.lock().unwrap() = Some((false, entered.clone(), resume.clone()));
    let worker = std::thread::spawn(move || {
        file.write_at(0, b"stale!!!!").unwrap();
        file
    });
    entered.wait();
    let new = RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &expected).unwrap();
    resume.wait();
    let old_file = worker.join().unwrap();
    assert!(old_file.sync_data().is_err());
    assert_eq!(read(&new), b"committed");
    write(&new, b"new root!");
    drop(old_file);
    drop(old);
    assert_eq!(read(&new), b"new root!");
}

#[test]
fn takeover_includes_commit_whose_success_reply_is_still_in_flight() {
    let f = Fixture::new();
    let old = f.create();
    write(&old, b"before!!!");
    let file = old.open("payload", false).unwrap();
    file.write_at(0, b"committed").unwrap();
    let entered = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    *f.writer.pause.lock().unwrap() = Some((true, entered.clone(), resume.clone()));
    let worker = std::thread::spawn(move || {
        file.sync_data().unwrap();
        file
    });
    entered.wait();
    let expected = inspect(f.admin.as_ref());
    let new = RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &expected).unwrap();
    resume.wait();
    let old_file = worker.join().unwrap();
    assert_eq!(read(&new), b"committed");
    assert!(old_file.write_at(0, b"stale!!!!").is_err());
}

#[test]
fn failed_fork_keeps_authoritative_root_and_requires_explicit_retry() {
    let f = Fixture::new();
    let old = f.create();
    write(&old, b"confirmed");
    let expected = inspect(f.admin.as_ref());
    let source = f
        .root
        .path()
        .join(&expected.current.as_ref().unwrap().namespace)
        .join("rollback.arena");
    let displaced = source.with_extension("saved");
    std::fs::rename(&source, &displaced).unwrap();
    assert!(RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &expected).is_err());
    let pending = inspect(f.admin.as_ref());
    assert_eq!(pending.current, expected.current);
    std::fs::rename(&displaced, &source).unwrap();
    assert!(RollbackBacking::open_remote(f.root.path(), f.writer.clone()).is_err());
    let retry = RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &pending).unwrap();
    assert_eq!(read(&retry), b"confirmed");
}

#[test]
fn seeded_writes_truncation_and_takeovers_preserve_the_file_oracle() {
    let f = Fixture::new();
    let mut backing = f.create();
    write(&backing, &vec![0; 16384]);
    let mut oracle = vec![0; 16384];
    let mut seed = 0x983fe31u64;
    for step in 0..100 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let file = backing.open("payload", false).unwrap();
        let offset = (seed as usize) % 16000;
        let payload = [(seed >> 32) as u8; 127];
        file.write_at(offset as u64, &payload).unwrap();
        oracle.resize(oracle.len().max(offset + 127), 0);
        oracle[offset..offset + 127].copy_from_slice(&payload);
        if step % 7 == 0 {
            let len = 8192 + (seed as usize % 8193);
            file.set_len(len as u64).unwrap();
            oracle.resize(len, 0);
        }
        file.sync_data().unwrap();
        drop(file);
        assert_eq!(read(&backing), oracle, "step {step}");
        if step % 20 == 19 {
            let expected = inspect(f.admin.as_ref());
            let next = RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &expected)
                .unwrap();
            assert!(backing.check_freshness().is_err());
            backing = next;
        }
    }
    assert_eq!(read(&backing), oracle);
}

#[test]
fn lost_claim_activation_and_release_replies_are_idempotent() {
    for action in ["claim", "activate", "release"] {
        let f = Fixture::new();
        *f.writer.lose_transition.lock().unwrap() = Some(action);
        let b = f.create();
        write(&b, b"confirmed");
        drop(b);
        let b = RollbackBacking::open_remote(f.root.path(), f.writer.clone()).unwrap();
        assert_eq!(read(&b), b"confirmed");
    }
}

#[test]
fn unresolved_commit_reply_poison_preserves_remote_committed_generation() {
    let f = Fixture::new();
    let old = f.create();
    write(&old, b"before!!!");
    let file = old.open("payload", false).unwrap();
    file.write_at(0, b"committed").unwrap();
    f.writer
        .lose_all_advance_replies
        .store(true, Ordering::SeqCst);
    assert!(file.sync_data().is_err());
    f.writer
        .lose_all_advance_replies
        .store(false, Ordering::SeqCst);
    assert!(old.check_freshness().is_err());
    let expected = inspect(f.admin.as_ref());
    let new = RollbackBacking::takeover_remote(f.root.path(), f.admin.clone(), &expected).unwrap();
    drop(file);
    drop(old);
    assert_eq!(read(&new), b"committed");
    new.check_freshness().unwrap();
}
