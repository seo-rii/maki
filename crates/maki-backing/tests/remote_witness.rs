use std::io;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{
    namespace, Action, Descriptor, Phase, Record, Request, Role, StateStore,
};
use maki_backing::witness::Anchor;
use maki_backing::{Backing, BackingFile, FileBacking, VolumeLock};
use tempfile::tempdir;

const ID: [u8; 16] = [1; 16];
// Process spawning momentarily inherits every thread's open flock descriptor
// until exec closes CLOEXEC fds. Serialize fixtures around that global fork
// boundary so another test's immediate drop/reopen cannot see a child-held fd.
// The dedicated CAS test still runs all 16 contender threads concurrently.
static PROCESS_FIXTURES: Mutex<()> = Mutex::new(());
fn op(n: u8, current: &Record, action: Action) -> Request {
    Request {
        operation_id: [n; 16],
        expected: Some(current.clone()),
        action,
    }
}
fn inspect(store: &mut StateStore) -> Record {
    store
        .handle(
            Role::Writer,
            &Request {
                operation_id: [0; 16],
                expected: None,
                action: Action::Inspect,
            },
        )
        .unwrap()
}
fn claim(store: &mut StateStore, n: u8) -> Record {
    let old = inspect(store);
    store
        .handle(Role::Writer, &op(n, &old, Action::Claim))
        .unwrap()
}
fn activate(store: &mut StateStore, n: u8, claimed: &Record) -> Record {
    let old = claimed.current.as_ref();
    let descriptor = Descriptor {
        anchor: old.map(|d| d.anchor.clone()).unwrap_or(Anchor {
            identity: ID,
            generation: 0,
            root: [3; 32],
        }),
        epoch: old.map(|d| d.epoch).unwrap_or(0),
        namespace: namespace(claimed.fence, claimed.session),
    };
    store
        .handle(
            Role::Writer,
            &op(n, claimed, Action::Activate { descriptor }),
        )
        .unwrap()
}
fn active(store: &mut StateStore) -> Record {
    let claimed = claim(store, 1);
    activate(store, 2, &claimed)
}

#[test]
fn explicit_enrollment_and_missing_state_fail_closed() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    assert!(StateStore::open(dir.path()).is_err());
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let current = inspect(&mut store);
    assert_eq!(current.identity, ID);
    assert_eq!(current.phase, Phase::Released);
    assert!(current.current.is_none());
    drop(store);
    assert!(StateStore::create(dir.path(), ID).is_err());
    assert!(StateStore::create(&dir.path().join("nil"), [0; 16]).is_err());
    assert_eq!(inspect(&mut StateStore::open(dir.path()).unwrap()), current);
}

#[test]
fn claim_activate_advance_release_reopen_preserves_freshness() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let current = active(&mut store);
    assert_eq!(current.fence, 1);
    let advance = op(
        3,
        &current,
        Action::Advance {
            anchor: Anchor {
                identity: ID,
                generation: 1,
                root: [4; 32],
            },
        },
    );
    let newer = store.handle(Role::Writer, &advance).unwrap();
    let released = store
        .handle(Role::Writer, &op(4, &newer, Action::Release))
        .unwrap();
    drop(store);
    let mut store = StateStore::open(dir.path()).unwrap();
    assert_eq!(inspect(&mut store), released);
    let claimed = claim(&mut store, 5);
    assert_eq!(claimed.fence, 2);
    let reopened = activate(&mut store, 6, &claimed);
    assert_ne!(
        reopened.current.as_ref().unwrap().namespace,
        current.current.as_ref().unwrap().namespace
    );
    assert_eq!(
        reopened.current.unwrap().anchor,
        newer.current.unwrap().anchor
    );
}

#[test]
fn active_writer_blocks_normal_claim_and_all_stale_mutations() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let old = active(&mut store);
    assert!(store
        .handle(Role::Writer, &op(3, &old, Action::Claim))
        .is_err());
    assert!(store
        .handle(Role::Writer, &op(3, &old, Action::Takeover))
        .is_err());
    let claimed = store
        .handle(Role::Admin, &op(3, &old, Action::Takeover))
        .unwrap();
    let new = activate(&mut store, 4, &claimed);
    for action in [
        Action::Release,
        Action::Advance {
            anchor: Anchor {
                identity: ID,
                generation: 1,
                root: [5; 32],
            },
        },
        Action::Takeover,
    ] {
        assert!(store.handle(Role::Admin, &op(5, &old, action)).is_err());
        assert_eq!(inspect(&mut store), new);
    }
}

#[test]
fn lost_response_exact_retry_survives_restart_but_operation_id_reuse_fails() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let prior = inspect(&mut store);
    let request = op(1, &prior, Action::Claim);
    let result = store.handle(Role::Writer, &request).unwrap();
    assert_eq!(store.handle(Role::Writer, &request).unwrap(), result);
    drop(store);
    let mut store = StateStore::open(dir.path()).unwrap();
    assert_eq!(store.handle(Role::Writer, &request).unwrap(), result);
    let changed = op(1, &result, Action::Release);
    assert!(store.handle(Role::Writer, &changed).is_err());
    assert_eq!(inspect(&mut store), result);
}

#[test]
fn restore_requires_admin_and_advances_epoch_and_current_generation() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let first = active(&mut store);
    let source = first.current.clone().unwrap();
    let current = store
        .handle(
            Role::Writer,
            &op(
                3,
                &first,
                Action::Advance {
                    anchor: Anchor {
                        identity: ID,
                        generation: 1,
                        root: [4; 32],
                    },
                },
            ),
        )
        .unwrap();
    let request = op(
        4,
        &current,
        Action::ClaimRestore {
            source: source.clone(),
        },
    );
    assert!(store.handle(Role::Writer, &request).is_err());
    let claimed = store.handle(Role::Admin, &request).unwrap();
    assert_eq!(claimed.restore_source, Some(source));
    assert_eq!(claimed.current, current.current);
    let descriptor = Descriptor {
        anchor: Anchor {
            identity: ID,
            generation: 2,
            root: [7; 32],
        },
        epoch: 1,
        namespace: namespace(claimed.fence, claimed.session),
    };
    let request = op(5, &claimed, Action::Activate { descriptor });
    assert!(store.handle(Role::Writer, &request).is_err());
    let restored = store.handle(Role::Admin, &request).unwrap();
    assert_eq!(restored.current.as_ref().unwrap().epoch, 1);
    assert_eq!(restored.current.as_ref().unwrap().anchor.generation, 2);
    // Role checks precede successful-operation replay too.
    assert!(store.handle(Role::Writer, &request).is_err());
    assert!(store
        .handle(Role::Admin, &op(6, &current, Action::Release))
        .is_err());
    assert_eq!(inspect(&mut store), restored);
}

#[test]
fn restore_wrong_identity_future_source_and_unclaimed_activation_rejected() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let current = active(&mut store);
    for field in 0..3 {
        let mut source = current.current.clone().unwrap();
        match field {
            0 => source.anchor.identity = [8; 16],
            1 => source.anchor.generation += 1,
            _ => source.epoch += 1,
        }
        assert!(store
            .handle(
                Role::Admin,
                &op(3, &current, Action::ClaimRestore { source })
            )
            .is_err());
    }
    assert!(store
        .handle(
            Role::Admin,
            &op(
                3,
                &current,
                Action::Activate {
                    descriptor: current.current.clone().unwrap()
                }
            )
        )
        .is_err());
    assert_eq!(inspect(&mut store), current);
}

#[test]
fn activation_cannot_reuse_namespace_or_change_anchor_on_normal_claim() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let initial = active(&mut store);
    let claimed = store
        .handle(Role::Admin, &op(3, &initial, Action::Takeover))
        .unwrap();
    for field in 0..5 {
        let mut descriptor = initial.current.clone().unwrap();
        descriptor.namespace = namespace(claimed.fence, claimed.session);
        match field {
            0 => descriptor.namespace = initial.current.as_ref().unwrap().namespace.clone(),
            1 => descriptor.anchor.root = [9; 32],
            2 => descriptor.anchor.generation += 1,
            3 => descriptor.epoch += 1,
            _ => descriptor.anchor.identity = [9; 16],
        }
        assert!(store
            .handle(
                Role::Writer,
                &op(4, &claimed, Action::Activate { descriptor })
            )
            .is_err());
        assert_eq!(inspect(&mut store), claimed);
    }
}

#[test]
fn mutation_requires_nonzero_id_and_exact_full_expected_record() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let current = inspect(&mut store);
    for request in [
        Request {
            operation_id: [1; 16],
            expected: None,
            action: Action::Claim,
        },
        op(0, &current, Action::Claim),
    ] {
        assert!(store.handle(Role::Writer, &request).is_err());
    }
    let mut request = op(1, &current, Action::Claim);
    request.expected.as_mut().unwrap().last_operation = [2; 16];
    assert!(store.handle(Role::Writer, &request).is_err());
    assert_eq!(inspect(&mut store), current);
}

#[test]
fn corrupt_truncated_and_noncanonical_store_are_rejected() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    for damage in 0..3 {
        let dir = tempdir().unwrap();
        drop(StateStore::create(dir.path(), ID).unwrap());
        let path = dir.path().join("remote.state");
        let mut bytes = std::fs::read(&path).unwrap();
        match damage {
            0 => bytes[0] ^= 1,
            1 => {
                bytes.pop();
            }
            _ => bytes.extend_from_slice(b" "),
        }
        std::fs::write(path, bytes).unwrap();
        assert!(StateStore::open(dir.path()).is_err());
    }
}

#[test]
fn external_state_change_permanently_poisons_open_handle() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let path = dir.path().join("remote.state");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"corrupt").unwrap();
    let request = Request {
        operation_id: [0; 16],
        expected: None,
        action: Action::Inspect,
    };
    assert!(store.handle(Role::Writer, &request).is_err());
    std::fs::write(path, bytes).unwrap();
    assert!(store.handle(Role::Writer, &request).is_err());
}

#[test]
fn independent_service_processes_cannot_share_one_authority_lock() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let store = StateStore::create(dir.path(), ID).unwrap();
    assert_eq!(
        StateStore::open(dir.path()).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(store);
    assert!(StateStore::open(dir.path()).is_ok());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    TempWrite,
    TempSync,
    Rename,
    DirectorySync,
}
struct FaultBacking {
    inner: FileBacking,
    fault: Arc<Mutex<Option<Fault>>>,
}
struct FaultFile {
    inner: Arc<dyn BackingFile>,
    fault: Arc<Mutex<Option<Fault>>>,
    temporary: bool,
}
fn fail(fault: &Mutex<Option<Fault>>, point: Fault) -> io::Result<()> {
    let mut slot = fault.lock().unwrap();
    if *slot == Some(point) {
        *slot = None;
        Err(io::Error::other("injected witness persistence failure"))
    } else {
        Ok(())
    }
}
impl BackingFile for FaultFile {
    fn read_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(o, b)
    }
    fn write_at(&self, o: u64, b: &[u8]) -> io::Result<()> {
        if self.temporary {
            fail(&self.fault, Fault::TempWrite)?;
        }
        self.inner.write_at(o, b)
    }
    fn set_len(&self, n: u64) -> io::Result<()> {
        self.inner.set_len(n)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        if self.temporary {
            fail(&self.fault, Fault::TempSync)?;
        }
        self.inner.sync_data()
    }
}
impl Backing for FaultBacking {
    fn open(&self, p: &str, c: bool) -> io::Result<Arc<dyn BackingFile>> {
        Ok(Arc::new(FaultFile {
            inner: self.inner.open(p, c)?,
            fault: self.fault.clone(),
            temporary: p == "remote.next",
        }))
    }
    fn exists(&self, p: &str) -> io::Result<bool> {
        self.inner.exists(p)
    }
    fn remove(&self, p: &str) -> io::Result<()> {
        self.inner.remove(p)
    }
    fn rename(&self, a: &str, b: &str) -> io::Result<()> {
        fail(&self.fault, Fault::Rename)?;
        self.inner.rename(a, b)
    }
    fn create_dir_all(&self, p: &str) -> io::Result<()> {
        self.inner.create_dir_all(p)
    }
    fn list(&self, p: &str) -> io::Result<Vec<String>> {
        self.inner.list(p)
    }
    fn sync_dir(&self, p: &str) -> io::Result<()> {
        fail(&self.fault, Fault::DirectorySync)?;
        self.inner.sync_dir(p)
    }
    fn try_lock(&self, p: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(p)
    }
}

#[test]
fn every_publication_failure_poisons_and_reopen_resolves_exact_old_or_new() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    for point in [
        Fault::TempWrite,
        Fault::TempSync,
        Fault::Rename,
        Fault::DirectorySync,
    ] {
        let dir = tempdir().unwrap();
        drop(StateStore::create(dir.path(), ID).unwrap());
        let backing = Arc::new(FaultBacking {
            inner: FileBacking::new(dir.path()).unwrap(),
            fault: Arc::new(Mutex::new(None)),
        });
        let mut store = StateStore::open_backing(backing.clone()).unwrap();
        let before = inspect(&mut store);
        let request = op(1, &before, Action::Claim);
        *backing.fault.lock().unwrap() = Some(point);
        assert!(store.handle(Role::Writer, &request).is_err(), "{point:?}");
        assert!(store
            .handle(
                Role::Writer,
                &Request {
                    operation_id: [0; 16],
                    expected: None,
                    action: Action::Inspect
                }
            )
            .is_err());
        drop(store);
        let mut reopened = StateStore::open(dir.path()).unwrap();
        let observed = inspect(&mut reopened);
        assert!(
            observed == before
                || (observed.phase == Phase::Claimed && observed.last_operation == [1; 16])
        );
        let resolved = reopened.handle(Role::Writer, &request).unwrap();
        assert_eq!(resolved.phase, Phase::Claimed);
        assert_eq!(resolved.fence, 1);
    }
}

#[test]
fn reopen_must_republish_before_serving_any_response() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    for point in [
        Fault::TempWrite,
        Fault::TempSync,
        Fault::Rename,
        Fault::DirectorySync,
    ] {
        let dir = tempdir().unwrap();
        drop(StateStore::create(dir.path(), ID).unwrap());
        let backing = Arc::new(FaultBacking {
            inner: FileBacking::new(dir.path()).unwrap(),
            fault: Arc::new(Mutex::new(Some(point))),
        });
        assert!(StateStore::open_backing(backing).is_err(), "{point:?}");
    }
}

#[test]
fn concurrent_full_record_claims_have_exactly_one_winner() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let current = inspect(&mut store);
    let store = Arc::new(Mutex::new(store));
    let barrier = Arc::new(std::sync::Barrier::new(16));
    let joins: Vec<_> = (1..=16)
        .map(|n| {
            let store = store.clone();
            let barrier = barrier.clone();
            let current = current.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .lock()
                    .unwrap()
                    .handle(Role::Writer, &op(n, &current, Action::Claim))
            })
        })
        .collect();
    let outcomes: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(inspect(&mut store.lock().unwrap()).fence, 1);
}

#[test]
fn child_process_lock_probe() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let Some(path) = std::env::var_os("MAKI_REMOTE_WITNESS_TEST_LOCK_PATH") else {
        return;
    };
    assert_eq!(
        StateStore::open(std::path::Path::new(&path))
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn stable_file_lock_excludes_a_separate_process() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let _store = StateStore::create(dir.path(), ID).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_process_lock_probe"])
        .env("MAKI_REMOTE_WITNESS_TEST_LOCK_PATH", dir.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
}

#[test]
fn deterministic_sequence_preserves_monotone_fences_generations_and_stale_rejection() {
    let _fixture_guard = PROCESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let mut current = active(&mut store);
    let mut generation = 0;
    let mut fence = 1;
    let mut epoch = 0;
    let mut history = vec![current.clone()];
    let mut seed = 0x7654_3210_fedc_ba98u64;
    for index in 3u64..303 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mut id = [0; 16];
        id[..8].copy_from_slice(&index.to_le_bytes());
        id[8..].copy_from_slice(&seed.to_le_bytes());
        let action = if current.phase == Phase::Active {
            match seed % 4 {
                0 => Action::Release,
                1 => Action::Takeover,
                2 => Action::ClaimRestore {
                    source: history[(seed as usize) % history.len()]
                        .current
                        .clone()
                        .unwrap(),
                },
                _ => Action::Advance {
                    anchor: Anchor {
                        identity: ID,
                        generation: generation + 1,
                        root: [(seed & 255) as u8; 32],
                    },
                },
            }
        } else if current.phase == Phase::Released {
            Action::Claim
        } else {
            let mut descriptor = current.current.clone().unwrap();
            descriptor.namespace = namespace(current.fence, current.session);
            if current.phase == Phase::RestoreClaimed {
                descriptor.epoch += 1;
                descriptor.anchor.generation += 1;
                descriptor.anchor.root = [index as u8; 32];
            }
            Action::Activate { descriptor }
        };
        match &action {
            Action::Claim | Action::Takeover | Action::ClaimRestore { .. } => fence += 1,
            Action::Advance { .. } => generation += 1,
            Action::Activate { .. } if current.phase == Phase::RestoreClaimed => {
                generation += 1;
                epoch += 1;
            }
            _ => {}
        }
        let request = Request {
            operation_id: id,
            expected: Some(current.clone()),
            action,
        };
        current = store.handle(Role::Admin, &request).unwrap();
        assert_eq!(store.handle(Role::Admin, &request).unwrap(), current);
        assert_eq!(current.fence, fence);
        assert_eq!(
            current.current.as_ref().unwrap().anchor.generation,
            generation
        );
        assert_eq!(current.current.as_ref().unwrap().epoch, epoch);
        if current.phase == Phase::Active {
            history.push(current.clone());
        }
        let stale = &history[0];
        assert!(store
            .handle(Role::Admin, &op(255, stale, Action::Release))
            .is_err());
        if index % 31 == 0 {
            drop(store);
            store = StateStore::open(dir.path()).unwrap();
            assert_eq!(inspect(&mut store), current);
        }
    }
}
