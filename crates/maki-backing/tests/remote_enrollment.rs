use maki_backing::remote_witness::{
    namespace, Action, CanonicalState, Descriptor, Phase, Record, Request, Role, StateStore,
};
use maki_backing::witness::Anchor;
use tempfile::tempdir;

const ID: [u8; 16] = [11; 16];
fn request(n: u8, expected: &Record, action: Action) -> Request {
    Request {
        operation_id: [n; 16],
        expected: Some(expected.clone()),
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
fn recover_action() -> Action {
    serde_json::from_str(r#"{"type":"recover_enrollment"}"#)
        .expect("explicit enrollment recovery action must exist")
}
fn activate(store: &mut StateStore, claimed: &Record, n: u8) -> Record {
    let descriptor = Descriptor {
        anchor: Anchor {
            identity: ID,
            generation: 0,
            root: [17; 32],
        },
        epoch: 0,
        namespace: namespace(claimed.fence, claimed.session),
    };
    store
        .handle(
            Role::Admin,
            &request(n, claimed, Action::Activate { descriptor }),
        )
        .unwrap()
}

#[test]
fn interrupted_claim_requires_admin_and_fences_every_old_candidate() {
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let initial = inspect(&mut store);
    let first = store
        .handle(Role::Writer, &request(1, &initial, Action::Claim))
        .unwrap();
    let recovery = request(2, &first, recover_action());
    assert_eq!(
        store.handle(Role::Writer, &recovery).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(inspect(&mut store), first);
    let recovered = store.handle(Role::Admin, &recovery).unwrap();
    assert_eq!(recovered.identity, ID);
    assert_eq!(recovered.phase, Phase::Claimed);
    assert_eq!(recovered.fence, first.fence + 1);
    assert!(recovered.current.is_none());
    assert_ne!(recovered.session, first.session);
    let old_descriptor = Descriptor {
        anchor: Anchor {
            identity: ID,
            generation: 0,
            root: [17; 32],
        },
        epoch: 0,
        namespace: namespace(first.fence, first.session),
    };
    assert!(store
        .handle(
            Role::Writer,
            &request(
                3,
                &first,
                Action::Activate {
                    descriptor: old_descriptor
                }
            )
        )
        .is_err());
    assert!(store
        .handle(Role::Writer, &request(4, &first, Action::Release))
        .is_err());
    assert_eq!(inspect(&mut store), recovered);
    let active = activate(&mut store, &recovered, 5);
    assert_eq!(active.current.unwrap().anchor.identity, ID);
}

#[test]
fn enrollment_recovery_lost_reply_replays_once_across_restart() {
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let initial = inspect(&mut store);
    let claimed = store
        .handle(Role::Writer, &request(1, &initial, Action::Claim))
        .unwrap();
    let recovery = request(2, &claimed, recover_action());
    let accepted = store.handle(Role::Admin, &recovery).unwrap();
    assert_eq!(store.handle(Role::Admin, &recovery).unwrap(), accepted);
    drop(store);
    let mut store = StateStore::open(dir.path()).unwrap();
    assert_eq!(store.handle(Role::Admin, &recovery).unwrap(), accepted);
    assert!(store.handle(Role::Writer, &recovery).is_err());
    assert!(store
        .handle(Role::Admin, &request(2, &accepted, Action::Release))
        .is_err());
    assert_eq!(inspect(&mut store), accepted);
}

#[test]
fn activation_reply_uncertainty_can_never_reset_initialized_volume() {
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let initial = inspect(&mut store);
    let claimed = store
        .handle(Role::Writer, &request(1, &initial, Action::Claim))
        .unwrap();
    let active = activate(&mut store, &claimed, 2);
    assert!(store
        .handle(Role::Admin, &request(3, &active, recover_action()))
        .is_err());
    assert!(store
        .handle(Role::Admin, &request(4, &claimed, recover_action()))
        .is_err());
    assert_eq!(inspect(&mut store), active);
    let released = store
        .handle(Role::Writer, &request(5, &active, Action::Release))
        .unwrap();
    assert!(store
        .handle(Role::Admin, &request(6, &released, recover_action()))
        .is_err());
    let takeover = store
        .handle(Role::Admin, &request(7, &released, Action::Takeover))
        .unwrap();
    assert!(store
        .handle(Role::Admin, &request(8, &takeover, recover_action()))
        .is_err());
    assert_eq!(inspect(&mut store).current, active.current);
}

#[test]
fn marker_only_interruption_can_be_explicitly_recovered_before_first_claim() {
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let initial = inspect(&mut store);
    let recovered = store
        .handle(Role::Admin, &request(1, &initial, recover_action()))
        .unwrap();
    assert_eq!(recovered.fence, 1);
    assert_eq!(recovered.phase, Phase::Claimed);
    assert!(recovered.current.is_none());
    assert!(store
        .handle(Role::Writer, &request(2, &recovered, Action::Claim))
        .is_err());
}

#[test]
fn uninitialized_takeover_must_use_explicit_recovery_action() {
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let initial = inspect(&mut store);
    assert!(store
        .handle(Role::Admin, &request(1, &initial, Action::Takeover))
        .is_err());
    assert_eq!(inspect(&mut store), initial);
}

#[test]
fn stale_or_foreign_enrollment_recovery_expected_record_never_mutates_authority() {
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let initial = inspect(&mut store);
    let claimed = store
        .handle(Role::Writer, &request(1, &initial, Action::Claim))
        .unwrap();
    assert!(store
        .handle(Role::Admin, &request(2, &initial, recover_action()))
        .is_err());
    let mut foreign = claimed.clone();
    foreign.identity = [12; 16];
    assert!(store
        .handle(Role::Admin, &request(3, &foreign, recover_action()))
        .is_err());
    assert_eq!(inspect(&mut store), claimed);
}

#[test]
fn repeated_enrollment_interruption_keeps_monotonic_fence_without_replacing_identity() {
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let mut record = inspect(&mut store);
    for n in 1..=100 {
        let request = request(n, &record, recover_action());
        record = store.handle(Role::Admin, &request).unwrap();
        assert_eq!(record.identity, ID);
        assert_eq!(record.fence, u64::from(n));
        assert!(record.current.is_none());
        assert_eq!(store.handle(Role::Admin, &request).unwrap(), record);
        if n % 10 == 0 {
            drop(store);
            store = StateStore::open(dir.path()).unwrap();
            assert_eq!(inspect(&mut store), record);
        }
    }
    assert_eq!(
        activate(&mut store, &record, 101)
            .current
            .unwrap()
            .anchor
            .generation,
        0
    );
}

#[test]
fn canonical_machine_and_file_authority_match_bytes_and_failures_through_all_phases() {
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let mut machine = CanonicalState::initial(ID).unwrap();
    assert_eq!(
        machine.encode().unwrap(),
        std::fs::read(dir.path().join("remote.state")).unwrap()
    );
    let mut source = None;
    for index in 1u64..=400 {
        let current = machine.record().clone();
        let mut operation_id = [19; 16];
        operation_id[..8].copy_from_slice(&index.to_le_bytes());
        let (role, action) = if let Some(old) = &current.current {
            source.get_or_insert_with(|| old.clone());
            match current.phase {
                Phase::Released => (Role::Writer, Action::Claim),
                Phase::Claimed => {
                    let mut descriptor = old.clone();
                    descriptor.namespace = namespace(current.fence, current.session);
                    (Role::Writer, Action::Activate { descriptor })
                }
                Phase::RestoreClaimed => (
                    Role::Admin,
                    Action::Activate {
                        descriptor: Descriptor {
                            anchor: Anchor {
                                identity: ID,
                                generation: old.anchor.generation + 1,
                                root: [index as u8; 32],
                            },
                            epoch: old.epoch + 1,
                            namespace: namespace(current.fence, current.session),
                        },
                    },
                ),
                Phase::Active => match index % 7 {
                    0 => (
                        Role::Admin,
                        Action::ClaimRestore {
                            source: source.clone().unwrap(),
                        },
                    ),
                    1 => (Role::Admin, Action::Takeover),
                    2 => (Role::Writer, Action::Release),
                    3 => (Role::Admin, Action::RecoverEnrollment),
                    4 => (Role::Writer, Action::Takeover),
                    _ => (
                        Role::Writer,
                        Action::Advance {
                            anchor: Anchor {
                                identity: ID,
                                generation: old.anchor.generation + 1,
                                root: [index as u8; 32],
                            },
                        },
                    ),
                },
            }
        } else {
            if index == 1 {
                (Role::Writer, Action::Claim)
            } else if index == 2 {
                (Role::Admin, Action::RecoverEnrollment)
            } else {
                (
                    Role::Admin,
                    Action::Activate {
                        descriptor: Descriptor {
                            anchor: Anchor {
                                identity: ID,
                                generation: 0,
                                root: [21; 32],
                            },
                            epoch: 0,
                            namespace: namespace(current.fence, current.session),
                        },
                    },
                )
            }
        };
        let request = Request {
            operation_id,
            expected: Some(current),
            action,
        };
        let before = machine.encode().unwrap();
        let applied = machine.apply(role, &request);
        assert_eq!(machine.encode().unwrap(), before, "immutable input {index}");
        let persisted = store.handle(role, &request);
        match (applied, persisted) {
            (Ok(next), Ok(record)) => {
                assert_eq!(next.record(), &record, "record {index}");
                assert_eq!(
                    next.apply(role, &request).unwrap(),
                    next,
                    "exact replay {index}"
                );
                assert_eq!(
                    store.handle(role, &request).unwrap(),
                    record,
                    "persisted replay {index}"
                );
                machine = next;
            }
            (Err(a), Err(b)) => assert_eq!(a.kind(), b.kind(), "rejection {index}"),
            other => panic!("adapter disagreement {index}: {other:?}"),
        }
        let bytes = machine.encode().unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("remote.state")).unwrap(),
            bytes,
            "durable bytes {index}"
        );
        assert_eq!(
            CanonicalState::decode(&bytes).unwrap(),
            machine,
            "roundtrip {index}"
        );
        if index % 20 == 0 {
            drop(store);
            store = StateStore::open(dir.path()).unwrap();
            assert_eq!(inspect(&mut store), *machine.record(), "restart {index}");
        }
    }
    assert!(machine.record().current.as_ref().unwrap().epoch > 1);
}

#[test]
fn canonical_initialization_and_role_bound_replay_fail_closed() {
    assert!(CanonicalState::initial([0; 16]).is_err());
    let initial = CanonicalState::initial(ID).unwrap();
    let recovery = request(1, initial.record(), Action::RecoverEnrollment);
    let accepted = initial.apply(Role::Admin, &recovery).unwrap();
    assert!(accepted.apply(Role::Writer, &recovery).is_err());
    let mut changed_body = recovery.clone();
    changed_body.action = Action::Release;
    assert!(accepted.apply(Role::Admin, &changed_body).is_err());
    assert_eq!(accepted.apply(Role::Admin, &recovery).unwrap(), accepted);
    let mut bytes = accepted.encode().unwrap();
    bytes[12] ^= 1;
    assert!(CanonicalState::decode(&bytes).is_err());
    assert!(initial
        .apply(
            Role::Admin,
            &Request {
                operation_id: [0; 16],
                expected: Some(initial.record().clone()),
                action: Action::RecoverEnrollment
            }
        )
        .is_err());
}

#[test]
fn enrollment_fence_exhaustion_cannot_wrap_to_a_reusable_initial_session() {
    use sha2::{Digest, Sha256};
    let initial = CanonicalState::initial(ID).unwrap();
    let accepted = initial
        .apply(
            Role::Admin,
            &request(1, initial.record(), Action::RecoverEnrollment),
        )
        .unwrap();
    let bytes = accepted.encode().unwrap();
    let body = std::str::from_utf8(&bytes[12..bytes.len() - 32])
        .unwrap()
        .replace("\"fence\":1", "\"fence\":18446744073709551615");
    let mut envelope = b"MAKIRW01".to_vec();
    envelope.extend_from_slice(&(body.len() as u32).to_le_bytes());
    envelope.extend_from_slice(body.as_bytes());
    let mut checksum = Sha256::new();
    checksum.update(b"maki-remote-witness-state-v1\0");
    checksum.update(&envelope);
    envelope.extend_from_slice(&checksum.finalize());
    let exhausted = CanonicalState::decode(&envelope).unwrap();
    assert_eq!(exhausted.record().fence, u64::MAX);
    let prior = exhausted.encode().unwrap();
    assert!(exhausted
        .apply(
            Role::Admin,
            &request(2, exhausted.record(), Action::RecoverEnrollment)
        )
        .is_err());
    assert_eq!(exhausted.encode().unwrap(), prior);
}

#[test]
fn concurrent_admin_enrollment_recovery_full_record_cas_has_exactly_one_winner() {
    use std::sync::{Arc, Barrier, Mutex};
    let dir = tempdir().unwrap();
    let mut store = StateStore::create(dir.path(), ID).unwrap();
    let initial = inspect(&mut store);
    let claimed = store
        .handle(Role::Writer, &request(1, &initial, Action::Claim))
        .unwrap();
    let store = Arc::new(Mutex::new(store));
    let barrier = Arc::new(Barrier::new(16));
    let mut workers = Vec::new();
    for n in 2..18 {
        let store = store.clone();
        let barrier = barrier.clone();
        let expected = claimed.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            store.lock().unwrap().handle(
                Role::Admin,
                &request(n, &expected, Action::RecoverEnrollment),
            )
        }));
    }
    let mut accepted = Vec::new();
    for worker in workers {
        match worker.join().unwrap() {
            Ok(record) => accepted.push(record),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
        }
    }
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].identity, ID);
    assert_eq!(accepted[0].fence, claimed.fence + 1);
    assert_eq!(inspect(&mut store.lock().unwrap()), accepted[0]);
}
