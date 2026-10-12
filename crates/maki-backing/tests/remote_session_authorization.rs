//! BUG-033: observing a predecessor never grants ownership of its writer session.
use maki_backing::remote_witness::{
    Action, CanonicalState, Descriptor, Request, Role, SessionAuthorization, StateStore,
};
use maki_backing::witness::Anchor;

fn mutation(state: &CanonicalState, n: u8, action: Action) -> Request {
    Request {
        authorization: Some(
            maki_backing::remote_witness::SessionAuthorization::from_bytes([17; 32]),
        ),
        operation_id: [n; 16],
        expected: Some(state.record().clone()),
        action,
    }
}

#[test]
fn inspected_active_record_does_not_authorize_release() {
    let state = CanonicalState::initial([1; 16]).unwrap();
    let state = state
        .apply(Role::Writer, &mutation(&state, 1, Action::Claim))
        .unwrap();
    let descriptor = Descriptor {
        anchor: Anchor {
            identity: [1; 16],
            generation: 0,
            root: [8; 32],
        },
        epoch: 0,
        namespace: maki_backing::remote_witness::namespace(
            state.record().fence,
            state.record().session,
        ),
    };
    let state = state
        .apply(
            Role::Writer,
            &mutation(&state, 2, Action::Activate { descriptor }),
        )
        .unwrap();
    let mut unauthorized = mutation(&state, 3, Action::Release);
    unauthorized.authorization = None;
    assert_eq!(
        state.apply(Role::Writer, &unauthorized).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn inspected_claim_does_not_authorize_activation_or_enrollment_release() {
    let state = CanonicalState::initial([1; 16]).unwrap();
    let state = state
        .apply(Role::Writer, &mutation(&state, 1, Action::Claim))
        .unwrap();
    let descriptor = Descriptor {
        anchor: Anchor {
            identity: [1; 16],
            generation: 0,
            root: [8; 32],
        },
        epoch: 0,
        namespace: maki_backing::remote_witness::namespace(
            state.record().fence,
            state.record().session,
        ),
    };
    for action in [Action::Activate { descriptor }, Action::Release] {
        let mut unauthorized = mutation(&state, 3, action);
        unauthorized.authorization = None;
        assert_eq!(
            state.apply(Role::Writer, &unauthorized).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}

fn descriptor(state: &CanonicalState) -> Descriptor {
    Descriptor {
        anchor: state.record().current.as_ref().map_or(
            Anchor {
                identity: [1; 16],
                generation: 0,
                root: [8; 32],
            },
            |value| value.anchor.clone(),
        ),
        epoch: state
            .record()
            .current
            .as_ref()
            .map_or(0, |value| value.epoch),
        namespace: maki_backing::remote_witness::namespace(
            state.record().fence,
            state.record().session,
        ),
    }
}

#[test]
fn stolen_public_predecessor_and_old_writer_key_cannot_mutate_admin_takeover() {
    let state = CanonicalState::initial([1; 16]).unwrap();
    let claimed = state
        .apply(Role::Writer, &mutation(&state, 1, Action::Claim))
        .unwrap();
    let active = claimed
        .apply(
            Role::Writer,
            &mutation(
                &claimed,
                2,
                Action::Activate {
                    descriptor: descriptor(&claimed),
                },
            ),
        )
        .unwrap();
    let mut takeover = mutation(&active, 3, Action::Takeover);
    takeover.authorization = Some(SessionAuthorization::from_bytes([23; 32]));
    assert_eq!(
        active.apply(Role::Writer, &takeover).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let taken = active.apply(Role::Admin, &takeover).unwrap();
    let next_descriptor = descriptor(&taken);
    let actions = [
        Action::Release,
        Action::Activate {
            descriptor: next_descriptor.clone(),
        },
    ];
    for action in actions {
        // Same authenticated writer role and exact new public predecessor, but
        // the process retained only the previous session's private key.
        let stale = mutation(&taken, 4, action);
        assert_eq!(
            taken.apply(Role::Writer, &stale).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    let mut activation = mutation(
        &taken,
        5,
        Action::Activate {
            descriptor: next_descriptor,
        },
    );
    activation.authorization = takeover.authorization.clone();
    let active = taken.apply(Role::Admin, &activation).unwrap();
    let old_key_release = mutation(&active, 6, Action::Release);
    let old_key_advance = mutation(
        &active,
        7,
        Action::Advance {
            anchor: Anchor {
                identity: [1; 16],
                generation: 1,
                root: [9; 32],
            },
        },
    );
    for request in [old_key_release, old_key_advance] {
        assert_eq!(
            active.apply(Role::Writer, &request).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    let mut owner_release = mutation(&active, 8, Action::Release);
    owner_release.authorization = takeover.authorization;
    assert!(active.apply(Role::Admin, &owner_release).is_ok());
}

#[test]
fn same_writer_old_key_cannot_release_an_admin_enrollment_recovery() {
    let state = CanonicalState::initial([1; 16]).unwrap();
    let claimed = state
        .apply(Role::Writer, &mutation(&state, 1, Action::Claim))
        .unwrap();
    let mut recovery = mutation(&claimed, 2, Action::RecoverEnrollment);
    recovery.authorization = Some(SessionAuthorization::from_bytes([31; 32]));
    let recovered = claimed.apply(Role::Admin, &recovery).unwrap();
    let request = mutation(&recovered, 3, Action::Release);
    assert_eq!(
        recovered.apply(Role::Writer, &request).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let mut request = mutation(
        &recovered,
        4,
        Action::Activate {
            descriptor: descriptor(&recovered),
        },
    );
    request.authorization = recovery.authorization;
    assert!(recovered.apply(Role::Admin, &request).is_ok());
}

#[test]
fn exact_replay_is_key_bound_and_private_authority_hash_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::create(directory.path(), [1; 16]).unwrap();
    let state = CanonicalState::initial([1; 16]).unwrap();
    let request = mutation(&state, 1, Action::Claim);
    let claimed = store.handle(Role::Writer, &request).unwrap();
    assert_eq!(store.handle(Role::Writer, &request).unwrap(), claimed);
    drop(store);
    let bytes = std::fs::read(directory.path().join("remote.state")).unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes[12..bytes.len() - 32]).unwrap();
    assert_eq!(body["format"], 2);
    assert!(body["record"].get("authorization").is_none());
    assert!(body["record"].get("session_authorization_hash").is_none());
    assert!(body.get("session_authorization_hash").is_some());
    let encoded_key = serde_json::to_string(request.authorization.as_ref().unwrap()).unwrap();
    assert!(!std::str::from_utf8(&bytes[12..bytes.len() - 32])
        .unwrap()
        .contains(&encoded_key));
    let mut reopened = StateStore::open(directory.path()).unwrap();
    assert_eq!(reopened.handle(Role::Writer, &request).unwrap(), claimed);
    let mut wrong_key = request.clone();
    wrong_key.authorization = Some(SessionAuthorization::from_bytes([99; 32]));
    assert!(reopened.handle(Role::Writer, &wrong_key).is_err());
    wrong_key.authorization = None;
    assert!(reopened.handle(Role::Writer, &wrong_key).is_err());
    let current = CanonicalState::decode(&bytes).unwrap();
    let debug = format!("{current:?}");
    assert!(!debug.contains("session_authorization_hash"));
    assert!(!debug.contains("last_request_hash"));
    let release = mutation(&current, 2, Action::Release);
    assert!(reopened.handle(Role::Writer, &release).is_ok());
}

#[test]
fn malformed_keys_and_credentialless_or_nil_claims_are_refused() {
    let state = CanonicalState::initial([1; 16]).unwrap();
    for authorization in [None, Some(SessionAuthorization::from_bytes([0; 32]))] {
        let mut claim = mutation(&state, 1, Action::Claim);
        claim.authorization = authorization;
        assert!(state.apply(Role::Writer, &claim).is_err());
    }
    for bytes in ["[]", "[1]", "null", "\"secret\"", "[256]", "[1,\"secret\"]"] {
        assert!(serde_json::from_str::<SessionAuthorization>(bytes).is_err());
    }
    let mut oversized = vec![1u8; 33];
    assert!(serde_json::from_slice::<SessionAuthorization>(
        &serde_json::to_vec(&oversized).unwrap()
    )
    .is_err());
    oversized.truncate(32);
    let key =
        serde_json::from_slice::<SessionAuthorization>(&serde_json::to_vec(&oversized).unwrap())
            .unwrap();
    assert_eq!(format!("{key:?}"), "SessionAuthorization(<redacted>)");
}

#[test]
fn legacy_authority_v1_is_rejected_without_rewriting_its_evidence() {
    use sha2::{Digest, Sha256};
    let body = br#"{"format":1,"record":{"identity":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"current":null,"fence":0,"session":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"phase":"released","restore_source":null,"last_operation":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},"last_request_hash":null}"#;
    let mut bytes = b"MAKIRW01".to_vec();
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    let mut checksum = Sha256::new();
    checksum.update(b"maki-remote-witness-state-v1\0");
    checksum.update(&bytes);
    bytes.extend_from_slice(&checksum.finalize());
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "ea09320612df918579eb6cb2c2527bc1b4884348dd9f4f00b3b89551ece992c8"
    );
    assert!(CanonicalState::decode(&bytes).is_err());
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("remote.state"), &bytes).unwrap();
    assert!(StateStore::open(directory.path()).is_err());
    assert_eq!(
        std::fs::read(directory.path().join("remote.state")).unwrap(),
        bytes
    );
}
