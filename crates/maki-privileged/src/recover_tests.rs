use super::*;

#[test]
fn recovery_backend_probe_rejects_unknown_pid_metadata() {
    let fixture = Fixture::new();
    let sysfs = fixture.0.join("sys");
    let device = sysfs.join("nbd3");
    std::fs::create_dir_all(&device).unwrap();
    assert_eq!(nbd_backend_at(&sysfs, "/dev/nbd3").unwrap(), None);
    // A loop gives a deterministic metadata error even for a root test runner.
    std::os::unix::fs::symlink("pid", device.join("pid")).unwrap();
    assert!(
        nbd_backend_at(&sysfs, "/dev/nbd3").is_err(),
        "an unreadable PID attribute is not proof of disconnection"
    );
    std::fs::remove_file(device.join("pid")).unwrap();
    std::fs::write(device.join("pid"), "1234\n").unwrap();
    assert!(nbd_backend_at(&sysfs, "/dev/nbd3").is_err());
    std::fs::write(device.join("backend"), "maki-test-identity\n").unwrap();
    assert_eq!(
        nbd_backend_at(&sysfs, "/dev/nbd3").unwrap().as_deref(),
        Some("maki-test-identity")
    );
}

fn attached() -> (Fixture, TrustedState, AttachRequest, ObservedSystem) {
    let fixture = Fixture::new();
    let state = fixture.state();
    let mut req = request();
    req.mountpoint = fixture.0.join("mount").to_str().unwrap().into();
    std::fs::create_dir(&req.mountpoint).unwrap();
    std::fs::write(
        Path::new(&req.mountpoint).join(SENTINEL_FILE),
        &req.volume_uuid,
    )
    .unwrap();
    let sysfs = fixture.0.join("sys");
    std::fs::create_dir_all(sysfs.join("nbd3/holders")).unwrap();
    std::fs::write(sysfs.join("nbd3/dev"), "43:3\n").unwrap();
    let mut system = ObservedSystem {
        fake: FakeSystem::default(),
        sysfs,
    };
    execute_with(&plan_attach(&req), Some(&state), &mut system).unwrap();
    system.fake.steps.clear();
    system.fake.backends.clear();
    (fixture, state, req, system)
}

fn activation_crashed() -> (Fixture, TrustedState, AttachRequest, ObservedSystem) {
    activation_interrupted(false)
}

fn activation_interrupted(
    before_activation: bool,
) -> (Fixture, TrustedState, AttachRequest, ObservedSystem) {
    let fixture = Fixture::new();
    let state = fixture.state();
    let req = request();
    let sysfs = fixture.0.join("sys");
    std::fs::create_dir_all(sysfs.join("nbd3/holders")).unwrap();
    std::fs::write(sysfs.join("nbd3/dev"), "43:3\n").unwrap();
    std::fs::write(sysfs.join("nbd3/size"), "1024\n").unwrap();
    let mut system = ObservedSystem {
        fake: FakeSystem {
            process_death_before_activation: before_activation,
            process_death_after_activation: !before_activation,
            ..Default::default()
        },
        sysfs,
    };
    let death = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = execute_with(&plan_attach(&req), Some(&state), &mut system);
    }));
    assert!(death.is_err(), "fixture must stop after publishing intent");
    let record = state.read("pg").unwrap().unwrap();
    let serialized = serde_json::to_value(&record).unwrap();
    assert!(
        serialized.get("recovery_intent").is_some(),
        "verified pre-activation identity was not durably published: {serialized}"
    );
    assert!(record.recovery.is_none());
    assert_eq!(system.fake.vg_active, !before_activation);
    system.fake.process_death_before_activation = false;
    system.fake.process_death_after_activation = false;
    system.fake.steps.clear();
    system.fake.backends.clear();
    (fixture, state, req, system)
}

#[test]
fn empty_intent_cleanup_accepts_disconnected_capacity_reset() {
    let (_fixture, state, req, mut system) = activation_interrupted(true);
    let record = state.read("pg").unwrap().unwrap();
    assert!(!system.fake.vg_active && !system.fake.mounted);
    std::fs::write(system.sysfs.join("nbd3/size"), "0\n").unwrap();

    cleanup_with(&plan_detach(&req), &state, &mut system).unwrap();

    assert!(system.fake.steps.is_empty(), "empty cleanup is record-only");
    assert!(state.read("pg").unwrap().is_none());
    assert!(record.recovery_intent.is_some());
    cleanup_with(&plan_detach(&req), &state, &mut system).unwrap();
    assert!(system.fake.steps.is_empty(), "cleanup retry is idempotent");
}

fn record_intent_partition(state: &TrustedState) -> BoundDeviceRecord {
    let mut value = serde_json::to_value(state.read("pg").unwrap().unwrap()).unwrap();
    value["recovery_intent"]["verified"]["devices"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "path": "/dev/nbd3p1", "number": [43, 4], "start": 8, "sectors": 512,
        }));
    let record = serde_json::from_value(value).unwrap();
    state.write(&record).unwrap();
    record
}

fn add_intent_partition(system: &ObservedSystem, name: &str) {
    let root = system.sysfs.join(name);
    std::fs::create_dir_all(root.join("holders")).unwrap();
    std::fs::write(root.join("dev"), "43:4\n").unwrap();
    std::fs::write(root.join("partition"), "1\n").unwrap();
    std::fs::write(root.join("start"), "8\n").unwrap();
    std::fs::write(root.join("size"), "512\n").unwrap();
}

#[test]
fn empty_intent_cleanup_accepts_disappeared_or_unchanged_recorded_partitions() {
    for partition_present in [false, true] {
        let (_fixture, state, req, mut system) = activation_interrupted(true);
        record_intent_partition(&state);
        if partition_present {
            add_intent_partition(&system, "nbd3p1");
        }
        std::fs::write(system.sysfs.join("nbd3/size"), "0\n").unwrap();

        cleanup_with(&plan_detach(&req), &state, &mut system).unwrap();

        assert!(system.fake.steps.is_empty());
        assert!(state.read("pg").unwrap().is_none());
    }
}

#[test]
fn empty_intent_cleanup_rejects_changed_present_device_identity() {
    for (path, value) in [
        ("nbd3/dev", "43:9\n"),
        ("nbd3/size", "2048\n"),
        ("nbd3p1/dev", "43:9\n"),
        ("nbd3p1/start", "16\n"),
        ("nbd3p1/size", "256\n"),
        ("nbd3p1/partition", "2\n"),
    ] {
        let (_fixture, state, req, mut system) = activation_interrupted(true);
        let record = record_intent_partition(&state);
        add_intent_partition(&system, "nbd3p1");
        std::fs::write(system.sysfs.join("nbd3/size"), "0\n").unwrap();
        std::fs::write(system.sysfs.join(path), value).unwrap();

        assert!(
            cleanup_with(&plan_detach(&req), &state, &mut system).is_err(),
            "accepted changed device at {path}"
        );
        assert!(system.fake.steps.is_empty());
        assert_eq!(state.read("pg").unwrap(), Some(record));
    }
}

#[test]
fn empty_intent_cleanup_rejects_new_partitions_holders_and_mounts() {
    for foreign in ["partition", "holder", "mount", "missing-device"] {
        let (_fixture, state, req, mut system) = activation_interrupted(true);
        let record = state.read("pg").unwrap().unwrap();
        std::fs::write(system.sysfs.join("nbd3/size"), "0\n").unwrap();
        match foreign {
            "partition" => add_intent_partition(&system, "nbd3p1"),
            "holder" => {
                std::fs::write(system.sysfs.join("nbd3/holders/dm-99"), "").unwrap();
            }
            "mount" => system.fake.mounted = true,
            "missing-device" => std::fs::remove_dir_all(system.sysfs.join("nbd3")).unwrap(),
            _ => unreachable!(),
        }

        assert!(
            cleanup_with(&plan_detach(&req), &state, &mut system).is_err(),
            "accepted {foreign}"
        );
        assert!(system.fake.steps.is_empty());
        assert_eq!(state.read("pg").unwrap(), Some(record));
    }
}

#[test]
fn empty_intent_cleanup_rechecks_backend_before_retiring_record() {
    for fault in [BackendFault::Foreign, BackendFault::Unreadable] {
        for probe in [1, 3, 4] {
            let (_fixture, state, req, mut system) = activation_interrupted(true);
            let record = state.read("pg").unwrap().unwrap();
            system.fake.backend_probes.set(0);
            system.fake.backend_fault_on_probe = Some((probe, fault));

            assert!(
                cleanup_with(&plan_detach(&req), &state, &mut system).is_err(),
                "retired after backend fault at probe {probe}"
            );
            assert!(system.fake.steps.is_empty());
            assert_eq!(state.read("pg").unwrap(), Some(record));
        }
    }
}

#[test]
fn empty_intent_cleanup_rechecks_resources_before_retiring_record() {
    let (_fixture, state, req, mut system) = activation_interrupted(true);
    let record = state.read("pg").unwrap().unwrap();
    system.fake.recovery_observations.set(0);
    system.fake.holder_after_recovery_observation = true;

    assert!(
        cleanup_with(&plan_detach(&req), &state, &mut system).is_err(),
        "a holder appeared after the empty observation"
    );
    assert!(system.fake.steps.is_empty());
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

#[test]
fn empty_intent_relaxation_never_authorizes_live_mapping_cleanup() {
    let (_fixture, state, req, mut system) = activation_crashed();
    let record = state.read("pg").unwrap().unwrap();
    assert!(system.fake.vg_active);
    std::fs::write(system.sysfs.join("nbd3/size"), "0\n").unwrap();

    assert!(cleanup_with(&plan_detach(&req), &state, &mut system).is_err());
    assert!(system.fake.steps.is_empty());
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

#[test]
fn empty_intent_capacity_reset_exception_requires_an_absent_backend() {
    let (_fixture, state, req, mut system) = activation_interrupted(true);
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    std::fs::write(system.sysfs.join("nbd3/size"), "0\n").unwrap();

    assert!(cleanup_with(&plan_detach(&req), &state, &mut system).is_err());
    assert!(system.fake.steps.is_empty());
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

#[test]
fn recovery_uses_persisted_pre_activation_identity_after_process_death() {
    let (_fixture, state, req, mut system) = activation_crashed();
    recover_with(&plan_detach(&req), &state, &mut system).unwrap();
    assert_eq!(system.fake.steps, ["lvm-deactivate"]);
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn connected_detach_rejects_changed_pre_activation_identity_without_mutation() {
    for (path, value) in [
        ("dm-0/dm/uuid", "LVM-another-volume\n"),
        (
            "dm-0/dm/uuid",
            "LVM-aaaaaabbbbccccddddeeeeffffgggggghhhhhhiiiijjjjkkkkllllmmmmnnnnnn-foreign\n",
        ),
        ("dm-0/dm/name", "vg_maki_pg-other\n"),
        ("dm-0/slaves/nbd4", ""),
        ("nbd3/holders/dm-99", ""),
    ] {
        let (_fixture, state, req, mut system) = activation_crashed();
        let record = state.read("pg").unwrap().unwrap();
        system
            .fake
            .backends
            .insert(record.device.clone(), record.connection_id.clone());
        std::fs::write(system.sysfs.join(path), value).unwrap();

        let result = execute_with(&plan_detach(&req), Some(&state), &mut system);

        assert!(
            result.is_err(),
            "detach accepted changed identity at {path}"
        );
        assert!(
            system.fake.steps.is_empty(),
            "detach mutated after {path} changed: {:?}",
            system.fake.steps
        );
        assert_eq!(state.read("pg").unwrap(), Some(record));
    }
}

#[test]
fn connected_detach_uses_exact_pre_activation_identity() {
    let (_fixture, state, req, mut system) = activation_crashed();
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());

    execute_with(&plan_detach(&req), Some(&state), &mut system).unwrap();

    assert_eq!(system.fake.steps, ["lvm-deactivate", "nbd-disconnect"]);
    assert_eq!(system.fake.scoped_lvm_deactivations, 1);
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn connected_detach_rechecks_the_backend_before_intent_deactivation() {
    let (_fixture, state, req, mut system) = activation_crashed();
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    system.fake.backend_probes.set(0);
    system.fake.backend_fault_on_probe = Some((5, BackendFault::Foreign));

    assert!(execute_with(&plan_detach(&req), Some(&state), &mut system).is_err());

    assert!(system.fake.steps.is_empty());
    assert_eq!(system.fake.scoped_lvm_deactivations, 0);
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

/// The hook's rollback carries no unmount step at all. Even an observer that
/// reported a mount for an activation intent (the production one refuses
/// that state outright) could only stop it.
#[test]
fn the_failed_start_rollback_has_no_unmount_to_run() {
    let (_fixture, state, req, mut system) = activation_crashed();
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    system.fake.mounted = true;

    let result = finish_interrupted_activation_with(&plan_detach(&req), &state, &mut system.fake);

    assert!(result.is_err(), "{result:?}");
    assert!(system.fake.steps.is_empty(), "{:?}", system.fake.steps);
    assert!(system.fake.mounted && system.fake.vg_active);
    assert_eq!(state.read("pg").unwrap(), Some(record));

    system.fake.mounted = false;
    assert!(finish_interrupted_activation_with(&plan_detach(&req), &state, &mut system).unwrap());
    assert_eq!(system.fake.steps, ["lvm-deactivate", "nbd-disconnect"]);
    assert_eq!(system.fake.scoped_lvm_deactivations, 1);
    assert!(state.read("pg").unwrap().is_none());
}

/// The hook must neither queue behind another volume's helper when it has
/// nothing to do, nor hold up the coordinator beyond its deadline when it has.
#[test]
fn the_failed_start_rollback_queues_for_the_attach_lock_only_with_an_intent() {
    let (_fixture, state, req, mut system) = attached();
    let plan = plan_detach(&req);
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    let busy = state.lock().unwrap();
    let patient = || Instant::now() + Duration::from_secs(3);
    let started = Instant::now();

    // A complete attachment, then no record at all: not this path's.
    assert!(!finish_interrupted_activation_by(&plan, &state, &mut system, patient()).unwrap());
    state.remove("pg").unwrap();
    assert!(!finish_interrupted_activation_by(&plan, &state, &mut system, patient()).unwrap());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(system.fake.steps.is_empty());

    let (_fixture, state, req, mut system) = activation_crashed();
    let plan = plan_detach(&req);
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    drop(busy);
    let busy = state.lock().unwrap();
    let started = Instant::now();
    let soon = started + Duration::from_millis(150);
    let error = finish_interrupted_activation_by(&plan, &state, &mut system, soon).unwrap_err();
    assert!(
        matches!(&error, ExecError::Io(error) if error.kind() == io::ErrorKind::TimedOut),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(system.fake.steps.is_empty());
    assert_eq!(state.read("pg").unwrap(), Some(record));

    drop(busy);
    assert!(finish_interrupted_activation_by(&plan, &state, &mut system, patient()).unwrap());
    assert_eq!(system.fake.steps, ["lvm-deactivate", "nbd-disconnect"]);
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn connected_detach_cleans_a_verified_partial_activation() {
    let (fixture, state, req, mut system) = activation_crashed();
    let record_path = fixture.0.join("state/pg.nbd");
    let mut serialized: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    let internal = "111111-aaaa-bbbb-cccc-dddd-eeee-ffffff";
    serialized["recovery_intent"]["verified"]["lvs"]["pool"] = internal.into();
    serialized["recovery_intent"]["verified"]["layouts"][internal] = serde_json::json!(["linear"]);
    std::fs::write(&record_path, serde_json::to_vec(&serialized).unwrap()).unwrap();
    let record = state.read("pg").unwrap().unwrap();

    std::fs::remove_dir_all(system.sysfs.join("dm-0")).unwrap();
    std::fs::remove_file(system.sysfs.join("nbd3/holders/dm-0")).unwrap();
    for directory in ["dm-1/dm", "dm-1/slaves", "dm-1/holders"] {
        std::fs::create_dir_all(system.sysfs.join(directory)).unwrap();
    }
    std::fs::write(system.sysfs.join("dm-1/dm/name"), "vg_maki_pg-pool\n").unwrap();
    std::fs::write(
        system.sysfs.join("dm-1/dm/uuid"),
        "LVM-aaaaaabbbbccccddddeeeeffffgggggg111111aaaabbbbccccddddeeeeffffff\n",
    )
    .unwrap();
    std::fs::write(system.sysfs.join("dm-1/dev"), "253:1\n").unwrap();
    std::fs::write(system.sysfs.join("dm-1/slaves/nbd3"), "").unwrap();
    std::fs::write(system.sysfs.join("nbd3/holders/dm-1"), "").unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());

    execute_with(&plan_detach(&req), Some(&state), &mut system).unwrap();

    assert_eq!(system.fake.steps, ["lvm-deactivate", "nbd-disconnect"]);
    assert_eq!(system.fake.scoped_lvm_deactivations, 1);
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn completed_activation_promotes_intent_to_recovery_proof() {
    let (_fixture, state, _req, _system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    assert!(record.recovery.is_some());
    assert!(record.recovery_intent.is_none());
    assert!(
        serde_json::to_value(record)
            .unwrap()
            .get("recovery_intent")
            .is_none(),
        "completed records must not retain the transient intent"
    );
}

#[test]
fn persisted_recovery_intent_rejects_noncanonical_device_paths() {
    let (fixture, state, _req, _system) = activation_crashed();
    let path = fixture.0.join("state/pg.nbd");
    let mut serialized: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    serialized["recovery_intent"]["verified"]["devices"][0]["path"] =
        "/dev/../../etc/passwd".into();
    std::fs::write(&path, serde_json::to_vec(&serialized).unwrap()).unwrap();
    assert!(
        state.read("pg").is_err(),
        "persisted recovery command inputs must be revalidated"
    );
}

#[test]
fn pre_activation_recovery_intent_rejects_changed_identity_without_mutation() {
    for (path, value) in [
        ("dm-0/dm/name", "vg_foreign-data\n"),
        ("dm-0/dm/uuid", "LVM-another-volume\n"),
        ("nbd3/dev", "43:9\n"),
        ("dm-0/slaves/nbd4", ""),
        ("nbd3/holders/dm-99", ""),
    ] {
        let (_fixture, state, req, mut system) = activation_crashed();
        let record = state.read("pg").unwrap().unwrap();
        std::fs::write(system.sysfs.join(path), value).unwrap();
        let result = recover_with(&plan_detach(&req), &state, &mut system);
        assert!(result.is_err(), "accepted changed identity at {path}");
        assert!(system.fake.steps.is_empty(), "mutated after {path}");
        assert_eq!(state.read("pg").unwrap(), Some(record));
    }
}

#[test]
fn pre_activation_recovery_intent_never_authorizes_an_upper_layer() {
    let (_fixture, state, req, mut system) = activation_crashed();
    let record = state.read("pg").unwrap().unwrap();
    system.fake.mounted = true;
    assert!(recover_with(&plan_detach(&req), &state, &mut system).is_err());
    assert!(system.fake.steps.is_empty());
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

#[test]
fn recovery_removes_owned_mappings_after_backend_crash() {
    let (_fixture, state, req, mut system) = attached();
    let result = recover_with(&plan_detach(&req), &state, &mut system);
    assert!(
        result.is_ok(),
        "recover left our crashed attachment stranded: {result:?}"
    );
    assert_eq!(system.fake.steps, ["umount", "lvm-deactivate"]);
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn recovery_does_not_need_a_sentinel_on_the_dead_filesystem() {
    let (_fixture, state, req, mut system) = attached();
    std::fs::remove_file(Path::new(&req.mountpoint).join(SENTINEL_FILE)).unwrap();
    let result = recover_with(&plan_detach(&req), &state, &mut system);
    assert!(
        result.is_ok(),
        "recovery touched or required the dead sentinel: {result:?}"
    );
    assert_eq!(system.fake.steps, ["umount", "lvm-deactivate"]);
}

#[test]
fn recovery_rejects_a_live_backend_without_cleanup() {
    let (_fixture, state, req, mut system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    assert!(recover_with(&plan_detach(&req), &state, &mut system).is_err());
    assert!(system.fake.steps.is_empty());
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

#[test]
fn cleanup_falls_back_to_recorded_mappings_when_lvm_cannot_read_a_dead_server() {
    let (_fixture, state, req, mut system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    system.fake.nonzero_at = Some("lvm-deactivate");

    let result = cleanup_with(&plan_detach(&req), &state, &mut system);

    assert!(
        result.is_ok(),
        "trusted cleanup stranded a mapping after the server died: {result:?}"
    );
    assert_eq!(
        system.fake.steps,
        [
            "umount",
            "lvm-deactivate",
            "dm-proof-deactivate",
            "nbd-disconnect"
        ]
    );
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn cleanup_does_not_fallback_when_lvm_did_not_return_a_nonzero_status() {
    let (_fixture, state, req, mut system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    system.fake.fail_at = Some("lvm-deactivate");

    assert!(cleanup_with(&plan_detach(&req), &state, &mut system).is_err());

    assert_eq!(system.fake.steps, ["umount", "lvm-deactivate"]);
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

/// A `vgchange` that a signal terminated never reported whether it could
/// deactivate the volume group, and may have stopped halfway. Only LVM's own
/// nonzero exit lets cleanup remove the mapping directly; the next cleanup
/// runs LVM again.
#[test]
fn cleanup_does_not_fallback_when_lvm_was_killed_by_a_signal() {
    let (_fixture, state, req, mut system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    system.fake.signalled_at = Some("lvm-deactivate");

    let error = cleanup_with(&plan_detach(&req), &state, &mut system).unwrap_err();

    assert!(error.to_string().contains("status None"), "{error}");
    assert_eq!(system.fake.steps, ["umount", "lvm-deactivate"]);
    assert!(system.fake.vg_active, "the mapping was removed directly");
    assert_eq!(state.read("pg").unwrap(), Some(record));

    // LVM exits this time: nonzero enters the fallback as before.
    system.fake.signalled_at = None;
    system.fake.nonzero_at = Some("lvm-deactivate");
    system.fake.steps.clear();
    cleanup_with(&plan_detach(&req), &state, &mut system).unwrap();
    assert_eq!(
        system.fake.steps,
        ["lvm-deactivate", "dm-proof-deactivate", "nbd-disconnect"]
    );
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn cleanup_rechecks_the_backend_before_proof_scoped_deactivation() {
    let (_fixture, state, req, mut system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    system.fake.nonzero_at = Some("lvm-deactivate");
    system.fake.backend_fault_after = Some(("lvm-deactivate", BackendFault::Foreign));

    assert!(cleanup_with(&plan_detach(&req), &state, &mut system).is_err());

    assert_eq!(system.fake.steps, ["umount", "lvm-deactivate"]);
    assert!(
        system.fake.vg_active,
        "mapping changed after backend replacement"
    );
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

#[test]
fn connected_cleanup_rejects_a_mapping_changed_since_the_recovery_proof() {
    let (_fixture, state, req, mut system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    system
        .fake
        .backends
        .insert(record.device.clone(), record.connection_id.clone());
    std::fs::write(
        system.sysfs.join("dm-0/dm/uuid"),
        "LVM-1111112222333344445555666677778888889999aaaabbbbccccddddeeeeeeee\n",
    )
    .unwrap();

    let result = cleanup_with(&plan_detach(&req), &state, &mut system);

    assert!(result.is_err(), "cleanup accepted a replaced LVM mapping");
    assert!(
        system.fake.steps.is_empty(),
        "cleanup mutated changed storage"
    );
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

#[test]
fn recovery_checks_backend_absence_around_every_observation() {
    for probe in 1..=6 {
        for fault in [BackendFault::Foreign, BackendFault::Unreadable] {
            let (_fixture, state, req, mut system) = attached();
            let record = state.read("pg").unwrap().unwrap();
            system.fake.backend_probes.set(0);
            system.fake.backend_fault_on_probe = Some((probe, fault));
            let result = recover_with(&plan_detach(&req), &state, &mut system);
            assert!(result.is_err(), "probe {probe}, {fault:?}: {result:?}");
            assert_eq!(
                system.fake.steps.len(),
                (probe - 1) / 2,
                "probe {probe}, {fault:?}"
            );
            assert!(!system.fake.steps.contains(&"nbd-disconnect"));
            assert_eq!(state.read("pg").unwrap(), Some(record));
        }
    }
}

#[test]
fn recovery_rejects_changed_kernel_identities_without_cleanup() {
    for (path, value) in [
        ("dm-0/dm/uuid", "LVM-another-volume\n"),
        ("dm-0/dm/name", "vg_maki_foreign-data\n"),
        ("dm-0/dev", "253:9\n"),
        ("nbd3/dev", "43:9\n"),
        ("dm-0/slaves/nbd4", ""),
        ("nbd3/holders/dm-99", ""),
    ] {
        let (_fixture, state, req, mut system) = attached();
        let record = state.read("pg").unwrap().unwrap();
        std::fs::write(system.sysfs.join(path), value).unwrap();
        assert!(
            recover_with(&plan_detach(&req), &state, &mut system).is_err(),
            "accepted {path}"
        );
        assert!(system.fake.steps.is_empty(), "mutated after {path}");
        assert_eq!(state.read("pg").unwrap(), Some(record));
    }
}

#[test]
fn recovery_rejects_incomplete_dependency_observation() {
    let (_fixture, state, req, mut system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    std::fs::remove_file(system.sysfs.join("nbd3/holders/dm-0")).unwrap();
    assert!(
        recover_with(&plan_detach(&req), &state, &mut system).is_err(),
        "accepted a slave edge with no matching holder during topology change"
    );
    assert!(system.fake.steps.is_empty());
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

#[test]
fn recovery_retains_identity_when_cleanup_fails_before_or_after_its_effect() {
    for step in ["umount", "lvm-deactivate"] {
        for after_effect in [false, true] {
            let (_fixture, state, req, mut system) = attached();
            let record = state.read("pg").unwrap().unwrap();
            if after_effect {
                system.fake.fail_after_at = Some(step);
            } else {
                system.fake.fail_at = Some(step);
            }
            assert!(recover_with(&plan_detach(&req), &state, &mut system).is_err());
            assert_eq!(state.read("pg").unwrap(), Some(record));
            system.fake.fail_at = None;
            system.fake.fail_after_at = None;
            system.fake.steps.clear();
            recover_with(&plan_detach(&req), &state, &mut system).unwrap();
            assert_eq!(
                system.fake.steps,
                match (step, after_effect) {
                    ("umount", false) => vec!["umount", "lvm-deactivate"],
                    ("umount", true) | ("lvm-deactivate", false) => vec!["lvm-deactivate"],
                    _ => vec![],
                }
            );
            assert!(state.read("pg").unwrap().is_none());
        }
    }
}

#[test]
fn legacy_record_without_proof_or_intent_remains_fail_closed() {
    let (_fixture, state, req, mut system) = attached();
    // This is the durable state left by a crash between VG activation and the
    // atomic proof write. It cannot authorize cleanup of the active mapping.
    let mut record = state.read("pg").unwrap().unwrap();
    record.recovery = None;
    state.write(&record).unwrap();
    system.fake.mounted = false;
    assert!(recover_with(&plan_detach(&req), &state, &mut system).is_err());
    assert!(system.fake.steps.is_empty());
    assert_eq!(state.read("pg").unwrap(), Some(record));
}

#[test]
fn recovery_refuses_an_extra_mount_and_never_reads_the_sentinel() {
    let (_fixture, state, _req, system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    let mounts = format!(
        "{}41 25 253:0 /subdir /container/data rw - xfs /dev/mapper/vg_maki_pg-data rw\n",
        system.mounts(&record)
    );
    assert!(recover::observe(&record, mounts.as_bytes(), &system.sysfs).is_err());
    let sentinel = Path::new(&record.attachment.mountpoint).join(SENTINEL_FILE);
    std::fs::remove_file(&sentinel).unwrap();
    std::fs::create_dir(&sentinel).unwrap();
    assert!(
        recover::observe(&record, system.mounts(&record).as_bytes(), &system.sysfs)
            .unwrap()
            .mounted
    );
}

#[test]
fn mountinfo_unicode_whitespace_preserves_recovery_and_complete_mount_identity() {
    let (_fixture, state, _req, system) = attached();
    let mut record = state.read("pg").unwrap().unwrap();
    for space in ['\u{00a0}', '\u{2003}', '\u{3000}'] {
        record.attachment.mountpoint = format!("/srv/audit{space}data");
        let mounts = system.mounts(&record);
        assert!(
            recover::observe(&record, mounts.as_bytes(), &system.sysfs)
                .unwrap()
                .mounted
        );
        assert_eq!(
            recover::observe_complete(&record, mounts.as_bytes(), &system.sysfs)
                .unwrap()
                .device,
            (253, 0)
        );

        let extra = format!("{mounts}41 25 253:0 / /srv/other{space}data rw - xfs /dev/dm-0 rw\n");
        assert!(recover::observe(&record, extra.as_bytes(), &system.sysfs).is_err());
    }
}

#[test]
fn non_utf8_mount_records_keep_recovery_and_gate_checks_exact() {
    let (_fixture, state, _req, system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    let mounts = system.mounts(&record);
    let mountpoint = record.attachment.mountpoint.as_bytes();
    let foreign = b"42 25 0:61 / /home/user/fuse-\xff rw,nosuid,nodev - fuse.\xfe \xfd rw\n";
    let table = [mounts.as_bytes(), foreign].concat();
    assert!(
        recover::observe(&record, &table, &system.sysfs)
            .unwrap()
            .mounted
    );
    assert_eq!(
        recover::observe_complete(&record, &table, &system.sysfs)
            .unwrap()
            .device,
        (253, 0)
    );

    // A second mount of a recorded device is refused whatever its path.
    let extra = b"43 25 253:0 / /container/\xff rw - xfs /dev/dm-0 rw\n";
    let table = [mounts.as_bytes(), extra].concat();
    assert!(recover::observe(&record, &table, &system.sysfs).is_err());

    // The workload gate refuses a nested mount with a non-UTF-8 name.
    let nested = [
        b"44 40 0:62 / ".as_slice(),
        mountpoint,
        b"/\xff rw - tmpfs tmpfs rw\n",
    ]
    .concat();
    let table = [mounts.as_bytes(), &nested].concat();
    assert!(recover::observe_complete(&record, &table, &system.sysfs).is_err());

    // The gate's snapshot is the exact record, so records that differ only
    // in undecodable bytes are different snapshots.
    let snapshot = |source: &[u8]| {
        let line = [
            b"40 25 253:0 / ".as_slice(),
            mountpoint,
            b" rw,nosuid,nodev - xfs ",
            source,
            b" rw\n",
        ]
        .concat();
        recover::observe_complete(&record, &line, &system.sysfs).unwrap()
    };
    assert_ne!(snapshot(b"/dev/\xfe"), snapshot(b"/dev/\xff"));
}

/// Linux prints a mount whose source string is empty (`mount -t tmpfs ''
/// /dir`) as an empty field: `- tmpfs  rw,...`. One such mount anywhere in
/// the namespace must not block recovery or the workload gate, and the
/// gate's checks keep reading the fields after it.
#[test]
fn empty_mount_sources_keep_recovery_and_gate_checks_exact() {
    let (_fixture, state, _req, system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    let mounts = system.mounts(&record);
    let mountpoint = record.attachment.mountpoint.clone();
    let error = |table: &str| {
        recover::observe_complete(&record, table.as_bytes(), &system.sysfs)
            .unwrap_err()
            .to_string()
    };

    let table = format!("{mounts}42 25 0:41 / /run/empty rw,relatime - tmpfs  rw,mode=755\n");
    assert!(
        recover::observe(&record, table.as_bytes(), &system.sysfs)
            .unwrap()
            .mounted
    );
    assert_eq!(
        recover::observe_complete(&record, table.as_bytes(), &system.sysfs)
            .unwrap()
            .device,
        (253, 0)
    );

    // The volume's own record with an empty source is still the volume.
    let volume = format!("40 25 253:0 / {mountpoint} rw,nosuid,nodev - xfs  rw\n");
    assert_eq!(
        recover::observe_complete(&record, volume.as_bytes(), &system.sysfs)
            .unwrap()
            .device,
        (253, 0)
    );
    let read_only = format!("40 25 253:0 / {mountpoint} rw,nosuid,nodev - xfs  ro\n");
    assert_eq!(error(&read_only), "workload mount is read-only");

    // Nested and second mounts are still refused whatever their source.
    let nested = format!("{mounts}44 40 0:62 / {mountpoint}/wal rw - tmpfs  rw\n");
    assert_eq!(error(&nested), "workload volume contains a nested mount");
    let extra = format!("{mounts}43 25 253:0 / /container/data rw - xfs  rw\n");
    let refused = recover::observe(&record, extra.as_bytes(), &system.sysfs).unwrap_err();
    assert!(
        refused.to_string().contains("has another mount"),
        "{refused}"
    );
}

/// The workload gate reads every record itself: only the source field can
/// be empty, and any other malformed record refuses.
#[test]
fn the_workload_gate_refuses_records_with_other_empty_fields() {
    let (_fixture, state, _req, system) = attached();
    let record = state.read("pg").unwrap().unwrap();
    let mounts = system.mounts(&record);
    let gate = |extra: &str| {
        let table = format!("{mounts}{extra}");
        recover::observe_complete(&record, table.as_bytes(), &system.sysfs)
    };
    assert!(gate("42 25 0:41 / /run/x rw - tmpfs  rw\n").is_ok());
    for extra in [
        "42 25 0:41 /  /run/x rw - tmpfs tmpfs rw\n",
        "42 25 0:41 / /run/x rw  - tmpfs tmpfs rw\n",
        "42 25 0:41 / /run/x rw -  tmpfs rw\n",
        "42 25 0:41 / /run/x rw - tmpfs tmpfs \n",
        "42 25 0:41 / /run/x rw - tmpfs tmpfs\n",
    ] {
        assert!(gate(extra).is_err(), "{extra:?}");
    }
}

/// Preflight admits a volume group on up to 64 candidate devices (the NBD
/// device and 63 partitions) holding up to 64 logical volumes. The proof
/// taken after activation has to hold every one of them, the trusted record
/// has to store it, and the later observers have to accept the same
/// topology. Here every LV spans every partition PV and carries a name as
/// long as device-mapper allows, the largest record an admitted VG produces.
#[test]
fn the_largest_inventory_preflight_admits_is_proven_and_recorded() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let sysfs = fixture.0.join("sys");
    let block = |name: &str, number: String| {
        for directory in ["holders", "slaves"] {
            std::fs::create_dir_all(sysfs.join(name).join(directory)).unwrap();
        }
        std::fs::write(sysfs.join(name).join("dev"), number).unwrap();
    };
    let partition = |index: usize| {
        let name = format!("nbd3p{index}");
        block(&name, format!("43:{}\n", 48 + index));
        std::fs::write(sysfs.join(&name).join("partition"), format!("{index}\n")).unwrap();
        name
    };
    block("nbd3", "43:48\n".into());
    let partitions: Vec<_> = (1..=63).map(partition).collect();
    for index in 0..64 {
        let lv = if index == 0 {
            "data".to_string()
        } else {
            format!("{:x<116}", format!("lv{index}_"))
        };
        let kernel = format!("dm-{index}");
        block(&kernel, format!("253:{index}\n"));
        std::fs::create_dir_all(sysfs.join(&kernel).join("dm")).unwrap();
        std::fs::write(
            sysfs.join(&kernel).join("dm/name"),
            format!("vg_maki_pg-{lv}\n"),
        )
        .unwrap();
        std::fs::write(
            sysfs.join(&kernel).join("dm/uuid"),
            format!("LVM-aaaaaabbbbccccddddeeeeffffgggggg{index:06}iiiijjjjkkkkllllmmmmnnnnnn\n"),
        )
        .unwrap();
        for partition in &partitions {
            std::fs::write(sysfs.join(&kernel).join("slaves").join(partition), "").unwrap();
            std::fs::write(sysfs.join(partition).join("holders").join(&kernel), "").unwrap();
        }
    }
    let mut record = BoundDeviceRecord {
        version: 1,
        volume: "pg".into(),
        attachment: (&request()).into(),
        device: "/dev/nbd3".into(),
        connection_id: "maki-11111111-2222-4333-8444-555555555555".into(),
        recovery: None,
        recovery_intent: None,
    };

    let proof = recover::capture(&record, b"", &sysfs)
        .expect("the proof holds what preflight admits: 64 devices and 64 logical volumes");
    record.recovery = Some(proof);
    let encoded = serde_json::to_value(&record).unwrap();
    assert_eq!(
        encoded["recovery"]["nodes"].as_array().map(Vec::len),
        Some(128)
    );
    state.write(&record).unwrap();
    assert_eq!(state.read("pg").unwrap(), Some(record.clone()));
    assert!(
        recover::observe(&record, b"", &sysfs).unwrap().vg_active,
        "recovery accepts the recorded topology"
    );

    // A 65th candidate device is more than preflight admits, and more than
    // the proof is sized for.
    partition(64);
    assert!(recover::capture(&record, b"", &sysfs).is_err());
}

/// The same inventory is taken when an activation outlived the helper: the
/// persisted intent names all 64 LVs, and recovery has to see every one of
/// their mappings before it deactivates them and retires the record.
#[test]
fn an_interrupted_64_lv_activation_is_recovered_from_its_intent() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let mut system = inventory_system(&fixture, 64, false);
    system.inner.fake.process_death_after_activation = true;
    let death = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = execute_with(&plan_attach(&request()), Some(&state), &mut system);
    }));
    assert!(death.is_err(), "fixture must stop after activation");
    system.inner.fake.process_death_after_activation = false;
    let record = state.read("pg").unwrap().unwrap();
    assert!(record.recovery.is_none() && record.recovery_intent.is_some());
    assert!(system.inner.sysfs.join("dm-63").exists());
    // The backend went away with the helper; the 64 mappings remain.
    system.inner.fake.backends.clear();
    system.inner.fake.steps.clear();

    cleanup_with(&plan_detach(&request()), &state, &mut system).unwrap();

    assert_eq!(system.inner.fake.steps, ["lvm-deactivate"]);
    assert!(!system.inner.sysfs.join("dm-63").exists());
    assert!(state.read("pg").unwrap().is_none());
}
