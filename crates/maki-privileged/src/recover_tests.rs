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
    let fixture = Fixture::new();
    let state = fixture.state();
    let req = request();
    let sysfs = fixture.0.join("sys");
    std::fs::create_dir_all(sysfs.join("nbd3/holders")).unwrap();
    std::fs::write(sysfs.join("nbd3/dev"), "43:3\n").unwrap();
    std::fs::write(sysfs.join("nbd3/size"), "1024\n").unwrap();
    let mut system = ObservedSystem {
        fake: FakeSystem {
            process_death_after_activation: true,
            ..Default::default()
        },
        sysfs,
    };
    let death = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = execute_with(&plan_attach(&req), Some(&state), &mut system);
    }));
    assert!(
        death.is_err(),
        "fixture must stop between activation and proof"
    );
    let record = state.read("pg").unwrap().unwrap();
    let serialized = serde_json::to_value(&record).unwrap();
    assert!(
        serialized.get("recovery_intent").is_some(),
        "verified pre-activation identity was not durably published: {serialized}"
    );
    assert!(record.recovery.is_none());
    assert!(system.fake.vg_active);
    system.fake.process_death_after_activation = false;
    system.fake.steps.clear();
    system.fake.backends.clear();
    (fixture, state, req, system)
}

#[test]
fn recovery_uses_persisted_pre_activation_identity_after_process_death() {
    let (_fixture, state, req, mut system) = activation_crashed();
    recover_with(&plan_detach(&req), &state, &mut system).unwrap();
    assert_eq!(system.fake.steps, ["lvm-deactivate"]);
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
    assert!(recover::observe(&record, &mounts, &system.sysfs).is_err());
    let sentinel = Path::new(&record.attachment.mountpoint).join(SENTINEL_FILE);
    std::fs::remove_file(&sentinel).unwrap();
    std::fs::create_dir(&sentinel).unwrap();
    assert!(
        recover::observe(&record, &system.mounts(&record), &system.sysfs)
            .unwrap()
            .mounted
    );
}
