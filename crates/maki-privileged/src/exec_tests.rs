use super::*;

/// Fixture directories are named by pid + wall clock; the clock can repeat
/// within one process (coarse ticks), so a per-process sequence keeps them
/// unique.
static FIXTURE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use crate::config::{parse, AttachOverrides};
use crate::plan::{
    plan_attach, plan_detach, plan_grow, AttachRequest, GrowRequest, AUTO_NBD_DEVICE,
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "maki-exec-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                | (u128::from(FIXTURE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    << 96)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn state(&self) -> TrustedState {
        TrustedState::open_beneath(
            File::open(&self.0).unwrap(),
            Path::new("state"),
            self.0.metadata().unwrap().uid(),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request() -> AttachRequest {
    parse("volume_uuid = '0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c'\n")
        .unwrap()
        .into_request("pg", AttachOverrides::default(), true)
        .unwrap()
}

#[derive(Clone, Copy, Debug)]
enum BackendFault {
    Foreign,
    Missing,
    Unreadable,
}

#[derive(Default)]
struct FakeSystem {
    backends: HashMap<String, String>,
    steps: Vec<&'static str>,
    fail_at: Option<&'static str>,
    readiness_failure: bool,
    replace_on_failure: bool,
    replace_after_deactivate: bool,
    obstruct_record_cleanup: Option<PathBuf>,
    mounted: bool,
    vg_active: bool,
    fail_after_at: Option<&'static str>,
    foreign_mount: bool,
    foreign_vg: bool,
    extra_holders: bool,
    observation_error: bool,
    backend_fault_after: Option<(&'static str, BackendFault)>,
}

impl System for FakeSystem {
    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError> {
        self.steps.push(step.kind());
        if self.fail_at == Some(step.kind()) {
            if self.replace_on_failure {
                self.backends
                    .insert("/dev/nbd3".into(), "other-connection".into());
            }
            return Err(identity_error("fixture command failed"));
        }
        match step {
            PlannedStep::MountXfs { .. } => self.mounted = true,
            PlannedStep::Umount { .. } => {
                if !self.mounted {
                    return Err(identity_error("fixture mount is already absent"));
                }
                self.mounted = false;
            }
            PlannedStep::LvmActivate { .. } => self.vg_active = true,
            PlannedStep::NbdConnect { device, .. } => {
                self.backends
                    .insert(device.clone(), identifier.unwrap().to_string());
            }
            PlannedStep::NbdDisconnect { device } => {
                self.backends.remove(device);
                if let Some(path) = &self.obstruct_record_cleanup {
                    std::fs::remove_file(path).unwrap();
                    std::fs::create_dir(path).unwrap();
                }
            }
            PlannedStep::LvmDeactivate { .. } => {
                self.vg_active = false;
                if self.replace_after_deactivate {
                    self.backends
                        .insert("/dev/nbd3".into(), "other-connection".into());
                }
            }
            _ => {}
        }
        if self.fail_after_at == Some(step.kind()) {
            return Err(identity_error("fixture command failed after its effect"));
        }
        Ok(())
    }

    fn wait_ready(&mut self, _step: &PlannedStep, _device: &str) -> Result<(), ExecError> {
        if self.readiness_failure {
            Err(identity_error("fixture readiness timeout"))
        } else {
            Ok(())
        }
    }

    fn allocate(&mut self) -> Result<String, ExecError> {
        Ok("/dev/nbd3".into())
    }

    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        if let Some((step, fault)) = self.backend_fault_after {
            if self.steps.contains(&step) {
                return match fault {
                    BackendFault::Foreign => Ok(Some("other-connection".into())),
                    BackendFault::Missing => Ok(None),
                    BackendFault::Unreadable => Err(io::Error::other("fixture backend unreadable")),
                };
            }
        }
        Ok(self.backends.get(device).cloned())
    }

    fn detach_observation(&self, _record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        if self.observation_error
            || (self.mounted && self.foreign_mount)
            || (self.vg_active && self.foreign_vg)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture mismatched or unreadable attachment",
            ));
        }
        Ok(DetachObservation {
            mounted: self.mounted,
            vg_active: self.vg_active,
            nbd_in_use: self.vg_active || self.extra_holders,
        })
    }
}

#[test]
fn new_auto_and_fixed_attachments_record_and_verify_the_kernel_identifier() {
    for device in [AUTO_NBD_DEVICE, "/dev/nbd3"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let _lock = state.lock().unwrap();
        let mut system = FakeSystem::default();
        let mut request = request();
        request.nbd_device = device.into();
        execute_with(&plan_attach(&request), Some(&state), &mut system).unwrap();
        let record = state.read("pg").unwrap().unwrap();
        assert_eq!(record.device, "/dev/nbd3");
        assert_eq!(record.attachment.volume_uuid, request.volume_uuid);
        assert_eq!(
            system.backend(&record.device).unwrap(),
            Some(record.connection_id)
        );
        system.steps.clear();
        execute_with(&plan_detach(&request), Some(&state), &mut system).unwrap();
        assert_eq!(system.steps, ["umount", "lvm-deactivate", "nbd-disconnect"]);
        assert!(state.read("pg").unwrap().is_none());
        assert!(system.backends.is_empty());
    }
}

#[test]
fn missing_or_mismatched_identity_refuses_detach_before_any_command() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem::default();
    let mut request = request();
    request.nbd_device = "/dev/nbd3".into();
    assert!(execute_with(&plan_detach(&request), Some(&state), &mut system).is_err());
    assert!(
        system.steps.is_empty(),
        "a pinned device must not bypass the record"
    );
    execute_with(&plan_attach(&request), Some(&state), &mut system).unwrap();
    system.steps.clear();
    for field in [
        "volume_uuid",
        "nbd_socket",
        "nbd_device",
        "mountpoint",
        "vg_name",
        "lv_name",
    ] {
        let mut changed = request.clone();
        match field {
            "volume_uuid" => changed.volume_uuid = "11111111-2222-4333-8444-555555555555".into(),
            "nbd_socket" => changed.nbd_socket = "/run/maki/other/nbd.sock".into(),
            "nbd_device" => changed.nbd_device = "/dev/nbd4".into(),
            "mountpoint" => changed.mountpoint = "/srv/other".into(),
            "vg_name" => changed.vg_name = "vg_other".into(),
            "lv_name" => changed.lv_name = "other".into(),
            _ => unreachable!(),
        }
        assert!(
            execute_with(&plan_detach(&changed), Some(&state), &mut system).is_err(),
            "{field}"
        );
        assert!(system.steps.is_empty(), "{field}");
    }
    system
        .backends
        .insert("/dev/nbd3".into(), "reconnected-device".into());
    assert!(execute_with(&plan_detach(&request), Some(&state), &mut system).is_err());
    assert!(system.steps.is_empty());
}

#[test]
fn a_disconnected_stale_record_can_be_replaced_but_an_active_attachment_cannot() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem::default();
    let mut request = request();
    request.nbd_device = "/dev/nbd3".into();
    execute_with(&plan_attach(&request), Some(&state), &mut system).unwrap();
    let before = state.read("pg").unwrap().unwrap();
    system.steps.clear();
    assert!(execute_with(&plan_attach(&request), Some(&state), &mut system).is_err());
    assert!(system.steps.is_empty());
    assert_eq!(state.read("pg").unwrap().unwrap(), before);
    // A truly stale record can be replaced only when the volume is *fully*
    // detached: no backend, and no live mount/VG/holder either (FUP-002).
    system.backends.clear();
    system.mounted = false;
    system.vg_active = false;
    execute_with(&plan_attach(&request), Some(&state), &mut system).unwrap();
    assert_ne!(
        state.read("pg").unwrap().unwrap().connection_id,
        before.connection_id
    );
}

#[test]
fn readiness_failure_rolls_back_only_the_attachment_just_created() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem {
        readiness_failure: true,
        ..Default::default()
    };
    let error = execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap_err();
    assert!(matches!(
        error,
        ExecError::RolledBack {
            rollback_failed: 0,
            ..
        }
    ));
    assert_eq!(system.steps.last(), Some(&"nbd-disconnect"));
    assert!(system.backends.is_empty());
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn record_cleanup_error_keeps_the_original_rollback_result() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem {
        readiness_failure: true,
        obstruct_record_cleanup: Some(fixture.0.join("state/pg.nbd")),
        ..Default::default()
    };
    let error = execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap_err();
    assert!(
        matches!(
            error,
            ExecError::RolledBack {
                rollback_failed: 0,
                ..
            }
        ),
        "{error}"
    );
    assert!(error.to_string().contains("fixture readiness timeout"));
    assert!(system.backends.is_empty());
}

#[test]
fn rollback_does_not_disconnect_a_replacement_connection() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem {
        fail_at: Some("mount-xfs"),
        replace_on_failure: true,
        ..Default::default()
    };
    let error = execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap_err();
    assert!(matches!(
        error,
        ExecError::RolledBack {
            rollback_failed: 1,
            ..
        }
    ));
    assert!(!system.steps.contains(&"nbd-disconnect"));
    assert_eq!(
        system.backends.get("/dev/nbd3").map(String::as_str),
        Some("other-connection")
    );
    assert!(state.read("pg").unwrap().is_some());
}

#[test]
fn r3_foreign_backend_stops_every_rollback_mutation() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem {
        fail_at: Some("mount-xfs"),
        replace_on_failure: true,
        ..Default::default()
    };
    assert!(execute_with(&plan_attach(&request()), Some(&state), &mut system).is_err());
    assert!(state.read("pg").unwrap().is_some());
    for forbidden in ["umount", "lvm-deactivate", "nbd-disconnect"] {
        assert!(
            !system.steps.contains(&forbidden),
            "backend ownership was lost, but rollback ran {forbidden}: {:?}",
            system.steps
        );
    }
}

fn assert_rollback_rechecks_backend_before_each_step(fault: BackendFault) {
    for (changed_after, expected) in [
        ("verify-mount-identity", vec![]),
        ("umount", vec!["umount"]),
        ("lvm-deactivate", vec!["umount", "lvm-deactivate"]),
    ] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let _lock = state.lock().unwrap();
        let mut system = FakeSystem {
            fail_at: Some("verify-mount-identity"),
            backend_fault_after: Some((changed_after, fault)),
            ..Default::default()
        };
        let error = execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap_err();
        let destructive: Vec<_> = system
            .steps
            .iter()
            .copied()
            .filter(|step| matches!(*step, "umount" | "lvm-deactivate" | "nbd-disconnect"))
            .collect();
        assert_eq!(destructive, expected, "{fault:?} after {changed_after}");
        // Absence is safe only after all upper layers were already removed.
        let clean = matches!(fault, BackendFault::Missing) && expected.len() == 2;
        assert!(
            matches!(error, ExecError::RolledBack { rollback_failed, .. }
                if rollback_failed == usize::from(!clean)),
            "{fault:?} after {changed_after}: {error}"
        );
        assert_eq!(
            state.read("pg").unwrap().is_none(),
            clean,
            "retain the recovery identity unless all resources are gone"
        );
        assert_eq!(system.mounted, expected.is_empty());
        assert_eq!(system.vg_active, expected.len() < 2);
        assert!(system.backends.contains_key("/dev/nbd3"));
    }
}

#[test]
fn r3_foreign_backend_is_rechecked_before_each_rollback_step() {
    assert_rollback_rechecks_backend_before_each_step(BackendFault::Foreign);
}

#[test]
fn r3_unreadable_backend_is_rechecked_before_each_rollback_step() {
    assert_rollback_rechecks_backend_before_each_step(BackendFault::Unreadable);
}

#[test]
fn r3_missing_backend_with_live_resources_stops_rollback() {
    assert_rollback_rechecks_backend_before_each_step(BackendFault::Missing);
}

#[test]
fn r3_absent_backend_without_live_resources_retires_record() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem {
        fail_at: Some("nbd-connect"),
        ..Default::default()
    };
    let error = execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap_err();
    assert!(matches!(
        error,
        ExecError::RolledBack {
            rollback_failed: 0,
            ..
        }
    ));
    assert!(!system
        .steps
        .iter()
        .any(|step| matches!(*step, "umount" | "lvm-deactivate" | "nbd-disconnect")));
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn detach_rechecks_identity_immediately_before_disconnect() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem::default();
    execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap();
    system.steps.clear();
    system.replace_after_deactivate = true;
    assert!(execute_with(&plan_detach(&request()), Some(&state), &mut system).is_err());
    assert_eq!(system.steps, ["umount", "lvm-deactivate"]);
    assert_eq!(
        system.backends.get("/dev/nbd3").map(String::as_str),
        Some("other-connection")
    );
}

#[test]
fn partial_detach_retry_resumes_after_completed_unmount_and_deactivation() {
    for failure in ["lvm-deactivate", "nbd-disconnect"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let _lock = state.lock().unwrap();
        let mut system = FakeSystem::default();
        execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap();
        system.fail_at = Some(failure);
        assert!(execute_with(&plan_detach(&request()), Some(&state), &mut system).is_err());
        assert!(!system.mounted);
        assert!(state.read("pg").unwrap().is_some());
        system.steps.clear();
        system.fail_at = None;
        execute_with(&plan_detach(&request()), Some(&state), &mut system)
            .unwrap_or_else(|error| panic!("retry after {failure}: {error}"));
        assert_eq!(
            system.steps,
            if failure == "lvm-deactivate" {
                vec!["lvm-deactivate", "nbd-disconnect"]
            } else {
                vec!["nbd-disconnect"]
            }
        );
        assert!(!system.vg_active);
        assert!(system.backends.is_empty());
        assert!(state.read("pg").unwrap().is_none());
    }
}

#[test]
fn completed_detach_retry_retires_record_without_repeating_commands() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem::default();
    execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap();
    let record = state.read("pg").unwrap().unwrap();
    execute_with(&plan_detach(&request()), Some(&state), &mut system).unwrap();
    // Model process death after the kernel disconnect but before record retirement.
    state.write(&record).unwrap();
    system.steps.clear();
    execute_with(&plan_detach(&request()), Some(&state), &mut system).unwrap();
    assert!(system.steps.is_empty());
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn detach_retry_handles_commands_that_fail_after_completing_their_effect() {
    for failure in ["umount", "lvm-deactivate", "nbd-disconnect"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let _lock = state.lock().unwrap();
        let mut system = FakeSystem::default();
        execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap();
        system.fail_after_at = Some(failure);
        assert!(execute_with(&plan_detach(&request()), Some(&state), &mut system).is_err());
        assert!(state.read("pg").unwrap().is_some());
        system.fail_after_at = None;
        system.steps.clear();
        execute_with(&plan_detach(&request()), Some(&state), &mut system).unwrap();
        assert_eq!(
            system.steps,
            match failure {
                "umount" => vec!["lvm-deactivate", "nbd-disconnect"],
                "lvm-deactivate" => vec!["nbd-disconnect"],
                _ => vec![],
            }
        );
        assert!(state.read("pg").unwrap().is_none());
        assert!(system.backends.is_empty());
    }
}

#[test]
fn detach_refuses_changed_incomplete_or_unreadable_state_before_any_command() {
    for case in ["mount", "vg", "disconnected", "probe", "holders"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let _lock = state.lock().unwrap();
        let mut system = FakeSystem::default();
        execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap();
        system.steps.clear();
        match case {
            "mount" => system.foreign_mount = true,
            "vg" => system.foreign_vg = true,
            "disconnected" => system.backends.clear(),
            "probe" => system.observation_error = true,
            "holders" => {
                system.mounted = false;
                system.vg_active = false;
                system.extra_holders = true;
            }
            _ => unreachable!(),
        }
        assert!(
            execute_with(&plan_detach(&request()), Some(&state), &mut system).is_err(),
            "{case}"
        );
        assert!(system.steps.is_empty(), "{case}");
        assert!(state.read("pg").unwrap().is_some());
    }
}

fn grow_request() -> GrowRequest {
    let r = request();
    GrowRequest {
        volume: r.volume,
        volume_uuid: r.volume_uuid,
        nbd_socket: r.nbd_socket,
        vg_name: r.vg_name,
        lv_name: r.lv_name,
        add_bytes: 1 << 30,
        mountpoint: r.mountpoint,
    }
}

/// BUG-018: grow ran `lvextend`/`xfs_growfs` with no trusted record and no
/// attach lock, so it could extend an LVM/XFS unrelated to any current
/// attachment. It must refuse before any command when no record backs it.
#[test]
fn review_next_grow_requires_trusted_attachment_before_commands() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem::default();
    // No attach record for this volume.
    assert!(execute_with(&plan_grow(&grow_request()), Some(&state), &mut system).is_err());
    assert!(
        system.steps.is_empty(),
        "grow ran commands without a trusted attach record"
    );
    // The attach state lock is mandatory for a grow.
    let mut system = FakeSystem::default();
    assert!(execute_with(&plan_grow(&grow_request()), None, &mut system).is_err());
    assert!(system.steps.is_empty());
}

/// BUG-018: a grow whose targets differ from the record, or whose live NBD
/// backend no longer matches the recorded identity, must be refused before
/// any command; a matching grow of the live attachment runs.
#[test]
fn review_next_grow_rejects_reused_backend_and_changed_targets() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem::default();
    execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap();
    system.steps.clear();

    // Changed targets: a different VG/LV/mountpoint/uuid does not match.
    let mutations: [fn(&mut GrowRequest); 4] = [
        |g| g.vg_name = "vg_other".into(),
        |g| g.lv_name = "other".into(),
        |g| g.mountpoint = "/srv/other".into(),
        |g| g.volume_uuid = "11111111-2222-4333-8444-555555555555".into(),
    ];
    for mutate in mutations {
        let mut changed = grow_request();
        mutate(&mut changed);
        assert!(execute_with(&plan_grow(&changed), Some(&state), &mut system).is_err());
        assert!(
            system.steps.is_empty(),
            "a changed-target grow ran commands"
        );
    }

    // Reused backend: the device now carries a different connection identity.
    system
        .backends
        .insert("/dev/nbd3".into(), "reconnected-other".into());
    assert!(execute_with(&plan_grow(&grow_request()), Some(&state), &mut system).is_err());
    assert!(system.steps.is_empty());

    // A matching grow of the live attachment runs both commands.
    let live = state.read("pg").unwrap().unwrap().connection_id;
    system.backends.insert("/dev/nbd3".into(), live);
    execute_with(&plan_grow(&grow_request()), Some(&state), &mut system).unwrap();
    assert_eq!(system.steps, ["lvextend", "xfs-growfs"]);
    // The record is retained: a grow is not a detach.
    assert!(state.read("pg").unwrap().is_some());
}

/// Review R01 (2026-09-07): rollback compensations ran even after an earlier
/// one failed, so a failed umount did not stop the disconnect beneath it —
/// the backing could be torn out from under a still-mounted filesystem. A
/// failed upper-level cleanup must stop the destructive lower-level cleanup.
#[test]
fn audit_20260907_failed_unmount_must_not_disconnect_live_mount() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem {
        fail_after_at: Some("verify-mount-identity"),
        fail_at: Some("umount"),
        ..Default::default()
    };
    assert!(execute_with(&plan_attach(&request()), Some(&state), &mut system).is_err());
    assert!(
        system.mounted,
        "the injected umount failed before its effect"
    );
    assert!(
        !system.steps.contains(&"nbd-disconnect"),
        "rollback attempted NBD disconnect after failed umount: {:?}",
        system.steps
    );
    assert!(system.backends.contains_key("/dev/nbd3"));
    assert!(state.read("pg").unwrap().is_some());
}

/// Review R01 (2026-09-07): a command can report failure *after* its effect
/// took hold. Unlike NbdConnect, a failed mount was not folded into the
/// executed prefix, so rollback skipped its umount while still disconnecting
/// its backing. Rollback re-observes and either unmounts the live mount or
/// leaves its backing connected.
#[test]
fn audit_20260907_mount_failure_after_effect_requires_reobservation() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem {
        fail_after_at: Some("mount-xfs"),
        ..Default::default()
    };
    assert!(execute_with(&plan_attach(&request()), Some(&state), &mut system).is_err());
    // Either verified cleanup removes the mount, or its live backing must stay.
    assert!(
        !system.mounted || system.backends.contains_key("/dev/nbd3"),
        "failed mount command had an effect but rollback disconnected it: {:?}",
        system.steps
    );
}

/// Review R03 (2026-09-07): grow verified only the stored config and the live
/// NBD identity, not the current mount / VG topology, so a replaced mountpoint
/// or a foreign VG mapping (both leaving the record and NBD id intact) still
/// ran lvextend/xfs_growfs. Grow now re-observes the live attachment and
/// refuses before any mutation.
#[test]
fn audit_20260907_grow_rechecks_live_mount_and_vg_topology() {
    for fault in 0..3 {
        let fixture = Fixture::new();
        let state = fixture.state();
        let _lock = state.lock().unwrap();
        let mut system = FakeSystem::default();
        execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap();
        system.steps.clear();
        match fault {
            0 => system.foreign_mount = true,
            1 => system.foreign_vg = true,
            _ => system.observation_error = true,
        }
        // The trusted config and live NBD identifier are unchanged. Only the
        // currently mounted filesystem / active mapping became unsafe.
        let result = execute_with(&plan_grow(&grow_request()), Some(&state), &mut system);
        assert!(result.is_err(), "grow accepted live topology fault {fault}");
        assert!(
            !system.steps.contains(&"lvextend") && !system.steps.contains(&"xfs-growfs"),
            "grow changed storage before rejecting fault {fault}: {:?}",
            system.steps
        );
    }
}

// ---------- Follow-up review 2026-09-08: FUP-001 / FUP-002 / FUP-003 ----------

/// FUP-001: when the live state cannot be re-observed during rollback (EIO /
/// EACCES), the destructive lower-level teardown must halt rather than
/// disconnect a device whose mappings are unknown, and the trusted record must
/// be preserved for recovery.
#[test]
fn followup_observation_failure_after_activation_must_not_disconnect() {
    let f = Fixture::new();
    let state = f.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem {
        fail_after_at: Some("lvm-activate"),
        observation_error: true,
        ..Default::default()
    };
    assert!(execute_with(&plan_attach(&request()), Some(&state), &mut system).is_err());
    assert!(system.vg_active, "fixture must leave activation in effect");
    assert!(
        !system.steps.contains(&"nbd-disconnect"),
        "unknown mappings must block lower teardown: {:?}",
        system.steps
    );
    assert!(
        state.read("pg").unwrap().is_some(),
        "preserve recovery provenance"
    );
}

/// FUP-002: a missing NBD backend does not authorize replacing the trusted
/// record while a live mount / VG / holder remains — that would discard the
/// recovery identity of a still partly-attached volume.
#[test]
fn followup_stale_backend_with_live_mapping_must_not_replace_record() {
    let f = Fixture::new();
    let state = f.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem::default();
    execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap();
    let old = state.read("pg").unwrap().unwrap();
    system.backends.clear();
    system.steps.clear();
    assert!(system.mounted && system.vg_active);
    assert!(execute_with(&plan_attach(&request()), Some(&state), &mut system).is_err());
    assert!(
        system.steps.is_empty(),
        "reattach must not mutate an incompletely detached volume: {:?}",
        system.steps
    );
    assert_eq!(state.read("pg").unwrap().unwrap(), old);
}

/// FUP-003: grow operates in place on a mounted, active filesystem; a missing
/// mount must be refused before any lvextend.
#[test]
fn followup_grow_requires_a_live_mount_before_extending_lv() {
    let f = Fixture::new();
    let state = f.state();
    let _lock = state.lock().unwrap();
    let mut system = FakeSystem::default();
    execute_with(&plan_attach(&request()), Some(&state), &mut system).unwrap();
    system.mounted = false;
    system.steps.clear();
    assert!(execute_with(&plan_grow(&grow_request()), Some(&state), &mut system).is_err());
    assert!(
        system.steps.is_empty(),
        "missing mount must be rejected before lvextend: {:?}",
        system.steps
    );
}

/// Command execution and kernel files are fixtures, while sentinel I/O,
/// mountinfo parsing, the final mount verifier, and executor ordering are
/// the actual implementation. No subprocess or real block device is used.
struct ReviewForeignMountSystem {
    inner: FakeSystem,
    mountinfo: String,
    sysfs: PathBuf,
}

impl ReviewForeignMountSystem {
    fn observe(&self, mountpoint: &str, nbd_device: &str, touch: bool) -> MountObservation {
        let entry = parse_mountinfo(&self.mountinfo, mountpoint);
        let start = entry.as_ref().and_then(|mount| {
            std::fs::read_dir(&self.sysfs)
                .unwrap()
                .flatten()
                .find(|device| {
                    std::fs::read_to_string(device.path().join("dev"))
                        .is_ok_and(|number| number.trim() == mount.major_minor)
                })
                .map(|device| device.file_name().to_string_lossy().into_owned())
        });
        let backing_devices = start
            .map(|start| {
                let mut slaves_of = |name: &str| {
                    std::fs::read_dir(self.sysfs.join(name).join("slaves"))
                        .map(|entries| {
                            entries
                                .flatten()
                                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                                .collect()
                        })
                        .unwrap_or_default()
                };
                resolve_leaf_devices(&start, &mut slaves_of)
                    .into_iter()
                    .map(|leaf| nbd_device_of(&leaf).unwrap_or_else(|| format!("/dev/{leaf}")))
                    .collect()
            })
            .unwrap_or_default();
        MountObservation {
            mountpoint_exists: Path::new(mountpoint).is_dir(),
            fstype: entry.as_ref().map(|entry| entry.fstype.clone()),
            fs_uuid: Some("11111111-2222-4333-8444-555555555555".into()),
            sentinel_volume_uuid: if touch {
                read_sentinel(mountpoint)
            } else {
                None
            },
            nbd_connected: self
                .sysfs
                .join(format!("nbd{}", nbd_index(nbd_device).unwrap()))
                .join("pid")
                .exists(),
            rw_probe_ok: touch && entry.is_some() && rw_probe(mountpoint),
            backing_devices,
        }
    }
}

impl System for ReviewForeignMountSystem {
    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError> {
        self.inner.run_step(step, identifier)?;
        match step {
            PlannedStep::VerifyMountDevice {
                mountpoint,
                nbd_device,
            } => {
                let observed = self.observe(mountpoint, nbd_device, false);
                verify_mount_device(nbd_device, &observed)?;
                Ok(())
            }
            PlannedStep::WriteSentinel {
                mountpoint,
                volume_uuid,
            } => write_sentinel(step, mountpoint, volume_uuid),
            PlannedStep::VerifyMountIdentity {
                mountpoint,
                volume_uuid,
                fs_uuid,
                nbd_device,
            } => {
                let observed = self.observe(mountpoint, nbd_device, true);
                verify_mount_identity(
                    &MountExpectation {
                        fs_uuid: fs_uuid.clone(),
                        volume_uuid: volume_uuid.clone(),
                        nbd_device: nbd_device.clone(),
                    },
                    &observed,
                )?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn wait_ready(&mut self, step: &PlannedStep, device: &str) -> Result<(), ExecError> {
        self.inner.wait_ready(step, device)
    }

    fn allocate(&mut self) -> Result<String, ExecError> {
        self.inner.allocate()
    }

    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        self.inner.backend(device)
    }

    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        crate::detach::observe(record, &self.mountinfo, &self.sysfs)
    }
}

#[test]
fn review_next_attach_rejects_a_logical_volume_backed_by_an_unrelated_disk() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let _lock = state.lock().unwrap();
    let mountpoint = fixture.0.join("filesystem");
    std::fs::create_dir(&mountpoint).unwrap();
    let sysfs = fixture.0.join("sysfs");
    for directory in ["nbd3/holders", "dm-0/dm", "dm-0/slaves/sda", "sda/slaves"] {
        std::fs::create_dir_all(sysfs.join(directory)).unwrap();
    }
    for (path, contents) in [
        ("nbd3/pid", "123\n"),
        ("nbd3/dev", "43:96\n"),
        ("dm-0/dev", "253:0\n"),
        ("dm-0/dm/name", "vg_maki_pg-data\n"),
        ("dm-0/dm/uuid", "LVM-fixture\n"),
    ] {
        std::fs::write(sysfs.join(path), contents).unwrap();
    }
    let mut request = request();
    request.mountpoint = mountpoint.to_str().unwrap().into();
    request.init_sentinel = true;
    // fs_uuid is unpinned, as in the default first-boot configuration. The
    // configured VG/LV resolves to a local-disk mapping, not our NBD export.
    assert!(request.fs_uuid.is_none());
    let mut system = ReviewForeignMountSystem {
        inner: FakeSystem::default(),
        mountinfo: format!(
            "50 1 253:0 / {} rw - xfs /dev/mapper/vg_maki_pg-data rw\n",
            request.mountpoint
        ),
        sysfs,
    };
    let expected_record = BoundDeviceRecord {
        version: 1,
        volume: request.volume.clone(),
        attachment: (&request).into(),
        device: "/dev/nbd3".into(),
        connection_id: "maki-fixture".into(),
    };
    // Positive control: the production topology observer rejects this exact
    // mapping, and the fixture resolves its leaf to the unrelated local disk.
    let topology_error = system.detach_observation(&expected_record).unwrap_err();
    assert!(
        topology_error
            .to_string()
            .contains("not backed exclusively by the recorded NBD device"),
        "{topology_error}"
    );
    assert_eq!(
        system
            .observe(&request.mountpoint, "/dev/nbd3", false)
            .backing_devices,
        ["/dev/sda"]
    );

    let result = execute_with(&plan_attach(&request), Some(&state), &mut system);
    assert!(system.inner.steps.contains(&"verify-mount-device"));
    assert!(
        result.is_err() && read_sentinel(&request.mountpoint).is_none(),
        "attach accepted/initialized a non-NBD filesystem: result={result:?}, sentinel={:?}; commands={:?}",
        read_sentinel(&request.mountpoint),
        system.inner.steps
    );
}
