use super::*;
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use crate::config::{parse, AttachOverrides};
use crate::plan::{plan_attach, plan_detach, AttachRequest, AUTO_NBD_DEVICE};

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
    system.backends.clear();
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
