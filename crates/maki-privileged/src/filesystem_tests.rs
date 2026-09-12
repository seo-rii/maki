use super::*;
use std::os::unix::process::ExitStatusExt;

const FILESYSTEM_UUID: &str = "11111111-2222-4333-8444-555555555555";
const OTHER_UUID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

/// Uses the production executor, kernel observers, sentinel operations and
/// final verifier. Only commands and the filesystem probe are fixtures.
struct FilesystemSystem {
    inner: ObservedSystem,
    filesystem_type: &'static str,
    filesystem_uuid: Option<String>,
    rw_probes: usize,
    filesystem_probes: usize,
    probe_override: Option<std::process::Output>,
    replace_mapping_before_probe: bool,
    replace_mapping_after_probe: bool,
}

impl System for FilesystemSystem {
    fn recovery_proof(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<Option<recover::RecoveryProof>> {
        let proof = self.inner.recovery_proof(record)?;
        if self.replace_mapping_before_probe {
            std::fs::write(self.inner.sysfs.join("dm-0/dm/uuid"), "foreign-mapper\n")?;
        }
        Ok(proof)
    }

    fn recovery_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        self.inner.recovery_observation(record)
    }

    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError> {
        self.inner.run_step(step, identifier)?;
        match step {
            PlannedStep::VerifyFilesystemIdentity { fs_uuid, .. } => {
                self.filesystem_probes += 1;
                let output = self.probe_override.take().unwrap_or_else(|| {
                    probe_output(
                        0,
                        format!(
                            "TYPE={}\n{}",
                            self.filesystem_type,
                            self.filesystem_uuid
                                .as_ref()
                                .map(|uuid| format!("UUID={uuid}\n"))
                                .unwrap_or_default()
                        )
                        .as_bytes(),
                    )
                });
                verify_filesystem_probe(fs_uuid.as_deref(), &output)?;
                if self.replace_mapping_after_probe {
                    std::fs::write(self.inner.sysfs.join("dm-0/dm/uuid"), "foreign-mapper\n")?;
                }
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
                self.rw_probes += 1;
                verify_mount_identity(
                    &MountExpectation {
                        fs_uuid: fs_uuid.clone(),
                        volume_uuid: volume_uuid.clone(),
                        nbd_device: nbd_device.clone(),
                    },
                    &MountObservation {
                        mountpoint_exists: Path::new(mountpoint).is_dir(),
                        fstype: Some(self.filesystem_type.into()),
                        fs_uuid: self.filesystem_uuid.clone(),
                        sentinel_volume_uuid: read_sentinel(mountpoint),
                        nbd_connected: self.inner.backend(nbd_device)?.is_some(),
                        rw_probe_ok: rw_probe(mountpoint),
                        backing_devices: vec![nbd_device.clone()],
                    },
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
        self.inner.detach_observation(record)
    }

    fn rollback_observation(
        &self,
        record: &BoundDeviceRecord,
        allow_missing: bool,
    ) -> io::Result<DetachObservation> {
        self.inner.rollback_observation(record, allow_missing)
    }
}

fn filesystem_fixture() -> (Fixture, TrustedState, AttachRequest, FilesystemSystem) {
    let fixture = Fixture::new();
    let state = fixture.state();
    let mut req = request();
    req.fs_uuid = Some(FILESYSTEM_UUID.into());
    req.init_sentinel = true;
    req.mountpoint = fixture.0.join("mount").to_str().unwrap().into();
    std::fs::create_dir(&req.mountpoint).unwrap();
    let sysfs = fixture.0.join("sys");
    std::fs::create_dir_all(sysfs.join("nbd3/holders")).unwrap();
    std::fs::write(sysfs.join("nbd3/dev"), "43:3\n").unwrap();
    let system = FilesystemSystem {
        inner: ObservedSystem {
            fake: FakeSystem::default(),
            sysfs,
        },
        filesystem_type: "xfs",
        filesystem_uuid: Some(FILESYSTEM_UUID.into()),
        rw_probes: 0,
        filesystem_probes: 0,
        probe_override: None,
        replace_mapping_before_probe: false,
        replace_mapping_after_probe: false,
    };
    (fixture, state, req, system)
}

fn assert_mount_was_not_attempted(req: &AttachRequest, system: &FilesystemSystem) {
    assert!(
        !system.inner.fake.steps.contains(&"mount-xfs"),
        "filesystem rejection happened after mount: {:?}",
        system.inner.fake.steps
    );
    assert!(read_sentinel(&req.mountpoint).is_none());
    assert_eq!(system.rw_probes, 0);
}

#[test]
fn mismatched_filesystem_uuid_refuses_before_mount_or_sentinel_write() {
    let (_fixture, state, req, mut system) = filesystem_fixture();
    let _lock = state.lock().unwrap();
    system.filesystem_uuid = Some(OTHER_UUID.into());
    let error = execute_with(&plan_attach(&req), Some(&state), &mut system).unwrap_err();
    assert!(
        error.to_string().contains("filesystem UUID mismatch"),
        "{error}"
    );
    assert_mount_was_not_attempted(&req, &system);
}

#[test]
fn non_xfs_filesystem_refuses_before_mount_even_without_uuid_pin() {
    let (_fixture, state, mut req, mut system) = filesystem_fixture();
    let _lock = state.lock().unwrap();
    req.fs_uuid = None;
    system.filesystem_type = "ext4";
    let error = execute_with(&plan_attach(&req), Some(&state), &mut system).unwrap_err();
    assert!(error.to_string().contains("is not XFS"), "{error}");
    assert_mount_was_not_attempted(&req, &system);
}

fn probe_output(status: i32, stdout: &[u8]) -> std::process::Output {
    std::process::Output {
        status: std::process::ExitStatus::from_raw(status << 8),
        stdout: stdout.to_vec(),
        stderr: Vec::new(),
    }
}

#[test]
fn matching_filesystem_and_optional_uuid_contract_still_attach() {
    for pinned in [true, false] {
        let (_fixture, state, mut req, mut system) = filesystem_fixture();
        let _lock = state.lock().unwrap();
        if !pinned {
            req.fs_uuid = None;
            system.filesystem_uuid = None;
        }
        execute_with(&plan_attach(&req), Some(&state), &mut system).unwrap();
        assert_eq!(system.filesystem_probes, 1);
        assert_eq!(system.rw_probes, 1);
        assert_eq!(
            read_sentinel(&req.mountpoint),
            Some(req.volume_uuid.clone())
        );
        assert!(system.inner.fake.mounted);
        assert!(state.read("pg").unwrap().unwrap().recovery.is_some());
    }
}

#[test]
fn missing_pinned_uuid_and_failed_or_ambiguous_probes_never_mount() {
    for output in [
        probe_output(0, b"TYPE=xfs\n"),
        probe_output(2, b"TYPE=xfs\n"),
        probe_output(4, b"TYPE=xfs\n"),
        probe_output(8, format!("TYPE=xfs\nUUID={FILESYSTEM_UUID}\n").as_bytes()),
    ] {
        let (_fixture, state, req, mut system) = filesystem_fixture();
        let _lock = state.lock().unwrap();
        system.probe_override = Some(output);
        assert!(execute_with(&plan_attach(&req), Some(&state), &mut system).is_err());
        assert_eq!(system.filesystem_probes, 1);
        assert_mount_was_not_attempted(&req, &system);
        assert!(state.read("pg").unwrap().is_none());
    }
}

#[test]
fn filesystem_probe_rejects_malformed_or_conflicting_identity_evidence() {
    for stdout in [
        Vec::new(),
        b"UUID=11111111-2222-4333-8444-555555555555\n".to_vec(),
        b"TYPE=xfs\nTYPE=ext4\n".to_vec(),
        format!("TYPE=xfs\nUUID={FILESYSTEM_UUID}\nUUID={OTHER_UUID}\n").into_bytes(),
        b"TYPE=xfs\nnot-a-tag\n".to_vec(),
        b"TYPE=xfs\nUUID=\0hidden\n".to_vec(),
        b"TYPE=xfs\nUUID=\xff\n".to_vec(),
        vec![b'x'; command::Policy::PROBE.max_output_bytes + 1],
    ] {
        assert!(
            verify_filesystem_probe(Some(FILESYSTEM_UUID), &probe_output(0, &stdout)).is_err(),
            "accepted malformed identity evidence"
        );
    }
    // Export order is not specified, and an informational DEVNAME must not
    // be used instead of the device independently selected by the plan.
    verify_filesystem_probe(
        Some(FILESYSTEM_UUID),
        &probe_output(
            0,
            format!("UUID={FILESYSTEM_UUID}\nDEVNAME=/untrusted/alias\nTYPE=xfs\n").as_bytes(),
        ),
    )
    .unwrap();
}

#[test]
fn changed_backend_during_filesystem_probe_never_mounts_or_cleans_foreign_state() {
    let (_fixture, state, req, mut system) = filesystem_fixture();
    let _lock = state.lock().unwrap();
    system.inner.fake.backend_fault_after =
        Some(("verify-filesystem-identity", BackendFault::Foreign));
    assert!(execute_with(&plan_attach(&req), Some(&state), &mut system).is_err());
    assert_eq!(system.filesystem_probes, 1);
    assert_mount_was_not_attempted(&req, &system);
    assert!(state.read("pg").unwrap().is_some());
    assert!(!system.inner.fake.steps.contains(&"lvm-deactivate"));
    assert!(!system.inner.fake.steps.contains(&"nbd-disconnect"));
}

#[test]
fn mapping_identity_is_checked_before_and_after_the_filesystem_probe() {
    for replace_before in [true, false] {
        let (_fixture, state, req, mut system) = filesystem_fixture();
        let _lock = state.lock().unwrap();
        system.replace_mapping_before_probe = replace_before;
        system.replace_mapping_after_probe = !replace_before;
        assert!(execute_with(&plan_attach(&req), Some(&state), &mut system).is_err());
        assert_eq!(system.filesystem_probes, usize::from(!replace_before));
        assert_mount_was_not_attempted(&req, &system);
        assert!(state.read("pg").unwrap().is_some());
        assert!(!system.inner.fake.steps.contains(&"lvm-deactivate"));
        assert!(!system.inner.fake.steps.contains(&"nbd-disconnect"));
    }
}
