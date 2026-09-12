use super::*;
use std::cell::RefCell;
use std::os::unix::process::ExitStatusExt;

const FS_UUID: &str = "11111111-2222-4333-8444-555555555555";

struct GateSystem {
    inner: ObservedSystem,
    calls: RefCell<Vec<&'static str>>,
    mounts: Option<String>,
    filesystem: String,
    change_mapping_after_probe: bool,
    change_mapping_after_sentinel: bool,
}

impl workload_verify::WorkloadSystem for GateSystem {
    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        self.calls.borrow_mut().push("backend");
        self.inner.backend(device)
    }

    fn mounted(&self, record: &BoundDeviceRecord) -> io::Result<recover::VerifiedMount> {
        self.calls.borrow_mut().push("kernel");
        recover::observe_complete(
            record,
            self.mounts.as_deref().unwrap_or(&self.inner.mounts(record)),
            &self.inner.sysfs,
        )
    }

    fn filesystem(
        &self,
        _record: &BoundDeviceRecord,
        _mount: &recover::VerifiedMount,
        uuid: &str,
    ) -> Result<(), ExecError> {
        self.calls.borrow_mut().push("filesystem");
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: self.filesystem.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        let result = verify_filesystem_probe(Some(uuid), &output);
        if self.change_mapping_after_probe {
            std::fs::write(self.inner.sysfs.join("dm-0/dm/uuid"), "LVM-replaced\n").unwrap();
        }
        result
    }

    fn sentinel(
        &self,
        record: &BoundDeviceRecord,
        _mount: &recover::VerifiedMount,
    ) -> io::Result<String> {
        self.calls.borrow_mut().push("sentinel");
        let value = read_sentinel(&record.attachment.mountpoint)
            .ok_or_else(|| io::Error::other("sentinel unavailable"));
        if self.change_mapping_after_sentinel {
            std::fs::write(self.inner.sysfs.join("dm-0/dm/uuid"), "LVM-replaced\n").unwrap();
        }
        value
    }
}

fn fixture() -> (Fixture, TrustedState, AttachRequest, GateSystem) {
    let fixture = Fixture::new();
    let state = fixture.state();
    let lock = state.lock().unwrap();
    let mut req = request();
    req.fs_uuid = Some(FS_UUID.into());
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
    let mut inner = ObservedSystem {
        fake: FakeSystem::default(),
        sysfs,
    };
    execute_with(&plan_attach(&req), Some(&state), &mut inner).unwrap();
    inner.fake.steps.clear();
    inner.fake.backend_probes.set(0);
    let system = GateSystem {
        inner,
        calls: RefCell::new(Vec::new()),
        mounts: None,
        filesystem: format!("TYPE=xfs\nUUID={FS_UUID}\n"),
        change_mapping_after_probe: false,
        change_mapping_after_sentinel: false,
    };
    drop(lock);
    (fixture, state, req, system)
}

#[test]
fn gate_is_repeatable_without_commands_record_changes_or_probe_files() {
    let (fixture, state, req, system) = fixture();
    let record = std::fs::read(fixture.0.join("state/pg.nbd")).unwrap();
    let _lock = state.lock_existing().unwrap();
    for _ in 0..2 {
        workload_verify::verify_request(&req, &state, &system).unwrap();
        assert!(system.inner.fake.steps.is_empty());
        assert_eq!(
            std::fs::read(fixture.0.join("state/pg.nbd")).unwrap(),
            record
        );
        assert_eq!(std::fs::read_dir(&req.mountpoint).unwrap().count(), 1);
    }
}

#[test]
fn absent_foreign_or_unreadable_backend_never_opens_the_filesystem() {
    for fault in [
        BackendFault::Missing,
        BackendFault::Foreign,
        BackendFault::Unreadable,
    ] {
        let (_fixture, state, req, mut system) = fixture();
        system.inner.fake.backend_fault_on_probe = Some((1, fault));
        assert!(workload_verify::verify_request(&req, &state, &system).is_err());
        assert_eq!(*system.calls.borrow(), ["backend"]);
        assert!(system.inner.fake.steps.is_empty());
    }
}

#[test]
fn missing_proof_changed_config_or_device_and_unpinned_uuid_refuse_before_reads() {
    for case in ["proof", "config", "device", "uuid"] {
        let (_fixture, state, mut req, system) = fixture();
        match case {
            "proof" => {
                let mut record = state.read("pg").unwrap().unwrap();
                record.recovery = None;
                state.write(&record).unwrap();
            }
            "config" => req.volume_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into(),
            "device" => req.nbd_device = "/dev/nbd4".into(),
            "uuid" => req.fs_uuid = None,
            _ => unreachable!(),
        }
        assert!(
            workload_verify::verify_request(&req, &state, &system).is_err(),
            "{case}"
        );
        assert!(system.calls.borrow().is_empty(), "{case}");
    }
}

#[test]
fn complete_mapping_proof_is_required_before_filesystem_reads() {
    for case in [
        "changed_uuid",
        "missing_mapping",
        "missing_edge",
        "extra_holder",
    ] {
        let (_fixture, state, req, system) = fixture();
        match case {
            "changed_uuid" => {
                std::fs::write(system.inner.sysfs.join("dm-0/dm/uuid"), "LVM-other\n").unwrap()
            }
            "missing_mapping" => {
                std::fs::remove_dir_all(system.inner.sysfs.join("dm-0")).unwrap();
                std::fs::remove_file(system.inner.sysfs.join("nbd3/holders/dm-0")).unwrap();
            }
            "missing_edge" => {
                std::fs::remove_file(system.inner.sysfs.join("nbd3/holders/dm-0")).unwrap()
            }
            "extra_holder" => {
                std::fs::write(system.inner.sysfs.join("nbd3/holders/dm-99"), "").unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            workload_verify::verify_request(&req, &state, &system).is_err(),
            "{case}"
        );
        assert!(!system.calls.borrow().contains(&"filesystem"), "{case}");
        assert!(!system.calls.borrow().contains(&"sentinel"), "{case}");
    }
}

#[test]
fn cleanup_subset_evidence_does_not_authorize_a_workload_start() {
    let (_fixture, state, req, mut system) = fixture();
    let partition = system.inner.sysfs.join("nbd3p1");
    std::fs::create_dir_all(partition.join("holders")).unwrap();
    std::fs::write(partition.join("dev"), "43:4\n").unwrap();
    std::fs::write(partition.join("partition"), "1\n").unwrap();
    let mut record = state.read("pg").unwrap().unwrap();
    system.inner.fake.mounted = false;
    record.recovery = system.inner.recovery_proof(&record).unwrap();
    state.write(&record).unwrap();
    system.inner.fake.mounted = true;
    std::fs::remove_dir_all(partition).unwrap();
    assert!(
        system.inner.recovery_observation(&record).unwrap().mounted,
        "cleanup deliberately accepts the surviving subset"
    );
    assert!(workload_verify::verify_request(&req, &state, &system).is_err());
    assert!(!system.calls.borrow().contains(&"filesystem"));
    assert!(!system.calls.borrow().contains(&"sentinel"));
}

#[test]
fn missing_read_only_subtree_stacked_or_extra_mounts_refuse_the_gate() {
    for case in ["missing", "ro", "subtree", "stacked", "extra"] {
        let (_fixture, state, req, mut system) = fixture();
        let record = state.read("pg").unwrap().unwrap();
        let mount = system.inner.mounts(&record);
        system.mounts = Some(match case {
            "missing" => String::new(),
            "ro" => mount.replace(" rw", " ro"),
            "subtree" => mount.replace("253:0 / ", "253:0 /subdir "),
            "stacked" => format!("{mount}{mount}"),
            "extra" => format!("{mount}41 25 253:0 / /other rw - xfs /dev/dm-0 rw\n"),
            _ => unreachable!(),
        });
        assert!(
            workload_verify::verify_request(&req, &state, &system).is_err(),
            "{case}"
        );
        assert!(!system.calls.borrow().contains(&"filesystem"), "{case}");
    }
}

fn mountinfo_path(path: &str) -> String {
    path.replace('\\', "\\134").replace(' ', "\\040")
}

#[test]
fn foreign_descendant_mounts_refuse_the_gate_before_filesystem_reads() {
    for mount_name in ["mount", "mount with spaces", "mount\\literal"] {
        for child_first in [false, true] {
            let (fixture, state, mut req, mut system) = fixture();
            let mountpoint = fixture.0.join(mount_name);
            if Path::new(&req.mountpoint) != mountpoint {
                std::fs::rename(&req.mountpoint, &mountpoint).unwrap();
                req.mountpoint = mountpoint.to_str().unwrap().into();
            }
            let mut record = state.read("pg").unwrap().unwrap();
            record.attachment.mountpoint = req.mountpoint.clone();
            state.write(&record).unwrap();
            let root_mount = format!(
                "40 25 253:0 / {} rw - xfs /dev/dm-0 rw\n",
                mountinfo_path(&req.mountpoint)
            );
            let child_mount = format!(
                "41 40 8:1 / {} rw - ext4 /dev/sda1 rw\n",
                mountinfo_path(&format!("{}/data", req.mountpoint))
            );
            system.mounts = Some(if child_first {
                format!("{child_mount}{root_mount}")
            } else {
                format!("{root_mount}{child_mount}")
            });
            assert!(
                recover::observe(
                    &record,
                    system.mounts.as_deref().unwrap(),
                    &system.inner.sysfs
                )
                .is_ok(),
                "the existing cleanup observer keeps its prior contract"
            );
            assert!(
                workload_verify::verify_request(&req, &state, &system).is_err(),
                "foreign data path hidden below {mount_name}, child_first={child_first}"
            );
            assert!(!system.calls.borrow().contains(&"filesystem"));
            assert!(!system.calls.borrow().contains(&"sentinel"));
            assert!(system.inner.fake.steps.is_empty());
        }
    }
}

#[test]
fn unrelated_sibling_mount_with_the_same_text_prefix_does_not_block_the_gate() {
    let (_fixture, state, req, mut system) = fixture();
    let record = state.read("pg").unwrap().unwrap();
    let sibling = format!(
        "41 25 8:1 / {}-other/data rw - ext4 /dev/sda1 rw\n",
        mountinfo_path(&req.mountpoint)
    );
    system.mounts = Some(format!("{}{sibling}", system.inner.mounts(&record)));
    workload_verify::verify_request(&req, &state, &system).unwrap();
    assert!(system.inner.fake.steps.is_empty());
}

#[test]
fn root_mount_gate_treats_every_other_absolute_mount_as_a_descendant() {
    let (_fixture, state, _req, system) = fixture();
    crate::config::check_abs_path("mountpoint", "/").unwrap();
    let mut record = state.read("pg").unwrap().unwrap();
    record.attachment.mountpoint = "/".into();
    let root = "40 25 253:0 / / rw - xfs /dev/dm-0 rw\n";
    assert!(recover::observe_complete(&record, root, &system.inner.sysfs).is_ok());
    let nested = format!("{root}41 40 0:9 / /proc rw - proc proc rw\n");
    assert!(recover::observe_complete(&record, &nested, &system.inner.sysfs).is_err());
}

#[test]
fn filesystem_pin_and_sentinel_must_both_match_without_initialization() {
    for case in [
        "fs_uuid",
        "fstype",
        "ambiguous",
        "sentinel",
        "missing_sentinel",
    ] {
        let (_fixture, state, mut req, mut system) = fixture();
        req.init_sentinel = true; // A first-attach option never authorizes gate writes.
        let sentinel = Path::new(&req.mountpoint).join(SENTINEL_FILE);
        match case {
            "fs_uuid" => system.filesystem = "TYPE=xfs\nUUID=wrong\n".into(),
            "fstype" => system.filesystem = format!("TYPE=ext4\nUUID={FS_UUID}\n"),
            "ambiguous" => {
                system.filesystem = format!("TYPE=xfs\nUUID={FS_UUID}\nUUID={FS_UUID}\n")
            }
            "sentinel" => std::fs::write(&sentinel, "wrong").unwrap(),
            "missing_sentinel" => std::fs::remove_file(&sentinel).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            workload_verify::verify_request(&req, &state, &system).is_err(),
            "{case}"
        );
        assert!(system.inner.fake.steps.is_empty());
        if case == "missing_sentinel" {
            assert!(!sentinel.exists());
        }
    }
}

#[test]
fn topology_and_backend_are_rechecked_after_each_filesystem_read() {
    for after_sentinel in [false, true] {
        let (_fixture, state, req, mut system) = fixture();
        system.change_mapping_after_probe = !after_sentinel;
        system.change_mapping_after_sentinel = after_sentinel;
        assert!(workload_verify::verify_request(&req, &state, &system).is_err());
        assert_eq!(system.calls.borrow().contains(&"sentinel"), after_sentinel);
    }
    let (_fixture, state, req, system) = fixture();
    workload_verify::verify_request(&req, &state, &system).unwrap();
    let probes = system.inner.fake.backend_probes.get();
    assert_eq!(probes, 6);
    for probe in 1..=probes {
        for fault in [
            BackendFault::Missing,
            BackendFault::Foreign,
            BackendFault::Unreadable,
        ] {
            let (_fixture, state, req, mut system) = fixture();
            system.inner.fake.backend_fault_on_probe = Some((probe, fault));
            assert!(
                workload_verify::verify_request(&req, &state, &system).is_err(),
                "probe {probe}: {fault:?}"
            );
            assert!(system.inner.fake.steps.is_empty());
        }
    }
}

#[test]
fn descriptor_sentinel_reader_rejects_wrong_devices_links_and_unbounded_files() {
    let fixture = Fixture::new();
    let mount = fixture.0.join("mount");
    std::fs::create_dir(&mount).unwrap();
    let sentinel = mount.join(SENTINEL_FILE);
    std::fs::write(&sentinel, "volume\n").unwrap();
    let dev = mount.metadata().unwrap().dev();
    let device = (libc::major(dev), libc::minor(dev));
    let read = || workload_verify::read_mounted_sentinel(mount.to_str().unwrap(), device);
    let file = File::open(&sentinel).unwrap();
    let old_access = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
    file.set_times(std::fs::FileTimes::new().set_accessed(old_access))
        .unwrap();
    assert_eq!(read().unwrap(), "volume");
    assert_eq!(file.metadata().unwrap().accessed().unwrap(), old_access);
    assert!(workload_verify::read_mounted_sentinel(
        mount.to_str().unwrap(),
        (device.0.wrapping_add(1), device.1)
    )
    .is_err());
    std::fs::write(&sentinel, vec![b'x'; SENTINEL_MAX_BYTES as usize + 1]).unwrap();
    assert!(read().is_err());
    std::fs::remove_file(&sentinel).unwrap();
    let outside = fixture.0.join("outside");
    std::fs::write(&outside, "volume").unwrap();
    std::os::unix::fs::symlink(&outside, &sentinel).unwrap();
    assert!(read().is_err());
    std::fs::remove_file(&sentinel).unwrap();
    std::fs::create_dir(&sentinel).unwrap();
    assert!(read().is_err());
    std::fs::remove_dir(&sentinel).unwrap();
    let fifo = std::ffi::CString::new(sentinel.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(read().is_err());
}
