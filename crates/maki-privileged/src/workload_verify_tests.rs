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
            self.mounts
                .as_deref()
                .unwrap_or(&self.inner.mounts(record))
                .as_bytes(),
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
fn review_f05_existing_record_and_sentinel_accept_volume_uuid_case_changes() {
    for record_upper in [false, true] {
        for config_upper in [false, true] {
            for sentinel_upper in [false, true] {
                let (_fixture, state, mut req, system) = fixture();
                let _lock = state.lock_existing().unwrap();
                let mut record = state.read("pg").unwrap().unwrap();
                if record_upper {
                    record.attachment.volume_uuid.make_ascii_uppercase();
                    state.write(&record).unwrap();
                }
                let sentinel = if sentinel_upper {
                    req.volume_uuid.to_ascii_uppercase()
                } else {
                    req.volume_uuid.clone()
                };
                std::fs::write(Path::new(&req.mountpoint).join(SENTINEL_FILE), sentinel).unwrap();
                if config_upper {
                    req.volume_uuid.make_ascii_uppercase();
                }
                workload_verify::verify_request(&req, &state, &system).unwrap();
            }
        }
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
    // "suid"/"dev": a mount without `nosuid`/`nodev` (one made before
    // R5-002, or remounted) honours setuid bits or device nodes from the
    // untrusted volume and must not be opened to the workload.
    for case in [
        "missing", "ro", "subtree", "stacked", "extra", "suid", "dev",
    ] {
        let (_fixture, state, req, mut system) = fixture();
        let record = state.read("pg").unwrap().unwrap();
        let mount = system.inner.mounts(&record);
        system.mounts = Some(match case {
            "missing" => String::new(),
            "ro" => mount.replace(" rw", " ro"),
            "subtree" => mount.replace("253:0 / ", "253:0 /subdir "),
            "stacked" => format!("{mount}{mount}"),
            "extra" => format!("{mount}41 25 253:0 / /other rw - xfs /dev/dm-0 rw\n"),
            "suid" => mount.replace("rw,nosuid,nodev -", "rw,nodev -"),
            "dev" => mount.replace("rw,nosuid,nodev -", "rw,nosuid -"),
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
                "40 25 253:0 / {} rw,nosuid,nodev - xfs /dev/dm-0 rw\n",
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
                    system.mounts.as_deref().unwrap().as_bytes(),
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
    let root = "40 25 253:0 / / rw,nosuid,nodev - xfs /dev/dm-0 rw\n";
    assert!(recover::observe_complete(&record, root.as_bytes(), &system.inner.sysfs).is_ok());
    let nested = format!("{root}41 40 0:9 / /proc rw - proc proc rw\n");
    assert!(recover::observe_complete(&record, nested.as_bytes(), &system.inner.sysfs).is_err());
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

/// Run `f` on a fresh thread whose effective capability set lacks
/// CAP_FOWNER, as in a workload unit whose `CapabilityBoundingSet=` drops
/// it (`ExecStartPre=!` keeps the bounding set). Linux capabilities belong
/// to a thread, so no other test is affected. None when the capability
/// cannot be dropped this way.
fn without_cap_fowner<T: Send>(f: impl FnOnce() -> T + Send) -> Option<T> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CAP_FOWNER: u32 = 3;
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut header = Header {
                    version: CAPABILITY_VERSION_3,
                    pid: 0,
                };
                let mut data = [Data::default(); 2];
                // SAFETY: header and a two-element data array are the v3 ABI;
                // pid 0 names the calling thread only.
                let read = unsafe {
                    libc::syscall(
                        libc::SYS_capget,
                        &mut header as *mut Header,
                        data.as_mut_ptr(),
                    )
                };
                if read != 0 || data[0].effective & (1 << CAP_FOWNER) == 0 {
                    return None;
                }
                data[0].effective &= !(1 << CAP_FOWNER);
                // SAFETY: as above; dropping an effective capability is always
                // permitted and affects only this thread.
                let set = unsafe {
                    libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr())
                };
                (set == 0).then(f)
            })
            .join()
            .unwrap()
    })
}

#[test]
fn descriptor_sentinel_reader_does_not_need_cap_fowner_for_workload_owned_files() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: fixtures owned by another user need root");
        return;
    }
    // The workload user owns the volume root (and may replace the sentinel);
    // O_NOATIME on an inode the caller does not own needs CAP_FOWNER.
    for workload_owns_root in [true, false] {
        let fixture = Fixture::new();
        let mount = fixture.0.join("mount");
        std::fs::create_dir(&mount).unwrap();
        let sentinel = mount.join(SENTINEL_FILE);
        std::fs::write(&sentinel, "volume\n").unwrap();
        let owned = if workload_owns_root {
            vec![&mount, &sentinel]
        } else {
            vec![&sentinel]
        };
        for path in owned {
            std::os::unix::fs::chown(path, Some(65534), Some(65534)).unwrap();
        }
        let dev = mount.metadata().unwrap().dev();
        let device = (libc::major(dev), libc::minor(dev));
        let read = |device| workload_verify::read_mounted_sentinel(mount.to_str().unwrap(), device);
        assert_eq!(read(device).unwrap(), "volume", "control: with CAP_FOWNER");
        let Some(result) = without_cap_fowner(|| read(device)) else {
            eprintln!("skipping: CAP_FOWNER cannot be dropped from a test thread");
            return;
        };
        assert_eq!(
            result.unwrap(),
            "volume",
            "the gate fails in a unit without CAP_FOWNER (root owned: {})",
            !workload_owns_root
        );
        // The device binding still decides what is read.
        let wrong = (device.0.wrapping_add(1), device.1);
        assert!(without_cap_fowner(|| read(wrong)).unwrap().is_err());
    }
}

#[test]
fn sentinel_opens_drop_only_o_noatime_and_only_when_it_is_refused() {
    let base = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    for (refusal, retried) in [
        (libc::EPERM, true),
        (libc::EACCES, false),
        (libc::ENOENT, false),
        (libc::ELOOP, false),
    ] {
        for retry_fails in [false, true] {
            let calls = RefCell::new(Vec::new());
            let result = workload_verify::open_noatime(base, |flags| {
                calls.borrow_mut().push(flags);
                if flags & libc::O_NOATIME != 0 {
                    Err(io::Error::from_raw_os_error(refusal))
                } else if retry_fails {
                    Err(io::Error::from_raw_os_error(libc::EACCES))
                } else {
                    File::open("/dev/null")
                }
            });
            if retried {
                assert_eq!(*calls.borrow(), [base | libc::O_NOATIME, base]);
                assert_eq!(result.is_ok(), !retry_fails);
            } else {
                assert_eq!(*calls.borrow(), [base | libc::O_NOATIME], "{refusal}");
                assert_eq!(result.unwrap_err().raw_os_error(), Some(refusal));
            }
        }
    }
}

/// The gate reads one file by a path the operator chose, the volume's attach
/// configuration. When it cannot, the error names that file: the operating
/// system's error alone left the journal of a gated workload with "No such
/// file or directory" and no hint of what to create.
#[test]
fn a_gate_names_the_configuration_it_cannot_read() {
    let path = Path::new("/maki-review-no-such-directory/pg.toml");
    let error = workload_verify::gate_config(path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        error.to_string(),
        format!(
            "attach config /maki-review-no-such-directory/pg.toml: {}",
            io::Error::from_raw_os_error(libc::ENOENT)
        )
    );
}
