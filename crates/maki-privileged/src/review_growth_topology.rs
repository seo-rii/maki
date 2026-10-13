//! BUG-076: unsupported PV topology is rejected before in-place mutation.

use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "maki-review-grow-{}-{}",
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

struct GrowthSystem {
    root: PathBuf,
    connection: String,
    mountpoint: String,
    size: u64,
    add_partition: bool,
    fail_after_extension: bool,
    steps: Vec<&'static str>,
}

impl GrowthSystem {
    fn mounts(&self) -> String {
        format!(
            "40 25 253:0 / {} rw,nosuid,nodev - xfs /dev/mapper/vg_maki_pg-data rw\n",
            self.mountpoint
        )
    }
}

impl System for GrowthSystem {
    fn run_step(&mut self, step: &PlannedStep, _: Option<&str>) -> Result<(), ExecError> {
        self.steps.push(step.kind());
        match step {
            PlannedStep::LvExtend { target_bytes, .. } => {
                self.size = *target_bytes;
                if self.add_partition {
                    std::fs::write(self.root.join("dm-0/slaves/nbd3p2"), "").unwrap();
                    std::fs::write(self.root.join("nbd3p2/holders/dm-0"), "").unwrap();
                }
                if std::mem::take(&mut self.fail_after_extension) {
                    return Err(identity_error(
                        "extension completed before injected command failure",
                    ));
                }
            }
            PlannedStep::XfsGrowfs { .. } => {}
            _ => return Err(identity_error("unexpected growth step")),
        }
        Ok(())
    }

    fn wait_ready(&mut self, _: &PlannedStep, _: &str) -> Result<(), ExecError> {
        panic!("no device readiness in growth")
    }
    fn allocate(&mut self) -> Result<String, ExecError> {
        panic!("no allocation in growth")
    }
    fn backend(&self, _: &str) -> io::Result<Option<String>> {
        Ok(Some(self.connection.clone()))
    }
    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        crate::detach::observe(record, &self.mounts(), &self.root)
    }
    fn recovery_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        recover::observe(record, &self.mounts(), &self.root)
    }
    fn lv_size(&self, _: &str, _: &str) -> Result<u64, ExecError> {
        Ok(self.size)
    }
}

fn setup(partitioned: bool) -> (Fixture, TrustedState, Plan, BoundDeviceRecord, GrowthSystem) {
    let fixture = Fixture::new();
    let state = fixture.state();
    let request = crate::config::parse(
        "volume_uuid = '0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c'\nnbd_device = '/dev/nbd3'\n",
    )
    .unwrap()
    .into_request("pg", crate::config::AttachOverrides::default(), true)
    .unwrap();
    let root = fixture.0.join("sys");
    let names = if partitioned {
        vec!["nbd3", "nbd3p1", "nbd3p2", "dm-0"]
    } else {
        vec!["nbd3", "dm-0"]
    };
    for name in names {
        for directory in ["holders", "slaves"] {
            std::fs::create_dir_all(root.join(name).join(directory)).unwrap();
        }
    }
    std::fs::create_dir_all(root.join("dm-0/dm")).unwrap();
    for (path, content) in [
        ("nbd3/dev", "43:96"),
        ("dm-0/dev", "253:0"),
        ("dm-0/dm/name", "vg_maki_pg-data"),
        ("dm-0/dm/uuid", "LVM-fixture"),
    ] {
        std::fs::write(root.join(path), content).unwrap();
    }
    let pv = if partitioned {
        for (path, content) in [
            ("nbd3p1/dev", "43:97"),
            ("nbd3p2/dev", "43:98"),
            ("nbd3p1/partition", "1"),
            ("nbd3p2/partition", "2"),
        ] {
            std::fs::write(root.join(path), content).unwrap();
        }
        "nbd3p1"
    } else {
        "nbd3"
    };
    std::fs::write(root.join("dm-0/slaves").join(pv), "").unwrap();
    std::fs::write(root.join(pv).join("holders/dm-0"), "").unwrap();
    let mut record = BoundDeviceRecord {
        version: 1,
        volume: request.volume.clone(),
        attachment: (&request).into(),
        device: request.nbd_device.clone(),
        connection_id: "maki-11111111-2222-3333-4444-555555555555".into(),
        recovery: None,
        recovery_intent: None,
    };
    record.recovery = Some(recover::capture(&record, "", &root).unwrap());
    state.write(&record).unwrap();
    let plan = crate::plan::plan_grow(&crate::plan::GrowRequest {
        volume: request.volume,
        volume_uuid: request.volume_uuid,
        nbd_socket: request.nbd_socket,
        vg_name: request.vg_name,
        lv_name: request.lv_name,
        lvm_identity: None,
        target_bytes: 2 << 30,
        mountpoint: request.mountpoint.clone(),
    });
    let system = GrowthSystem {
        root,
        connection: record.connection_id.clone(),
        mountpoint: request.mountpoint,
        size: 1 << 30,
        add_partition: partitioned,
        fail_after_extension: false,
        steps: Vec::new(),
    };
    (fixture, state, plan, record, system)
}

#[test]
fn partition_pv_growth_is_refused_before_lv_or_filesystem_mutation() {
    let (_fixture, state, plan, record, mut system) = setup(true);
    recover::observe_complete(&record, &system.mounts(), &system.root).unwrap();
    let result = execute_with(&plan, Some(&state), &mut system);
    assert!(
        result.is_err(),
        "partition growth must be refused until proof transitions are supported"
    );
    assert!(
        system.steps.is_empty(),
        "mutation preceded refusal: {:?}",
        system.steps
    );
    assert_eq!(system.size, 1 << 30);
    assert_eq!(state.read(&record.volume).unwrap(), Some(record.clone()));
    recover::observe_complete(&record, &system.mounts(), &system.root).unwrap();
}

#[test]
fn partition_growth_retry_preserves_the_original_live_attachment() {
    let (_fixture, state, plan, record, mut system) = setup(true);
    for _ in 0..2 {
        assert!(execute_with(&plan, Some(&state), &mut system).is_err());
        assert!(
            system.steps.is_empty(),
            "unsupported retry changed the mapping"
        );
        recover::observe_complete(&record, &system.mounts(), &system.root).unwrap();
    }
}

#[test]
fn already_sized_partition_lv_does_not_bypass_the_growth_topology_gate() {
    let (_fixture, state, plan, _, mut system) = setup(true);
    system.size = 2 << 30;
    assert!(execute_with(&plan, Some(&state), &mut system).is_err());
    assert!(
        system.steps.is_empty(),
        "xfs-growfs ran on an unsupported topology"
    );
}

#[test]
fn whole_device_pv_growth_reaches_xfs_and_preserves_the_proof() {
    let (_fixture, state, plan, record, mut system) = setup(false);
    execute_with(&plan, Some(&state), &mut system).unwrap();
    assert_eq!(system.steps, ["lvextend", "xfs-growfs"]);
    assert_eq!(system.size, 2 << 30);
    assert_eq!(state.read(&record.volume).unwrap(), Some(record.clone()));
    recover::observe_complete(&record, &system.mounts(), &system.root).unwrap();
}

#[test]
fn whole_device_retry_after_completed_lvextend_only_grows_xfs() {
    let (_fixture, state, plan, record, mut system) = setup(false);
    system.fail_after_extension = true;
    assert!(execute_with(&plan, Some(&state), &mut system).is_err());
    assert_eq!(system.size, 2 << 30);
    system.steps.clear();
    execute_with(&plan, Some(&state), &mut system).unwrap();
    assert_eq!(system.steps, ["xfs-growfs"]);
    recover::observe_complete(&record, &system.mounts(), &system.root).unwrap();
}

#[test]
fn foreign_mapping_is_still_refused_before_growth() {
    let (_fixture, state, plan, _, mut system) = setup(false);
    std::fs::write(system.root.join("dm-0/dm/uuid"), "LVM-foreign").unwrap();
    assert!(execute_with(&plan, Some(&state), &mut system).is_err());
    assert!(system.steps.is_empty());
}
