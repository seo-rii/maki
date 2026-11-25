//! Step-fault sweeps for attach, detach, cleanup and the failed-start hook.
//!
//! The production executor, observers and trusted state run against a
//! simulated kernel: a fake `/sys/class/block` tree and a mount table that
//! only the simulated commands change. Every external command and every
//! observation is a numbered injection point. A command can exit nonzero, be
//! terminated by a signal or time out, each before or after it took effect,
//! and the helper itself can die at any point (a start timeout, the OOM
//! killer). After each fault the sweeps follow the packaged lifecycle and
//! require it to converge: nothing live, no record, and a fresh attach that
//! succeeds.
//!
//! The model is one volume with one linear LV on `/dev/nbd3`, or on a second
//! device, `/dev/nbd4`, where a sweep adds one. It knows what the helper's
//! ordering depends on: LVM finds a volume group by reading its metadata
//! from the PV, so every LVM command needs the daemon to be serving the
//! device, while `dmsetup` and the netlink disconnect do not; and netlink
//! NBD keeps a connection's `pid` and `backend` attributes after its server
//! died, until the device is disconnected and nothing holds it open.
//!
//! Something can have `/dev/nbd3` open without being a holder that sysfs
//! shows: a udev probe, an LVM scan, a monitoring agent. Every open holds a
//! reference to the device's configuration in the kernel. While the device
//! is unconnected, the kernel then refuses a connect as busy, which the
//! helper reports once its retries are over; and after an acknowledged
//! disconnect the device keeps showing the connection until the opener has
//! closed it. The kernel acknowledges a disconnect of a device that is
//! already disconnected, or has no connection. An opener can arrive or
//! leave, and the daemon can die, right before any command of a verb.
//! Real LVM, device-mapper, NBD and systemd are not involved. The helper
//! connects and disconnects with its own netlink requests rather than a
//! command; their endings are swept like a command's: a refusal (exit
//! status), an answer that never came (a timeout, a signal) and the helper
//! dying, each before or after the kernel applied the request.

use super::*;

use std::cell::{Cell, RefCell};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::{parse, AttachOverrides};
use crate::plan::{plan_attach, plan_detach, AttachRequest};

const VOLUME_UUID: &str = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";
const VG_UUID: &str = "aaaaaa-bbbb-cccc-dddd-eeee-ffff-gggggg";
const LV_UUID: &str = "hhhhhh-iiii-jjjj-kkkk-llll-mmmm-nnnnnn";
const PV_UUID: &str = "111111-2222-3333-4444-5555-6666-777777";
const DEVICE: &str = "/dev/nbd3";
const MAPPING: &str = "vg_maki_pg-data";
/// Marks the panic that stands for the helper process dying.
const HELPER_DIED: &str = "simulated helper death";

static WORLDS: AtomicU64 = AtomicU64::new(0);

/// Keep the hundreds of simulated deaths out of a failing sweep's output.
fn silence_simulated_deaths() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let simulated = info
                .payload()
                .downcast_ref::<String>()
                .is_some_and(|text| text.contains(HELPER_DIED));
            if !simulated {
                previous(info);
            }
        }));
    });
}

#[derive(Clone, Debug)]
struct Connection {
    /// `/dev/nbd3` or `/dev/nbd4`.
    device: String,
    backend: String,
    /// The daemon behind this connection still answers I/O.
    served: bool,
    /// The disconnect request ran. The kernel drops the connection once
    /// nothing holds the device open.
    disconnecting: bool,
}

#[derive(Clone, Debug, Default)]
struct Kernel {
    connection: Option<Connection>,
    mapped: bool,
    mounted: bool,
    sentinel: Option<String>,
    daemon_running: bool,
    /// Something has `/dev/nbd3` open that sysfs does not show as a holder.
    opener: bool,
}

/// What happens right before a numbered command of one verb.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Schedule {
    opener_opens_before: Option<usize>,
    opener_closes_before: Option<usize>,
    daemon_dies_before: Option<usize>,
    /// The opener closes after the executor's sleep of this number, counted
    /// from 1 in the verb: while it waits for a disconnected connection to
    /// go.
    opener_closes_after_sleep: Option<usize>,
}

/// What exists for the volume: (NBD connection, LV mapping, mount).
type Live = (bool, bool, bool);

/// How an external command ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// It exits with a nonzero status.
    Nonzero,
    /// A signal terminates it: there is no exit status.
    Signalled,
    /// It exceeds its deadline and the runner kills it.
    TimedOut,
    /// The helper dies around it; the command itself finishes or never ran.
    HelperDies,
}

const ENDS: [End; 4] = [End::Nonzero, End::Signalled, End::TimedOut, End::HelperDies];

impl End {
    fn report(self, command: &str) -> ExecError {
        let failed = |status| ExecError::StepFailed {
            step: command.into(),
            status,
            stderr: "external command output omitted".into(),
        };
        match self {
            End::Nonzero => failed(Some(5)),
            End::Signalled => failed(None),
            End::TimedOut => ExecError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "external command exceeded its execution deadline",
            )),
            End::HelperDies => panic!("{HELPER_DIED} at {command}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// Command number `at` ends this way, before or after its effect.
    Command {
        at: usize,
        end: End,
        took_effect: bool,
    },
    /// Observation number `at` cannot be read, or the helper dies there.
    Observation { at: usize, helper_dies: bool },
}

impl Fault {
    fn helper_dies(self) -> bool {
        matches!(
            self,
            Fault::Command {
                end: End::HelperDies,
                ..
            } | Fault::Observation {
                helper_dies: true,
                ..
            }
        )
    }
}

fn faults(commands: usize, observations: usize) -> Vec<Fault> {
    let mut all = Vec::new();
    for at in 1..=commands {
        for end in ENDS {
            for took_effect in [false, true] {
                all.push(Fault::Command {
                    at,
                    end,
                    took_effect,
                });
            }
        }
    }
    for at in 1..=observations {
        for helper_dies in [false, true] {
            all.push(Fault::Observation { at, helper_dies });
        }
    }
    all
}

struct World {
    directory: PathBuf,
    sysfs: PathBuf,
    mountinfo: PathBuf,
    mountpoint: String,
    kernel: RefCell<Kernel>,
    commands: Cell<usize>,
    observations: Cell<usize>,
    fault: Option<Fault>,
    /// `c<n>:<command>` and `o<n>:<observation>` in the order they ran.
    trace: RefCell<Vec<String>>,
    /// How a `--select vg_uuid=` command answers when LVM cannot read the PV:
    /// it exits nonzero, or it exits zero because no volume group matched.
    /// No LVM was available to decide which, so the sweeps run both.
    lvm_select_matches_nothing: bool,
    /// Events of the running verb.
    schedule: Schedule,
    /// The host also has `/dev/nbd4`, which nothing has open.
    second_device: Cell<bool>,
    /// The identifier of the last connection the helper made, the device of
    /// every connect it requested, and what it must never do, as it
    /// happened.
    ours: RefCell<Option<String>>,
    connect_targets: RefCell<Vec<String>>,
    violations: RefCell<Vec<String>>,
    /// The executor's manual clock: where it started, how long it has slept
    /// in all, and each sleep of the running verb.
    epoch: Instant,
    slept: Duration,
    sleeps: Vec<Duration>,
}

impl World {
    fn new(mountpoint: &str) -> Self {
        silence_simulated_deaths();
        // Like the real `/run/maki-attach`, the state lives on a tmpfs where
        // one is available: each record update syncs a file and a directory,
        // and the sweeps make thousands of them.
        let shm = Path::new("/dev/shm");
        let base = if shm.is_dir() {
            shm.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        let directory = base.join(format!(
            "maki-step-faults-{}-{}",
            std::process::id(),
            WORLDS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let world = Self {
            sysfs: directory.join("sys"),
            mountinfo: directory.join("mountinfo"),
            directory,
            mountpoint: mountpoint.into(),
            kernel: RefCell::new(Kernel {
                daemon_running: true,
                ..Kernel::default()
            }),
            commands: Cell::new(0),
            observations: Cell::new(0),
            fault: None,
            trace: RefCell::new(Vec::new()),
            lvm_select_matches_nothing: false,
            schedule: Schedule::default(),
            second_device: Cell::new(false),
            ours: RefCell::new(None),
            connect_targets: RefCell::new(Vec::new()),
            violations: RefCell::new(Vec::new()),
            epoch: Instant::now(),
            slept: Duration::ZERO,
            sleeps: Vec::new(),
        };
        world.publish();
        world
    }

    fn mounts(&self) -> String {
        let mut text = String::from("21 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n");
        if self.kernel.borrow().mounted {
            text.push_str(&format!(
                "40 21 253:0 / {} rw,noatime,nosuid,nodev - xfs /dev/mapper/{MAPPING} rw\n",
                self.mountpoint
            ));
        }
        text
    }

    /// Let the kernel react to the last change, then rewrite what the
    /// observers read.
    fn publish(&self) {
        let mut kernel = self.kernel.borrow_mut();
        // The configuration, and with it `pid` and `backend`, lives while
        // anything has the device open: a mapping, or an opener.
        if kernel.connection.as_ref().is_some_and(|connection| {
            connection.disconnecting
                && !kernel.mapped
                && !(kernel.opener && connection.device == DEVICE)
        }) {
            kernel.connection = None;
        }
        let _ = std::fs::remove_dir_all(&self.sysfs);
        let mut devices = vec![3];
        if self.second_device.get() {
            devices.push(4);
        }
        for index in devices {
            let name = format!("nbd{index}");
            let nbd = self.sysfs.join(&name);
            std::fs::create_dir_all(nbd.join("holders")).unwrap();
            std::fs::write(nbd.join("dev"), format!("43:{index}\n")).unwrap();
            let connection = kernel
                .connection
                .as_ref()
                .filter(|connection| connection.device == format!("/dev/{name}"));
            let size = if connection.is_some() {
                "1024\n"
            } else {
                "0\n"
            };
            std::fs::write(nbd.join("size"), size).unwrap();
            let Some(connection) = connection else {
                continue;
            };
            std::fs::write(nbd.join("pid"), "4242\n").unwrap();
            std::fs::write(nbd.join("backend"), format!("{}\n", connection.backend)).unwrap();
            if kernel.mapped {
                let dm = self.sysfs.join("dm-0");
                for directory in ["dm", "slaves", "holders"] {
                    std::fs::create_dir_all(dm.join(directory)).unwrap();
                }
                std::fs::write(dm.join("dev"), "253:0\n").unwrap();
                std::fs::write(dm.join("dm/name"), format!("{MAPPING}\n")).unwrap();
                let uuid = format!(
                    "LVM-{}{}\n",
                    VG_UUID.replace('-', ""),
                    LV_UUID.replace('-', "")
                );
                std::fs::write(dm.join("dm/uuid"), uuid).unwrap();
                std::fs::write(dm.join("slaves").join(&name), "").unwrap();
                std::fs::write(nbd.join("holders/dm-0"), "").unwrap();
            }
        }
        drop(kernel);
        std::fs::write(&self.mountinfo, self.mounts()).unwrap();
    }

    /// Something opens or closes `/dev/nbd3`.
    fn set_opener(&self, open: bool) {
        self.kernel.borrow_mut().opener = open;
        self.publish();
    }

    fn stop_daemon(&self) {
        let mut kernel = self.kernel.borrow_mut();
        kernel.daemon_running = false;
        if let Some(connection) = &mut kernel.connection {
            connection.served = false;
        }
    }

    /// A new daemon process serves new connections only: nothing revives the
    /// kernel connection of the process that stopped.
    fn start_daemon(&self) {
        self.kernel.borrow_mut().daemon_running = true;
    }

    /// The operator's `dmsetup remove` of the unused mapping.
    fn remove_unused_mapping_by_hand(&self) {
        {
            let mut kernel = self.kernel.borrow_mut();
            assert!(kernel.mapped && !kernel.mounted, "the mapping is in use");
            kernel.mapped = false;
        }
        self.publish();
    }

    fn served(&self) -> bool {
        self.kernel
            .borrow()
            .connection
            .as_ref()
            .is_some_and(|connection| connection.served)
    }

    /// One injectable observation.
    fn observe(&self, name: &str) -> io::Result<()> {
        let at = self.observations.get() + 1;
        self.observations.set(at);
        self.trace.borrow_mut().push(format!("o{at}:{name}"));
        match self.fault {
            Some(Fault::Observation {
                at: faulted,
                helper_dies,
            }) if faulted == at => {
                if helper_dies {
                    panic!("{HELPER_DIED} at observation {name}");
                }
                Err(io::Error::other("simulated unreadable observation"))
            }
            _ => Ok(()),
        }
    }

    /// One injectable external command.
    fn command(
        &mut self,
        name: &str,
        effect: impl FnOnce(&mut Self) -> Result<(), ExecError>,
    ) -> Result<(), ExecError> {
        let at = self.commands.get() + 1;
        self.commands.set(at);
        if self.schedule.opener_opens_before == Some(at) {
            self.set_opener(true);
        }
        if self.schedule.opener_closes_before == Some(at) {
            self.set_opener(false);
        }
        if self.schedule.daemon_dies_before == Some(at) {
            self.stop_daemon();
            self.publish();
        }
        self.trace.borrow_mut().push(format!("c{at}:{name}"));
        let fault = match self.fault {
            Some(Fault::Command {
                at: faulted,
                end,
                took_effect,
            }) if faulted == at => Some((end, took_effect)),
            _ => None,
        };
        if let Some((end, false)) = fault {
            return Err(end.report(name));
        }
        let result = effect(self);
        self.publish();
        match fault {
            Some((End::HelperDies, _)) => panic!("{HELPER_DIED} after {name}"),
            Some((end, _)) if result.is_ok() => Err(end.report(name)),
            _ => result,
        }
    }

    /// Attach's read-only LVM report and label probes.
    fn preflight(
        &self,
        record: &BoundDeviceRecord,
    ) -> Result<lvm_preflight::VerifiedLvm, ExecError> {
        if !self.served() {
            return Err(identity_error("LVM read-only report failed"));
        }
        let observed =
            crate::detach::observe_kernel(record, self.mounts().as_bytes(), &self.sysfs)?;
        if observed.mounted || observed.vg_active || observed.nbd_in_use {
            return Err(identity_error(
                "LVM preflight found an existing mount, mapping, or holder",
            ));
        }
        let number = (
            43,
            crate::probe::nbd_index(&record.device).expect("an NBD device"),
        );
        let report = serde_json::json!({"report": [{
            "vg": [{"vg_name": record.attachment.vg_name, "vg_uuid": VG_UUID, "vg_seqno": "1",
                "pv_count": "1", "vg_missing_pv_count": "0", "vg_partial": "0",
                "vg_exported": "0", "vg_systemid": "", "vg_lock_type": ""}],
            "pv": [{"pv_name": record.device, "pv_uuid": PV_UUID, "vg_uuid": VG_UUID,
                "pv_missing": "0", "pv_duplicate": "0"}],
            "lv": [{"lv_name": record.attachment.lv_name, "lv_uuid": LV_UUID,
                "vg_uuid": VG_UUID, "lv_layout": "linear"}]
        }]});
        Ok(lvm_preflight::validate(
            &serde_json::to_vec(&report).unwrap(),
            vec![lvm_preflight::Device {
                path: record.device.clone(),
                number,
                start: 0,
                sectors: 1024,
            }],
            [(record.device.clone(), PV_UUID.to_string())].into(),
            &record.attachment.vg_name,
            &record.attachment.lv_name,
            record.attachment.lvm_identity.as_ref(),
            |path| {
                if path == record.device {
                    Ok(number)
                } else {
                    Err(io::Error::other("foreign device"))
                }
            },
        )?)
    }

    /// `vgchange` deactivating the volume group, by name or scoped to the
    /// recorded devices and VG UUID.
    fn lvm_deactivate(&mut self, scoped: bool) -> Result<(), ExecError> {
        if !self.served() {
            if scoped && self.lvm_select_matches_nothing {
                return Ok(());
            }
            return Err(End::Nonzero.report("vgchange: volume group not found"));
        }
        let mut kernel = self.kernel.borrow_mut();
        if kernel.mounted {
            return Err(End::Nonzero.report("vgchange: logical volume in use"));
        }
        kernel.mapped = false;
        Ok(())
    }

    /// The scoped LVM wrappers report an unsuccessful command as an identity
    /// refusal, never as a failed step with a status.
    fn scoped(result: Result<(), ExecError>, message: &str) -> Result<(), ExecError> {
        result.map_err(|error| match error {
            ExecError::StepFailed { .. } => identity_error(message),
            other => other,
        })
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl Clock for World {
    fn now(&self) -> Instant {
        self.epoch + self.slept
    }
    fn sleep(&mut self, duration: Duration) {
        self.slept += duration;
        self.sleeps.push(duration);
        if self.schedule.opener_closes_after_sleep == Some(self.sleeps.len()) {
            self.set_opener(false);
        }
    }
}

impl System for World {
    fn lvm_preflight(
        &mut self,
        record: &BoundDeviceRecord,
    ) -> Result<lvm_preflight::VerifiedLvm, ExecError> {
        let mut verified = None;
        self.command("lvm-report", |world| {
            verified = Some(world.preflight(record)?);
            Ok(())
        })?;
        Ok(verified.expect("a successful report was validated"))
    }

    fn activate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
        attempted: &mut bool,
    ) -> Result<(), ExecError> {
        if &self.preflight(record)? != verified {
            return Err(identity_error(
                "LVM metadata or candidate identity changed before activation",
            ));
        }
        verify_connection(record, self)?;
        *attempted = true;
        let result = self.command("vgchange-activate", |world| {
            if !world.served() {
                return Err(End::Nonzero.report("vgchange: volume group not found"));
            }
            world.kernel.borrow_mut().mapped = true;
            Ok(())
        });
        Self::scoped(result, "scoped LVM activation failed")
    }

    fn verify_activated_lvm(
        &self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        self.observe("verify-activated-lvm")?;
        lvm_preflight::verify_mapping(record, verified, &self.sysfs)
    }

    fn verify_rollback_lvm(
        &self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        self.observe("verify-rollback-lvm")?;
        lvm_preflight::verify_rollback_mapping(record, verified, &self.sysfs)
    }

    fn deactivate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        _verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        verify_connection(record, self)?;
        let result = self.command("vgchange-deactivate-scoped", |world| {
            world.lvm_deactivate(true)
        });
        Self::scoped(result, "scoped LVM rollback failed")
    }

    fn recover_deactivate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        lvm_preflight::verify_recovery_rollback_mapping(record, verified, &self.sysfs)?;
        if self.backend(&record.device)?.is_some() {
            return Err(identity_error(
                "NBD backend reappeared before recovery deactivation",
            ));
        }
        let result = self.command("vgchange-deactivate-scoped", |world| {
            world.lvm_deactivate(true)
        });
        Self::scoped(result, "scoped LVM recovery deactivation failed")
    }

    /// `dmsetup remove` needs no LVM metadata, so it works over a device
    /// nothing serves. Which mapping it may remove is decided by
    /// `recover::deactivate_connected_from_proof`, covered by its own tests.
    fn deactivate_lvm_from_proof(&mut self, record: &BoundDeviceRecord) -> Result<(), ExecError> {
        verify_connection(record, self)?;
        if record.recovery.is_none() {
            return Err(identity_error("attachment has no completed recovery proof"));
        }
        let observed = recover::observe(record, self.mounts().as_bytes(), &self.sysfs)?;
        if observed.mounted {
            return Err(identity_error(
                "cannot directly deactivate a mounted recovery mapping",
            ));
        }
        if !observed.vg_active {
            return Ok(());
        }
        self.command("dmsetup-remove", |world| {
            world.kernel.borrow_mut().mapped = false;
            Ok(())
        })
    }

    fn recovery_proof(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<Option<recover::RecoveryProof>> {
        self.observe("recovery-proof")?;
        recover::capture(record, self.mounts().as_bytes(), &self.sysfs).map(Some)
    }

    fn recovery_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        self.observe("recovery-observation")?;
        recover::observe(record, self.mounts().as_bytes(), &self.sysfs)
    }

    fn disconnected_recovery_observation(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<DetachObservation> {
        self.observe("disconnected-recovery-observation")?;
        recover::observe_disconnected(record, self.mounts().as_bytes(), &self.sysfs)
    }

    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError> {
        let unverified =
            |message: &str| ExecError::Verify(crate::verify::MountVerifyError(message.into()));
        self.command(step.kind(), |world| match step {
            PlannedStep::ModprobeNbd => Ok(()),
            PlannedStep::NbdConnect { device, .. } => {
                world.connect_targets.borrow_mut().push(device.clone());
                let mut kernel = world.kernel.borrow_mut();
                if kernel.connection.is_some() {
                    // The executor checks the backend before it connects: a
                    // request for a device that shows a connection, live or
                    // lingering, would be a second connect.
                    world
                        .violations
                        .borrow_mut()
                        .push("a connect was requested while a device shows a connection".into());
                }
                if !kernel.daemon_running || kernel.connection.is_some() {
                    return Err(End::Nonzero.report("NBD_CMD_CONNECT"));
                }
                if kernel.opener && device == DEVICE {
                    return Err(ExecError::DeviceBusy {
                        step: "NBD_CMD_CONNECT".into(),
                        message: "Device or resource busy".into(),
                    });
                }
                let backend: String = identifier.expect("connect identifier").into();
                *world.ours.borrow_mut() = Some(backend.clone());
                kernel.connection = Some(Connection {
                    device: device.clone(),
                    backend,
                    served: true,
                    disconnecting: false,
                });
                Ok(())
            }
            PlannedStep::SetBlockSize { .. } if world.served() => Ok(()),
            PlannedStep::SetBlockSize { .. } => Err(End::Nonzero.report("blockdev")),
            PlannedStep::LvmDeactivate { .. } => world.lvm_deactivate(false),
            PlannedStep::VerifyFilesystemIdentity { .. } | PlannedStep::MountXfs { .. } => {
                if !world.served() || !world.kernel.borrow().mapped {
                    return Err(End::Nonzero.report("cannot read the logical volume"));
                }
                if matches!(step, PlannedStep::MountXfs { .. }) {
                    world.kernel.borrow_mut().mounted = true;
                }
                Ok(())
            }
            PlannedStep::VerifyMountDevice { .. } if world.kernel.borrow().mounted => Ok(()),
            PlannedStep::VerifyMountDevice { .. } => {
                Err(unverified("nothing is mounted at the mountpoint"))
            }
            PlannedStep::WriteSentinel { volume_uuid, .. }
            | PlannedStep::VerifyMountIdentity { volume_uuid, .. } => {
                if !world.served() || !world.kernel.borrow().mounted {
                    return Err(unverified("the mounted filesystem cannot be read"));
                }
                let mut kernel = world.kernel.borrow_mut();
                if matches!(step, PlannedStep::WriteSentinel { .. }) {
                    kernel.sentinel.get_or_insert_with(|| volume_uuid.clone());
                }
                if kernel.sentinel.as_ref() != Some(volume_uuid) {
                    return Err(unverified("Maki volume sentinel is missing or different"));
                }
                Ok(())
            }
            PlannedStep::Umount { .. } => {
                let mut kernel = world.kernel.borrow_mut();
                if !kernel.mounted {
                    return Err(End::Nonzero.report("umount: not mounted"));
                }
                kernel.mounted = false;
                Ok(())
            }
            PlannedStep::NbdDisconnect { device } => {
                let mut kernel = world.kernel.borrow_mut();
                // The kernel acknowledges a disconnect of a device without
                // a connection, and of one already disconnected. The helper
                // never asks for the first, nor for another's connection.
                let Some(connection) = kernel
                    .connection
                    .as_mut()
                    .filter(|connection| &connection.device == device)
                else {
                    world
                        .violations
                        .borrow_mut()
                        .push(format!("a disconnect of {device}, which has no connection"));
                    return Ok(());
                };
                if Some(&connection.backend) != world.ours.borrow().as_ref() {
                    world
                        .violations
                        .borrow_mut()
                        .push("a disconnect of a connection the helper did not make".into());
                }
                connection.served = false;
                connection.disconnecting = true;
                Ok(())
            }
            PlannedStep::LvmActivate { .. }
            | PlannedStep::LvExtend { .. }
            | PlannedStep::XfsGrowfs { .. } => Err(identity_error("not part of these sweeps")),
        })
    }

    fn wait_ready(&mut self, _step: &str, _device: &str) -> Result<(), ExecError> {
        self.command("wait-ready", |world| {
            if world.served() {
                Ok(())
            } else {
                Err(identity_error("device did not become ready"))
            }
        })
    }

    fn allocate(&mut self) -> Result<String, ExecError> {
        self.observe("allocate")?;
        allocation::allocate(&self.sysfs, &self.mountinfo)
    }

    fn allocate_excluding(&mut self, reserved: &BTreeSet<String>) -> Result<String, ExecError> {
        self.observe("allocate")?;
        allocation::allocate_excluding(&self.sysfs, &self.mountinfo, reserved)
    }

    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        self.observe("backend")?;
        nbd_backend_at(&self.sysfs, device)
    }

    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        self.observe("detach-observation")?;
        crate::detach::observe(record, self.mounts().as_bytes(), &self.sysfs)
    }
}

#[derive(Clone, Copy, Debug)]
enum Verb {
    Attach,
    Detach,
    Cleanup,
    Recover,
    /// The storage part of the attach unit's `ExecStopPost` hook.
    FailedStartHook,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Done,
    Refused(String),
    HelperDied,
}

struct Case {
    world: World,
    state: TrustedState,
    request: AttachRequest,
}

impl Case {
    fn new() -> Self {
        let request = parse(&format!(
            "volume_uuid = '{VOLUME_UUID}'\ninit_sentinel = true\n"
        ))
        .unwrap()
        .into_request("pg", AttachOverrides::default(), true)
        .unwrap();
        let world = World::new(&request.mountpoint);
        let state = TrustedState::open_beneath(
            File::open(&world.directory).unwrap(),
            Path::new("state"),
            world.directory.metadata().unwrap().uid(),
        )
        .unwrap();
        Self {
            world,
            state,
            request,
        }
    }

    fn attached() -> Self {
        let mut case = Self::new();
        assert_eq!(case.run(None, Verb::Attach), Outcome::Done);
        assert!(case.fully_attached());
        case
    }

    /// Run one helper invocation from its first command, with at most one
    /// fault.
    fn run(&mut self, fault: Option<Fault>, verb: Verb) -> Outcome {
        self.run_scheduled(fault, Schedule::default(), verb)
    }

    /// One helper invocation with events at chosen commands.
    fn run_scheduled(&mut self, fault: Option<Fault>, schedule: Schedule, verb: Verb) -> Outcome {
        self.world.schedule = schedule;
        self.world.commands.set(0);
        self.world.observations.set(0);
        self.world.trace.borrow_mut().clear();
        self.world.sleeps.clear();
        self.world.fault = fault;
        let (world, state) = (&mut self.world, &self.state);
        let attach = plan_attach(&self.request);
        let detach = plan_detach(&self.request);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match verb {
            Verb::Attach => execute_with(&attach, Some(state), world),
            Verb::Detach => execute_with(&detach, Some(state), world),
            Verb::Cleanup => cleanup_with(&detach, state, world),
            Verb::Recover => recover_with(&detach, state, world),
            Verb::FailedStartHook => {
                finish_interrupted_activation_with(&detach, state, world).map(drop)
            }
        }));
        self.world.fault = None;
        self.world.schedule = Schedule::default();
        match result {
            Ok(Ok(())) => Outcome::Done,
            Ok(Err(error)) => Outcome::Refused(error.to_string()),
            Err(payload) => {
                let died = payload
                    .downcast_ref::<String>()
                    .is_some_and(|text| text.contains(HELPER_DIED));
                assert!(died, "the executor panicked");
                Outcome::HelperDied
            }
        }
    }

    /// The injection points of a fault-free run.
    fn points(&self) -> (usize, usize) {
        (self.world.commands.get(), self.world.observations.get())
    }

    fn ran(&self, command: &str) -> bool {
        self.world
            .trace
            .borrow()
            .iter()
            .any(|entry| entry.starts_with('c') && entry.ends_with(&format!(":{command}")))
    }

    fn commands_run(&self) -> Vec<String> {
        self.world
            .trace
            .borrow()
            .iter()
            .filter(|entry| entry.starts_with('c'))
            .cloned()
            .collect()
    }

    fn record(&self) -> Option<BoundDeviceRecord> {
        self.state.read("pg").unwrap()
    }

    fn live(&self) -> Live {
        let kernel = self.world.kernel.borrow();
        (kernel.connection.is_some(), kernel.mapped, kernel.mounted)
    }

    fn clean(&self) -> bool {
        self.live() == (false, false, false) && self.record().is_none()
    }

    fn fully_attached(&self) -> bool {
        self.live() == (true, true, true)
            && self
                .record()
                .is_some_and(|record| record.recovery.is_some() && record.recovery_intent.is_none())
            && self.record_covers_live_state().is_ok()
    }

    /// However a run ended, whatever is live must be named by the trusted
    /// record, under the connection identity that record stores. Otherwise
    /// no later verb could prove ownership and clean it up.
    fn record_covers_live_state(&self) -> Result<(), String> {
        let live = self.live();
        if live == (false, false, false) {
            return Ok(());
        }
        let Some(record) = self.record() else {
            return Err(format!("{live:?} is live without a trusted record"));
        };
        let kernel = self.world.kernel.borrow();
        match &kernel.connection {
            Some(connection)
                if record.device != connection.device
                    || connection.backend != record.connection_id =>
            {
                Err("the record does not name the live connection".into())
            }
            _ => Ok(()),
        }
    }

    /// The packaged units after a failed `maki-attach@` start. The unit's
    /// `ExecStopPost` hook runs while `maki@` is still up; `maki-recover@`
    /// then stops the daemon (`Conflicts=`) before it runs `cleanup`, and
    /// only its success starts the lifecycle again.
    fn packaged_failed_start_recovery(&mut self) -> Result<(), String> {
        let hook = self.run(None, Verb::FailedStartHook);
        self.record_covers_live_state()?;
        self.world.stop_daemon();
        let cleanup = self.run(None, Verb::Cleanup);
        if cleanup != Outcome::Done || !self.clean() {
            return Err(format!(
                "hook {hook:?}; cleanup after the daemon stopped {cleanup:?}; left {:?}, record {}",
                self.live(),
                self.record().is_some()
            ));
        }
        self.restart()
    }

    fn restart(&mut self) -> Result<(), String> {
        self.world.start_daemon();
        match self.run(None, Verb::Attach) {
            Outcome::Done if self.fully_attached() => Ok(()),
            other => Err(format!("the next attach: {other:?}, {:?}", self.live())),
        }
    }
}

/// The fault that kills the helper right after `command` took effect.
fn death_after(command: &str) -> Fault {
    let mut baseline = Case::new();
    assert_eq!(baseline.run(None, Verb::Attach), Outcome::Done);
    let trace = baseline.world.trace.borrow();
    let at = trace
        .iter()
        .filter(|entry| entry.starts_with('c'))
        .position(|entry| entry.ends_with(&format!(":{command}")))
        .unwrap_or_else(|| panic!("attach runs no {command}: {trace:?}"));
    Fault::Command {
        at: at + 1,
        end: End::HelperDies,
        took_effect: true,
    }
}

/// An attach whose helper died between `vgchange --activate y` taking effect
/// and the mapping proof: the record holds only the activation intent.
fn interrupted_activation(lvm_select_matches_nothing: bool) -> Case {
    let mut case = Case::new();
    case.world.lvm_select_matches_nothing = lvm_select_matches_nothing;
    let death = death_after("vgchange-activate");
    assert_eq!(case.run(Some(death), Verb::Attach), Outcome::HelperDied);
    let record = case.record().unwrap();
    assert!(record.recovery_intent.is_some() && record.recovery.is_none());
    assert_eq!(case.live(), (true, true, false));
    case
}

/// The deactivation of an activation intent is a device-scoped `vgchange`,
/// and LVM must read the volume group from the NBD device to run it. The
/// recovery coordinator stops the daemon before its cleanup, so the intent
/// has to be consumed by the failed-start hook, while the daemon still
/// serves reads; otherwise nothing in the product can remove the mapping.
#[test]
fn an_attach_killed_in_the_activation_window_is_recovered_by_the_packaged_units() {
    for lvm_select_matches_nothing in [false, true] {
        let mut case = interrupted_activation(lvm_select_matches_nothing);
        case.packaged_failed_start_recovery()
            .unwrap_or_else(|problem| {
                panic!("select matches nothing = {lvm_select_matches_nothing}: {problem}")
            });
    }
}

#[test]
fn a_failed_attach_start_converges_through_the_packaged_recovery() {
    let mut baseline = Case::new();
    assert_eq!(baseline.run(None, Verb::Attach), Outcome::Done);
    assert!(baseline.fully_attached());
    let (commands, observations) = baseline.points();
    let mut problems = Vec::new();
    for lvm_select_matches_nothing in [false, true] {
        for fault in faults(commands, observations) {
            let mut case = Case::new();
            case.world.lvm_select_matches_nothing = lvm_select_matches_nothing;
            let first = case.run(Some(fault), Verb::Attach);
            let context = format!("{fault:?} -> {first:?}");
            let mut check = |result: Result<(), String>| {
                if let Err(problem) = result {
                    problems.push(format!("{context}: {problem}"));
                }
            };
            check(case.record_covers_live_state());
            match &first {
                Outcome::Done => {
                    check(case.fully_attached().then_some(()).ok_or_else(|| {
                        format!("success without a complete attachment: {:?}", case.live())
                    }));
                    continue;
                }
                // A rollback that reports no failed step must leave nothing.
                Outcome::Refused(text)
                    if text.contains("rolled back") && !text.contains("FAILED") =>
                {
                    check(
                        case.clean()
                            .then_some(())
                            .ok_or_else(|| format!("a complete rollback left {:?}", case.live())),
                    );
                }
                _ => {}
            }
            check(case.packaged_failed_start_recovery());
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn a_faulted_teardown_converges_when_cleanup_is_retried() {
    let mut problems = Vec::new();
    for (name, verb, daemon_stopped) in [
        ("detach", Verb::Detach, false),
        ("cleanup", Verb::Cleanup, false),
        ("cleanup after the daemon stopped", Verb::Cleanup, true),
    ] {
        let prepare = || {
            let case = Case::attached();
            if daemon_stopped {
                case.world.stop_daemon();
            }
            case
        };
        let mut baseline = prepare();
        assert_eq!(baseline.run(None, verb), Outcome::Done, "{name}");
        assert!(baseline.clean(), "{name}");
        let (commands, observations) = baseline.points();
        for fault in faults(commands, observations) {
            let mut case = prepare();
            let first = case.run(Some(fault), verb);
            let context = format!("{name}: {fault:?} -> {first:?}");
            if let Err(problem) = case.record_covers_live_state() {
                problems.push(format!("{context}: {problem}"));
            }
            let mut converged = first == Outcome::Done;
            let mut retries = Vec::new();
            for _ in 0..3 {
                if converged {
                    break;
                }
                let retry = case.run(None, Verb::Cleanup);
                converged = retry == Outcome::Done;
                retries.push(retry);
            }
            if !converged || !case.clean() {
                problems.push(format!(
                    "{context}: retries {retries:?} left {:?}",
                    case.live()
                ));
            } else if let Err(problem) = case.restart() {
                problems.push(format!("{context}: {problem}"));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The hook finishes one thing: the rollback of an activation whose helper
/// did not live to record it. Every other state is the coordinator's, which
/// stops the registered workloads first; in particular the hook never
/// unmounts.
#[test]
fn the_failed_start_hook_touches_only_an_interrupted_activation() {
    let mut fresh = Case::new();
    assert_eq!(fresh.run(None, Verb::FailedStartHook), Outcome::Done);
    assert!(fresh.commands_run().is_empty() && fresh.clean());

    for (command, live) in [
        ("nbd-connect", (true, false, false)),
        // The proof is published between activation and this probe.
        ("verify-filesystem-identity", (true, true, false)),
        ("mount-xfs", (true, true, true)),
    ] {
        let mut case = Case::new();
        assert_eq!(
            case.run(Some(death_after(command)), Verb::Attach),
            Outcome::HelperDied
        );
        let record = case.record().unwrap();
        assert!(record.recovery_intent.is_none(), "{command}");
        assert_eq!(case.live(), live, "{command}");
        assert_eq!(case.run(None, Verb::FailedStartHook), Outcome::Done);
        assert!(case.commands_run().is_empty(), "{command}");
        assert_eq!(case.live(), live, "{command}");
        assert_eq!(case.record(), Some(record), "{command}");
    }

    let mut attached = Case::attached();
    assert_eq!(attached.run(None, Verb::FailedStartHook), Outcome::Done);
    assert!(attached.commands_run().is_empty() && attached.fully_attached());

    // An intent whose connection is gone or replaced is not the hook's
    // either: recovery retires the first, and nothing may touch the second.
    for foreign in [false, true] {
        let mut case = interrupted_activation(false);
        let record = case.record().unwrap();
        case.world.kernel.borrow_mut().connection = foreign.then(|| Connection {
            device: DEVICE.into(),
            backend: "maki-ffffffff-ffff-4fff-8fff-ffffffffffff".into(),
            served: true,
            disconnecting: false,
        });
        case.world.publish();
        assert_eq!(case.run(None, Verb::FailedStartHook), Outcome::Done);
        assert!(case.commands_run().is_empty(), "foreign = {foreign}");
        assert_eq!(case.record(), Some(record));
        assert!(case.live().1, "the mapping was removed");
    }
}

/// Whatever goes wrong inside the hook's rollback, the coordinator that
/// follows either converges or refuses with the record and the mapping
/// intact, and never removes the mapping directly.
#[test]
fn a_faulted_rollback_in_the_failed_start_hook_leaves_cleanup_to_the_coordinator() {
    let mut baseline = Case::new();
    assert_eq!(baseline.run(None, Verb::Attach), Outcome::Done);
    let (commands, observations) = baseline.points();
    let mut interrupted = 0;
    let mut problems = Vec::new();
    for death in faults(commands, observations)
        .into_iter()
        .filter(|fault| fault.helper_dies())
    {
        let prepare = || {
            let mut case = Case::new();
            assert_eq!(case.run(Some(death), Verb::Attach), Outcome::HelperDied);
            case
        };
        let mut unfaulted = prepare();
        if unfaulted
            .record()
            .is_none_or(|record| record.recovery_intent.is_none())
        {
            continue;
        }
        interrupted += 1;
        assert_eq!(
            unfaulted.run(None, Verb::FailedStartHook),
            Outcome::Done,
            "{death:?}"
        );
        assert!(unfaulted.clean(), "{death:?}");
        let (commands, observations) = unfaulted.points();
        for fault in faults(commands, observations) {
            let mut case = prepare();
            let hook = case.run(Some(fault), Verb::FailedStartHook);
            let context = format!("{death:?}, hook {fault:?} -> {hook:?}");
            let mut check = |result: Result<(), String>| {
                if let Err(problem) = result {
                    problems.push(format!("{context}: {problem}"));
                }
            };
            check(case.record_covers_live_state());
            case.world.stop_daemon();
            let cleanup = case.run(None, Verb::Cleanup);
            check(case.record_covers_live_state());
            if cleanup == Outcome::Done {
                check(
                    case.clean()
                        .then_some(())
                        .ok_or_else(|| format!("cleanup succeeded over {:?}", case.live())),
                );
            } else {
                // Only the state nothing can deactivate without the daemon
                // may remain, and the operator's documented step ends it.
                check(
                    (case.live() == (true, true, false) && !case.ran("dmsetup-remove"))
                        .then_some(())
                        .ok_or_else(|| format!("{cleanup:?} left {:?}", case.live())),
                );
                if case.live().1 {
                    case.world.remove_unused_mapping_by_hand();
                }
                let retry = case.run(None, Verb::Cleanup);
                check(
                    (retry == Outcome::Done && case.clean())
                        .then_some(())
                        .ok_or_else(|| format!("{retry:?} after the manual removal")),
                );
            }
            check(case.restart());
        }
    }
    assert!(interrupted >= 2, "no activation window was swept");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The state the hook cannot reach: the daemon stopped or failed before the
/// intent was consumed. Cleanup must refuse, say why, and keep everything;
/// one manual removal of the unused mapping lets it finish.
#[test]
fn an_interrupted_activation_nothing_serves_stays_refused_until_the_mapping_is_removed() {
    for lvm_select_matches_nothing in [false, true] {
        let mut case = interrupted_activation(lvm_select_matches_nothing);
        let record = case.record().unwrap();
        case.world.stop_daemon();

        for verb in [
            Verb::FailedStartHook,
            Verb::Cleanup,
            Verb::Cleanup,
            Verb::Detach,
            Verb::Recover,
        ] {
            let outcome = case.run(None, verb);
            // The hook may also find nothing it can act on.
            assert!(
                matches!(outcome, Outcome::Refused(_))
                    || matches!((verb, &outcome), (Verb::FailedStartHook, Outcome::Done)),
                "{verb:?}: {outcome:?}"
            );
            // The refusal says what is left, where, and what LVM would need.
            if let (Verb::Cleanup | Verb::Detach, Outcome::Refused(text)) = (verb, &outcome) {
                for expected in [
                    "the interrupted activation on /dev/nbd3",
                    "LVM reads the volume group from that device",
                    "keeping the attach record",
                ] {
                    assert!(text.contains(expected), "{verb:?}: {text}");
                }
                assert!(!text.contains("rolled back"), "{verb:?}: {text}");
            }
            assert!(!case.ran("dmsetup-remove"), "{verb:?}");
            assert!(!case.ran("nbd-disconnect"), "{verb:?}");
            assert_eq!(case.live(), (true, true, false), "{verb:?}");
            assert_eq!(case.record(), Some(record.clone()), "{verb:?}");
        }

        // A new daemon process changes nothing for the old kernel connection.
        case.world.start_daemon();
        assert!(matches!(case.run(None, Verb::Cleanup), Outcome::Refused(_)));
        let attach = case.run(None, Verb::Attach);
        assert!(
            matches!(&attach, Outcome::Refused(text) if text.contains("still connected")),
            "{attach:?}"
        );
        assert_eq!(case.record(), Some(record));

        case.world.remove_unused_mapping_by_hand();
        assert_eq!(case.run(None, Verb::Cleanup), Outcome::Done);
        assert_eq!(case.commands_run(), ["c1:nbd-disconnect"]);
        assert!(case.clean());
        case.restart().unwrap();
    }
}

impl Case {
    /// What the helper must never have done.
    fn violations(&self) -> Result<(), String> {
        let violations = self.world.violations.borrow();
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations.join("; "))
        }
    }

    fn checks(&self) -> Result<(), String> {
        self.record_covers_live_state()?;
        self.violations()
    }

    /// The device still shows a connection whose disconnect the kernel
    /// acknowledged.
    fn lingering(&self) -> bool {
        self.world
            .kernel
            .borrow()
            .connection
            .as_ref()
            .is_some_and(|connection| connection.disconnecting)
    }

    /// Bring the volume down as the packaged units, and then an operator,
    /// would, beside an opener that lets go at `late`: 0 before anything
    /// else runs, 1 after the failed-start hook, 2 only after the
    /// coordinator's cleanup ran twice. While the opener holds the device a
    /// cleanup may refuse; once it has let go, cleanup must finish, except
    /// in the documented state of an activation intent nothing serves,
    /// which one manual removal of the unused mapping ends. Then a fresh
    /// attach must succeed.
    fn converge(&mut self, failed_start: bool, late: usize) -> Result<(), String> {
        if late == 0 {
            self.world.set_opener(false);
        }
        let hook = failed_start.then(|| self.run(None, Verb::FailedStartHook));
        self.checks()
            .map_err(|problem| format!("after the hook {hook:?}: {problem}"))?;
        if late == 1 {
            self.world.set_opener(false);
        }
        self.world.stop_daemon();
        let mut cleanups = vec![self.run(None, Verb::Cleanup)];
        self.checks()
            .map_err(|problem| format!("after cleanup {cleanups:?}: {problem}"))?;
        if late >= 2 {
            // A second cleanup under the same conditions changes nothing
            // for the worse.
            cleanups.push(self.run(None, Verb::Cleanup));
            self.checks()
                .map_err(|problem| format!("after cleanups {cleanups:?}: {problem}"))?;
            self.world.set_opener(false);
            cleanups.push(self.run(None, Verb::Cleanup));
            self.checks()
                .map_err(|problem| format!("after cleanups {cleanups:?}: {problem}"))?;
        }
        let left = |case: &Self, cleanups: &[Outcome]| {
            format!(
                "hook {hook:?}; cleanups {cleanups:?} left {:?}, record {}, lingering {}",
                case.live(),
                case.record().is_some(),
                case.lingering()
            )
        };
        if cleanups.last() != Some(&Outcome::Done) {
            let intent_nothing_serves = self.live() == (true, true, false)
                && !self.ran("dmsetup-remove")
                && self
                    .record()
                    .is_some_and(|record| record.recovery_intent.is_some());
            if !intent_nothing_serves {
                return Err(left(self, &cleanups));
            }
            self.world.remove_unused_mapping_by_hand();
            cleanups.push(self.run(None, Verb::Cleanup));
            self.checks()?;
        }
        if cleanups.last() != Some(&Outcome::Done) || !self.clean() {
            return Err(left(self, &cleanups));
        }
        self.restart()?;
        self.checks()
    }
}

/// How many commands and observations a fault-free attach has, and which
/// command connects.
fn attach_shape() -> (usize, usize, usize) {
    let mut baseline = Case::new();
    assert_eq!(baseline.run(None, Verb::Attach), Outcome::Done);
    let (commands, observations) = baseline.points();
    let connect = baseline
        .commands_run()
        .iter()
        .position(|entry| entry.ends_with(":nbd-connect"))
        .expect("attach connects")
        + 1;
    (commands, observations, connect)
}

fn report(problems: Vec<String>) {
    assert!(
        problems.is_empty(),
        "{} problems, the first 40:\n{}",
        problems.len(),
        problems
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Something opens the device before any command of an attach and closes
/// it before a later one, or outlives the attach. Held open at the connect,
/// the only device is refused and the attach rolls back; opened later, it
/// changes nothing.
#[test]
fn an_opener_during_an_attach_fails_it_cleanly_or_not_at_all() {
    let (commands, _, connect) = attach_shape();
    let mut problems = Vec::new();
    let (mut refused, mut attached) = (0, 0);
    for opens in 1..=commands {
        for closes in (opens + 1..=commands).map(Some).chain([None]) {
            for late in 0..3 {
                if closes.is_some() && late > 0 {
                    continue;
                }
                let mut case = Case::new();
                let schedule = Schedule {
                    opener_opens_before: Some(opens),
                    opener_closes_before: closes,
                    daemon_dies_before: None,
                    ..Schedule::default()
                };
                let first = case.run_scheduled(None, schedule, Verb::Attach);
                let context = format!(
                    "opens before c{opens}, closes before {closes:?}, late {late} -> {first:?}"
                );
                if let Err(problem) = case.checks() {
                    problems.push(format!("{context}: {problem}"));
                }
                let held_at_the_connect =
                    opens <= connect && closes.is_none_or(|closes| closes > connect);
                if first == Outcome::Done {
                    attached += 1;
                    if !case.fully_attached() || held_at_the_connect {
                        problems.push(format!("{context}: an attachment that cannot be"));
                    }
                } else {
                    refused += 1;
                    if !held_at_the_connect {
                        problems.push(format!("{context}: refused a device nothing held"));
                    }
                    if let Err(problem) = case.converge(true, late) {
                        problems.push(format!("{context}: {problem}"));
                    }
                }
            }
        }
    }
    assert!(
        refused > 0 && attached > 0,
        "{refused} refused, {attached} attached"
    );
    report(problems);
}

/// Every fault of an attach, beside an opener that arrived before some
/// command and is still there when the helper ends. A rollback whose
/// disconnect the kernel acknowledged then leaves a device that still shows
/// the connection: its record must stay, and everything must end once the
/// opener lets go.
#[test]
fn a_faulted_attach_beside_an_opener_converges_once_it_lets_go() {
    let (commands, observations, _) = attach_shape();
    let mut problems = Vec::new();
    let mut lingered = 0;
    for opens in 1..=commands {
        for fault in faults(commands, observations) {
            for late in 0..3 {
                let mut case = Case::new();
                let schedule = Schedule {
                    opener_opens_before: Some(opens),
                    ..Schedule::default()
                };
                let first = case.run_scheduled(Some(fault), schedule, Verb::Attach);
                let context = format!("opens before c{opens}, {fault:?}, late {late} -> {first:?}");
                if case.lingering() {
                    lingered += 1;
                    if case.record().is_none() {
                        problems.push(format!(
                            "{context}: no record over a device that shows the connection"
                        ));
                    }
                }
                if let Err(problem) = case.checks() {
                    problems.push(format!("{context}: {problem}"));
                }
                if first == Outcome::Done {
                    if !case.fully_attached() {
                        problems.push(format!("{context}: success without an attachment"));
                    }
                    continue;
                }
                if let Err(problem) = case.converge(true, late) {
                    problems.push(format!("{context}: {problem}"));
                }
            }
        }
    }
    assert!(lingered > 0, "no rollback met the opener");
    report(problems);
}

/// Detach and cleanup, fault-free and under every fault, while something
/// has the device open from before the verb or from some command on: a
/// verb never succeeds over a device that still shows the connection, and
/// keeps its record until it no longer does.
#[test]
fn a_teardown_beside_an_opener_keeps_its_record_until_the_backend_is_gone() {
    let mut problems = Vec::new();
    let mut lingered = 0;
    for (name, verb, daemon_stopped) in [
        ("detach", Verb::Detach, false),
        ("cleanup", Verb::Cleanup, false),
        ("cleanup after the daemon stopped", Verb::Cleanup, true),
    ] {
        let prepare = || {
            let case = Case::attached();
            if daemon_stopped {
                case.world.stop_daemon();
            }
            case
        };
        let mut baseline = prepare();
        assert_eq!(baseline.run(None, verb), Outcome::Done, "{name}");
        let (commands, observations) = baseline.points();
        let all: Vec<Option<Fault>> = [None]
            .into_iter()
            .chain(faults(commands, observations).into_iter().map(Some))
            .collect();
        // 0: the opener is there before the verb starts.
        for opens in 0..=commands {
            for fault in &all {
                for late in [0, 2] {
                    let mut case = prepare();
                    let schedule = if opens == 0 {
                        case.world.set_opener(true);
                        Schedule::default()
                    } else {
                        Schedule {
                            opener_opens_before: Some(opens),
                            ..Schedule::default()
                        }
                    };
                    let first = case.run_scheduled(*fault, schedule, verb);
                    let context = format!(
                        "{name}: opens before c{opens}, {fault:?}, late {late} -> {first:?}"
                    );
                    if case.lingering() {
                        lingered += 1;
                        if first == Outcome::Done {
                            problems.push(format!(
                                "{context}: success over a device that shows the connection"
                            ));
                        }
                    }
                    if let Err(problem) = case.checks() {
                        problems.push(format!("{context}: {problem}"));
                    }
                    if let Err(problem) = case.converge(false, late) {
                        problems.push(format!("{context}: {problem}"));
                    }
                }
            }
        }
    }
    assert!(lingered > 0, "no disconnect met the opener");
    report(problems);
}

/// The daemon dies right before any command of an attach, with and without
/// an opener.
#[test]
fn a_daemon_that_dies_during_an_attach_leaves_what_cleanup_ends() {
    let (commands, _, _) = attach_shape();
    let mut problems = Vec::new();
    for dies in 1..=commands {
        for opens in (1..=commands).map(Some).chain([None]) {
            for late in 0..3 {
                if opens.is_none() && late > 0 {
                    continue;
                }
                let mut case = Case::new();
                let schedule = Schedule {
                    opener_opens_before: opens,
                    opener_closes_before: None,
                    daemon_dies_before: Some(dies),
                    ..Schedule::default()
                };
                let first = case.run_scheduled(None, schedule, Verb::Attach);
                let context = format!(
                    "daemon dies before c{dies}, opener before {opens:?}, late {late} -> {first:?}"
                );
                if let Err(problem) = case.checks() {
                    problems.push(format!("{context}: {problem}"));
                }
                // An attach that finished before it could notice is torn
                // down like any attachment nothing serves.
                if let Err(problem) = case.converge(first != Outcome::Done, late) {
                    problems.push(format!("{context}: {problem}"));
                }
            }
        }
    }
    report(problems);
}

/// The daemon dies right before any command of a detach, a cleanup or the
/// failed-start hook's rollback, with and without an opener.
#[test]
fn a_daemon_that_dies_during_a_teardown_leaves_what_cleanup_ends() {
    let mut problems = Vec::new();
    for (name, verb, interrupted) in [
        ("detach", Verb::Detach, false),
        ("cleanup", Verb::Cleanup, false),
        ("failed-start hook", Verb::FailedStartHook, true),
    ] {
        let prepare = || {
            if interrupted {
                interrupted_activation(false)
            } else {
                Case::attached()
            }
        };
        let mut baseline = prepare();
        assert_eq!(baseline.run(None, verb), Outcome::Done, "{name}");
        let (commands, _) = baseline.points();
        for dies in 1..=commands {
            for opener in [false, true] {
                for late in [0, 2] {
                    if !opener && late > 0 {
                        continue;
                    }
                    let mut case = prepare();
                    case.world.set_opener(opener);
                    let schedule = Schedule {
                        daemon_dies_before: Some(dies),
                        ..Schedule::default()
                    };
                    let first = case.run_scheduled(None, schedule, verb);
                    let context = format!(
                        "{name}: daemon dies before c{dies}, opener {opener}, late {late} -> {first:?}"
                    );
                    if let Err(problem) = case.checks() {
                        problems.push(format!("{context}: {problem}"));
                    }
                    if let Err(problem) = case.converge(false, late) {
                        problems.push(format!("{context}: {problem}"));
                    }
                }
            }
        }
    }
    report(problems);
}

/// While a device still shows the recorded connection after an acknowledged
/// disconnect, every verb says so or does nothing, keeps the record and
/// changes nothing; detach and cleanup say so after they waited 15 s for it
/// to go, looking every 100 ms. A retry sends the disconnect again, which
/// the kernel acknowledges again. Once the opener has let go, cleanup
/// retires the record without a command.
#[test]
fn every_verb_keeps_the_record_of_a_backend_that_outlived_its_disconnect() {
    let waited = vec![NBD_RELEASE_INTERVAL; 150];
    let mut case = Case::attached();
    case.world.set_opener(true);
    let detach = case.run(None, Verb::Detach);
    assert!(
        matches!(&detach, Outcome::Refused(text) if text.contains("disconnect has not completed")),
        "{detach:?}"
    );
    assert_eq!(
        case.commands_run(),
        ["c1:umount", "c2:lvm-deactivate", "c3:nbd-disconnect"]
    );
    assert_eq!(case.world.sleeps, waited);
    assert!(case.lingering());
    let record = case.record().expect("the record is kept");
    case.checks().unwrap();

    for (verb, says, commands) in [
        (Verb::Attach, "recorded device is still connected", &[][..]),
        (Verb::Recover, "backend is still connected", &[]),
        (Verb::FailedStartHook, "", &[]),
        (
            Verb::Detach,
            "disconnect has not completed",
            &["c1:nbd-disconnect"],
        ),
        (
            Verb::Cleanup,
            "disconnect has not completed",
            &["c1:nbd-disconnect"],
        ),
    ] {
        let outcome = case.run(None, verb);
        match &outcome {
            Outcome::Refused(text) => assert!(text.contains(says), "{verb:?}: {text}"),
            // The hook has nothing to roll back here.
            Outcome::Done => assert!(matches!(verb, Verb::FailedStartHook), "{verb:?}"),
            Outcome::HelperDied => panic!("{verb:?}"),
        }
        assert_eq!(case.commands_run(), commands, "{verb:?}");
        let sleeps = if commands.is_empty() {
            &[][..]
        } else {
            &waited
        };
        assert_eq!(case.world.sleeps, sleeps, "{verb:?}");
        assert_eq!(case.record(), Some(record.clone()), "{verb:?}");
        assert!(case.lingering(), "{verb:?}");
        case.checks().unwrap();
    }

    case.world.set_opener(false);
    assert_eq!(case.run(None, Verb::Cleanup), Outcome::Done);
    assert!(case.commands_run().is_empty() && case.clean());
    case.restart().unwrap();
}

/// An opener that held the device at the disconnect (a probe of an earlier
/// event, a monitoring tool) and lets go while detach or cleanup waits: the
/// verb retires the record in the same run, without a second disconnect,
/// also when the opener lets go at the last look, 15 s after the
/// disconnect; with the daemon still serving and after it stopped.
#[test]
fn a_teardown_retires_its_record_once_the_opener_lets_go_during_its_wait() {
    for (name, verb, daemon_stopped) in [
        ("detach", Verb::Detach, false),
        ("cleanup", Verb::Cleanup, false),
        ("cleanup after the daemon stopped", Verb::Cleanup, true),
    ] {
        for sleeps in [1, 12, 150] {
            let mut case = Case::attached();
            if daemon_stopped {
                case.world.stop_daemon();
            }
            case.world.set_opener(true);
            let schedule = Schedule {
                opener_closes_after_sleep: Some(sleeps),
                ..Schedule::default()
            };
            let outcome = case.run_scheduled(None, schedule, verb);
            let context = format!("{name}, opener lets go after sleep {sleeps}");
            assert_eq!(outcome, Outcome::Done, "{context}");
            let commands = if daemon_stopped {
                // Nothing serves LVM's reads: cleanup removes the mapping
                // its proof names.
                [
                    "c1:umount",
                    "c2:lvm-deactivate",
                    "c3:dmsetup-remove",
                    "c4:nbd-disconnect",
                ]
                .as_slice()
            } else {
                ["c1:umount", "c2:lvm-deactivate", "c3:nbd-disconnect"].as_slice()
            };
            assert_eq!(case.commands_run(), commands, "{context}");
            assert_eq!(
                case.world.sleeps,
                vec![NBD_RELEASE_INTERVAL; sleeps],
                "{context}"
            );
            assert!(case.clean(), "{context}: {:?}", case.live());
            case.checks().unwrap();
            case.restart().unwrap();
        }
    }
}
/// The failed-start hook rolls an interrupted activation back with detach's
/// steps and waits after its disconnect as detach does. An opener that held
/// the device at the disconnect and lets go during the wait leaves nothing
/// live and no record after the one run. One that stays keeps the record,
/// after 150 looks, and the coordinator's cleanup ends it once the opener
/// has let go. The hook's deadline for its commands ends the wait.
#[test]
fn the_failed_start_hook_waits_for_an_opener_after_its_disconnect() {
    let rollback = ["c1:vgchange-deactivate-scoped", "c2:nbd-disconnect"];
    for lvm_select_matches_nothing in [false, true] {
        for sleeps in [1, 30, 150] {
            let context = format!(
                "select matches nothing {lvm_select_matches_nothing}, opener lets go after \
                 sleep {sleeps}"
            );
            let mut case = interrupted_activation(lvm_select_matches_nothing);
            case.world.set_opener(true);
            let schedule = Schedule {
                opener_closes_after_sleep: Some(sleeps),
                ..Schedule::default()
            };
            let outcome = case.run_scheduled(None, schedule, Verb::FailedStartHook);
            assert_eq!(outcome, Outcome::Done, "{context}");
            assert_eq!(case.commands_run(), rollback, "{context}");
            assert_eq!(
                case.world.sleeps,
                vec![NBD_RELEASE_INTERVAL; sleeps],
                "{context}"
            );
            assert!(case.clean(), "{context}: {:?}", case.live());
            case.checks().unwrap();
            case.restart().unwrap();
        }

        let context = format!("select matches nothing {lvm_select_matches_nothing}");
        let mut case = interrupted_activation(lvm_select_matches_nothing);
        case.world.set_opener(true);
        let outcome = case.run(None, Verb::FailedStartHook);
        assert!(
            matches!(&outcome, Outcome::Refused(text) if text.contains("disconnect has not completed")),
            "{context}: {outcome:?}"
        );
        assert_eq!(case.commands_run(), rollback, "{context}");
        assert_eq!(
            case.world.sleeps,
            vec![NBD_RELEASE_INTERVAL; 150],
            "{context}"
        );
        assert!(case.lingering() && case.record().is_some(), "{context}");
        case.checks().unwrap();
        // The coordinator stops the daemon before its cleanup.
        case.world.set_opener(false);
        case.world.stop_daemon();
        assert_eq!(case.run(None, Verb::Cleanup), Outcome::Done, "{context}");
        assert!(case.clean(), "{context}: {:?}", case.live());
        case.restart().unwrap();

        let budget = Duration::from_millis(1950);
        let mut case = interrupted_activation(lvm_select_matches_nothing);
        case.world.set_opener(true);
        let outcome = {
            let _bounded = command::finish_by(Instant::now() + budget);
            case.run(None, Verb::FailedStartHook)
        };
        assert!(
            matches!(&outcome, Outcome::Refused(text) if text.contains("disconnect has not completed")),
            "{context}, {budget:?}: {outcome:?}"
        );
        let waited = case.world.sleeps.iter().sum::<Duration>();
        assert!(
            !waited.is_zero() && waited <= budget,
            "{context}: waited {waited:?}"
        );
        assert!(case.lingering() && case.record().is_some(), "{context}");
        case.checks().unwrap();
    }
}

/// With `/dev/nbd3` held open and `/dev/nbd4` free, an attach gives the
/// first up and ends on the second, and every fault on the way leaves a
/// state the packaged recovery ends: whichever device the record names when
/// the helper stops, nothing live is outside it.
#[test]
fn an_attach_past_a_held_device_converges_under_every_fault() {
    let held = || {
        let case = Case::new();
        case.world.second_device.set(true);
        case.world.set_opener(true);
        case
    };
    let mut baseline = held();
    assert_eq!(baseline.run(None, Verb::Attach), Outcome::Done);
    assert!(baseline.fully_attached());
    assert_eq!(
        *baseline.world.connect_targets.borrow(),
        ["/dev/nbd3", "/dev/nbd4"]
    );
    assert_eq!(baseline.record().unwrap().device, "/dev/nbd4");
    let (commands, observations) = baseline.points();

    let mut problems = Vec::new();
    let mut recorded = std::collections::BTreeSet::new();
    for fault in faults(commands, observations) {
        for late in 0..3 {
            let mut case = held();
            let first = case.run(Some(fault), Verb::Attach);
            let context = format!("{fault:?}, late {late} -> {first:?}");
            if let Some(record) = case.record() {
                recorded.insert(record.device);
            }
            if let Err(problem) = case.checks() {
                problems.push(format!("{context}: {problem}"));
            }
            if first == Outcome::Done {
                if !case.fully_attached() {
                    problems.push(format!("{context}: success without an attachment"));
                }
                continue;
            }
            if let Err(problem) = case.converge(true, late) {
                problems.push(format!("{context}: {problem}"));
            }
        }
    }
    // A helper that stopped on either side of the move was swept.
    assert_eq!(
        recorded.into_iter().collect::<Vec<_>>(),
        ["/dev/nbd3", "/dev/nbd4"]
    );
    report(problems);
}
