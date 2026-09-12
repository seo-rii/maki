//! Plan executor (Linux only): runs each planned step via the corresponding
//! system utility, with real mount-identity verification (review M-006),
//! NBD device allocation under the attach lock, readiness waits, and
//! reverse rollback of the executed prefix when a step fails (review
//! M-016). All decision logic lives in the pure planner, verifier and
//! probe parsers so it is testable everywhere; this module only gathers
//! facts and runs commands.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

#[path = "command.rs"]
mod command;

#[path = "recover.rs"]
pub(crate) mod recover;

#[path = "workload_verify.rs"]
mod workload_verify;

#[path = "lvm_preflight.rs"]
mod lvm_preflight;

use crate::detach::DetachObservation;
use crate::plan::{Plan, PlannedStep, SENTINEL_FILE};
use crate::probe::{
    choose_free_nbd, nbd_device_of, nbd_index, parse_mountinfo, resolve_leaf_devices,
};
use crate::state::{BoundDeviceRecord, TrustedState};
use crate::verify::{
    verify_filesystem_identity, verify_mount_device, verify_mount_identity, MountExpectation,
    MountObservation,
};

/// Serializes attach helpers system-wide (device allocation + connect).
pub const ATTACH_LOCK_PATH: &str = "/run/maki-attach/attach.lock";
const NBD_READY_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("step {step:?} failed with status {status:?}: {stderr}")]
    StepFailed {
        step: String,
        status: Option<i32>,
        stderr: String,
    },
    #[error("step {step:?} failed: {message}")]
    Step { step: String, message: String },
    #[error("{0}")]
    Verify(#[from] crate::verify::MountVerifyError),
    #[error("no free /dev/nbdN device (all connected or module not loaded)")]
    NoFreeDevice,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A step failed and the executed prefix was rolled back.
    #[error("{error}; rolled back {rolled_back} step(s){}", if *.rollback_failed > 0 { format!(", {} rollback step(s) FAILED - manual cleanup required", .rollback_failed) } else { String::new() })]
    RolledBack {
        #[source]
        error: Box<ExecError>,
        rolled_back: usize,
        rollback_failed: usize,
    },
}

fn run(step: &PlannedStep, program: &str, args: &[&str]) -> Result<(), ExecError> {
    tracing::info!("maki-attach: {step}");
    let out = command::capture(Command::new(program).args(args), command::Policy::STEP)?;
    if !out.status.success() {
        return Err(ExecError::StepFailed {
            step: step.to_string(),
            status: out.status.code(),
            stderr: "external command output omitted".into(),
        });
    }
    Ok(())
}

/// Held for the whole attach so two helpers cannot pick the same device;
/// the file lock is released when this is dropped.
pub struct AttachLock {
    _file: File,
    state: TrustedState,
}

pub fn lock_attach() -> io::Result<AttachLock> {
    let state = TrustedState::open()?;
    let file = state.lock()?;
    Ok(AttachLock { _file: file, state })
}

fn nbd_connected(device: &str) -> bool {
    match nbd_index(device) {
        Some(n) => Path::new(&format!("/sys/block/nbd{n}/pid")).exists(),
        None => false,
    }
}

/// Keep absence and an unreadable kernel observation distinct: recovery may
/// tear down upper layers only when the backend is known to be absent.
fn nbd_backend_at(sysfs: &Path, device: &str) -> io::Result<Option<String>> {
    let index = nbd_index(device)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid NBD device"))?;
    let path = sysfs.join(format!("nbd{index}"));
    match std::fs::read_to_string(path.join("backend")) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value.trim().to_string())),
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => match std::fs::symlink_metadata(path.join("pid")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "connected NBD device has no backend identifier; netlink identity support is required",
            )),
        },
    }
}

/// Lowest free `/dev/nbdN` according to sysfs (a connected device has a
/// `pid` attribute). Call with the attach lock held.
pub fn allocate_nbd_device() -> Result<String, ExecError> {
    let mut devices = Vec::new();
    for entry in std::fs::read_dir("/sys/class/block")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("nbd") && name[3..].chars().all(|c| c.is_ascii_digit()) {
            let connected = entry.path().join("pid").exists();
            devices.push((name, connected));
        }
    }
    choose_free_nbd(&devices).ok_or(ExecError::NoFreeDevice)
}

fn wait_nbd_ready(step: &PlannedStep, device: &str) -> Result<(), ExecError> {
    let Some(n) = nbd_index(device) else {
        return Err(ExecError::Step {
            step: step.to_string(),
            message: format!("{device} is not a /dev/nbdN device"),
        });
    };
    let size_path = format!("/sys/block/nbd{n}/size");
    let started = Instant::now();
    loop {
        let size: u64 = std::fs::read_to_string(&size_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if size > 0 && nbd_connected(device) {
            return Ok(());
        }
        if started.elapsed() > NBD_READY_TIMEOUT {
            return Err(ExecError::Step {
                step: step.to_string(),
                message: format!("{device} did not become ready within {NBD_READY_TIMEOUT:?}"),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn blkid_uuid(device: &str) -> Option<String> {
    let out = command::capture(
        Command::new("blkid").args(["-o", "value", "-s", "UUID", device]),
        command::Policy::PROBE,
    )
    .ok()?;
    if !out.status.success() {
        return None;
    }
    let uuid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if uuid.is_empty() {
        None
    } else {
        Some(uuid)
    }
}

/// Treat probe failure and ambiguous/malformed output as unavailable evidence.
/// Low-level blkid probing bypasses its cache; successful process exit alone
/// does not establish the requested TYPE or UUID tags.
fn verify_filesystem_probe(
    expected_uuid: Option<&str>,
    output: &std::process::Output,
) -> Result<(), ExecError> {
    if !output.status.success() {
        return Err(ExecError::StepFailed {
            step: "verify-filesystem-identity".into(),
            status: output.status.code(),
            stderr: "filesystem probe failed or returned ambiguous evidence".into(),
        });
    }
    let invalid = || ExecError::Step {
        step: "verify-filesystem-identity".into(),
        message: "filesystem probe returned invalid identity evidence".into(),
    };
    if output.stdout.len() > command::Policy::PROBE.max_output_bytes {
        return Err(invalid());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| invalid())?;
    let mut filesystem_type = None;
    let mut filesystem_uuid = None;
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once('=').ok_or_else(invalid)?;
        if key.is_empty() || value.is_empty() || line.chars().any(char::is_control) {
            return Err(invalid());
        }
        let field = match key {
            "TYPE" => &mut filesystem_type,
            "UUID" => &mut filesystem_uuid,
            // DEVNAME and other informational tags do not select the device.
            _ => continue,
        };
        if field.replace(value).is_some() {
            return Err(invalid());
        }
    }
    verify_filesystem_identity(expected_uuid, filesystem_type, filesystem_uuid)?;
    Ok(())
}

/// Longest sentinel the helper reads: a UUID plus slack. Anything larger
/// is not a sentinel (and must not be read into memory as root).
pub const SENTINEL_MAX_BYTES: u64 = 4096;

/// Read the sentinel under `mountpoint`. The mount root belongs to the
/// workload, so as root we never follow a symlink there (`O_NOFOLLOW`),
/// never open anything but a regular file, and never read more than
/// [`SENTINEL_MAX_BYTES`] (O-01).
pub fn read_sentinel(mountpoint: &str) -> Option<String> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = Path::new(mountpoint).join(SENTINEL_FILE);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > SENTINEL_MAX_BYTES {
        return None;
    }
    let mut text = String::new();
    file.take(SENTINEL_MAX_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    let value = text.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Create the sentinel if absent; refuse to change an existing one.
fn write_sentinel(
    step: &PlannedStep,
    mountpoint: &str,
    volume_uuid: &str,
) -> Result<(), ExecError> {
    match read_sentinel(mountpoint) {
        Some(existing) if existing == volume_uuid => Ok(()),
        Some(existing) => Err(ExecError::Step {
            step: step.to_string(),
            message: format!(
                "sentinel already holds a different volume uuid {existing:?}; refusing to overwrite"
            ),
        }),
        None => {
            let path = Path::new(mountpoint).join(SENTINEL_FILE);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(volume_uuid.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            File::open(mountpoint)?.sync_all()?;
            Ok(())
        }
    }
}

/// Write, fsync, read back and remove a probe file under the mountpoint.
///
/// The mount root is the workload's: the probe is created with
/// `O_CREAT|O_EXCL|O_NOFOLLOW` under an unpredictable name and read back
/// through the same descriptor, so a planted symlink, FIFO or file of that
/// name can neither be followed, truncated as root, nor block the helper
/// (O-01).
pub fn rw_probe(mountpoint: &str) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    let nonce = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{:x}{:x}", std::process::id(), t)
    };
    let path = Path::new(mountpoint).join(format!(".maki-rw-probe.{nonce}"));
    let result = (|| -> io::Result<bool> {
        let payload = format!("maki-rw-probe {}", std::process::id());
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
        let mut back = String::new();
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.take(SENTINEL_MAX_BYTES).read_to_string(&mut back)?;
        Ok(back == payload)
    })();
    let _ = std::fs::remove_file(&path);
    result.unwrap_or(false)
}

/// The block devices a mounted device (`major:minor`) ultimately lives
/// on: the sysfs name behind `/sys/dev/block/M:m`, then the `slaves`
/// relation down to devices with none (device-mapper and MD stack that
/// way). Partitions fold into their NBD device. Empty when sysfs cannot
/// answer, which the verifier treats as "not proven".
fn sysfs_leaf_devices(major_minor: &str) -> Vec<String> {
    let start = std::fs::read_link(format!("/sys/dev/block/{major_minor}"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
    let Some(start) = start else {
        return Vec::new();
    };
    let mut slaves_of = |name: &str| -> Vec<String> {
        std::fs::read_dir(format!("/sys/class/block/{name}/slaves"))
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    resolve_leaf_devices(&start, &mut slaves_of)
        .into_iter()
        .map(|leaf| nbd_device_of(&leaf).unwrap_or_else(|| format!("/dev/{leaf}")))
        .collect()
}

/// Gather every fact the verifier needs about a mounted volume. Only the
/// topology facts are collected when `touch` is false: nothing is written
/// to a filesystem whose device has not been verified yet (F02).
fn observe(mountpoint: &str, nbd_device: &str, touch: bool) -> MountObservation {
    let mountpoint_exists = Path::new(mountpoint).is_dir();
    let entry = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|text| parse_mountinfo(&text, mountpoint));
    let fstype = entry.as_ref().map(|e| e.fstype.clone());
    let fs_uuid = entry.as_ref().and_then(|e| blkid_uuid(&e.source));
    let backing_devices = entry
        .as_ref()
        .map(|e| sysfs_leaf_devices(&e.major_minor))
        .unwrap_or_default();
    MountObservation {
        mountpoint_exists,
        fstype,
        fs_uuid,
        sentinel_volume_uuid: if touch {
            read_sentinel(mountpoint)
        } else {
            None
        },
        nbd_connected: nbd_connected(nbd_device),
        rw_probe_ok: touch && entry.is_some() && rw_probe(mountpoint),
        backing_devices,
    }
}

/// Gather every fact the verifier needs about a mounted volume.
pub fn observe_mount(mountpoint: &str, nbd_device: &str) -> MountObservation {
    observe(mountpoint, nbd_device, true)
}

/// The upstream netlink API names a target as `nbdN`; `/dev/nbdN` is used by
/// block-device tools but is rejected by nbd-client's netlink parser.
fn nbd_client_target(device: &str) -> Result<String, ExecError> {
    nbd_index(device)
        .map(|index| format!("nbd{index}"))
        .ok_or_else(|| identity_error("invalid NBD device for nbd-client"))
}

fn run_step(step: &PlannedStep, connection_id: Option<&str>) -> Result<(), ExecError> {
    match step {
        PlannedStep::ModprobeNbd => run(step, "modprobe", &["nbd"]),
        PlannedStep::NbdConnect {
            socket,
            device,
            block_size,
        } => {
            let bs = block_size.to_string();
            let target = nbd_client_target(device)?;
            let identifier =
                connection_id.ok_or_else(|| identity_error("missing connect identifier"))?;
            run(
                step,
                "nbd-client",
                &[
                    "-unix",
                    socket,
                    &target,
                    "-b",
                    &bs,
                    "-identifier",
                    identifier,
                ],
            )
        }
        PlannedStep::SetBlockSize { device, block_size } => run(
            step,
            "blockdev",
            &["--setbsz", &block_size.to_string(), device],
        ),
        PlannedStep::LvmActivate { .. } => Err(identity_error(
            "LVM activation requires a connected record and verified preflight",
        )),
        PlannedStep::LvmDeactivate { vg_name } => run(step, "vgchange", &["-an", vg_name]),
        PlannedStep::VerifyFilesystemIdentity { device, fs_uuid } => {
            let output = command::capture(
                Command::new("blkid").args([
                    "--probe",
                    "--output",
                    "export",
                    "--match-tag",
                    "TYPE",
                    "--match-tag",
                    "UUID",
                    device,
                ]),
                command::Policy::PROBE,
            )?;
            verify_filesystem_probe(fs_uuid.as_deref(), &output)
        }
        PlannedStep::MountXfs { device, mountpoint } => run(
            step,
            "mount",
            &["-t", "xfs", "-o", "noatime", device, mountpoint],
        ),
        PlannedStep::VerifyMountDevice {
            mountpoint,
            nbd_device,
        } => {
            tracing::info!("maki-attach: {step}");
            let observed = observe(mountpoint, nbd_device, false);
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
            tracing::info!("maki-attach: {step}");
            let observed = observe_mount(mountpoint, nbd_device);
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
        PlannedStep::Umount { mountpoint } => run(step, "umount", &[mountpoint.as_str()]),
        PlannedStep::NbdDisconnect { device } => {
            let target = nbd_client_target(device)?;
            run(step, "nbd-client", &["-d", &target])
        }
        PlannedStep::LvExtend {
            vg_name,
            lv_name,
            target_bytes,
        } => run(
            step,
            "lvextend",
            &[
                "-L",
                &format!("{target_bytes}b"),
                &format!("{vg_name}/{lv_name}"),
            ],
        ),
        PlannedStep::XfsGrowfs { mountpoint } => run(step, "xfs_growfs", &[mountpoint.as_str()]),
    }
}

fn identity_error(message: impl Into<String>) -> ExecError {
    ExecError::Step {
        step: "nbd-identity".into(),
        message: message.into(),
    }
}

/// System interactions are isolated so tests exercise the same ordering,
/// record validation, and rollback decisions without touching devices.
trait System {
    fn lvm_preflight(
        &mut self,
        _record: &BoundDeviceRecord,
    ) -> Result<lvm_preflight::VerifiedLvm, ExecError> {
        Err(identity_error("LVM metadata preflight is unavailable"))
    }
    fn activate_lvm(
        &mut self,
        _record: &BoundDeviceRecord,
        _verified: &lvm_preflight::VerifiedLvm,
        _attempted: &mut bool,
    ) -> Result<(), ExecError> {
        Err(identity_error("verified LVM activation is unavailable"))
    }
    fn verify_activated_lvm(
        &self,
        _record: &BoundDeviceRecord,
        _verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        Err(io::Error::other(
            "activated LVM identity cannot be verified",
        ))
    }
    fn verify_rollback_lvm(
        &self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        self.verify_activated_lvm(record, verified)
    }
    fn deactivate_lvm(
        &mut self,
        _record: &BoundDeviceRecord,
        _verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        Err(identity_error("verified LVM rollback is unavailable"))
    }
    fn recover_deactivate_lvm(
        &mut self,
        _record: &BoundDeviceRecord,
        _verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        Err(identity_error(
            "verified LVM recovery deactivation is unavailable",
        ))
    }
    fn recovery_proof(
        &self,
        _record: &BoundDeviceRecord,
    ) -> io::Result<Option<recover::RecoveryProof>> {
        Ok(None)
    }
    fn recovery_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        self.detach_observation(record)
    }
    fn lv_size(&self, _vg: &str, _lv: &str) -> Result<u64, ExecError> {
        Err(identity_error("logical volume size cannot be observed"))
    }
    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError>;
    fn wait_ready(&mut self, step: &PlannedStep, device: &str) -> Result<(), ExecError>;
    fn allocate(&mut self) -> Result<String, ExecError>;
    fn backend(&self, device: &str) -> io::Result<Option<String>>;
    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation>;
    fn rollback_observation(
        &self,
        record: &BoundDeviceRecord,
        _allow_missing_sentinel: bool,
    ) -> io::Result<DetachObservation> {
        self.detach_observation(record)
    }
}

struct LinuxSystem;

impl System for LinuxSystem {
    fn lvm_preflight(
        &mut self,
        record: &BoundDeviceRecord,
    ) -> Result<lvm_preflight::VerifiedLvm, ExecError> {
        lvm_preflight::prepare(record)
    }
    fn activate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
        attempted: &mut bool,
    ) -> Result<(), ExecError> {
        lvm_preflight::activate(record, verified, attempted)
    }
    fn verify_activated_lvm(
        &self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        lvm_preflight::verify_mapping(record, verified, Path::new("/sys/class/block"))
    }
    fn verify_rollback_lvm(
        &self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        lvm_preflight::verify_rollback_mapping(record, verified, Path::new("/sys/class/block"))
    }
    fn deactivate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        lvm_preflight::deactivate(record, verified)
    }
    fn recover_deactivate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        lvm_preflight::deactivate_recovery(record, verified)
    }
    fn recovery_proof(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<Option<recover::RecoveryProof>> {
        recover::capture(
            record,
            &std::fs::read_to_string("/proc/self/mountinfo")?,
            Path::new("/sys/class/block"),
        )
        .map(Some)
    }
    fn recovery_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        recover::observe(
            record,
            &std::fs::read_to_string("/proc/self/mountinfo")?,
            Path::new("/sys/class/block"),
        )
    }
    fn lv_size(&self, vg: &str, lv: &str) -> Result<u64, ExecError> {
        let out = command::capture(
            Command::new("blockdev").args(["--getsize64", &format!("/dev/{vg}/{lv}")]),
            command::Policy::PROBE,
        )?;
        if !out.status.success() {
            return Err(identity_error("logical volume size probe failed"));
        }
        std::str::from_utf8(&out.stdout)
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .filter(|size| *size > 0)
            .ok_or_else(|| identity_error("logical volume size probe returned invalid bytes"))
    }
    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError> {
        run_step(step, identifier)
    }

    fn wait_ready(&mut self, step: &PlannedStep, device: &str) -> Result<(), ExecError> {
        wait_nbd_ready(step, device)
    }

    fn allocate(&mut self) -> Result<String, ExecError> {
        allocate_nbd_device()
    }

    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        nbd_backend_at(Path::new("/sys/block"), device)
    }

    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        crate::detach::observe(
            record,
            &std::fs::read_to_string("/proc/self/mountinfo")?,
            Path::new("/sys/class/block"),
        )
    }

    fn rollback_observation(
        &self,
        record: &BoundDeviceRecord,
        allow_missing_sentinel: bool,
    ) -> io::Result<DetachObservation> {
        crate::detach::observe_rollback(
            record,
            &std::fs::read_to_string("/proc/self/mountinfo")?,
            Path::new("/sys/class/block"),
            allow_missing_sentinel,
        )
    }
}

fn verify_connection(record: &BoundDeviceRecord, system: &impl System) -> Result<(), ExecError> {
    if system.backend(&record.device)?.as_deref() != Some(&record.connection_id) {
        return Err(identity_error(format!(
            "{} no longer has the recorded attachment identity; refusing to disconnect",
            record.device,
        )));
    }
    Ok(())
}

/// The connected, recorded mapping must still be unmounted before a block
/// probe or mount uses it. Repeat after probing, since probing can block.
fn verify_mount_target(record: &BoundDeviceRecord, system: &impl System) -> Result<(), ExecError> {
    verify_connection(record, system)?;
    if record.recovery.is_some() {
        let observed = system.recovery_observation(record)?;
        if observed.mounted || !observed.vg_active {
            return Err(identity_error(
                "mount target or mapping changed after recording recovery identity",
            ));
        }
        verify_connection(record, system)?;
    }
    Ok(())
}

fn verify_detach_state(
    record: &BoundDeviceRecord,
    system: &impl System,
) -> Result<(bool, DetachObservation), ExecError> {
    let connected = match system.backend(&record.device)? {
        Some(identifier) if identifier == record.connection_id => true,
        Some(_) => {
            return Err(identity_error(
                "recorded NBD device has a different backend identity",
            ))
        }
        None => false,
    };
    let observed = if record.recovery_intent.is_some() {
        system.recovery_observation(record)?
    } else {
        system.detach_observation(record)?
    };
    if !connected && (observed.mounted || observed.vg_active || observed.nbd_in_use) {
        return Err(identity_error(
            "NBD connection is absent but the attachment still has active mounts or mappings",
        ));
    }
    Ok((connected, observed))
}

/// Re-observe the live attachment a grow is about to mutate: the recorded
/// backend must still be connected under its identity, and the observed mount
/// and VG must belong to this attachment (not foreign) and be readable. A
/// grow that verified only the NBD identity could `lvextend`/`xfs_growfs` a
/// replaced mountpoint or a foreign VG mapping even though the stored config
/// and the live NBD identity still matched (review R03). Shares
/// `verify_detach_state`'s observation so grow and detach agree on what "the
/// live attachment" is; unlike detach it requires the connection present.
fn verify_live_attachment(
    record: &BoundDeviceRecord,
    system: &impl System,
) -> Result<(), ExecError> {
    let (connected, observed) = verify_detach_state(record, system)?;
    if !connected {
        return Err(identity_error(
            "recorded NBD device is no longer connected; refusing to grow",
        ));
    }
    // A grow operates in place on a mounted, active filesystem. A missing
    // mount or an inactive VG means the target is not the live attachment the
    // record names — extending it would lvextend an unmounted or foreign LV
    // (and xfs_growfs would then fail) — so require both before any mutation
    // (FUP-003).
    if !observed.mounted || !observed.vg_active {
        return Err(identity_error(
            "attachment is not fully live (mount or VG mapping missing); refusing to grow",
        ));
    }
    Ok(())
}

/// Roll back a failed attach by re-observing live state and tearing down what
/// is actually present — mount, then VG, then our own NBD backend — top layer
/// first. Returns `true` only if it fully cleaned up. It never removes a lower
/// layer while an upper one remains, verifies backend ownership before every
/// teardown, and *fails closed* (stops and keeps the trusted record) on any
/// command failure, remaining holder, or unreadable observation — so a lower
/// layer is never torn out from under an unknown or still-live upper one
/// (R01 / FUP-001 / R3-002).
fn attach_rollback(
    plan: &Plan,
    record: &BoundDeviceRecord,
    system: &mut impl System,
    rolled_back: &mut usize,
    allow_missing_sentinel: bool,
    activation: Option<&lvm_preflight::VerifiedLvm>,
) -> bool {
    // Each successful step removes one of at most three layers; the bound just
    // guards against an observation that never converges.
    for _ in 0..16 {
        let observed = match system.rollback_observation(record, allow_missing_sentinel) {
            Ok(o) => o,
            Err(e) => {
                tracing::error!("maki-attach: rollback halted, live state unreadable: {e}");
                return false;
            }
        };
        if (observed.mounted || observed.vg_active)
            && activation
                .is_none_or(|identity| system.verify_rollback_lvm(record, identity).is_err())
        {
            tracing::error!(
                "maki-attach: rollback halted; upper mapping has no verified activation identity"
            );
            return false;
        }
        // Topology alone cannot prove ownership of a reused NBD device. Check
        // its recorded nonce after each observation, before any upper-layer
        // teardown as well as disconnect. Missing identity permits cleanup
        // only when observation proves that every live resource is gone.
        match system.backend(&record.device) {
            Ok(Some(id)) if id == record.connection_id => {}
            Ok(None) if !observed.mounted && !observed.vg_active && !observed.nbd_in_use => {
                return true;
            }
            Ok(None) => {
                tracing::error!(
                    "maki-attach: rollback halted, backend absent with live resources; \
                     keeping the attach record"
                );
                return false;
            }
            Ok(Some(_)) => {
                tracing::warn!(
                    "maki-attach: rollback left a replaced/foreign backend in place; \
                     keeping the attach record"
                );
                return false;
            }
            Err(e) => {
                tracing::error!("maki-attach: rollback halted, backend unreadable: {e}");
                return false;
            }
        }
        let step = if observed.mounted {
            plan.steps.iter().find_map(|s| match s {
                PlannedStep::MountXfs { mountpoint, .. } => Some(PlannedStep::Umount {
                    mountpoint: mountpoint.clone(),
                }),
                _ => None,
            })
        } else if observed.vg_active {
            plan.steps.iter().find_map(|s| match s {
                PlannedStep::LvmActivate { vg_name } => Some(PlannedStep::LvmDeactivate {
                    vg_name: vg_name.clone(),
                }),
                _ => None,
            })
        } else if observed.nbd_in_use {
            tracing::error!("maki-attach: rollback halted, device still has holders");
            return false;
        } else {
            Some(PlannedStep::NbdDisconnect {
                device: record.device.clone(),
            })
        };
        let Some(step) = step else {
            return false;
        };
        let done = matches!(step, PlannedStep::NbdDisconnect { .. });
        let result = if matches!(step, PlannedStep::LvmDeactivate { .. }) {
            system.deactivate_lvm(record, activation.expect("active VG identity was checked"))
        } else {
            system.run_step(&step, None)
        };
        if let Err(e) = result {
            tracing::error!("maki-attach: rollback step {step} failed: {e}; stopping");
            return false;
        }
        *rolled_back += 1;
        if done {
            return true;
        }
    }
    false
}

fn detach_step_needed(
    step: &PlannedStep,
    record: &BoundDeviceRecord,
    system: &impl System,
) -> Result<bool, ExecError> {
    let (connected, observed) = verify_detach_state(record, system)?;
    match step {
        PlannedStep::Umount { .. } => Ok(observed.mounted),
        PlannedStep::LvmDeactivate { .. } if !observed.mounted => Ok(observed.vg_active),
        PlannedStep::NbdDisconnect { .. }
            if !observed.mounted && !observed.vg_active && !observed.nbd_in_use =>
        {
            Ok(connected)
        }
        _ => Err(identity_error(
            "earlier detach steps have not completed; refusing to deactivate or disconnect",
        )),
    }
}

/// Execute under one root-controlled lock, resolving runtime records only
/// after taking it. A pinned device never bypasses identity verification.
pub fn execute(plan: &Plan) -> Result<(), ExecError> {
    let needs_lock = plan.steps.iter().any(|s| {
        matches!(
            s,
            PlannedStep::NbdConnect { .. }
                | PlannedStep::NbdDisconnect { .. }
                | PlannedStep::LvExtend { .. }
                | PlannedStep::XfsGrowfs { .. }
        )
    });
    let lock = if needs_lock {
        Some(lock_attach()?)
    } else {
        None
    };
    execute_with(
        plan,
        lock.as_ref().map(|lock| &lock.state),
        &mut LinuxSystem,
    )
}

fn execute_with(
    plan: &Plan,
    state: Option<&TrustedState>,
    system: &mut impl System,
) -> Result<(), ExecError> {
    let mut plan = plan.clone();
    let connects = plan
        .steps
        .iter()
        .any(|s| matches!(s, PlannedStep::NbdConnect { .. }));
    let disconnects = plan
        .steps
        .iter()
        .any(|s| matches!(s, PlannedStep::NbdDisconnect { .. }));
    if plan.steps.iter().any(|step| matches!(step, PlannedStep::LvmActivate { vg_name }
        if !connects || plan.attachment.as_ref().is_none_or(|identity| &identity.vg_name != vg_name))) {
        return Err(identity_error("LVM activation plan is not bound to the attachment identity"));
    }
    // A grow changes an existing attachment's LVM/XFS in place. It must be
    // held against the same trusted record and serialized under the attach
    // lock as attach/detach, or it could extend an unrelated volume group,
    // or run while a detach is in flight (BUG-018).
    let grows = plan.steps.iter().any(|s| {
        matches!(
            s,
            PlannedStep::LvExtend { .. } | PlannedStep::XfsGrowfs { .. }
        )
    });
    let mut record = None;
    if connects || disconnects || grows {
        let state = state.ok_or_else(|| identity_error("attach state lock is required"))?;
        let prior = state.read(&plan.volume)?;
        if connects {
            if let Some(prior) = &prior {
                if system.backend(&prior.device)?.is_some() {
                    return Err(identity_error(
                        "recorded device is still connected; detach or verify its stale state before attaching",
                    ));
                }
                // A missing NBD backend is not proof the volume is fully
                // detached: a crashed daemon can leave a live mount, an active
                // VG, or other holders behind. Replacing the trusted record
                // then would discard the recovery identity of a volume that is
                // still partly attached, so re-observe and refuse unless every
                // upper-layer resource is also gone (FUP-002). An unreadable
                // observation fails closed via `?`.
                let observed = system.detach_observation(prior)?;
                if observed.mounted || observed.vg_active || observed.nbd_in_use {
                    return Err(identity_error(
                        "recorded device is disconnected but the attachment still has an active \
                         mount, VG mapping, or holder; complete detach before re-attaching",
                    ));
                }
            }
        } else {
            let prior = prior.ok_or_else(|| identity_error(format!(
                "no trusted attach record at {}; legacy device-only records are not imported, and a pinned device cannot bypass verification",
                crate::plan::bound_device_record_path(&plan.volume).display(),
            )))?;
            if plan.attachment.as_ref() != Some(&prior.attachment)
                || plan.steps.iter().any(|step| {
                    matches!(step,
                        PlannedStep::NbdDisconnect { device }
                            if device != crate::plan::AUTO_NBD_DEVICE && device != &prior.device
                    )
                })
            {
                let what = if disconnects { "detach" } else { "grow" };
                return Err(identity_error(format!(
                    "{what} configuration does not match the trusted attach record",
                )));
            }
            if disconnects {
                // Verify before umount or VG deactivation can affect anything.
                verify_detach_state(&prior, system)?;
                plan.bind_device(&prior.device);
            } else {
                // Grow: the attachment must still be the live one whose
                // identity the record names *and* whose live mount / VG the
                // record describes, before any lvextend/xfs_growfs — a stored
                // config plus a matching NBD identity can still coexist with a
                // replaced mountpoint or a changed active VG mapping (R03).
                verify_live_attachment(&prior, system)?;
            }
            record = Some(prior);
        }
    }
    if plan.needs_device_allocation() {
        system.run_step(&PlannedStep::ModprobeNbd, None)?;
        let device = system.allocate()?;
        tracing::info!("maki-attach: allocated {device}");
        plan.bind_device(&device);
        println!("# bound NBD device: {device}");
    }
    if connects {
        let device = plan
            .steps
            .iter()
            .find_map(|s| match s {
                PlannedStep::NbdConnect { device, .. } => Some(device.clone()),
                _ => None,
            })
            .unwrap();
        if system.backend(&device)?.is_some() {
            return Err(identity_error("requested NBD device is already connected"));
        }
        let nonce = std::fs::read_to_string("/proc/sys/kernel/random/uuid")?;
        let prepared = BoundDeviceRecord {
            version: 1,
            volume: plan.volume.clone(),
            attachment: plan
                .attachment
                .clone()
                .ok_or_else(|| identity_error("missing attachment configuration identity"))?,
            device,
            connection_id: format!("maki-{}", nonce.trim()),
            recovery: None,
            recovery_intent: None,
        };
        // A new operation owns only resources it creates. Refuse an already
        // mounted target, active VG, or holder before connecting or publishing
        // a record that could later authorize their rollback.
        let before = system.detach_observation(&prepared)?;
        if before.mounted || before.vg_active || before.nbd_in_use {
            return Err(identity_error(
                "new attachment has pre-existing mounts, mappings, or holders; refusing to adopt them",
            ));
        }
        // Persist the unique identity before connecting: process death
        // cannot leave an unrecorded connection or authorize a later reuse
        // of the same /dev/nbdN by a different attachment.
        state.unwrap().write(&prepared)?;
        record = Some(prepared);
    }

    let mut activation_identity = None;
    let mut activation_attempted = false;
    for step in &plan.steps {
        if grows {
            // Never let a changed mount/backend slip between lvextend and
            // xfs_growfs. Absolute targets make retries safe after either
            // command performed its effect but reported failure.
            verify_live_attachment(record.as_ref().unwrap(), system)?;
            if let PlannedStep::LvExtend {
                vg_name,
                lv_name,
                target_bytes,
            } = step
            {
                if *target_bytes == 0 {
                    return Err(identity_error("growth target must be positive"));
                }
                if system.lv_size(vg_name, lv_name)? >= *target_bytes {
                    continue;
                }
                verify_live_attachment(record.as_ref().unwrap(), system)?;
            }
        }
        if disconnects && !connects {
            // Reobserve before each step: a previous attempt may already
            // have completed it, or the mount/device may have changed.
            if !detach_step_needed(step, record.as_ref().unwrap(), system)? {
                continue;
            }
        }
        // `nbd-client` connecting and the device becoming ready are two
        // outcomes: once the connect command runs, a partially-connected
        // device is cleaned up by the observation-based rollback below, which
        // disconnects any backend that carries our identity — so a readiness
        // timeout (or a failure after the kernel was configured) never leaks a
        // connected device (O-07), without a separately tracked prefix.
        let result = match step {
            PlannedStep::NbdConnect { device, .. } => {
                let record = record.as_ref().unwrap();
                match system.run_step(step, Some(&record.connection_id)) {
                    Ok(()) => match system
                        .wait_ready(step, device)
                        .and_then(|()| verify_connection(record, system))
                    {
                        Ok(()) => continue,
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
            PlannedStep::NbdDisconnect { .. } => {
                verify_connection(record.as_ref().unwrap(), system)
                    .and_then(|()| system.run_step(step, None))
            }
            PlannedStep::LvmActivate { .. } if connects => {
                let current = record.as_mut().unwrap();
                verify_connection(current, system).and_then(|()| {
                    let verified = system.lvm_preflight(current)?;
                    verify_connection(current, system)?;
                    activation_identity = Some(verified.clone());
                    current.recovery_intent = Some(recover::RecoveryIntent::new(&verified));
                    state.unwrap().write(current)?;
                    verify_connection(current, system)?;
                    system.activate_lvm(current, &verified, &mut activation_attempted)?;
                    verify_connection(current, system)?;
                    system.verify_activated_lvm(current, &verified)?;
                    current.recovery = system.recovery_proof(current)?;
                    current.recovery_intent = None;
                    verify_connection(current, system)?;
                    state.unwrap().write(current)?;
                    Ok(())
                })
            }
            PlannedStep::LvmDeactivate { .. } if disconnects && !connects => {
                let current = record.as_ref().unwrap();
                if let Some(intent) = &current.recovery_intent {
                    verify_connection(current, system)?;
                    let observed = system.recovery_observation(current)?;
                    if observed.mounted || !observed.vg_active {
                        return Err(identity_error(
                            "persisted activation intent no longer identifies an active, unmounted mapping",
                        ));
                    }
                    system.verify_rollback_lvm(current, intent.verified())?;
                    verify_connection(current, system)?;
                    system.deactivate_lvm(current, intent.verified())
                } else {
                    system.run_step(step, None)
                }
            }
            PlannedStep::VerifyFilesystemIdentity { .. } if connects => {
                let current = record.as_ref().unwrap();
                verify_mount_target(current, system).and_then(|()| {
                    system.run_step(step, None)?;
                    verify_mount_target(current, system)
                })
            }
            PlannedStep::MountXfs { .. } if connects => {
                verify_mount_target(record.as_ref().unwrap(), system)
                    .and_then(|()| system.run_step(step, None))
            }
            other => system.run_step(other, None),
        };
        if let Err(error) = result {
            // Roll back by re-observing live state and tearing down what is
            // actually present, top layer first, halting on any unknown or
            // still-live upper layer (R01 / FUP-001). Attach only: a failed
            // detach is resumed on the next attempt, never rolled back.
            let mut rolled_back = 0usize;
            let clean = if connects {
                attach_rollback(
                    &plan,
                    record.as_ref().unwrap(),
                    system,
                    &mut rolled_back,
                    plan.steps
                        .iter()
                        .any(|s| matches!(s, PlannedStep::WriteSentinel { .. })),
                    activation_identity
                        .as_ref()
                        .filter(|_| activation_attempted),
                )
            } else {
                true
            };
            if connects && clean {
                let record = record.as_ref().unwrap();
                if matches!(system.backend(&record.device), Ok(None)) {
                    if let Err(error) = state.unwrap().remove(&plan.volume) {
                        // Preserve the original failure and rollback outcome.
                        // The record cannot authorize a different backend even
                        // if its cleanup failed.
                        tracing::warn!(
                            "maki-attach: rolled back but could not retire attach record: {error}"
                        );
                    }
                }
            }
            return Err(ExecError::RolledBack {
                error: Box::new(error),
                rolled_back,
                rollback_failed: usize::from(!clean),
            });
        }
    }
    // A completed detach retires the record; a failed one keeps it so the
    // next attempt still knows the device.
    if disconnects && !connects {
        state.unwrap().remove(&plan.volume)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "exec_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "command_tests.rs"]
mod command_tests;

/// Recover only disconnected storage, under the same root-controlled lock as attach.
/// Callers must stop workloads first; this command never starts or repairs a database.
pub fn recover(plan: &Plan) -> Result<(), ExecError> {
    let lock = lock_attach()?;
    recover_with(plan, &lock.state, &mut LinuxSystem)
}

/// Converge trusted storage state under the attach lock.
///
/// An absent record is already clean. A record whose backend still has the
/// recorded connection identity follows the regular detach path; an absent
/// backend follows disconnected recovery. Foreign and unreadable backends
/// fail closed before either path can mutate storage.
pub fn cleanup(plan: &Plan) -> Result<(), ExecError> {
    let lock = lock_attach()?;
    cleanup_with(plan, &lock.state, &mut LinuxSystem)
}

/// Check the current caller namespace's complete attachment before starting
/// a workload. Uses existing trusted state and config only, without repairs.
pub fn verify(volume: &str, config_path: &str) -> Result<(), ExecError> {
    workload_verify::execute(volume, config_path)
}

fn recover_with(
    plan: &Plan,
    state: &TrustedState,
    system: &mut impl System,
) -> Result<(), ExecError> {
    recover::execute(plan, state, system)
}

fn cleanup_with(
    plan: &Plan,
    state: &TrustedState,
    system: &mut impl System,
) -> Result<(), ExecError> {
    let Some(record) = state.read(&plan.volume)? else {
        return Ok(());
    };
    match system.backend(&record.device)? {
        Some(connection_id) if connection_id == record.connection_id => {
            execute_with(plan, Some(state), system)
        }
        None => recover_with(plan, state, system),
        Some(_) => Err(identity_error(
            "recorded NBD device has a foreign backend; refusing cleanup",
        )),
    }
}
