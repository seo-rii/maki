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

use crate::plan::{rollback_steps, Plan, PlannedStep, SENTINEL_FILE};
use crate::probe::{choose_free_nbd, nbd_index, parse_mountinfo};
use crate::verify::{verify_mount_identity, MountExpectation, MountObservation};

/// Serializes attach helpers system-wide (device allocation + connect).
pub const ATTACH_LOCK_PATH: &str = "/run/maki/attach.lock";
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
    let out = Command::new(program).args(args).output()?;
    if !out.status.success() {
        return Err(ExecError::StepFailed {
            step: step.to_string(),
            status: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(())
}

/// Held for the whole attach so two helpers cannot pick the same device;
/// the file lock is released when this is dropped.
pub struct AttachLock {
    _file: File,
}

pub fn lock_attach() -> io::Result<AttachLock> {
    if let Some(dir) = Path::new(ATTACH_LOCK_PATH).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(ATTACH_LOCK_PATH)?;
    file.lock()?;
    Ok(AttachLock { _file: file })
}

fn nbd_connected(device: &str) -> bool {
    match nbd_index(device) {
        Some(n) => Path::new(&format!("/sys/block/nbd{n}/pid")).exists(),
        None => false,
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
    let out = Command::new("blkid")
        .args(["-o", "value", "-s", "UUID", device])
        .output()
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

/// Gather every fact the verifier needs about a mounted volume.
pub fn observe_mount(mountpoint: &str, nbd_device: &str) -> MountObservation {
    let mountpoint_exists = Path::new(mountpoint).is_dir();
    let entry = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|text| parse_mountinfo(&text, mountpoint));
    let fstype = entry.as_ref().map(|e| e.fstype.clone());
    let fs_uuid = entry.as_ref().and_then(|e| blkid_uuid(&e.source));
    MountObservation {
        mountpoint_exists,
        fstype,
        fs_uuid,
        sentinel_volume_uuid: read_sentinel(mountpoint),
        nbd_connected: nbd_connected(nbd_device),
        rw_probe_ok: entry.is_some() && rw_probe(mountpoint),
    }
}

fn run_step(step: &PlannedStep) -> Result<(), ExecError> {
    match step {
        PlannedStep::ModprobeNbd => run(step, "modprobe", &["nbd"]),
        PlannedStep::NbdConnect {
            socket,
            device,
            block_size,
        } => {
            let bs = block_size.to_string();
            run(step, "nbd-client", &["-unix", socket, device, "-b", &bs])?;
            wait_nbd_ready(step, device)
        }
        PlannedStep::SetBlockSize { device, block_size } => run(
            step,
            "blockdev",
            &["--setbsz", &block_size.to_string(), device],
        ),
        PlannedStep::LvmActivate { vg_name } => run(step, "vgchange", &["-ay", vg_name]),
        PlannedStep::LvmDeactivate { vg_name } => run(step, "vgchange", &["-an", vg_name]),
        PlannedStep::MountXfs { device, mountpoint } => run(
            step,
            "mount",
            &["-t", "xfs", "-o", "noatime", device, mountpoint],
        ),
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
                },
                &observed,
            )?;
            Ok(())
        }
        PlannedStep::Umount { mountpoint } => run(step, "umount", &[mountpoint.as_str()]),
        PlannedStep::NbdDisconnect { device } => run(step, "nbd-client", &["-d", device]),
        PlannedStep::LvExtend {
            vg_name,
            lv_name,
            add_bytes,
        } => run(
            step,
            "lvextend",
            &[
                "-L",
                &format!("+{add_bytes}b"),
                &format!("{vg_name}/{lv_name}"),
            ],
        ),
        PlannedStep::XfsGrowfs { mountpoint } => run(step, "xfs_growfs", &[mountpoint.as_str()]),
    }
}

/// Execute a plan. A plan that still needs an NBD device gets one allocated
/// under the attach lock (held for the whole run). If a step fails, the
/// executed prefix is rolled back in reverse and the original error is
/// returned with the rollback outcome.
pub fn execute(plan: &Plan) -> Result<(), ExecError> {
    let mut plan = plan.clone();
    if plan.unresolved_disconnect() {
        return Err(ExecError::Step {
            step: "nbd-disconnect".to_string(),
            message: format!(
                "the NBD device is on auto and no device was recorded at attach ({}); \
                 refusing to guess which device to disconnect (pass --nbd-device)",
                crate::plan::bound_device_record_path(&plan.volume).display()
            ),
        });
    }
    // Connecting *and* disconnecting serialize under the attach lock: a
    // detach racing another volume's attach must not touch its device.
    let needs_lock = plan.steps.iter().any(|s| {
        matches!(
            s,
            PlannedStep::NbdConnect { .. } | PlannedStep::NbdDisconnect { .. }
        )
    });
    let _lock = if needs_lock {
        Some(lock_attach()?)
    } else {
        None
    };
    if plan.needs_device_allocation() {
        // The module must be loaded before sysfs lists any nbd device.
        run(&PlannedStep::ModprobeNbd, "modprobe", &["nbd"])?;
        let device = allocate_nbd_device()?;
        tracing::info!("maki-attach: allocated {device}");
        plan.bind_device(&device);
        println!("# bound NBD device: {device}");
    }
    // Remember the device an attach binds, for the detach that follows
    // (O-02). Written before connecting so a crash between the two leaves
    // at worst a stale record naming an unconnected device.
    let connects = plan.steps.iter().find_map(|s| match s {
        PlannedStep::NbdConnect { device, .. } => Some(device.clone()),
        _ => None,
    });
    if let Some(device) = &connects {
        let record = crate::plan::bound_device_record_path(&plan.volume);
        if let Some(dir) = record.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&record, format!("{device}\n"))?;
    }

    let mut executed: Vec<PlannedStep> = Vec::new();
    for step in &plan.steps {
        // `nbd-client` connecting and the device becoming ready are two
        // outcomes: once the connect succeeded the step counts as executed
        // even if readiness times out, so the rollback disconnects it
        // instead of leaking a connected device (O-07).
        let result = match step {
            PlannedStep::NbdConnect {
                socket,
                device,
                block_size,
            } => {
                let bs = block_size.to_string();
                match run(step, "nbd-client", &["-unix", socket, device, "-b", &bs]) {
                    Ok(()) => {
                        executed.push(step.clone());
                        match wait_nbd_ready(step, device) {
                            Ok(()) => continue,
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            other => run_step(other),
        };
        if let Err(error) = result {
            let rollback = rollback_steps(&executed);
            let mut failed = 0usize;
            for compensating in &rollback {
                if let Err(e) = run_step(compensating) {
                    failed += 1;
                    tracing::error!("maki-attach: rollback step {compensating} failed: {e}");
                }
            }
            return Err(ExecError::RolledBack {
                error: Box::new(error),
                rolled_back: rollback.len() - failed,
                rollback_failed: failed,
            });
        }
        executed.push(step.clone());
    }
    // A completed detach retires the record; a failed one keeps it so the
    // next attempt still knows the device.
    if plan
        .steps
        .iter()
        .any(|s| matches!(s, PlannedStep::NbdDisconnect { .. }))
        && connects.is_none()
    {
        let _ = std::fs::remove_file(crate::plan::bound_device_record_path(&plan.volume));
    }
    Ok(())
}
