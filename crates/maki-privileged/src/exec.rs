//! Plan executor (Linux only): runs each planned step via the corresponding
//! system utility, with real mount-identity verification (review M-006),
//! NBD device allocation under the attach lock, readiness waits, and
//! reverse rollback of the executed prefix when a step fails (review
//! M-016). All decision logic lives in the pure planner, verifier and
//! probe parsers so it is testable everywhere; this module only gathers
//! facts and runs commands.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[path = "command.rs"]
pub(crate) mod command;

#[path = "recover.rs"]
pub(crate) mod recover;

#[path = "workload_verify.rs"]
mod workload_verify;

#[path = "lvm_preflight.rs"]
mod lvm_preflight;

#[path = "allocation.rs"]
mod allocation;

#[path = "displaced.rs"]
mod displaced;

use crate::detach::DetachObservation;
use crate::plan::{Plan, PlannedStep, MOUNT_OPTIONS, SENTINEL_FILE};
use crate::probe::{nbd_device_of, nbd_index, parse_mountinfo, resolve_leaf_devices};
use crate::state::{BoundDeviceRecord, StateLock, TrustedState};
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
    #[error(
        "no free /dev/nbdN device (all connected, in use or named by an attach record, or module \
         not loaded)"
    )]
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

/// Refuse a mountpoint whose path a non-trusted user could redirect.
///
/// `mount(8)` resolves the path it is given, as root, and the directories
/// along it may belong to the workload. Every ancestor must therefore be a
/// real directory (not a symlink) owned by a `trusted` uid and not writable
/// by group or others, so the path cannot change between this check and the
/// mount; the mountpoint itself must be such a directory too. Rollback and
/// detach look for the mount at the configured path, so a redirected mount
/// (say over `/etc`) could never be undone.
pub fn check_mount_target(mountpoint: &str, trusted: &[u32]) -> Result<(), ExecError> {
    use std::os::unix::fs::MetadataExt;

    let refuse = |message: String| ExecError::Step {
        step: "mount-target".into(),
        message,
    };
    let path = Path::new(mountpoint);
    if !path.is_absolute() {
        return Err(refuse(format!("mountpoint {mountpoint:?} is not absolute")));
    }
    let mut prefix = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        prefix.push(component);
        let meta = std::fs::symlink_metadata(&prefix)
            .map_err(|e| refuse(format!("{}: {e}", prefix.display())))?;
        if meta.file_type().is_symlink() {
            return Err(refuse(format!(
                "{} is a symlink; a mountpoint path must not contain one",
                prefix.display()
            )));
        }
        if !meta.is_dir() {
            return Err(refuse(format!("{} is not a directory", prefix.display())));
        }
        // The mountpoint itself follows the same rule (R5-024): a workload
        // owning it could stack a FUSE mount there between this check and
        // the mount. It is hidden once the volume is mounted, so this costs
        // the workload nothing; the volume's own root carries its ownership.
        let what = if index + 1 == components.len() {
            "the mountpoint directory"
        } else {
            "every ancestor of the mountpoint"
        };
        if !trusted.contains(&meta.uid()) {
            return Err(refuse(format!(
                "{} is owned by uid {}; {what} must be owned by root",
                prefix.display(),
                meta.uid()
            )));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(refuse(format!(
                "{} is writable by group or others (mode {:04o}); the mountpoint path could \
                 be replaced or mounted over before the mount",
                prefix.display(),
                meta.mode() & 0o7777
            )));
        }
    }
    Ok(())
}

fn run(step: &PlannedStep, program: &str, args: &[&str]) -> Result<(), ExecError> {
    tracing::info!("maki-attach: {step}");
    let out = command::capture(
        command::controlled(program).args(args),
        command::Policy::STEP,
    )?;
    if !out.status.success() {
        return Err(ExecError::StepFailed {
            step: step.to_string(),
            status: out.status.code(),
            stderr: "external command output omitted".into(),
        });
    }
    Ok(())
}

/// Load the attach configuration for a verb that executes: only an existing,
/// root-owned file below root-owned directories without group/other write
/// access, read through held descriptors. The verb runs as root on what the
/// file says (mountpoint, VG, NBD socket), so a file a non-root user could
/// write would hand them those choices (R5-030).
pub fn load_trusted_config(path: impl AsRef<Path>) -> Result<crate::config::AttachConfig, String> {
    let path = path.as_ref();
    let text = crate::state::read_verify_config(path).map_err(|error| {
        format!(
            "attach config {path:?} must be a root-owned regular file below root-owned \
             directories without group/other write access: {error}"
        )
    })?;
    crate::config::parse(&text).map_err(|error| error.to_string())
}

/// Held for the whole attach so two helpers cannot pick the same device;
/// the file lock is released when this is dropped.
pub struct AttachLock {
    _lock: StateLock,
    state: TrustedState,
}

pub fn lock_attach() -> io::Result<AttachLock> {
    let state = TrustedState::open()?;
    let lock = state.lock()?;
    Ok(AttachLock { _lock: lock, state })
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

/// The mount table of the helper's namespace.
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// Read the mount table as bytes. Linux escapes only space, tab, newline
/// and backslash in its fields and emits every other byte as is, so one
/// mount anywhere in the namespace whose path or source is not UTF-8 (a
/// user's FUSE mount, a Latin-1 CIFS or USB mount) is ordinary state, not a
/// failed observation. The `probe` parsers compare the exact bytes.
fn read_mountinfo() -> io::Result<Vec<u8>> {
    std::fs::read(MOUNTINFO)
}

/// Lowest unused `/dev/nbdN` in sysfs and the current mount namespace.
/// Connections, root/partition holders and direct mounts occupy a device.
/// Call with the attach lock held; observation failures refuse allocation.
/// This is the kernel's view only: an attach also leaves out every device
/// that another volume's trusted record names.
pub fn allocate_nbd_device() -> Result<String, ExecError> {
    allocation::allocate(Path::new("/sys/class/block"), Path::new(MOUNTINFO))
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

/// The filesystem UUID probe for a mount source. The source comes from
/// mountinfo and is chosen by whoever mounted there (a FUSE `fsname` can be
/// anything), so only an absolute path is probed, and `--` ends blkid's
/// options before it (BUG-096). The topology check still decides whether
/// the device is the volume's.
fn blkid_uuid_command(device: &str) -> Option<std::process::Command> {
    if !device.starts_with('/') {
        return None;
    }
    let mut command = command::controlled("blkid");
    command.args(["-o", "value", "-s", "UUID", "--", device]);
    Some(command)
}

fn blkid_uuid(device: &str) -> Option<String> {
    let out = command::capture(&mut blkid_uuid_command(device)?, command::Policy::PROBE).ok()?;
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

/// Publish only a fully written, synced sentinel, without replacing an
/// existing name. An identical sentinel is rewritten before every retry sync:
/// failed fsync may have cleared its dirty pages while leaving readable bytes.
fn write_sentinel(
    step: &PlannedStep,
    mountpoint: &str,
    volume_uuid: &str,
) -> Result<(), ExecError> {
    write_sentinel_with_boundary(step, mountpoint, volume_uuid, |_| Ok(()))
}

fn write_sentinel_with_boundary(
    step: &PlannedStep,
    mountpoint: &str,
    volume_uuid: &str,
    mut boundary: impl FnMut(&'static str) -> io::Result<()>,
) -> Result<(), ExecError> {
    use std::ffi::CString;
    use std::io::{Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(mountpoint)?;
    let name = CString::new(SENTINEL_FILE).expect("constant contains no NUL");
    let open_existing = || -> io::Result<File> {
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    };
    let payload = format!("{volume_uuid}\n");
    let persist = |file: &mut File,
                   boundary: &mut dyn FnMut(&'static str) -> io::Result<()>|
     -> io::Result<()> {
        boundary("write")?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(payload.as_bytes())?;
        file.set_len(payload.len() as u64)?;
        boundary("file-sync")?;
        file.sync_all()
    };
    let persist_existing = |mut file: File,
                            boundary: &mut dyn FnMut(&'static str) -> io::Result<()>|
     -> Result<(), ExecError> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > SENTINEL_MAX_BYTES {
            return Err(identity_error("sentinel is not a single regular file"));
        }
        let mut existing = String::new();
        (&mut file)
            .take(SENTINEL_MAX_BYTES)
            .read_to_string(&mut existing)?;
        if !existing.trim().eq_ignore_ascii_case(volume_uuid) {
            // Existing bytes belong to the workload and can be plaintext
            // unrelated to any UUID. Keep them out of every error rendering.
            return Err(ExecError::Step {
                step: step.to_string(),
                message: "sentinel does not match the expected volume UUID; refusing to overwrite"
                    .into(),
            });
        }
        persist(&mut file, boundary)?;
        Ok(())
    };
    match open_existing() {
        Ok(file) => persist_existing(file, &mut boundary)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Names are unguessable and operations stay below the pinned
            // directory descriptor even if the mountpoint path is renamed.
            let mut nonce = [0u8; 16];
            let mut filled = 0;
            while filled < nonce.len() {
                let amount = unsafe {
                    libc::getrandom(nonce[filled..].as_mut_ptr().cast(), nonce.len() - filled, 0)
                };
                if amount < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error.into());
                }
                if amount == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "empty random source",
                    )
                    .into());
                }
                filled += amount as usize;
            }
            let temporary = CString::new(format!(
                ".maki-sentinel.tmp-{:032x}",
                u128::from_le_bytes(nonce)
            ))
            .unwrap();
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_RDWR
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error().into());
            }
            struct Pending<'a> {
                directory: &'a File,
                name: CString,
            }
            impl Drop for Pending<'_> {
                fn drop(&mut self) {
                    unsafe {
                        libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
                    }
                }
            }
            let pending = Pending {
                directory: &directory,
                name: temporary,
            };
            let mut file = unsafe { File::from_raw_fd(descriptor) };
            persist(&mut file, &mut boundary)?;
            boundary("publish")?;
            let result = unsafe {
                libc::renameat2(
                    directory.as_raw_fd(),
                    pending.name.as_ptr(),
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    // A concurrent publisher is validated and re-synced by
                    // the same existing-file path; never replace its inode.
                    persist_existing(open_existing()?, &mut boundary)?;
                } else {
                    return Err(error.into());
                }
            } else {
                boundary("published")?;
            }
            // The temporary name is now absent. Its guard also cleans up
            // unpublished partial writes and every failure before rename.
            drop(pending);
        }
        Err(error) => return Err(error.into()),
    }
    boundary("directory-sync")?;
    directory.sync_all()?;
    Ok(())
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
/// to a filesystem whose device has not been verified yet (F02). A mount
/// table that cannot be read is an error, never "nothing is mounted".
fn observe(mountpoint: &str, nbd_device: &str, touch: bool) -> io::Result<MountObservation> {
    let mountpoint_exists = Path::new(mountpoint).is_dir();
    let entry = parse_mountinfo(&read_mountinfo()?, mountpoint);
    let fstype = entry.as_ref().map(|e| e.fstype.clone());
    let fs_uuid = entry.as_ref().and_then(|e| blkid_uuid(&e.source));
    let backing_devices = entry
        .as_ref()
        .map(|e| sysfs_leaf_devices(&e.major_minor))
        .unwrap_or_default();
    Ok(MountObservation {
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
        mount_options: entry.map(|e| e.mount_options).unwrap_or_default(),
        backing_devices,
    })
}

/// Gather every fact the verifier needs about a mounted volume.
pub fn observe_mount(mountpoint: &str, nbd_device: &str) -> io::Result<MountObservation> {
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
                command::controlled("blkid").args([
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
        PlannedStep::MountXfs { device, mountpoint } => {
            check_mount_target(mountpoint, &[0])?;
            run(
                step,
                "mount",
                &["-t", "xfs", "-o", MOUNT_OPTIONS, device, mountpoint],
            )
        }
        PlannedStep::VerifyMountDevice {
            mountpoint,
            nbd_device,
        } => {
            tracing::info!("maki-attach: {step}");
            let observed = observe(mountpoint, nbd_device, false)?;
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
            let observed = observe_mount(mountpoint, nbd_device)?;
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
            ..
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

/// The command ran to its own end and reported failure. A command that a
/// signal terminated has no exit status: it never said whether it could do
/// its work, and may have stopped halfway through it.
fn exited_nonzero(error: &ExecError) -> bool {
    matches!(error, ExecError::StepFailed { status: Some(code), .. } if *code != 0)
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
    fn deactivate_lvm_from_proof(&mut self, _record: &BoundDeviceRecord) -> Result<(), ExecError> {
        Err(identity_error(
            "proof-scoped device-mapper deactivation is unavailable",
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
    fn disconnected_recovery_observation(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<DetachObservation> {
        self.recovery_observation(record)
    }
    fn lv_size(&self, _vg: &str, _lv: &str) -> Result<u64, ExecError> {
        Err(identity_error("logical volume size cannot be observed"))
    }
    /// Tell the operator which device the plan's `auto` became. Only the
    /// real system prints.
    fn announce_bound_device(&mut self, _device: &str) {}
    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError>;
    fn wait_ready(&mut self, step: &PlannedStep, device: &str) -> Result<(), ExecError>;
    fn allocate(&mut self) -> Result<String, ExecError>;
    /// A free device that is none of `reserved`, the devices other volumes'
    /// trusted records name. An implementation that knows only `allocate`
    /// cannot look past a reserved device; the executor refuses that answer.
    fn allocate_excluding(&mut self, _reserved: &BTreeSet<String>) -> Result<String, ExecError> {
        self.allocate()
    }
    fn backend(&self, device: &str) -> io::Result<Option<String>>;
    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation>;
    /// What the host still shows of `record`'s attachment, whose device
    /// carries another connection: see [`displaced::remains`].
    fn displaced_remains(
        &self,
        _record: &BoundDeviceRecord,
        _vg_uuid: &str,
    ) -> io::Result<Option<String>> {
        Err(io::Error::other(
            "the host's mappings and mounts cannot be observed",
        ))
    }
}

struct LinuxSystem;

impl System for LinuxSystem {
    fn announce_bound_device(&mut self, device: &str) {
        // Not `println!`, which panics when the write fails: this comes
        // after the NBD module is loaded and before the device is
        // connected, and a stdout nobody reads must not end the attach here.
        let _ = writeln!(io::stdout().lock(), "# bound NBD device: {device}");
    }

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
    fn deactivate_lvm_from_proof(&mut self, record: &BoundDeviceRecord) -> Result<(), ExecError> {
        recover::deactivate_connected_from_proof(record)
    }
    fn recovery_proof(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<Option<recover::RecoveryProof>> {
        recover::capture(record, &read_mountinfo()?, Path::new("/sys/class/block")).map(Some)
    }
    fn recovery_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        recover::observe(record, &read_mountinfo()?, Path::new("/sys/class/block"))
    }
    fn disconnected_recovery_observation(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<DetachObservation> {
        recover::observe_disconnected(record, &read_mountinfo()?, Path::new("/sys/class/block"))
    }
    fn lv_size(&self, vg: &str, lv: &str) -> Result<u64, ExecError> {
        let out = command::capture(
            command::controlled("blockdev").args(["--getsize64", &format!("/dev/{vg}/{lv}")]),
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

    fn allocate_excluding(&mut self, reserved: &BTreeSet<String>) -> Result<String, ExecError> {
        allocation::allocate_excluding(
            Path::new("/sys/class/block"),
            Path::new(MOUNTINFO),
            reserved,
        )
    }

    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        nbd_backend_at(Path::new("/sys/block"), device)
    }

    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        crate::detach::observe(record, &read_mountinfo()?, Path::new("/sys/class/block"))
    }

    fn displaced_remains(
        &self,
        record: &BoundDeviceRecord,
        vg_uuid: &str,
    ) -> io::Result<Option<String>> {
        displaced::remains(
            record,
            vg_uuid,
            &read_mountinfo()?,
            Path::new("/sys/class/block"),
        )
    }
}

/// The refusal of a verb that finds the recorded device connected under an
/// identity other than the recorded one. Nothing is changed and the record
/// is kept.
fn other_identity_message(record: &BoundDeviceRecord, refused: &str) -> String {
    format!(
        "{device} is recorded for volume {volume} but is connected under another identity; \
         refusing {refused} and keeping the attach record. Detach the volume or disconnect the \
         NBD client that uses {device} now, then run `maki-attach cleanup --volume {volume}`",
        device = record.device,
        volume = record.volume,
    )
}

fn other_identity(record: &BoundDeviceRecord, refused: &str) -> ExecError {
    identity_error(other_identity_message(record, refused))
}

/// Retire `record`, whose device was seen carrying the connection
/// `displaced_by`, when the host shows that nothing of the recorded
/// attachment remains; otherwise refuse `refused` and keep the record.
///
/// Nothing is run, and nothing of the device or of its present connection
/// is touched. The caller holds the attach lock, under which every record is
/// written, and has read `record` under it. The record is retired only when
/// it names its VG UUID, no other record names the device with the same or
/// no VG UUID, and two observations of the host, each followed by the same
/// backend, show nothing of the attachment (see [`displaced::remains`]).
fn retire_displaced(
    record: &BoundDeviceRecord,
    displaced_by: &str,
    refused: &str,
    state: &TrustedState,
    system: &impl System,
) -> Result<(), ExecError> {
    let kept = |reason: &dyn std::fmt::Display| {
        identity_error(format!(
            "{}. The record is not retired automatically: {reason}",
            other_identity_message(record, refused)
        ))
    };
    let vg_uuid = displaced::recorded_vg_uuid(record).map_err(|reason| kept(&reason))?;
    // With two records on one device, a mapping can be told to be the other
    // volume's only by its VG UUID.
    for other in state
        .records_of_other_volumes(&record.volume)
        .map_err(|error| kept(&error))?
        .into_iter()
        .filter(|other| other.device == record.device)
    {
        match displaced::recorded_vg_uuid(&other) {
            Ok(theirs) if theirs != vg_uuid => {}
            Ok(_) => {
                return Err(kept(&format!(
                    "the attach record of volume {} names {} with the same VG UUID, so their \
                     mappings cannot be told apart",
                    other.volume, other.device
                )))
            }
            Err(_) => {
                return Err(kept(&format!(
                    "the attach record of volume {} names {} and carries no VG UUID to tell \
                     their mappings apart",
                    other.volume, other.device
                )))
            }
        }
    }
    // A mapping or a mount can appear while the host is walked: look twice,
    // and hold the device to the same connection after each look.
    for _ in 0..2 {
        match system.displaced_remains(record, &vg_uuid) {
            Ok(None) => {}
            Ok(Some(remaining)) => return Err(kept(&remaining)),
            Err(error) => {
                return Err(kept(&format!(
                    "the host's mappings, holders and mounts cannot be read ({error})"
                )))
            }
        }
        if system.backend(&record.device)?.as_deref() != Some(displaced_by) {
            return Err(kept(&format!(
                "the connection on {} changed while the host was observed",
                record.device
            )));
        }
    }
    state.remove(&record.volume)?;
    tracing::warn!(
        "maki-attach: retired the attach record of volume {}: {} is connected under another \
         identity and nothing of the recorded attachment remains; nothing was run against the \
         device",
        record.volume,
        record.device
    );
    Ok(())
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
        Some(_) => return Err(other_identity(record, "to act on the attachment")),
        None => false,
    };
    observe_detach_state(record, system, connected)
}

/// The detach observation of `record`, whose device is `connected` under
/// the recorded identity or carries no backend.
fn observe_detach_state(
    record: &BoundDeviceRecord,
    system: &impl System,
    connected: bool,
) -> Result<(bool, DetachObservation), ExecError> {
    let observed = if record.recovery.is_some() || record.recovery_intent.is_some() {
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
    let (connected, observed) = match system.backend(&record.device)? {
        Some(identifier) if identifier != record.connection_id => {
            return Err(identity_error(format!(
                "{}. A grow needs the recorded attachment connected; cleanup retires the record \
                 without touching the device once it can show that nothing of the attachment \
                 remains",
                other_identity_message(record, "to grow")
            )))
        }
        backend => observe_detach_state(record, system, backend.is_some())?,
    };
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
    if !observed.writable {
        return Err(identity_error("grow requires a writable XFS mount"));
    }
    if let Some(proof) = &record.recovery {
        proof.verify_growth_topology(record)?;
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
    activation: Option<&lvm_preflight::VerifiedLvm>,
) -> bool {
    // Each successful step removes one of at most three layers; the bound just
    // guards against an observation that never converges.
    for _ in 0..16 {
        let observed = match system.detach_observation(record) {
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
    execute_with_options(plan, state, system, false)
}

fn execute_with_options(
    plan: &Plan,
    state: Option<&TrustedState>,
    system: &mut impl System,
    allow_proof_deactivation: bool,
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
    // The devices other volumes' trusted records name, by device. A record
    // can outlive its connection, and its device then shows no backend,
    // holder or mount: only the records, read under the attach lock every
    // writer holds, show that it is still that volume's.
    let mut reserved = BTreeMap::new();
    if connects || disconnects || grows {
        let state = state.ok_or_else(|| identity_error("attach state lock is required"))?;
        let prior = state.read(&plan.volume)?;
        if connects {
            if let Some(prior) = &prior {
                match system.backend(&prior.device)? {
                    None => {
                        // A missing NBD backend is not proof the volume is
                        // fully detached: a crashed daemon can leave a live
                        // mount, an active VG, or other holders behind.
                        // Replacing the trusted record then would discard the
                        // recovery identity of a volume that is still partly
                        // attached, so re-observe and refuse unless every
                        // upper-layer resource is also gone (FUP-002). An
                        // unreadable observation fails closed via `?`.
                        let observed = system.detach_observation(prior)?;
                        if observed.mounted || observed.vg_active || observed.nbd_in_use {
                            return Err(identity_error(
                                "recorded device is disconnected but the attachment still has an \
                                 active mount, VG mapping, or holder; complete detach before \
                                 re-attaching",
                            ));
                        }
                    }
                    Some(identifier) if identifier == prior.connection_id => {
                        return Err(identity_error(
                            "recorded device is still connected; detach or verify its stale state before attaching",
                        ))
                    }
                    // The device is another connection's now. Its holders are
                    // that connection's, so the check above cannot apply;
                    // the record goes only if nothing of it remains, and
                    // allocation below leaves the device out.
                    Some(identifier) => {
                        retire_displaced(prior, &identifier, "to attach", state, system)?
                    }
                }
            }
            // This volume's own record is judged above and replaced below.
            reserved = state.devices_of_other_volumes(&plan.volume)?;
        } else {
            let prior = prior.ok_or_else(|| identity_error(format!(
                "no trusted attach record at {}; legacy device-only records are not imported, and a pinned device cannot bypass verification",
                crate::plan::bound_device_record_path(&plan.volume).display(),
            )))?;
            if plan.attachment.as_ref() != Some(&prior.attachment)
                || plan.steps.iter().any(|step| {
                    matches!(step,
                        PlannedStep::NbdDisconnect { device } | PlannedStep::LvExtend { nbd_device: device, .. }
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
                let connected = match system.backend(&prior.device)? {
                    Some(identifier) if identifier == prior.connection_id => true,
                    // Another connection's device: nothing of this attachment
                    // is left to detach once the record is retired.
                    Some(identifier) => {
                        retire_displaced(&prior, &identifier, "to detach", state, system)?;
                        tracing::warn!(
                            "maki-attach: volume {} was not attached on {}; nothing was detached",
                            plan.volume,
                            prior.device
                        );
                        return Ok(());
                    }
                    None => false,
                };
                observe_detach_state(&prior, system, connected)?;
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
        // Only an attach takes a device: it holds the lock under which the
        // records were read, and publishes its own before connecting.
        if !connects {
            return Err(identity_error(
                "only an attach allocates an NBD device; this plan connects none",
            ));
        }
        system.run_step(&PlannedStep::ModprobeNbd, None)?;
        let device = system.allocate_excluding(&reserved.keys().cloned().collect())?;
        tracing::info!("maki-attach: allocated {device}");
        plan.bind_device(&device);
        system.announce_bound_device(&device);
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
        let attachment = plan
            .attachment
            .as_ref()
            .ok_or_else(|| identity_error("missing attachment configuration identity"))?;
        // An automatic device becomes concrete only after loading the module.
        crate::config::check_vg_device(&attachment.vg_name, &device)
            .map_err(|error| identity_error(error.to_string()))?;
        // A pinned device never went through allocation, and an allocated
        // one is checked again: another volume's record keeps its device.
        if let Some(owner) = reserved.get(&device) {
            return Err(identity_error(format!(
                "{device} is named by the attach record of volume {owner}; refusing to attach \
                 volume {volume} on it. If that attachment is gone, run `maki-attach cleanup \
                 --volume {owner}` first; otherwise use another nbd_device",
                volume = plan.volume,
            )));
        }
        if system.backend(&device)?.is_some() {
            return Err(identity_error("requested NBD device is already connected"));
        }
        let nonce = std::fs::read_to_string("/proc/sys/kernel/random/uuid")?;
        let prepared = BoundDeviceRecord {
            version: 1,
            volume: plan.volume.clone(),
            attachment: attachment.clone(),
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
        // Mounting over a filesystem already mounted below the mountpoint
        // hides it, and its owner's detach would then resolve the same path
        // inside this volume (BUG-118). The verify gate refuses the same.
        if before.nested {
            return Err(identity_error(
                "a filesystem is already mounted below the mountpoint; refusing to mount over it",
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
                ..
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
                    // The intent has no other way down: the direct removal
                    // below needs the completed mapping proof. LVM can also
                    // end successfully without having found the volume
                    // group, so look again instead of trusting its status.
                    let outcome = match system.deactivate_lvm(current, intent.verified()) {
                        Ok(()) => system
                            .recovery_observation(current)?
                            .vg_active
                            .then(|| "left its mapping active".to_string()),
                        Err(ExecError::Step { message, .. }) => Some(format!("failed ({message})")),
                        Err(error) => Some(format!("failed ({error})")),
                    };
                    if let Some(outcome) = outcome {
                        return Err(identity_error(format!(
                            "scoped LVM deactivation of the interrupted activation on {} \
                             {outcome}. LVM reads the volume group from that device and can \
                             deactivate the mapping only while the volume's daemon serves it; \
                             keeping the attach record",
                            current.device
                        )));
                    }
                    Ok(())
                } else {
                    match system.run_step(step, None) {
                        Err(error)
                            if allow_proof_deactivation
                                && current.recovery.is_some()
                                && exited_nonzero(&error) =>
                        {
                            system.deactivate_lvm_from_proof(current).map_err(|fallback| {
                                identity_error(format!(
                                    "LVM deactivation returned {error}; proof-scoped device-mapper deactivation failed: {fallback}"
                                ))
                            })
                        }
                        result => result,
                    }
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
    // Disconnect acknowledgement can precede the kernel dropping its last
    // open-device reference. Retire authority only after observing complete
    // teardown; otherwise a retry must still know which device it owns.
    if disconnects && !connects {
        let current = record.as_ref().unwrap();
        if system.backend(&current.device)?.is_some() {
            return Err(identity_error(
                "disconnect has not completed; keeping the attach record for cleanup retry",
            ));
        }
        let observed = system.disconnected_recovery_observation(current)?;
        if observed.mounted || observed.vg_active || observed.nbd_in_use {
            return Err(identity_error(
                "disconnect left active attachment resources; keeping the attach record",
            ));
        }
        if system.backend(&current.device)?.is_some() {
            return Err(identity_error(
                "backend appeared during final teardown verification; keeping the attach record",
            ));
        }
        // Match disconnected recovery's retirement boundary: a holder or
        // mapping can appear during the first empty observation even while
        // the backend remains absent. Confirm resources again before
        // surrendering the record's cleanup authority.
        let confirmed = system.disconnected_recovery_observation(current)?;
        if system.backend(&current.device)?.is_some() {
            return Err(identity_error(
                "backend appeared during final teardown verification; keeping the attach record",
            ));
        }
        if confirmed.mounted || confirmed.vg_active || confirmed.nbd_in_use {
            return Err(identity_error(
                "attachment gained live resources before record retirement",
            ));
        }
        state.unwrap().remove(&plan.volume)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "exec_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "review_growth_topology.rs"]
mod review_growth_topology;

#[cfg(test)]
#[path = "review_step_faults.rs"]
mod review_step_faults;

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
pub fn verify(volume: &str, config_path: impl AsRef<Path>) -> Result<(), ExecError> {
    workload_verify::execute(volume, config_path.as_ref())
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
            execute_with_options(plan, Some(state), system, true)
        }
        None => recover_with(plan, state, system),
        Some(identifier) => {
            // The connected and disconnected paths each compare the plan
            // with the record before their first step; so does this one.
            if plan.attachment.as_ref() != Some(&record.attachment)
                || plan.steps.iter().any(|step| {
                    matches!(step, PlannedStep::NbdDisconnect { device }
                        if device != crate::plan::AUTO_NBD_DEVICE && device != &record.device)
                })
            {
                return Err(identity_error(
                    "cleanup configuration does not match the trusted attach record",
                ));
            }
            retire_displaced(&record, &identifier, "cleanup", state, system)
        }
    }
}

/// Finish the rollback of an attach that died between activating the volume
/// group and recording the mapping proof. This is the storage work of the
/// attach unit's failed-start hook, and `plan` is the detach plan.
///
/// Such a record holds only the activation intent, and its mapping can be
/// deactivated only through LVM, which reads the volume group from the NBD
/// device. The recovery coordinator stops the daemon before its cleanup, so
/// that deactivation has to happen first, while the daemon still serves the
/// device. Nothing else is done here: a record without an intent, or one
/// whose device does not carry the recorded connection, is left to the
/// coordinator, which stops the registered workloads first. An intent never
/// authorized a mount, and this never unmounts.
///
/// The attach lock must be granted by `lock_deadline`, and every command
/// then finishes within `commands`: the hook runs inside the unit's stop
/// timeout, and the coordinator waits for it. Returns whether an
/// interrupted activation was found and rolled back.
pub fn finish_interrupted_activation(
    plan: &Plan,
    lock_deadline: Instant,
    commands: Duration,
) -> Result<bool, ExecError> {
    let Some(state) = existing_state()? else {
        return Ok(false);
    };
    finish_interrupted_activation_by(plan, &state, &mut LinuxSystem, lock_deadline, commands)
}

/// Whether `volume`'s trusted record holds an activation intent, the state
/// [`finish_interrupted_activation`] rolls back. It only reads: no lock, no
/// configuration, and a missing state directory is no record. The hook asks
/// this first, so that a failed start that left no intent is not reported
/// as a rollback that failed for an unrelated reason.
pub fn interrupted_activation(volume: &str) -> io::Result<bool> {
    match existing_state()? {
        Some(state) => holds_activation_intent(&state, volume),
        None => Ok(false),
    }
}

fn existing_state() -> io::Result<Option<TrustedState>> {
    match TrustedState::open_existing() {
        Ok(state) => Ok(Some(state)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn holds_activation_intent(state: &TrustedState, volume: &str) -> io::Result<bool> {
    Ok(state
        .read(volume)?
        .is_some_and(|record| record.recovery_intent.is_some()))
}

fn finish_interrupted_activation_by(
    plan: &Plan,
    state: &TrustedState,
    system: &mut impl System,
    lock_deadline: Instant,
    commands: Duration,
) -> Result<bool, ExecError> {
    // Most failed starts leave no intent, and a start often fails because the
    // global lock was busy for too long. Only the volume's own helper writes
    // its record, atomically, and that helper is gone: look before queueing
    // for the lock. The decision itself is made again under the lock.
    if !holds_activation_intent(state, &plan.volume)? {
        return Ok(false);
    }
    let _lock = state.lock_until(lock_deadline)?;
    // The commands' time starts once the lock is held: a lock granted late
    // in its wait must not leave the scoped deactivation less than that.
    let _bounded = command::finish_by(Instant::now() + commands);
    finish_interrupted_activation_with(plan, state, system)
}

fn finish_interrupted_activation_with(
    plan: &Plan,
    state: &TrustedState,
    system: &mut impl System,
) -> Result<bool, ExecError> {
    let Some(record) = state.read(&plan.volume)? else {
        return Ok(false);
    };
    if record.recovery_intent.is_none()
        || system.backend(&record.device)?.as_deref() != Some(record.connection_id.as_str())
    {
        return Ok(false);
    }
    // The connected detach path verifies the intent against the live kernel
    // state before and between its steps. Without an unmount step, a mount
    // it did not expect can only stop it.
    let mut plan = plan.clone();
    plan.steps
        .retain(|step| !matches!(step, PlannedStep::Umount { .. }));
    execute_with_options(&plan, Some(state), system, false)?;
    Ok(true)
}

#[cfg(test)]
#[path = "sentinel_tests.rs"]
mod sentinel_tests;
