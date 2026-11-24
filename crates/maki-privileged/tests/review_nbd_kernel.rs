//! The helper's own NBD connect and disconnect against the real kernel:
//! nbdkit serves a memory export on a private socket, the helper's code
//! connects a free `/dev/nbdN` to it with a generated backend identifier,
//! and the device's sysfs attributes must show what the helper sent: the
//! identifier, the size, and the FLUSH and FUA flags (a write-back cache
//! with FUA). A write and an fsync go through the device, and after the
//! disconnect the device is free again.
//!
//! This needs root (the `nbd` family requires `CAP_SYS_ADMIN`), the `nbd`
//! kernel module and nbdkit. Without any of them the test says what is
//! missing and is skipped; `MAKI_TEST_REQUIRE_NBD=1`, which CI's root-only
//! step sets after loading the module, makes that a failure.
#![cfg(target_os = "linux")]

#[path = "support/nbdkit.rs"]
mod nbdkit;

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use maki_privileged::nbd_kernel::{connect, disconnect, NbdError};

const REQUIRE: &str = "MAKI_TEST_REQUIRE_NBD";
const SIZE: u64 = 64 << 20;
const BLOCK_SIZE: u32 = 4096;
const SETTLE: Duration = Duration::from_secs(15);

/// One test at a time: each picks a free device when it starts.
static KERNEL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The highest-numbered device that shows no connection and has no size,
/// or the one `below` it by that many. The first test takes the lowest free
/// one, as the helper's allocation does: after a disconnect, udev probes
/// the freed device, and the kernel refuses a connect while anything has it
/// open (the helper's connect retries that for a few seconds), so the tests
/// use different devices and none depends on another's timing.
fn free_device_from_the_top(below: usize) -> String {
    let mut free: Vec<u32> = std::fs::read_dir("/sys/block")
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().ok()?;
            let index: u32 = name.strip_prefix("nbd")?.parse().ok()?;
            let unused = !Path::new(&format!("/sys/block/{name}/pid")).exists()
                && sysfs(index, "size").as_deref() == Some("0");
            unused.then_some(index)
        })
        .collect();
    free.sort_unstable();
    free.reverse();
    let index = free.get(below).or(free.first()).expect("a free NBD device");
    format!("/dev/nbd{index}")
}

/// Report what is missing: a skip, or a failure when NBD is required.
fn missing(what: &str) {
    assert!(
        std::env::var_os(REQUIRE).is_none_or(|value| value != "1"),
        "{REQUIRE}=1, but {what}"
    );
    eprintln!("kernel NBD connect skipped: {what} (set {REQUIRE}=1 to fail instead)");
}

fn nbd_module_loaded() -> Result<(), String> {
    if Path::new("/sys/module/nbd").is_dir() {
        return Ok(());
    }
    let mut failures = Vec::new();
    for modprobe in ["modprobe", "/usr/sbin/modprobe", "/sbin/modprobe"] {
        match Command::new(modprobe).arg("nbd").output() {
            Ok(output) if output.status.success() && Path::new("/sys/module/nbd").is_dir() => {
                return Ok(())
            }
            Ok(output) => failures.push(format!(
                "{modprobe} nbd: {} {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => failures.push(format!("{modprobe}: {error}")),
        }
    }
    Err(format!(
        "the nbd kernel module is not loaded and cannot be loaded ({})",
        failures.join("; ")
    ))
}

fn sysfs(index: u32, attribute: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/block/nbd{index}/{attribute}"))
        .ok()
        .map(|value| value.trim().to_string())
}

fn wait_for(what: &str, condition: impl Fn() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < SETTLE,
            "{what} did not happen within {SETTLE:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Disconnects the device if the test ends before it did.
struct Connected(Option<u32>);

impl Drop for Connected {
    fn drop(&mut self) {
        if let Some(index) = self.0.take() {
            let _ = disconnect(index);
        }
    }
}

#[test]
fn the_helper_connects_and_disconnects_a_kernel_nbd_device() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return missing("the nbd netlink family needs root (CAP_SYS_ADMIN)");
    }
    if let Err(what) = nbd_module_loaded() {
        return missing(&what);
    }
    if !nbdkit::available("the_helper_connects_and_disconnects_a_kernel_nbd_device") {
        return missing("nbdkit is not installed");
    }
    let _one_at_a_time = KERNEL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let server = nbdkit::Server::start(&["memory", "64M"]);
    let device = maki_privileged::exec::allocate_nbd_device()
        .unwrap_or_else(|error| panic!("no free NBD device: {error}"));
    let index: u32 = device.strip_prefix("/dev/nbd").unwrap().parse().unwrap();
    let identifier = format!(
        "maki-{}",
        std::fs::read_to_string("/proc/sys/kernel/random/uuid")
            .unwrap()
            .trim()
    );

    let mut connected = Connected(Some(index));
    connect(server.socket(), index, BLOCK_SIZE, &identifier)
        .unwrap_or_else(|error| panic!("connect {device}: {error}: {}", server.log()));
    wait_for("the connection", || {
        Path::new(&format!("/sys/block/nbd{index}/pid")).exists()
            && sysfs(index, "size").is_some_and(|size| size != "0")
    });
    assert_eq!(
        sysfs(index, "backend").as_deref(),
        Some(identifier.as_str())
    );
    assert_eq!(sysfs(index, "size"), Some((SIZE / 512).to_string()));
    assert_eq!(
        sysfs(index, "queue/logical_block_size"),
        Some(BLOCK_SIZE.to_string())
    );
    // SEND_FLUSH and SEND_FUA reached the kernel.
    assert_eq!(
        sysfs(index, "queue/write_cache").as_deref(),
        Some("write back")
    );
    assert_eq!(sysfs(index, "queue/fua").as_deref(), Some("1"));

    // The kernel answers a connect of a connected device busy; the helper's
    // retry sees the connection and refuses: a definite failure that
    // changes nothing.
    match connect(server.socket(), index, BLOCK_SIZE, "maki-another") {
        Err(NbdError::Failed(message)) => assert!(
            message.contains("busy and now shows a connection"),
            "{message}"
        ),
        other => panic!("a second connect of {device}: {other:?}"),
    }
    assert_eq!(
        sysfs(index, "backend").as_deref(),
        Some(identifier.as_str())
    );

    {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device)
            .unwrap();
        let written = vec![0x5a; BLOCK_SIZE as usize];
        file.write_all_at(&written, 0).unwrap();
        file.sync_all().unwrap();
        let mut read = vec![0; BLOCK_SIZE as usize];
        file.read_exact_at(&mut read, 0).unwrap();
        assert_eq!(read, written);
    }

    disconnect(index).unwrap_or_else(|error| panic!("disconnect {device}: {error}"));
    connected.0 = None;
    wait_for("the disconnect", || {
        !Path::new(&format!("/sys/block/nbd{index}/pid")).exists()
            && sysfs(index, "backend").is_none_or(|backend| backend.is_empty())
    });
}

/// The provisioning verbs' path (`maki-attach nbd-connect` and
/// `nbd-disconnect`): a raw connection under its own identifier, a refused
/// disconnect under another one, and its own disconnect.
#[test]
fn a_provisioning_connection_is_disconnected_only_under_its_own_identifier() {
    use maki_privileged::exec::{connect_raw, disconnect_raw};

    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return missing("the nbd netlink family needs root (CAP_SYS_ADMIN)");
    }
    if let Err(what) = nbd_module_loaded() {
        return missing(&what);
    }
    if !nbdkit::available("a_provisioning_connection_is_disconnected_only_under_its_own_identifier")
    {
        return missing("nbdkit is not installed");
    }
    let _one_at_a_time = KERNEL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let server = nbdkit::Server::start(&["memory", "64M"]);
    let device = free_device_from_the_top(0);
    let index: u32 = device.strip_prefix("/dev/nbd").unwrap().parse().unwrap();
    let identifier = format!(
        "maki-bootstrap-{}",
        std::fs::read_to_string("/proc/sys/kernel/random/uuid")
            .unwrap()
            .trim()
    );
    let mut connected = Connected(Some(index));
    connect_raw(server.socket(), &device, BLOCK_SIZE, &identifier)
        .unwrap_or_else(|error| panic!("connect {device}: {error}: {}", server.log()));
    assert_eq!(
        sysfs(index, "backend").as_deref(),
        Some(identifier.as_str())
    );
    // A second raw connect of a connected device changes nothing.
    assert!(connect_raw(server.socket(), &device, BLOCK_SIZE, "maki-bootstrap-other").is_err());
    assert!(disconnect_raw(&device, "maki-bootstrap-other").is_err());
    assert_eq!(
        sysfs(index, "backend").as_deref(),
        Some(identifier.as_str())
    );
    disconnect_raw(&device, &identifier)
        .unwrap_or_else(|error| panic!("disconnect {device}: {error}"));
    connected.0 = None;
    // The provisioning disconnect returns only once the device shows no
    // connection: the kernel keeps the attributes while anything has the
    // device open, and its caller checks the device right away.
    assert!(
        !Path::new(&format!("/sys/block/nbd{index}/pid")).exists()
            && sysfs(index, "backend").is_none_or(|backend| backend.is_empty()),
        "{device} still shows the connection after the disconnect returned"
    );
    // Nothing left to disconnect is not a failure.
    disconnect_raw(&device, &identifier).unwrap();
}

/// The kernel refuses a connect while anything has the unconnected device
/// open, before it takes the socket. The helper keeps asking on the
/// connection it negotiated, and connects once the opener has let go.
#[test]
fn a_device_held_open_is_connected_once_it_is_released() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return missing("the nbd netlink family needs root (CAP_SYS_ADMIN)");
    }
    if let Err(what) = nbd_module_loaded() {
        return missing(&what);
    }
    if !nbdkit::available("a_device_held_open_is_connected_once_it_is_released") {
        return missing("nbdkit is not installed");
    }
    let _one_at_a_time = KERNEL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let server = nbdkit::Server::start(&["memory", "64M"]);
    let device = free_device_from_the_top(1);
    let index: u32 = device.strip_prefix("/dev/nbd").unwrap().parse().unwrap();
    let identifier = format!(
        "maki-{}",
        std::fs::read_to_string("/proc/sys/kernel/random/uuid")
            .unwrap()
            .trim()
    );
    const HELD: Duration = Duration::from_millis(700);
    let opener = std::fs::File::open(&device).unwrap();
    let releasing = std::thread::spawn(move || {
        std::thread::sleep(HELD);
        drop(opener);
    });

    let started = Instant::now();
    let mut connected = Connected(Some(index));
    connect(server.socket(), index, BLOCK_SIZE, &identifier)
        .unwrap_or_else(|error| panic!("connect {device}: {error}: {}", server.log()));
    assert!(
        started.elapsed() >= HELD,
        "{device} was connected after {:?}, while it was held open",
        started.elapsed()
    );
    releasing.join().unwrap();
    assert_eq!(
        sysfs(index, "backend").as_deref(),
        Some(identifier.as_str())
    );

    disconnect(index).unwrap_or_else(|error| panic!("disconnect {device}: {error}"));
    connected.0 = None;
    wait_for("the disconnect", || {
        !Path::new(&format!("/sys/block/nbd{index}/pid")).exists()
            && sysfs(index, "backend").is_none_or(|backend| backend.is_empty())
    });
}
