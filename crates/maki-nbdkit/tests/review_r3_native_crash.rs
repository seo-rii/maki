//! Rootless native process-crash qualification, not a power-loss test.
//! The client uses libnbd's synchronous ACKs and fsyncs an oracle outside
//! the killed daemon. Only disposable fake-provider volumes are modified.
//! Run with --test review_r3_native_crash; MAKI_NATIVE_CRASH_CYCLES=1..20
//! selects the number of FLUSH/FUA crash/restart cycles (default 3 each).
#![cfg(target_os = "linux")]

use std::io::{self, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(10);

// Published C API, present since libnbd 1.0:
// https://libguestfs.org/nbd_pwrite.3.html
// https://libguestfs.org/nbd_flush.3.html
// LIBNBD_CMD_FLAG_FUA=1, distinct from nbdkit's callback flag value:
// https://github.com/libguestfs/libnbd/blob/v1.14.2/generator/API.ml
// ctypes avoids requiring libnbd headers or Python bindings in addition to
// the libnbd runtime already installed with the native qualification tools.
const CLIENT: &str = r#"
import ctypes as c, json, os, pathlib, sys, time
lib = c.CDLL('libnbd.so.0')
def api(name, args, result=c.c_int):
    fn = getattr(lib, name); fn.argtypes = args; fn.restype = result; return fn
H, P, S, U64, U32 = c.c_void_p, c.c_void_p, c.c_size_t, c.c_uint64, c.c_uint32
create = api('nbd_create', [], H)
close = api('nbd_close', [H], None)
error = api('nbd_get_error', [], c.c_char_p)
connect = api('nbd_connect_unix', [H, c.c_char_p])
pwrite = api('nbd_pwrite', [H, P, S, U64, U32])
pread = api('nbd_pread', [H, P, S, U64, U32])
flush = api('nbd_flush', [H, U32])
can_fua = api('nbd_can_fua', [H])
can_flush = api('nbd_can_flush', [H])
def check(result):
    if result < 0: raise RuntimeError(error().decode('utf-8', 'replace'))
    return result
def durable_file(path, content, mode='w'):
    with open(path, mode) as out:
        out.write(content); out.flush(); os.fsync(out.fileno())
operation, socket, oracle, cycle, barrier, marker = sys.argv[1:]
cycle = int(cycle)
h = create()
if not h: raise RuntimeError(error().decode('utf-8', 'replace'))
try:
    check(connect(h, os.fsencode(socket)))
    if operation == 'write':
        if check(can_fua(h)) != 1 or check(can_flush(h)) != 1:
            raise RuntimeError('native export must support both FUA and FLUSH')
        acknowledged = []
        for unit in range(4):
            offset = (cycle * 4 + unit) * 4096
            payload = bytes((cycle * 37 + unit * 19 + i) % 256 for i in range(4096))
            buffer = c.create_string_buffer(payload, len(payload))
            check(pwrite(h, buffer, len(payload), offset, 1 if barrier == 'fua' else 0))
            record = json.dumps({'offset': offset, 'hex': payload.hex(), 'barrier': barrier}) + '\n'
            if barrier == 'fua': durable_file(oracle, record, 'a')
            else: acknowledged.append(record)
        if barrier == 'flush':
            check(flush(h, 0))
            durable_file(oracle, ''.join(acknowledged), 'a')
    elif operation == 'verify':
        expected = {}
        with open(oracle) as src:
            for line in src:
                row = json.loads(line); expected[row['offset']] = bytes.fromhex(row['hex'])
        if not expected: raise RuntimeError('external ACK oracle must not be empty')
        for offset, payload in expected.items():
            buffer = c.create_string_buffer(len(payload))
            check(pread(h, buffer, len(payload), offset, 0))
            if buffer.raw != payload:
                raise RuntimeError('ACKed bytes changed at offset %d' % offset)
    elif operation == 'pending':
        durable_file(marker + '.connected', 'connected')
        deadline = time.monotonic() + 8
        while not pathlib.Path(marker + '.go').exists():
            if time.monotonic() >= deadline: raise RuntimeError('pending-write trigger timeout')
            time.sleep(0.01)
        durable_file(marker + '.issued', 'about to call libnbd pwrite')
        payload = c.create_string_buffer(b'\xa5' * 4096, 4096)
        result = pwrite(h, payload, 4096, 1 << 20, 1)
        if result != -1:
            raise RuntimeError('stopped/killed server unexpectedly ACKed the pending write')
        durable_file(marker + '.failed', 'libnbd returned an error without ACK')
        # No oracle entry: the request never returned a successful FUA ACK.
    else: raise RuntimeError('unknown client operation')
finally:
    # Closing a client handle does not unload or drain the server. The parent
    # independently kills the still-running nbdkit process with SIGKILL.
    close(h)
"#;

fn prerequisites() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        for program in ["nbdkit", "nbdinfo", "python3"] {
            match Command::new(program).arg("--version").output() {
                Ok(output) => assert!(output.status.success(), "installed {program} cannot run"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    eprintln!(
                        "{program} unavailable; skipping optional native crash qualification"
                    );
                    return false;
                }
                Err(error) => panic!("native prerequisite {program} failed: {error}"),
            }
        }
        true
    })
}

struct Fixture {
    directory: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    socket: PathBuf,
    client: tempfile::NamedTempFile,
    oracle: tempfile::NamedTempFile,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("volume");
        let config = directory.path().join("config.toml");
        let socket = directory.path().join("nbd.sock");
        let control = directory.path().join("control.sock");
        let raw = format!(
            r#"
config_schema_version = 1
[volume]
name = "native-crash"
max_virtual_size = "2MiB"
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = {root:?}
[control]
socket = {control:?}
"#
        );
        std::fs::write(&config, &raw).unwrap();
        maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        let mut client = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        client.write_all(CLIENT.as_bytes()).unwrap();
        let oracle = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        Self {
            directory,
            root,
            config,
            socket,
            client,
            oracle,
        }
    }

    fn client(&self, operation: &str, cycle: usize, barrier: &str, marker: &Path) -> Process {
        self.client_python(operation, cycle, barrier, marker, false)
    }

    fn client_python(
        &self,
        operation: &str,
        cycle: usize,
        barrier: &str,
        marker: &Path,
        optimize: bool,
    ) -> Process {
        let mut command = Command::new("python3");
        if optimize {
            command.arg("-O").env("PYTHONOPTIMIZE", "1");
        }
        command
            .arg(self.client.path())
            .arg(operation)
            .arg(&self.socket)
            .arg(self.oracle.path())
            .arg(cycle.to_string())
            .arg(barrier)
            .arg(marker)
            .env_remove("NOTIFY_SOCKET")
            .env_remove("LIBNBD_DEBUG");
        Process::start(command, self.directory.path())
    }

    fn acknowledged_count(&self) -> usize {
        std::fs::read_to_string(self.oracle.path())
            .unwrap()
            .lines()
            .count()
    }

    fn segment(&self) -> PathBuf {
        let mut segments: Vec<_> =
            std::fs::read_dir(self.root.join(maki_format::layout::JOURNAL_DIR))
                .unwrap()
                .map(Result::unwrap)
                .filter(|entry| {
                    maki_format::layout::parse_journal_segment(&entry.file_name().to_string_lossy())
                        .is_some()
                })
                .map(|entry| entry.path())
                .collect();
        segments.sort();
        assert_eq!(
            segments.len(),
            1,
            "fixture must contain its uncheckpointed acknowledged journal segment"
        );
        segments.pop().unwrap()
    }
}

struct Process {
    child: Child,
    stderr: tempfile::NamedTempFile,
}

impl Process {
    fn start(mut command: Command, directory: &Path) -> Self {
        let stdout = tempfile::NamedTempFile::new_in(directory).unwrap();
        let stderr = tempfile::NamedTempFile::new_in(directory).unwrap();
        let child = command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(stdout.reopen().unwrap())
            .stderr(stderr.reopen().unwrap())
            .spawn()
            .unwrap();
        Self { child, stderr }
    }

    fn wait(&mut self, duration: Duration) -> Option<ExitStatus> {
        let started = Instant::now();
        while started.elapsed() < duration {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    fn kill_and_reap(&mut self) -> Option<ExitStatus> {
        if let Some(status) = self.child.try_wait().unwrap() {
            return Some(status);
        }
        // The unreaped child owns this process-group identity.
        assert_eq!(
            unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) },
            0
        );
        self.wait(Duration::from_secs(2))
    }

    fn diagnostics(&mut self) -> String {
        if self.kill_and_reap().is_none() {
            return "process did not reap; log left unread".into();
        }
        let mut bytes = Vec::new();
        self.stderr
            .reopen()
            .unwrap()
            .take(4096)
            .read_to_end(&mut bytes)
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn success(&mut self) {
        let status = self.wait(DEADLINE);
        assert!(
            status.is_some_and(|status| status.success()),
            "client failed or timed out: {}",
            self.diagnostics()
        );
    }

    fn crash(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "server exited before deliberate SIGKILL: {}",
            self.diagnostics()
        );
        let status = self.kill_and_reap().expect("SIGKILL reap deadline");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "must test abrupt termination, not clean unload"
        );
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

struct Server {
    process: Process,
    notify: UnixDatagram,
}

impl Server {
    fn start(fixture: &Fixture) -> Self {
        // Remove only the disposable NBD socket after the prior process was
        // killed and reaped. The plugin exercises its own stale control-socket
        // handling; no helper removes the control socket or volume metadata.
        match std::fs::symlink_metadata(&fixture.socket) {
            Ok(metadata) => {
                assert!(metadata.file_type().is_socket());
                std::fs::remove_file(&fixture.socket).unwrap();
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => panic!("NBD socket inventory: {error}"),
        }
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = fixture.directory.path().join(format!(
            "notify-{}.sock",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let notify = UnixDatagram::bind(&path).unwrap();
        notify
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let plugin = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("libmaki_nbdkit.so");
        assert!(plugin.is_file(), "missing cargo-built plugin");
        let mut command = Command::new("nbdkit");
        command
            .args(["--foreground", "--exit-with-parent", "-U"])
            .arg(&fixture.socket)
            .arg(plugin)
            .arg(format!("config={}", fixture.config.display()))
            .env("NOTIFY_SOCKET", path);
        Self {
            process: Process::start(command, fixture.directory.path()),
            notify,
        }
    }

    fn notification(&self) -> bool {
        let mut bytes = [0; 4096];
        match self.notify.recv(&mut bytes) {
            Ok(count) => bytes[..count]
                .split(|byte| *byte == b'\n')
                .any(|line| line == b"READY=1"),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                false
            }
            Err(error) => panic!("notification failed: {error}"),
        }
    }

    fn ready(&mut self) {
        let started = Instant::now();
        while started.elapsed() < DEADLINE {
            if self.notification() {
                return;
            }
            assert!(
                self.process.child.try_wait().unwrap().is_none(),
                "startup failed: {}",
                self.process.diagnostics()
            );
        }
        panic!("READY deadline: {}", self.process.diagnostics());
    }

    fn refused(&mut self) {
        let started = Instant::now();
        while started.elapsed() < DEADLINE {
            assert!(
                !self.notification(),
                "damaged acknowledged journal was accepted"
            );
            if let Some(status) = self.process.child.try_wait().unwrap() {
                assert!(!status.success());
                assert!(!self.notification());
                assert!(self.process.diagnostics().contains("startup failed"));
                return;
            }
        }
        panic!(
            "corrupt recovery did not fail before deadline: {}",
            self.process.diagnostics()
        );
    }
}

fn cycles() -> usize {
    let cycles = std::env::var("MAKI_NATIVE_CRASH_CYCLES")
        .map(|value| value.parse().expect("invalid crash-cycle count"))
        .unwrap_or(3);
    assert!((1..=20).contains(&cycles));
    cycles
}

fn repeated_crash(barrier: &str) {
    if !prerequisites() {
        return;
    }
    let fixture = Fixture::new();
    let mut server = Server::start(&fixture);
    server.ready();
    let marker = fixture.directory.path().join("unused-marker");
    for cycle in 0..cycles() {
        fixture.client("write", cycle, barrier, &marker).success();
        assert_eq!(fixture.acknowledged_count(), (cycle + 1) * 4);
        server.process.crash();
        server = Server::start(&fixture);
        server.ready();
        fixture.client("verify", cycle, barrier, &marker).success();
    }
    server.process.crash();
}

#[test]
fn acknowledged_flush_survives_repeated_sigkill_restart() {
    repeated_crash("flush");
}

#[test]
fn acknowledged_fua_survives_repeated_sigkill_restart() {
    repeated_crash("fua");
}

fn wait_file(path: &Path, process: &mut Process) {
    let started = Instant::now();
    while !path.exists() && started.elapsed() < DEADLINE {
        assert!(
            process.child.try_wait().unwrap().is_none(),
            "client stopped before marker: {}",
            process.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        path.exists(),
        "client marker timeout: {}",
        process.diagnostics()
    );
}

#[test]
fn unacknowledged_write_is_excluded_from_the_external_durable_oracle() {
    if !prerequisites() {
        return;
    }
    let fixture = Fixture::new();
    let marker = fixture.directory.path().join("pending");
    let mut server = Server::start(&fixture);
    server.ready();
    fixture.client("write", 0, "fua", &marker).success();
    let before = std::fs::read(fixture.oracle.path()).unwrap();
    let mut pending = fixture.client("pending", 0, "fua", &marker);
    wait_file(&marker.with_extension("connected"), &mut pending);
    assert_eq!(
        unsafe { libc::kill(server.process.child.id() as i32, libc::SIGSTOP) },
        0
    );
    let started = Instant::now();
    loop {
        let state =
            std::fs::read_to_string(format!("/proc/{}/status", server.process.child.id())).unwrap();
        if state
            .lines()
            .any(|line| line.starts_with("State:") && line.contains('T'))
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "server did not stop"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::write(marker.with_extension("go"), "go").unwrap();
    wait_file(&marker.with_extension("issued"), &mut pending);
    server.process.crash();
    pending.success();
    assert!(marker.with_extension("failed").exists());
    assert_eq!(std::fs::read(fixture.oracle.path()).unwrap(), before);
    let mut restarted = Server::start(&fixture);
    restarted.ready();
    fixture.client("verify", 0, "fua", &marker).success();
    restarted.process.crash();
}

fn corrupt_acknowledged_segment(remove: bool) {
    if !prerequisites() {
        return;
    }
    let fixture = Fixture::new();
    let marker = fixture.directory.path().join("unused-marker");
    let mut server = Server::start(&fixture);
    server.ready();
    fixture.client("write", 0, "fua", &marker).success();
    assert_eq!(fixture.acknowledged_count(), 4);
    server.process.crash();
    let segment = fixture.segment();
    if remove {
        std::fs::remove_file(segment).unwrap();
    } else {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(segment)
            .unwrap();
        let length = file.metadata().unwrap().len();
        assert!(
            length > 4096,
            "fixture needs an acknowledged payload to truncate"
        );
        file.set_len(length - 1).unwrap();
        file.sync_all().unwrap();
    }
    let mut restarted = Server::start(&fixture);
    restarted.refused();
}

#[test]
fn missing_acknowledged_segment_refuses_native_restart() {
    corrupt_acknowledged_segment(true);
}

#[test]
fn torn_acknowledged_segment_refuses_native_restart() {
    corrupt_acknowledged_segment(false);
}

#[test]
fn optimized_python_still_rejects_a_mismatched_external_ack_oracle() {
    if !prerequisites() {
        return;
    }
    let fixture = Fixture::new();
    let marker = fixture.directory.path().join("unused-marker");
    let mut server = Server::start(&fixture);
    server.ready();
    fixture.client("write", 0, "fua", &marker).success();
    fixture.client("verify", 0, "fua", &marker).success();
    let raw = std::fs::read_to_string(fixture.oracle.path()).unwrap();
    let mut rows: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let expected = rows[0]["hex"].as_str().unwrap();
    assert!(
        expected.starts_with("00"),
        "fixture first byte must actually differ"
    );
    rows[0]["hex"] = format!("ff{}", &expected[2..]).into();
    let mismatched = rows
        .iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>();
    std::fs::write(fixture.oracle.path(), mismatched).unwrap();
    let mut verifier = fixture.client_python("verify", 0, "fua", &marker, true);
    let status = verifier
        .wait(DEADLINE)
        .expect("optimized verifier deadline");
    assert!(
        !status.success(),
        "optimized interpreter must reject mismatched ACKed bytes"
    );
    assert!(verifier.diagnostics().contains("ACKed bytes changed"));
    server.process.crash();
}
