//! New-volume discard qualification across the adapter and native NBD boundary.

use maki_nbdkit::adapter::{NbdAdapter, EINVAL, ESHUTDOWN};

fn config(root: &std::path::Path, socket: &std::path::Path) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "discard-review"
max_virtual_size = "2MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = "{}"
journal_emergency_reserve_bytes = "0B"
[nbd]
minimum_io = 4096
preferred_io = 4096
maximum_io = "8KiB"
threads = 2
[control]
socket = "{}"
"#,
        root.display(),
        socket.display()
    )
}

struct Fixture {
    _directory: tempfile::TempDir,
    config_path: std::path::PathBuf,
}

impl Fixture {
    fn new(discard: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("volume");
        let socket = directory.path().join("control.sock");
        let raw = config(&root, &socket);
        let config_path = directory.path().join("volume.toml");
        std::fs::write(&config_path, &raw).unwrap();
        if discard {
            maki_nbdkit::daemon::create_volume_with_discard_from_config_str(&raw).unwrap();
        } else {
            maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        }
        Self {
            _directory: directory,
            config_path,
        }
    }

    fn open(&self) -> NbdAdapter {
        NbdAdapter::open_config(self.config_path.to_str().unwrap()).unwrap()
    }
}

#[test]
fn legacy_volume_does_not_advertise_or_accept_trim() {
    let fixture = Fixture::new(false);
    let adapter = fixture.open();
    assert!(!adapter.can_trim());
    adapter.pwrite(&[0x45; 4096], 0, true).unwrap();
    adapter
        .trim(0, 4096, true)
        .expect_err("legacy volume accepted discard");
    let mut data = [0; 4096];
    adapter.pread(&mut data, 0).unwrap();
    assert_eq!(data, [0x45; 4096]);
    adapter.shutdown().unwrap();
}

#[test]
fn discard_volume_trims_durably_and_can_be_overwritten() {
    let fixture = Fixture::new(true);
    let adapter = fixture.open();
    assert!(adapter.can_trim());
    adapter.pwrite(&[0x67; 8192], 0, true).unwrap();
    adapter.trim(0, 4096, true).unwrap();
    let mut data = [0xff; 8192];
    adapter.pread(&mut data, 0).unwrap();
    assert_eq!(&data[..4096], &[0; 4096]);
    assert_eq!(&data[4096..], &[0x67; 4096]);
    adapter.pwrite(&[0x89; 4096], 0, true).unwrap();
    adapter.shutdown().unwrap();

    let reopened = fixture.open();
    let mut rewritten = [0; 4096];
    reopened.pread(&mut rewritten, 0).unwrap();
    assert_eq!(rewritten, [0x89; 4096]);
    reopened.shutdown().unwrap();
}

#[test]
fn trim_obeys_request_bounds_and_stops_after_drain() {
    let fixture = Fixture::new(true);
    let adapter = fixture.open();
    for (offset, len) in [(512, 4096), (0, 512), (0, 12 * 1024), (2 << 20, 4096)] {
        assert_eq!(adapter.trim(offset, len, false).unwrap_err().errno, EINVAL);
    }
    adapter.shutdown().unwrap();
    assert_eq!(adapter.trim(0, 4096, false).unwrap_err().errno, ESHUTDOWN);
}

#[cfg(target_os = "linux")]
#[test]
fn native_nbd_negotiates_and_executes_trim() {
    use std::io::Write;
    use std::process::Command;

    if std::env::var_os("MAKI_DISCARD_NATIVE_CHILD").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_nbd_negotiates_and_executes_trim",
                "--nocapture",
            ])
            .env("MAKI_DISCARD_NATIVE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "native NBD child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }

    for program in ["nbdkit", "python3"] {
        if Command::new(program).arg("--version").output().is_err() {
            eprintln!("{program} unavailable; skipping native discard qualification");
            return;
        }
    }
    let fixture = Fixture::new(true);
    let plugin = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("libmaki_nbdkit.so");
    assert!(plugin.is_file(), "missing cargo-built plugin: {plugin:?}");
    let script = r#"
import ctypes as c, sys
lib = c.CDLL('libnbd.so.0')
def api(name, args, result=c.c_int):
    fn = getattr(lib, name); fn.argtypes = args; fn.restype = result; return fn
H, P, S, U64, U32 = c.c_void_p, c.c_void_p, c.c_size_t, c.c_uint64, c.c_uint32
create = api('nbd_create', [], H)
close = api('nbd_close', [H], None)
error = api('nbd_get_error', [], c.c_char_p)
connect_uri = api('nbd_connect_uri', [H, c.c_char_p])
can_trim = api('nbd_can_trim', [H])
pwrite = api('nbd_pwrite', [H, P, S, U64, U32])
trim = api('nbd_trim', [H, S, U64, U32])
pread = api('nbd_pread', [H, P, S, U64, U32])
shutdown = api('nbd_shutdown', [H, U32])
def check(result):
    if result < 0: raise RuntimeError(error().decode('utf-8', 'replace'))
    return result
h = create()
if not h: raise RuntimeError(error().decode('utf-8', 'replace'))
try:
    check(connect_uri(h, sys.argv[1].encode()))
    if check(can_trim(h)) != 1: raise RuntimeError('export did not negotiate trim')
    written = c.create_string_buffer(b'Z' * 4096, 4096)
    check(pwrite(h, written, 4096, 0, 1))
    check(trim(h, 4096, 0, 1))
    readback = c.create_string_buffer(4096)
    check(pread(h, readback, 4096, 0, 0))
    if readback.raw != b'\0' * 4096: raise RuntimeError('trimmed bytes did not read zero')
    rewritten = c.create_string_buffer(b'R' * 4096, 4096)
    check(pwrite(h, rewritten, 4096, 0, 1))
    check(pread(h, readback, 4096, 0, 0))
    if readback.raw != b'R' * 4096: raise RuntimeError('trimmed range could not be rewritten')
    check(shutdown(h, 0))
    print('native libnbd trim negotiated and executed')
finally:
    close(h)
"#;
    let mut client = tempfile::NamedTempFile::new_in(&fixture._directory).unwrap();
    client.write_all(script.as_bytes()).unwrap();
    let output = Command::new("nbdkit")
        .args(["--foreground", "--exit-with-parent", "-U", "-"])
        .arg(plugin)
        .arg(format!("config={}", fixture.config_path.display()))
        .args(["--run", "python3 \"$MAKI_LIBNBD_CLIENT\" \"$uri\""])
        .env("MAKI_LIBNBD_CLIENT", client.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native trim failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("native libnbd trim negotiated and executed"),
        "native client did not report completed trim: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    println!("native libnbd trim negotiated and executed without skip");
}
