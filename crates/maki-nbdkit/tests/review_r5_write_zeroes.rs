//! R5-036: WRITE_ZEROES longer than `nbd.maximum_io`.
//!
//! The plugin left zeroing to nbdkit's emulation, which turns a zero
//! request into one `pwrite` of the whole range. The NBD maximum block
//! size limits payloads only, so clients send larger zero requests
//! (nbdcopy sent 64 and 128 MiB, the kernel's `blkdev_issue_zeroout` and
//! `qemu-img` do the same), and the adapter refused every one above
//! `maximum_io` with EINVAL. Found while preparing the 2026-10-04
//! follow-up campaign. The plugin now zeroes natively, in chunks, and
//! discards whole units when the client allows it on a discard volume.

use maki_nbdkit::adapter::NbdAdapter;

const UNIT: usize = 4096;

fn config(root: &std::path::Path, socket: &std::path::Path) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "zero-review"
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
root = {}
journal_emergency_reserve_bytes = "0B"
[nbd]
minimum_io = 512
preferred_io = 4096
maximum_io = "8KiB"
threads = 2
[control]
socket = {}
"#,
        serde_json::to_string(root.to_str().unwrap()).unwrap(),
        serde_json::to_string(socket.to_str().unwrap()).unwrap()
    )
}

struct Fixture {
    _directory: tempfile::TempDir,
    config_path: std::path::PathBuf,
}

impl Fixture {
    fn new(discard: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let raw = config(
            &directory.path().join("volume"),
            &directory.path().join("control.sock"),
        );
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

const SPAN: usize = 12 * UNIT;

fn fill(adapter: &NbdAdapter) {
    for offset in (0..SPAN).step_by(8192) {
        adapter.pwrite(&[0x5a; 8192], offset as u64, false).unwrap();
    }
}

fn read_span(adapter: &NbdAdapter) -> Vec<u8> {
    let mut data = vec![0xff; SPAN];
    for (chunk, offset) in data.chunks_mut(8192).zip((0..).step_by(8192)) {
        adapter.pread(chunk, offset).unwrap();
    }
    data
}

/// Zero `[start, end)` and check every byte after a restart: zeros inside,
/// the original pattern outside. The range starts and ends inside a unit.
fn zero_and_check(discard: bool, may_trim: bool) {
    let fixture = Fixture::new(discard);
    let adapter = fixture.open();
    fill(&adapter);
    let (start, end) = (UNIT + 1536, 10 * UNIT + 512);
    adapter
        .zero(start as u64, end - start, may_trim, true)
        .expect("a zero request longer than maximum_io must succeed");
    adapter.shutdown().unwrap();

    let reopened = fixture.open();
    let data = read_span(&reopened);
    for (index, byte) in data.iter().enumerate() {
        let expected = if (start..end).contains(&index) {
            0
        } else {
            0x5a
        };
        assert_eq!(
            *byte, expected,
            "byte {index} (discard {discard}, may_trim {may_trim})"
        );
    }
    reopened.shutdown().unwrap();
}

#[test]
fn a_long_zero_writes_zeros_on_a_legacy_volume() {
    zero_and_check(false, true);
}

#[test]
fn a_long_zero_without_trim_writes_zeros_on_a_discard_volume() {
    zero_and_check(true, false);
}

#[test]
fn a_long_zero_may_discard_whole_units_on_a_discard_volume() {
    zero_and_check(true, true);
}

#[test]
fn zero_obeys_alignment_and_bounds() {
    let fixture = Fixture::new(true);
    let adapter = fixture.open();
    for (offset, length) in [
        (0, 0),
        (100, 512),
        (0, 100),
        (2 << 20, 512),
        ((2 << 20) - 512, 1024),
    ] {
        let error = adapter.zero(offset, length, true, false).unwrap_err();
        assert_eq!(
            error.errno,
            maki_nbdkit::adapter::EINVAL,
            "{offset} {length}"
        );
    }
    adapter.shutdown().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn native_nbd_zero_longer_than_the_maximum_block_size() {
    use std::io::Write;
    use std::process::Command;

    for program in ["nbdkit", "python3"] {
        if Command::new(program).arg("--version").output().is_err() {
            eprintln!("{program} unavailable; skipping native zero qualification");
            return;
        }
    }
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
can_zero = api('nbd_can_zero', [H])
can_fast_zero = api('nbd_can_fast_zero', [H])
pwrite = api('nbd_pwrite', [H, P, S, U64, U32])
zero = api('nbd_zero', [H, U64, U64, U32])
pread = api('nbd_pread', [H, P, S, U64, U32])
shutdown = api('nbd_shutdown', [H, U32])
FUA, NO_HOLE = 1, 2
def check(result):
    if result < 0: raise RuntimeError(error().decode('utf-8', 'replace'))
    return result
h = create()
if not h: raise RuntimeError(error().decode('utf-8', 'replace'))
try:
    check(connect_uri(h, sys.argv[1].encode()))
    if check(can_zero(h)) != 1: raise RuntimeError('export did not negotiate write zeroes')
    if check(can_fast_zero(h)) != 0: raise RuntimeError('fast zero advertised')
    written = c.create_string_buffer(b'Z' * 8192, 8192)
    readback = c.create_string_buffer(8192)
    for flags in (0, NO_HOLE):
        for offset in range(0, 1 << 20, 8192):
            check(pwrite(h, written, 8192, offset, 0))
        # 1 MiB minus 1 KiB: 128 times the 8 KiB maximum block size, both
        # ends inside a crypto unit.
        check(zero(h, (1 << 20) - 2048, 1024, flags | FUA))
        for offset in range(0, 1 << 20, 8192):
            check(pread(h, readback, 8192, offset, 0))
            expected = bytearray(b'\0' * 8192)
            if offset == 0: expected[:1024] = b'Z' * 1024
            if offset == (1 << 20) - 8192: expected[-1024:] = b'Z' * 1024
            if readback.raw != bytes(expected): raise RuntimeError('wrong bytes at %d (flags %d)' % (offset, flags))
    check(shutdown(h, 0))
    print('native libnbd zero negotiated and executed')
finally:
    close(h)
"#;
    for discard in [false, true] {
        let fixture = Fixture::new(discard);
        let mut client = tempfile::NamedTempFile::new_in(&fixture._directory).unwrap();
        client.write_all(script.as_bytes()).unwrap();
        let output = Command::new("nbdkit")
            .args(["--foreground", "--exit-with-parent", "-U", "-"])
            .arg(&plugin)
            .arg(format!("config={}", fixture.config_path.display()))
            .args(["--run", "python3 \"$MAKI_LIBNBD_CLIENT\" \"$uri\""])
            .env("MAKI_LIBNBD_CLIENT", client.path())
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .contains("native libnbd zero negotiated and executed"),
            "native zero failed (discard {discard}):\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
