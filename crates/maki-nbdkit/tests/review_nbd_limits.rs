//! BUG-011 / O-03: enforce the sizes promised to clients before touching
//! engine state, and exercise the actual sizing callback through nbdkit.
//! R5-038: a request above the advertised maximum is split, not refused.

use maki_format::config::{parse_config, ByteSize};
use maki_nbdkit::adapter::{NbdAdapter, EINVAL};

fn config(root: &str, socket: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "nbdlimits"
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
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[nbd]
minimum_io = 4096
preferred_io = 4096
maximum_io = "8KiB"
threads = 2
[control]
socket = "{socket}"
"#
    )
}

struct Fixture {
    directory: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("volume");
        let socket = directory.path().join("control.sock");
        let raw = config(
            &root.to_string_lossy().replace('\\', "/"),
            &socket.to_string_lossy().replace('\\', "/"),
        );
        let path = directory.path().join("volume.toml");
        std::fs::write(&path, &raw).unwrap();
        maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        Self { directory, path }
    }

    fn open(&self) -> NbdAdapter {
        assert!(self.directory.path().exists());
        NbdAdapter::open_config(self.path.to_str().unwrap()).unwrap()
    }
}

/// R5-038: the NBD maximum block size is advisory and the Linux NBD
/// client does not honour it: Debian 13's 6.12 kernel sends writes up to
/// `max_sectors_kb` (1280 KiB) to a 1 MiB export. Refusing them lost
/// buffered writes silently (mkfs.xfs exited 0 with a zeroed superblock).
/// Requests above `maximum_io` are served in chunks of at most that size,
/// each copied and admitted on its own, so the plaintext bound holds.
#[test]
fn oversized_reads_and_writes_are_served_in_chunks() {
    let fixture = Fixture::new();
    let adapter = fixture.open();
    // 20 KiB: two full 8 KiB chunks and a partial one, from an offset that
    // is not chunk aligned.
    let expected: Vec<u8> = (0..20 * 1024).map(|i| (i % 251) as u8).collect();
    adapter.pwrite(&expected, 4096, true).unwrap();
    let mut data = vec![0xAB; expected.len()];
    adapter.pread(&mut data, 4096).unwrap();
    assert_eq!(data, expected);
    adapter.shutdown().unwrap();
    drop(adapter);

    let reopened = fixture.open();
    let mut data = vec![0xAB; expected.len()];
    reopened.pread(&mut data, 4096).unwrap();
    assert_eq!(data, expected, "an oversized FUA write survives reopen");
    reopened.shutdown().unwrap();
}

#[test]
fn oversized_requests_are_still_checked_for_alignment_and_range() {
    let fixture = Fixture::new();
    let adapter = fixture.open();
    for (offset, length) in [
        (512, 12 * 1024),
        (0, 12 * 1024 + 512),
        ((2 << 20) - 8192, 12 * 1024),
    ] {
        let error = adapter
            .pwrite(&vec![0xCD; length], offset, true)
            .expect_err("misaligned or out of range");
        assert_eq!(error.errno, EINVAL, "{offset} {length}");
        let mut data = vec![0xAB; length];
        let error = adapter.pread(&mut data, offset).unwrap_err();
        assert_eq!(error.errno, EINVAL);
        assert!(data.iter().all(|byte| *byte == 0xAB), "buffer untouched");
    }
    let mut data = vec![0xFF; 8192];
    adapter.pread(&mut data, 0).unwrap();
    assert!(data.iter().all(|byte| *byte == 0), "volume unchanged");
    adapter.shutdown().unwrap();
}

#[test]
fn advertised_minimum_applies_to_both_request_offset_and_length() {
    let fixture = Fixture::new();
    let adapter = fixture.open();
    for (offset, length) in [(512, 4096), (0, 512)] {
        let error = adapter
            .pwrite(&vec![0xCE; length], offset, false)
            .expect_err("device-block aligned but below the advertised minimum");
        assert_eq!(error.errno, EINVAL);
        let mut data = vec![0xAF; length];
        let error = adapter.pread(&mut data, offset).unwrap_err();
        assert_eq!(error.errno, EINVAL);
        assert!(data.iter().all(|byte| *byte == 0xAF));
    }
    adapter.shutdown().unwrap();
}

#[test]
fn aligned_maximum_request_roundtrips_and_survives_reopen() {
    let fixture = Fixture::new();
    let adapter = fixture.open();
    assert_eq!(adapter.block_sizes(), (4096, 4096, 8192));
    let expected = vec![0xD1; 8192];
    adapter.pwrite(&expected, 4096, true).unwrap();
    adapter.shutdown().unwrap();
    drop(adapter);
    let reopened = fixture.open();
    let mut data = vec![0; 8192];
    reopened.pread(&mut data, 4096).unwrap();
    assert_eq!(data, expected);
    reopened.shutdown().unwrap();
}

#[test]
fn configuration_rejects_sizes_that_cannot_be_advertised_over_nbd() {
    let mut config = parse_config(&config("/tmp/unused-volume", "/tmp/unused.sock")).unwrap();
    config.backing.journal_max_bytes = ByteSize(16 << 30);
    config.nbd.maximum_io = ByteSize(1 << 32);
    let error = config.validate().expect_err("maximum must fit in u32");
    assert!(error.to_string().contains("nbd.maximum_io"), "{error}");

    config.nbd.maximum_io = ByteSize(1 << 20);
    config.nbd.minimum_io = 1 << 17;
    config.nbd.preferred_io = Some(1 << 17);
    let error = config.validate().expect_err("minimum is at most 64 KiB");
    assert!(error.to_string().contains("nbd.minimum_io"), "{error}");
}

#[cfg(target_os = "linux")]
#[test]
fn real_nbdkit_negotiates_configured_block_sizes() {
    use std::process::Command;

    // Adapter startup applies process-wide hardening. Keep the native
    // server/client qualification independent of sibling adapter tests.
    if std::env::var_os("MAKI_NBD_LIMITS_CHILD").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "real_nbdkit_negotiates_configured_block_sizes",
                "--nocapture",
            ])
            .env("MAKI_NBD_LIMITS_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "native NBD child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // Optional Linux qualification dependencies, also used by the documented
    // rootless NBD checks. No kernel device, root, or external service is used.
    for program in ["nbdkit", "nbdinfo"] {
        if Command::new(program).arg("--version").output().is_err() {
            eprintln!("{program} unavailable; skipping real NBD negotiation");
            return;
        }
    }
    let fixture = Fixture::new();
    let plugin = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("libmaki_nbdkit.so");
    assert!(plugin.is_file(), "missing cargo-built plugin: {plugin:?}");
    let output = Command::new("nbdkit")
        .args(["--foreground", "--exit-with-parent", "-U", "-"])
        .arg(plugin)
        .arg(format!("config={}", fixture.path.display()))
        .args(["--run", "nbdinfo --json --list \"$uri\""])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "nbdkit negotiation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let export = &report["exports"][0];
    assert_eq!(export["block_size_minimum"], 4096, "{report}");
    assert_eq!(export["block_size_preferred"], 4096, "{report}");
    assert_eq!(export["block_size_maximum"], 8192, "{report}");
}

/// R5-038 through real nbdkit: a client that ignores the advertised maximum
/// (libnbd with strict mode off, as the Linux NBD driver behaves) writes and
/// reads 20 KiB against the 8 KiB maximum.
#[cfg(target_os = "linux")]
#[test]
fn real_nbdkit_serves_requests_above_the_advertised_maximum() {
    use std::io::Write;
    use std::process::Command;

    for program in ["nbdkit", "python3"] {
        if Command::new(program).arg("--version").output().is_err() {
            eprintln!("{program} unavailable; skipping native oversized requests");
            return;
        }
    }
    let fixture = Fixture::new();
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
set_strict = api('nbd_set_strict_mode', [H, U32])
connect_uri = api('nbd_connect_uri', [H, c.c_char_p])
pwrite = api('nbd_pwrite', [H, P, S, U64, U32])
pread = api('nbd_pread', [H, P, S, U64, U32])
shutdown = api('nbd_shutdown', [H, U32])
def check(result):
    if result < 0: raise RuntimeError(error().decode('utf-8', 'replace'))
    return result
h = create()
try:
    check(set_strict(h, 0))
    check(connect_uri(h, sys.argv[1].encode()))
    payload = bytes((i * 7) % 251 for i in range(20 * 1024))
    check(pwrite(h, c.create_string_buffer(payload, len(payload)), len(payload), 4096, 1))
    readback = c.create_string_buffer(len(payload))
    check(pread(h, readback, len(payload), 4096, 0))
    if readback.raw != payload: raise RuntimeError('oversized readback differs')
    check(shutdown(h, 0))
    print('native oversized requests served')
finally:
    close(h)
"#;
    let mut client = tempfile::NamedTempFile::new().unwrap();
    client.write_all(script.as_bytes()).unwrap();
    let output = Command::new("nbdkit")
        .args(["--foreground", "--exit-with-parent", "-U", "-"])
        .arg(&plugin)
        .arg(format!("config={}", fixture.path.display()))
        .args(["--run", "python3 \"$MAKI_LIBNBD_CLIENT\" \"$uri\""])
        .env("MAKI_LIBNBD_CLIENT", client.path())
        .output()
        .unwrap();
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("native oversized requests served"),
        "native oversized requests failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
