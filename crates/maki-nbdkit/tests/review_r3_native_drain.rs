//! R3-008: the foreground process reports a failed administrative drain and
//! logs the failed unload barrier. This uses disposable files and userspace NBD.
#![cfg(target_os = "linux")]

use maki_control::protocol::{read_response, send_command, Request};
use std::path::Path;
use std::process::Command;

fn control(socket: &Path, command: &str) -> serde_json::Value {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
                send_command(&mut stream, &Request::new(command))
                    .await
                    .unwrap();
                read_response(&mut stream).await.unwrap()
            })
            .await
            .expect("control response deadline")
        })
}

// Invoked by nbdkit --run after its socket is listening. The ordinary test
// harness also discovers this function, in which case it has no fixture.
#[test]
fn native_failure_client() {
    let Some(root) = std::env::var_os("MAKI_DRAIN_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let socket = std::path::PathBuf::from(std::env::var_os("MAKI_DRAIN_TEST_CONTROL").unwrap());
    let uri = std::env::var("MAKI_DRAIN_TEST_URI").unwrap();
    let attached = Command::new("nbdinfo")
        .args(["--json", "--list", &uri])
        .output()
        .unwrap();
    assert!(attached.status.success(), "{attached:?}");

    // Make the checkpoint namespace unusable after recovery. This produces
    // a real filesystem failure even if the test is run as root; journal
    // durability can still succeed. Restore it in the parent after exit.
    std::fs::rename(root.join("checkpoint"), root.join("saved-checkpoint")).unwrap();
    std::fs::write(root.join("checkpoint"), []).unwrap();
    let source = root.join("test-source");
    std::fs::write(&source, vec![0x39; 2 << 20]).unwrap();
    let written = Command::new("nbdcopy")
        .args(["--flush", "--synchronous"])
        .arg(&source)
        .arg(&uri)
        .output()
        .unwrap();
    assert!(written.status.success(), "{written:?}");
    std::fs::remove_file(source).unwrap();

    let failure = control(&socket, "drain");
    assert_eq!(failure["ok"], false, "{failure}");
    assert!(failure["error"].as_str().is_some_and(|e| !e.is_empty()));
    let status = control(&socket, "status");
    assert_eq!(status["data"]["io_state"], "failed", "{status}");
    assert_eq!(status["data"]["drain_error"], failure["error"]);
    let backing = maki_backing::FileBacking::new(&root).unwrap();
    use maki_backing::Backing;
    assert!(backing.try_lock(maki_format::layout::VOLUME_LOCK).is_err());

    // Preserve the failure until nbdkit --run exits and calls plugin unload.
    // The child returns success: nbdkit's void unload callback cannot change
    // this process status into an administrative drain acknowledgement.
}

#[test]
fn foreground_nbdkit_reports_failed_drain_and_failed_unload() {
    for program in ["nbdkit", "nbdinfo", "nbdcopy", "timeout"] {
        if Command::new(program).arg("--version").output().is_err() {
            eprintln!("{program} unavailable; skipping userspace drain qualification");
            return;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    let socket = dir.path().join("control.sock");
    let config_path = dir.path().join("volume.toml");
    let config = format!(
        r#"
config_schema_version = 1
[volume]
name = "native-drain"
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
socket = {socket:?}
"#
    );
    std::fs::write(&config_path, &config).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&config).unwrap();
    let exe = std::env::current_exe().unwrap();
    let plugin = exe.parent().unwrap().join("libmaki_nbdkit.so");
    assert!(plugin.is_file(), "missing cargo-built plugin: {plugin:?}");
    let output = Command::new("timeout")
        .args(["--kill-after=2s", "30s", "nbdkit"])
        .args(["--foreground", "--exit-with-parent", "-U", "-"])
        .arg(plugin)
        .arg(format!("config={}", config_path.display()))
        .env("MAKI_DRAIN_TEST_ROOT", &root)
        .env("MAKI_DRAIN_TEST_CONTROL", &socket)
        .env("MAKI_DRAIN_TEST_EXE", exe)
        .args([
            "--run",
            "MAKI_DRAIN_TEST_URI=\"$uri\" \"$MAKI_DRAIN_TEST_EXE\" --exact native_failure_client --nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native client failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("maki-nbdkit: shutdown during unload failed:"),
        "foreground stderr lost failed unload: {stderr}"
    );

    // A process exit releases locks, but the failed drain intentionally did
    // not unlink the control socket. Stale-socket handling belongs to restart.
    use maki_backing::Backing;
    let backing = maki_backing::FileBacking::new(&root).unwrap();
    drop(backing.try_lock(maki_format::layout::VOLUME_LOCK).unwrap());
    assert!(socket.exists());
    std::fs::remove_file(root.join("checkpoint")).unwrap();
    std::fs::rename(root.join("saved-checkpoint"), root.join("checkpoint")).unwrap();
    let adapter =
        maki_nbdkit::adapter::NbdAdapter::open_config(config_path.to_str().unwrap()).unwrap();
    let mut recovered = [0; 4096];
    adapter.pread(&mut recovered, 0).unwrap();
    assert_eq!(recovered, [0x39; 4096]);
    adapter.shutdown().unwrap();
    assert!(!socket.exists());
}
