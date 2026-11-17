//! Audit (docs-prose): configuration.md says a root process "refuses a key
//! owned by the daemon user, so run it as that user instead". Attach runs
//! writable recovery before it constructs the provider, so by the time the
//! key is refused, a root process has already written to the daemon-owned
//! backing. This test records which files it leaves owned by root.
#![cfg(target_os = "linux")]

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use maki_format::config::parse_config;
use maki_nbdkit::daemon::{attach_from_config, create_volume_from_config_str};

const DAEMON_UID: u32 = 65534;

fn chown_tree(path: &Path, uid: u32) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: plain lchown on a path we own.
    assert_eq!(unsafe { libc::lchown(c.as_ptr(), uid, uid) }, 0);
    if path.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            chown_tree(&entry.unwrap().path(), uid);
        }
    }
}

fn root_owned(path: &Path, out: &mut Vec<PathBuf>) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    if meta.uid() == 0 {
        out.push(path.to_path_buf());
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            root_owned(&entry.unwrap().path(), out);
        }
    }
}

#[tokio::test]
async fn root_attach_refuses_the_daemon_key_only_after_recovery_wrote_as_root() {
    // SAFETY: plain geteuid.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol");
    let key = dir.path().join("vol.key");
    std::fs::write(&key, [7u8; 32]).unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let raw = format!(
        r#"config_schema_version = 1
[volume]
name = "audit-root"
max_virtual_size = "16MiB"
shard_logical_size = "8MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "file", name = "{key}" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{root}"
journal_segment_size = "1MiB"
journal_max_bytes = "8MiB"
checkpoint_reserve_bytes = "0"
journal_emergency_reserve_bytes = "0"
[control]
socket = "{sock}"
[security]
disable_core_dump = false
madv_dontdump = false
memory_lock_mode = "off"
[cache]
mode = "off"
lock_memory = false
"#,
        key = key.display(),
        root = root.display(),
        sock = dir.path().join("control.sock").display(),
    );
    create_volume_from_config_str(&raw).unwrap();
    // The packaged layout: the daemon user owns the backing and its key.
    chown_tree(&root, DAEMON_UID);
    chown_tree(&key, DAEMON_UID);
    let mut before = Vec::new();
    root_owned(&root, &mut before);
    assert!(before.is_empty(), "setup left root-owned files: {before:?}");

    let config = parse_config(&raw).unwrap();
    let error = match attach_from_config(&config).await {
        Ok(_) => panic!("root must refuse the daemon-owned key"),
        Err(error) => error.to_string(),
    };
    eprintln!("attach error: {error}");
    assert!(error.contains("owned by uid"), "unexpected error: {error}");

    let mut after = Vec::new();
    root_owned(&root, &mut after);
    eprintln!("root-owned after the refused attach: {after:?}");
    for path in &after {
        let meta = std::fs::metadata(path).unwrap();
        eprintln!("  {} mode {:o}", path.display(), meta.mode() & 0o7777);
    }
    assert!(
        after.is_empty(),
        "a refused root attach left root-owned files in the daemon's backing: {after:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_attach_with_a_journal_to_replay_leaves_root_owned_files_before_the_key_refusal() {
    // SAFETY: plain geteuid.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol");
    let key = dir.path().join("vol.key");
    std::fs::write(&key, [7u8; 32]).unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let raw = format!(
        r#"config_schema_version = 1
[volume]
name = "audit-root2"
max_virtual_size = "16MiB"
shard_logical_size = "8MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "file", name = "{key}" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{root}"
journal_segment_size = "64KiB"
journal_max_bytes = "8MiB"
checkpoint_reserve_bytes = "0"
journal_emergency_reserve_bytes = "0"
[control]
socket = "{sock}"
[security]
disable_core_dump = false
madv_dontdump = false
memory_lock_mode = "off"
[cache]
mode = "off"
lock_memory = false
"#,
        key = key.display(),
        root = root.display(),
        sock = dir.path().join("control.sock").display(),
    );
    create_volume_from_config_str(&raw).unwrap();
    let config = parse_config(&raw).unwrap();
    {
        // A daemon (here: root with a root-owned key) writes FUA data and
        // stops without a checkpoint, leaving journal records to replay.
        let engine = attach_from_config(&config).await.unwrap();
        let block = vec![0x5a; 64 * 1024];
        for i in 0..6u64 {
            engine.write(i * 256 * 1024, &block, true).await.unwrap();
        }
        drop(engine);
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let segments: Vec<_> = std::fs::read_dir(root.join("journal"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    eprintln!("journal before: {segments:?}");
    chown_tree(&root, DAEMON_UID);
    chown_tree(&key, DAEMON_UID);
    let mut before = Vec::new();
    root_owned(&root, &mut before);
    assert!(before.is_empty(), "setup left root-owned files: {before:?}");

    let error = match attach_from_config(&config).await {
        Ok(_) => panic!("root must refuse the daemon-owned key"),
        Err(error) => error.to_string(),
    };
    eprintln!("attach error: {error}");
    assert!(error.contains("owned by uid"), "unexpected error: {error}");
    let segments: Vec<_> = std::fs::read_dir(root.join("journal"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    eprintln!("journal after: {segments:?}");
    let mut after = Vec::new();
    root_owned(&root, &mut after);
    for path in &after {
        let meta = std::fs::metadata(path).unwrap();
        eprintln!("  root-owned: {} mode {:o}", path.display(), meta.mode() & 0o7777);
    }
    assert!(
        after.is_empty(),
        "a refused root attach left root-owned files in the daemon's backing: {after:?}"
    );
}
