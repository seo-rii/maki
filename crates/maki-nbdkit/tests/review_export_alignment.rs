//! BUG-136: every exported byte must be reachable by a minimum-I/O request.

use maki_format::config::parse_config;
use maki_nbdkit::adapter::NbdAdapter;
use maki_nbdkit::daemon::{attach_from_config, create_volume_from_config_str};

fn raw(root: &std::path::Path, socket: &std::path::Path, size: u64, minimum: u32) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "export-tail"
max_virtual_size = {size}
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "8KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "export-tail-v1"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 520
[backing]
root = {}
journal_emergency_reserve_bytes = "0B"
checkpoint_reserve_bytes = "0B"
[nbd]
minimum_io = {minimum}
preferred_io = 4096
maximum_io = "8KiB"
threads = 1
[control]
socket = {}
"#,
        serde_json::to_string(root.to_str().unwrap()).unwrap(),
        serde_json::to_string(socket.to_str().unwrap()).unwrap(),
    )
}

#[test]
fn configuration_rejects_an_export_with_an_unreachable_tail() {
    for size in [512, 4608, 8704] {
        let config = parse_config(&raw(
            std::path::Path::new("/tmp/export-unused-root"),
            std::path::Path::new("/tmp/export-unused.sock"),
            size,
            4096,
        ))
        .unwrap();
        let error = config
            .validate()
            .expect_err("accepted an export with a tail smaller than minimum_io");
        assert!(error.to_string().contains("max_virtual_size"), "{error}");
        assert!(error.to_string().contains("minimum_io"), "{error}");
    }
}

#[test]
fn create_rejects_inaccessible_exports_before_creating_backing_files() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let config = raw(&root, &directory.path().join("control.sock"), 4608, 4096);
    assert!(create_volume_from_config_str(&config).is_err());
    assert!(
        !root.exists(),
        "configuration refusal created backing state"
    );
}

#[tokio::test]
async fn attach_rejects_minimum_io_incompatible_with_stored_geometry() {
    let directory = tempfile::tempdir().unwrap();
    let raw = raw(
        &directory.path().join("volume"),
        &directory.path().join("control.sock"),
        4608,
        512,
    );
    let config = parse_config(&raw).unwrap();
    config.validate().unwrap();
    create_volume_from_config_str(&raw).unwrap();
    let engine = attach_from_config(&config).await.unwrap();
    engine.write(4096, &[0x5a; 512], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine.stop_checkpoint_worker().await;
    drop(engine);

    // Direct callers can change runtime negotiation without repeating config
    // validation. Recovery must cross-check the stored export geometry too.
    let mut incompatible = config.clone();
    incompatible.nbd.minimum_io = 4096;
    let error = match attach_from_config(&incompatible).await {
        Err(error) => error,
        Ok(_) => panic!("accepted an inaccessible tail in stored geometry"),
    };
    let message = error.to_string();
    assert!(message.contains("minimum_io"), "{message}");
    assert!(message.contains("stored"), "{message}");
    assert!(message.contains("max_virtual_size"), "{message}");

    let engine = attach_from_config(&config).await.unwrap();
    assert_eq!(engine.read(4096, 512).await.unwrap(), [0x5a; 512]);
}

#[test]
fn aligned_export_sizes_are_fully_accessible() {
    for (size, minimum) in [(512, 512), (4608, 512), (4096, 4096), (8192, 4096)] {
        let directory = tempfile::tempdir().unwrap();
        let raw = raw(
            &directory.path().join("volume"),
            &directory.path().join("control.sock"),
            size,
            minimum,
        );
        parse_config(&raw).unwrap().validate().unwrap();
        create_volume_from_config_str(&raw).unwrap();
        let config = directory.path().join("volume.toml");
        std::fs::write(&config, raw).unwrap();
        let adapter = NbdAdapter::open_config(config.to_str().unwrap()).unwrap();
        assert_eq!(adapter.get_size(), size);
        assert_eq!(adapter.block_sizes(), (minimum, 4096, 8192));
        let mut last = vec![0xff; minimum as usize];
        adapter.pread(&mut last, size - u64::from(minimum)).unwrap();
        assert!(last.iter().all(|byte| *byte == 0));
        adapter.shutdown().unwrap();
    }
}
