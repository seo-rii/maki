use std::process::{Command, Output};

use maki_backing::FileBacking;
use maki_format::superblock::{
    load_volume_superblock, SUPERBLOCK_VERSION_V2, SUPERBLOCK_VERSION_V3,
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .env(
            "MAKI_CREDENTIAL_DISCARD_CREATE_KEY",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .output()
        .expect("spawn maki")
}

fn config(root: &std::path::Path) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "discard-create"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "discard-create-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = {}
"#,
        serde_json::to_string(root.to_str().unwrap()).unwrap()
    )
}

#[test]
fn fixture_preserves_windows_path_separators() {
    let root = std::path::Path::new(r"C:\Users\maki\volume");
    let parsed = maki_format::config::parse_config(&config(root)).unwrap();
    assert_eq!(parsed.backing.root, root.to_str().unwrap());
}

fn field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.split_once(':').filter(|(key, _)| key.trim() == name))
        .map(|(_, value)| value.trim())
        .unwrap_or_else(|| panic!("missing {name:?} in inspect output:\n{output}"))
}

fn created(discard: bool) -> (u32, String) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let config_path = directory.path().join("volume.toml");
    std::fs::write(&config_path, config(&root)).unwrap();
    let mut args = vec!["volume", "create", config_path.to_str().unwrap()];
    if discard {
        args.push("--discard");
    }
    let output = run(&args);
    assert!(
        output.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let version = load_volume_superblock(&FileBacking::new(root).unwrap())
        .unwrap()
        .metadata_version;
    let inspect = run(&["volume", "inspect", config_path.to_str().unwrap()]);
    assert!(inspect.status.success());
    (version, String::from_utf8(inspect.stdout).unwrap())
}

#[test]
fn create_uses_v2_by_default_and_v3_only_with_explicit_discard() {
    let (v2, v2_inspect) = created(false);
    assert_eq!(v2, SUPERBLOCK_VERSION_V2);
    assert_eq!(field(&v2_inspect, "metadata envelope"), "2");
    assert_eq!(field(&v2_inspect, "discard map A/B bytes"), "0");

    let (v3, v3_inspect) = created(true);
    assert_eq!(v3, SUPERBLOCK_VERSION_V3);
    assert_eq!(field(&v3_inspect, "metadata envelope"), "3");
    assert_eq!(
        field(&v3_inspect, "discard map A/B bytes"),
        field(&v3_inspect, "allocation map A/B bytes")
    );
}

#[test]
fn discard_flag_never_reinitializes_an_existing_volume() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let config_path = directory.path().join("volume.toml");
    std::fs::write(&config_path, config(&root)).unwrap();
    let path = config_path.to_str().unwrap();
    assert!(run(&["volume", "create", path]).status.success());
    let output = run(&["volume", "create", path, "--discard"]);
    assert!(
        !output.status.success(),
        "discard flag reinitialized a volume"
    );
    assert_eq!(
        load_volume_superblock(&FileBacking::new(root).unwrap())
            .unwrap()
            .metadata_version,
        SUPERBLOCK_VERSION_V2
    );
}
