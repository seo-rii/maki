//! Actual CLI stderr must not reproduce rejected configuration input.
#[test]
fn rejected_config_values_and_keys_are_not_printed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.toml");
    for field in [
        "availability_policy = \"bad`S3NT1NEL0123456789abcdef\"",
        "key = 1234567890123456",
        "S3NT1NEL0123456789abcdef = true",
        r#"key = "bad\\\"S3NT1NEL0123456789abcdef""#,
    ] {
        std::fs::write(&path, format!("config_schema_version = 1\n[volume]\nname = \"safe-errors\"\nmax_virtual_size = \"1MiB\"\n[backing]\nroot = \"unused\"\n[crypto]\nprovider = \"local-aes-gcm-siv\"\ncrypto_compatibility_id = \"x\"\n{field}\n")).unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_maki"))
            .args(["volume", "inspect"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("S3NT1NEL0123456789abcdef"), "{text}");
            assert!(!text.contains("1234567890123456"), "{text}");
        }
        assert!(String::from_utf8_lossy(&output.stderr).contains("config parse error:"));
    }
}
