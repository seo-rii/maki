//! Use the explicit current artifact, never a guessed library from the build cache.
#![cfg(target_os = "linux")]

#[path = "support/native_plugin.rs"]
mod native_plugin;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn artifact(root: &Path, relative: &str) -> PathBuf {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"fixture").unwrap();
    path
}

#[test]
fn legacy_layout_supports_direct_cargo_test() {
    let root = tempfile::tempdir().unwrap();
    let plugin = artifact(root.path(), "debug/deps/libmaki_nbdkit.so");
    let executable = root.path().join("debug/deps/native-test-hash");
    assert_eq!(native_plugin::resolve(&executable, None).unwrap(), plugin);
    std::fs::remove_file(&plugin).unwrap();
    assert!(native_plugin::resolve(&executable, None).is_err());
}

#[test]
fn explicit_compiler_artifact_takes_precedence_over_stale_adjacent_library() {
    let root = tempfile::tempdir().unwrap();
    artifact(root.path(), "debug/deps/libmaki_nbdkit.so");
    let plugin = artifact(
        root.path(),
        "custom-build/profile/build/maki-nbdkit/lib-unit/out/libmaki_nbdkit.so",
    );
    for executable in [
        root.path().join("debug/deps/native-test-hash"),
        root.path()
            .join("custom-build/profile/build/maki-nbdkit/test-unit/out/native-test"),
    ] {
        assert_eq!(
            native_plugin::resolve(&executable, Some(plugin.as_os_str())).unwrap(),
            plugin
        );
    }
}

#[test]
fn invalid_explicit_artifacts_never_fall_back_to_an_adjacent_library() {
    let root = tempfile::tempdir().unwrap();
    artifact(root.path(), "debug/deps/libmaki_nbdkit.so");
    let executable = root.path().join("debug/deps/native-test-hash");
    let wrong_name = artifact(root.path(), "other.so");
    let missing = root.path().join("missing/libmaki_nbdkit.so");
    let directory = root.path().join("directory/libmaki_nbdkit.so");
    std::fs::create_dir_all(&directory).unwrap();
    for path in [
        wrong_name.as_os_str(),
        missing.as_os_str(),
        directory.as_os_str(),
        OsStr::new("libmaki_nbdkit.so"),
    ] {
        assert!(native_plugin::resolve(&executable, Some(path)).is_err());
    }
}

#[test]
fn new_layout_requires_the_exact_compiler_artifact() {
    let root = tempfile::tempdir().unwrap();
    artifact(
        root.path(),
        "debug/build/maki-nbdkit/old-library/out/libmaki_nbdkit.so",
    );
    let executable = root
        .path()
        .join("debug/build/maki-nbdkit/test-unit/out/native-test");
    assert!(native_plugin::resolve(&executable, None).is_err());
}

#[test]
fn the_running_cargo_invocation_supplies_a_real_plugin() {
    assert!(native_plugin::path().is_file());
}
