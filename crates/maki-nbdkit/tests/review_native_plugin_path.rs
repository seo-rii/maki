//! Resolve both Cargo layouts without selecting stale libraries from a build cache.
#![cfg(target_os = "linux")]

#[path = "support/native_plugin.rs"]
mod native_plugin;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn artifact(root: &Path, relative: &str) -> PathBuf {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"fixture").unwrap();
    path
}

fn search(paths: &[&Path]) -> OsString {
    std::env::join_paths(paths).unwrap()
}

#[test]
fn legacy_layout_uses_only_the_adjacent_library() {
    let root = tempfile::tempdir().unwrap();
    let plugin = artifact(root.path(), "debug/deps/libmaki_nbdkit.so");
    let other = artifact(root.path(), "release/deps/libmaki_nbdkit.so");
    let executable = root.path().join("debug/deps/native-test-hash");
    assert_eq!(
        native_plugin::resolve(&executable, &search(&[other.parent().unwrap()])).unwrap(),
        plugin
    );
    std::fs::remove_file(&plugin).unwrap();
    assert!(native_plugin::resolve(&executable, &search(&[other.parent().unwrap()])).is_err());
}

#[test]
fn new_layout_uses_only_active_dependencies_for_the_same_package_and_profile() {
    let root = tempfile::tempdir().unwrap();
    let package = root
        .path()
        .join("x86_64-unknown-linux-gnu/release/build/maki-nbdkit");
    let executable = package.join("test-unit/out/native-test");
    let plugin = artifact(&package, "active-library/out/libmaki_nbdkit.so");
    artifact(&package, "stale-library/out/libmaki_nbdkit.so");
    let other_profile = artifact(
        root.path(),
        "debug/build/maki-nbdkit/active/out/libmaki_nbdkit.so",
    );
    let other_package = artifact(
        root.path(),
        "x86_64-unknown-linux-gnu/release/build/other/active/out/libmaki_nbdkit.so",
    );
    let paths = search(&[
        other_profile.parent().unwrap(),
        other_package.parent().unwrap(),
        plugin.parent().unwrap(),
        plugin.parent().unwrap(), // repeated loader entries are not ambiguous
    ]);
    assert_eq!(native_plugin::resolve(&executable, &paths).unwrap(), plugin);
}

#[test]
fn new_layout_refuses_missing_or_ambiguous_active_libraries() {
    let root = tempfile::tempdir().unwrap();
    let package = root.path().join("debug/build/maki-nbdkit");
    let executable = package.join("test-unit/out/native-test");
    let first = artifact(&package, "first/out/libmaki_nbdkit.so");
    let second = artifact(&package, "second/out/libmaki_nbdkit.so");
    assert!(native_plugin::resolve(&executable, &OsString::new()).is_err());
    assert!(native_plugin::resolve(
        &executable,
        &search(&[first.parent().unwrap(), second.parent().unwrap()])
    )
    .is_err());
    std::fs::remove_file(&first).unwrap();
    assert!(native_plugin::resolve(&executable, &search(&[first.parent().unwrap()])).is_err());
}

#[test]
fn unknown_layout_does_not_search_arbitrary_library_paths() {
    let root = tempfile::tempdir().unwrap();
    let plugin = artifact(root.path(), "somewhere/libmaki_nbdkit.so");
    assert!(native_plugin::resolve(
        &root.path().join("unknown/native-test"),
        &search(&[plugin.parent().unwrap()])
    )
    .is_err());
}

#[test]
fn the_running_cargo_invocation_supplies_a_real_plugin() {
    assert!(native_plugin::path().is_file());
}
