//! Use the artifact selected from the current Cargo compiler messages.
//! Cargo 1.100 puts tests and cdylibs in different compilation-unit directories
//! and does not put cdylibs on LD_LIBRARY_PATH. Never scan cached unit hashes.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const PLUGIN: &str = "libmaki_nbdkit.so";

pub fn path() -> PathBuf {
    let executable = std::env::current_exe().expect("native test executable path");
    let selected = std::env::var_os("MAKI_NBDKIT_TEST_PLUGIN");
    resolve(&executable, selected.as_deref()).unwrap_or_else(|error| panic!("{error}"))
}

pub fn resolve(executable: &Path, selected: Option<&OsStr>) -> Result<PathBuf, String> {
    if let Some(selected) = selected {
        let path = PathBuf::from(selected);
        if path.is_absolute() && path.file_name() == Some(OsStr::new(PLUGIN)) && path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "MAKI_NBDKIT_TEST_PLUGIN is not an existing absolute {PLUGIN} path: {path:?}"
        ));
    }
    // Preserve direct `cargo test` support on Cargo <= 1.99. Newer Cargo
    // requires the wrapper to pass the exact library from compiler-artifact
    // JSON; test and library unit hashes cannot be inferred from each other.
    if let Some(directory) = executable.parent() {
        if directory.file_name() == Some(OsStr::new("deps")) {
            let plugin = directory.join(PLUGIN);
            if plugin.is_file() {
                return Ok(plugin);
            }
        }
    }
    Err(format!(
        "missing cargo-built native plugin for {executable:?}; run \
         python scripts/run_cargo_tests.py with the same cargo test arguments"
    ))
}
