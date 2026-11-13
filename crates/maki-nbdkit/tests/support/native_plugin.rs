//! Locate only the plugin produced for the current Cargo test invocation.
//! Cargo 1.100 moved each compilation unit out of the shared `deps` directory:
//! https://doc.rust-lang.org/cargo/reference/build-cache.html

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const PLUGIN: &str = "libmaki_nbdkit.so";

pub fn path() -> PathBuf {
    let executable = std::env::current_exe().expect("native test executable path");
    let search_path = std::env::var_os("LD_LIBRARY_PATH").unwrap_or_default();
    resolve(&executable, &search_path).unwrap_or_else(|error| panic!("{error}"))
}

pub fn resolve(executable: &Path, search_path: &OsStr) -> Result<PathBuf, String> {
    let directory = executable
        .parent()
        .ok_or_else(|| format!("native test has no parent directory: {executable:?}"))?;
    // Cargo <= 1.99 puts the test and its cdylib dependency together.
    if directory.file_name() == Some(OsStr::new("deps")) {
        let plugin = directory.join(PLUGIN);
        return plugin
            .is_file()
            .then_some(plugin.clone())
            .ok_or_else(|| format!("missing cargo-built plugin: {plugin:?}"));
    }

    // Cargo >= 1.100 gives the test and library different unit hashes:
    // <build-dir>/<profile>/build/maki-nbdkit/<unit>/out/<artifact>.
    // Cargo supplies the active dependency directories in LD_LIBRARY_PATH.
    // Search only those entries in this package/profile, never enumerate old
    // unit hashes or fall back to another profile's possibly stale artifact.
    let package = directory
        .parent()
        .and_then(Path::parent)
        .filter(|package| {
            directory.file_name() == Some(OsStr::new("out"))
                && package.file_name() == Some(OsStr::new("maki-nbdkit"))
                && package.parent().and_then(Path::file_name) == Some(OsStr::new("build"))
        })
        .ok_or_else(|| format!("unrecognized Cargo native test layout: {executable:?}"))?;
    let candidates: BTreeSet<_> = std::env::split_paths(search_path)
        .filter(|path| {
            path.file_name() == Some(OsStr::new("out"))
                && path.parent().and_then(Path::parent) == Some(package)
        })
        .map(|path| path.join(PLUGIN))
        .filter(|path| path.is_file())
        .collect();
    if candidates.len() != 1 {
        return Err(format!(
            "expected exactly one cargo-built plugin for {executable:?} in Cargo's \
             active dependency directories beneath {package:?}; found {candidates:?}"
        ));
    }
    Ok(candidates.into_iter().next().unwrap())
}
