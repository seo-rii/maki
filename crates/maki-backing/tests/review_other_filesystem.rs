//! The rollback fixtures' second filesystem (`tests/support/other_filesystem.rs`).
//! Where there is none, a fixture prints why and its test passes; a run that
//! does not show passing tests' output then reports a pass without
//! anything having run. `MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1`, which CI and
//! the background runner's rollback profile set, makes it a failure. The
//! helper is copied into each crate whose fixtures use it; the copies must
//! not drift apart.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Names the reference directory of a [`child_finds_no_second_filesystem`] run.
const CHILD: &str = "MAKI_TEST_OTHER_FILESYSTEM_CHILD";

/// Run by [`a_missing_second_filesystem_fails_only_when_one_is_required`]
/// in a child process; does nothing otherwise. The only candidate is the
/// reference directory itself, which is on its own filesystem.
#[test]
fn child_finds_no_second_filesystem() {
    let Some(reference) = std::env::var_os(CHILD) else {
        return;
    };
    let reference = PathBuf::from(reference);
    assert!(
        other_filesystem::tempdir_among(&reference, std::slice::from_ref(&reference)).is_none()
    );
}

fn child(reference: &Path, require: Option<&str>) -> (Output, String) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "child_finds_no_second_filesystem",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, reference)
        .env_remove(other_filesystem::REQUIRE);
    if let Some(value) = require {
        command.env(other_filesystem::REQUIRE, value);
    }
    let output = command.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output, text)
}

#[test]
fn a_missing_second_filesystem_fails_only_when_one_is_required() {
    let reference = tempfile::tempdir().unwrap();
    let notice = format!(
        "child_finds_no_second_filesystem: skipped: no temporary directory on a filesystem \
         other than that of {}",
        reference.path().display()
    );
    for require in [None, Some("0"), Some("")] {
        let (output, text) = child(reference.path(), require);
        assert!(output.status.success(), "{require:?}: {text}");
        assert!(text.contains(&notice), "{require:?}: {text}");
        assert!(text.contains("1 passed"), "{require:?}: {text}");
    }
    let (output, text) = child(reference.path(), Some("1"));
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("1 failed"), "{text}");
    assert!(
        text.contains("MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1 requires one"),
        "{text}"
    );
    assert!(!text.contains("skipped"), "{text}");
}

#[test]
fn every_copy_of_the_helper_is_the_same() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |copy: &str| {
        std::fs::read_to_string(workspace.join(copy))
            .unwrap_or_else(|error| panic!("{copy}: {error}"))
    };
    let original = read("crates/maki-backing/tests/support/other_filesystem.rs");
    for copy in [
        "crates/maki-core/tests/support/other_filesystem.rs",
        "crates/maki-nbdkit/tests/support/other_filesystem.rs",
        "bins/maki-benchmark/tests/support/other_filesystem.rs",
        "bins/maki/tests/support/other_filesystem.rs",
    ] {
        assert!(
            read(copy) == original,
            "{copy} differs from maki-backing's copy"
        );
    }
}
