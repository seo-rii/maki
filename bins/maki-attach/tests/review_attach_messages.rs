//! What `maki-attach` says when it cannot open one of its own files. The
//! operating system's error alone ("No such file or directory (os error
//! 2)") does not say whether the attach configuration, the attach state
//! directory or its lock is missing, nor that the helper's executing verbs
//! run as root: a workload gate that ran before any attach since boot left
//! only that line in the journal. Exit statuses are unchanged.

#![cfg(target_os = "linux")]

use std::process::{Command, Output};

/// A volume no host has a configuration or an attachment for.
const VOLUME: &str = "maki-review-no-such-volume";
const STATE: &str = "/run/maki-attach";
const CONFIG: &str = "/etc/maki/attach/maki-review-no-such-volume.toml";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .args(args)
        .output()
        .expect("spawn maki-attach")
}

fn is_root() -> bool {
    let uid = Command::new("id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&uid.stdout).trim() == "0"
}

/// The gate needs the attach state directory, its lock and the volume's
/// configuration, in that order. Whichever this host lacks first, the
/// error names it by its path.
#[test]
fn verify_names_the_file_it_cannot_open() {
    let out = run(&["verify", "--volume", VOLUME]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let named = [
        format!("error: attach state directory {STATE}: "),
        format!("error: attach lock {STATE}/attach.lock: "),
        format!("error: attach config {CONFIG}: "),
    ];
    assert!(
        named.iter().any(|start| stderr.starts_with(start.as_str())),
        "{stderr}"
    );
    assert!(out.stdout.is_empty(), "{:?}", out.stdout);
}

/// Without root every executing verb is refused at the attach state
/// directory, which only root may open or create. The error names the
/// directory and says whom to run as.
#[test]
fn an_executing_verb_without_root_names_the_state_directory_and_root() {
    if is_root() {
        // As root the verbs would really run.
        eprintln!("skipping: running as root");
        return;
    }
    let uuid = ["--uuid", "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c"];
    let volume = ["--volume", VOLUME];
    for verb in ["attach", "detach", "cleanup", "recover", "verify"] {
        let overrides: &[&str] = if verb == "verify" { &[] } else { &uuid };
        let out = run(&[&[verb], &volume[..], overrides].concat());
        assert_eq!(out.status.code(), Some(1), "{verb}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        // A host that has Maki installed keeps its configurations from
        // other users too: the helper then stops at that directory.
        if stderr.contains("/etc/maki/attach/") {
            continue;
        }
        let expected = format!(
            "error: attach state directory {STATE}: Permission denied (os error 13); run this \
             command as root"
        );
        assert!(
            stderr.lines().any(|line| line == expected),
            "{verb}: {stderr}"
        );
    }
}
