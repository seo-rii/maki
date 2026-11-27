//! The directory trees `helper_sysfs` builds below the temporary directory,
//! one per input. libFuzzer aborts the process on a failed assertion (its
//! panic hook), so a tree removed only when the reader's frame unwinds stays
//! behind for a crashing input, and so does one of a process that libFuzzer
//! ends without a panic (a timeout, the memory limit) or that is killed.
//!
//! Each case runs `helper_sysfs` in a child process (this test binary
//! again, with `MAKI_FUZZ_SYSFS_CHILD` naming what it does) whose temporary
//! directory is one of the test's own, and then reads what that directory
//! holds.
#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CHILD: &str = "MAKI_FUZZ_SYSFS_CHILD";
/// What a holding child prints once it has read its input.
const READY: &str = "maki-fuzz-sysfs-child-ready";
/// What a process's trees are kept in: `<prefix><pid>-<nanoseconds>-<n>`.
const PREFIX: &str = "maki-fuzz-sysfs-trees-";

fn seeds() -> Vec<Vec<u8>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../seeds/helper_sysfs");
    let mut names: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    names.sort();
    names
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect()
}

/// The child half: what `MAKI_FUZZ_SYSFS_CHILD` asks for, then exit.
fn child() {
    let Some(mode) = std::env::var_os(CHILD) else {
        return;
    };
    match mode.to_str().unwrap() {
        // Every seed, then a normal exit, as libFuzzer's at its time limit.
        "seeds" => {
            for seed in seeds() {
                maki_fuzz_harness::helper_sysfs(&seed);
            }
            std::process::exit(0);
        }
        // libfuzzer-sys's hook: the default report, then abort. It is
        // installed before the first input, which here is one whose reader
        // fails an assertion.
        "crash" => {
            let report = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                report(info);
                std::process::abort();
            }));
            let seed = seeds().remove(0);
            maki_privileged::exec::fuzzing::sysfs_with(&seed, |_, _, sysfs| {
                assert!(sysfs.is_dir(), "the reader runs on the input's tree");
                panic!("an assertion of the target failed");
            });
            unreachable!("the hook aborts");
        }
        // One input, then wait for the parent to close stdin: a process
        // that runs while another starts.
        "hold" => {
            maki_fuzz_harness::helper_sysfs(&seeds().remove(0));
            // libtest may print the test's name on the same line first.
            println!("{READY}");
            std::io::stdout().flush().unwrap();
            let _ = std::io::stdin().read_to_end(&mut Vec::new());
            std::process::exit(0);
        }
        other => panic!("unknown child {other}"),
    }
}

/// Run `test`'s child half as `mode` with `temp` as its temporary directory.
fn run(test: &str, mode: &str, temp: &Path) -> Output {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, mode)
        .env("TMPDIR", temp)
        .output()
        .unwrap()
}

/// A temporary directory of the test's own, removed when dropped.
struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "maki-review-sysfs-trees-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn entries(&self) -> Vec<String> {
        entries(&self.0)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn a_crashing_input_leaves_no_tree_behind() {
    use std::os::unix::process::ExitStatusExt;
    child();
    let temp = Temp::new("crash");
    let crashed = run("a_crashing_input_leaves_no_tree_behind", "crash", &temp.0);
    assert_eq!(crashed.status.signal(), Some(6), "{crashed:?}");
    let stderr = String::from_utf8_lossy(&crashed.stderr);
    assert!(
        stderr.contains("an assertion of the target failed"),
        "{stderr}"
    );
    // The process's own directory stays, as a process that aborts cannot
    // remove it, but without the tree of the input it aborted on.
    let left = temp.entries();
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].starts_with(PREFIX), "{left:?}");
    assert_eq!(entries(&temp.0.join(&left[0])), Vec::<String>::new());
    // The next process removes it when it starts, and its own when it ends.
    let next = run("a_crashing_input_leaves_no_tree_behind", "seeds", &temp.0);
    assert!(next.status.success(), "{next:?}");
    assert_eq!(temp.entries(), Vec::<String>::new());
}

#[test]
fn the_trees_of_ended_processes_are_removed_and_a_running_ones_kept() {
    child();
    let temp = Temp::new("sweep");
    // A process that ended in the middle of an input (a timeout, a kill):
    // its directory still holds that input's tree, and nobody locks it.
    let ended = temp.0.join(format!("{PREFIX}4242-1-0"));
    write(
        &ended.join("17/devices/virtual/block/nbd3/size"),
        "2097152\n",
    );
    // One a running process holds: its exclusive lock on the directory.
    let running = temp.0.join(format!("{PREFIX}4343-1-0"));
    write(&running.join("3/devices/virtual/block/nbd3/size"), "8\n");
    let lock = File::open(&running).unwrap();
    lock.try_lock().unwrap();
    // Neither a file of that name nor other names are a process's trees.
    write(&temp.0.join(format!("{PREFIX}file")), "kept\n");
    write(&temp.0.join("maki-fuzz-sysfs-4444-0/size"), "kept\n");
    write(&temp.0.join("unrelated/size"), "kept\n");
    let before = temp.entries();

    let output = run(
        "the_trees_of_ended_processes_are_removed_and_a_running_ones_kept",
        "seeds",
        &temp.0,
    );
    assert!(output.status.success(), "{output:?}");
    // The ended process's directory is gone, the running one's is as it
    // was, and the child, which ended normally, left nothing of its own.
    let expected: Vec<String> = before
        .into_iter()
        .filter(|name| *name != format!("{PREFIX}4242-1-0"))
        .collect();
    assert_eq!(temp.entries(), expected);
    assert_eq!(
        std::fs::read_to_string(running.join("3/devices/virtual/block/nbd3/size")).unwrap(),
        "8\n"
    );
    drop(lock);
}

#[test]
fn a_process_that_starts_keeps_the_trees_of_one_that_runs() {
    child();
    let temp = Temp::new("running");
    let mut running = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_process_that_starts_keeps_the_trees_of_one_that_runs",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "hold")
        .env("TMPDIR", &temp.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    let mut lines = BufReader::new(running.stdout.take().unwrap());
    while !line.contains(READY) {
        line.clear();
        assert_ne!(
            lines.read_line(&mut line).unwrap(),
            0,
            "the child ended early"
        );
    }
    let held = temp.entries();
    assert_eq!(held.len(), 1, "{held:?}");
    assert!(held[0].starts_with(PREFIX), "{held:?}");

    let output = run(
        "a_process_that_starts_keeps_the_trees_of_one_that_runs",
        "seeds",
        &temp.0,
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        temp.entries(),
        held,
        "the running process's directory was removed"
    );

    drop(running.stdin.take());
    assert!(running.wait().unwrap().success());
    assert_eq!(temp.entries(), Vec::<String>::new());
}
