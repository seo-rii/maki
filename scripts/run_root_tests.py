#!/usr/bin/env python3
"""Run the test targets that need root as root, from an unprivileged build.

Some regression tests give a fixture to another user, run a binary as the
daemon user, enter a private mount namespace or set the immutable flag.
Without root they print why they are skipped and pass, so the ordinary
workspace run says nothing about the behaviour they protect. ROOT_TARGETS
names every test target with such a case;
scripts/test_root_tests_validation.py fails for a target that probes its
privilege and is neither listed here nor classified there.

Usage: run_root_tests.py [--open-build-tree] <cargo test options> [-- <harness arguments>]

The cargo options select what is compiled, as for `cargo test`. Give the
ones of the unprivileged run (`--workspace --locked` in CI) and nothing is
rebuilt. Cargo always runs as the calling user; only the listed test
executables run as root, directly when the caller is root and through
`sudo -n` otherwise. There is no unprivileged fallback: without root the
run fails before anything is compiled.

Each executable starts in its package directory with a minimal environment
and a scratch TMPDIR under /tmp that other users can search (the fixtures
hand files to uid 65534) and that is removed as root afterwards. Some of
the targets run a built binary (`maki`, `maki-check`) as that user, so other
users must be able to reach the built executables. A directory in the way
(a 0750 home directory) fails the run; --open-build-tree adds search
permission for others to such directories for the duration of the run.

Anything a test still reports as skipped is listed at the end. A test that
reports it needs root although it ran as root fails the run, and so does an
entry owned by root left in the checkout or the build tree, which later
unprivileged steps and the build cache could not replace.
"""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
OWN_OPTION = "--open-build-tree"
# Other users can search /tmp; some fixtures hard-code it as well.
SCRATCH_PARENT = "/tmp"

# Source file of every test target with a case that skips without root.
ROOT_TARGETS = (
    # Files and directories root creates for, or refuses to take from, the
    # daemon user (uid 65534); the three under bins/ also run the built
    # binary as that user.
    "bins/maki-check/tests/review_root_created_ownership.rs",
    "bins/maki/tests/review_local_witness_owner.rs",
    "bins/maki/tests/review_root_created_ownership.rs",
    "crates/maki-backing/tests/review_local_witness_owner.rs",
    "crates/maki-backing/tests/review_root_created_ownership.rs",
    # "Owned by another user" refusals: the fixture is given away with chown.
    "bins/maki-benchmark/tests/review_volume_config_file.rs",
    "bins/maki-witness/tests/review_config_owner.rs",
    "bins/maki-witness/tests/review_state_owner.rs",
    "bins/maki/tests/review_volume_config_file.rs",
    "crates/maki-backing/tests/review_witness_state_owner.rs",
    "crates/maki-crypto-http/tests/review_tls_files.rs",
    "crates/maki-crypto-local/tests/review_secret_file_owner.rs",
    "crates/maki-nbdkit/tests/review_volume_config_file.rs",
    "crates/maki-witness/tests/review_tls_key_owner.rs",
    # A root-run takeover killed at its fchown, then attaches and GC as the
    # daemon user (the test re-executes itself as uid 65534).
    "crates/maki-backing/tests/review_remote_gc_unreadable.rs",
    # A private mount namespace (and a cgroup for the memory budget), a
    # read-only bind mount, the immutable flag.
    "crates/maki-backing/tests/review_restore_read_only_source.rs",
    "crates/maki-nbdkit/tests/review_memory_budget_mount_table.rs",
    "crates/maki-nbdkit/tests/review_memory_budget_mountinfo.rs",
    "crates/maki-privileged/tests/review_mountinfo_bytes.rs",
    "crates/maki-privileged/tests/review_mountinfo_empty_source.rs",
    # Unit tests: workload_verify_tests.rs gives the sentinel to uid 65534.
    "crates/maki-privileged/src/lib.rs",
)

# What a test prints when it leaves part of its work out, and the subset
# that blames missing root. `--show-output` prints a passing test's output
# below a header naming the test.
SKIP_NOTICE = re.compile(r"\bskip(?:s|ped|ping)?\b", re.IGNORECASE)
NEEDS_ROOT = re.compile(r"\bneeds? root\b", re.IGNORECASE)
OUTPUT_HEADER = re.compile(r"^---- (\S+) stdout ----$")


def fail(message):
    print(f"run_root_tests.py: {message}", file=sys.stderr)
    return 1


def compiled(lines):
    """Test executables by source file, and ordinary binaries; preserve diagnostics."""
    tests, binaries = {}, []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            print(line, end="", file=sys.stderr)
            continue
        if not isinstance(event, dict):
            continue
        if event.get("reason") == "compiler-message":
            rendered = event.get("message", {}).get("rendered")
            if rendered:
                print(rendered, end="", file=sys.stderr)
        executable = event.get("executable")
        if event.get("reason") != "compiler-artifact" or not executable:
            continue
        target = event.get("target", {})
        if event.get("profile", {}).get("test") is True:
            source = Path(target.get("src_path") or "")
            manifest = event.get("manifest_path")
            if manifest and source.is_absolute() and source.resolve().is_relative_to(ROOT):
                name = source.resolve().relative_to(ROOT).as_posix()
                tests[name] = (Path(executable), Path(manifest).resolve().parent)
        elif "bin" in target.get("kind", []):
            binaries.append(Path(executable))
    return tests, binaries


def root_command():
    """The prefix that starts a command as root, or None where there is none."""
    if os.geteuid() == 0:
        return []
    try:
        probe = subprocess.run(["sudo", "-n", "id", "-u"], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True)
    except OSError:
        return None
    if probe.returncode != 0 or probe.stdout.strip() != "0":
        return None
    return ["sudo", "-n"]


def closed_to_others(paths):
    """Entries among `paths` and the directories above them that others cannot search or run."""
    closed = []
    for path in paths:
        path = Path(path).resolve()
        for entry in (*reversed(path.parents), path):
            if not os.stat(entry).st_mode & stat.S_IXOTH and entry not in closed:
                closed.append(entry)
    return closed


def build_tree(executables):
    """Cargo's target directories holding `executables`: it tags them with CACHEDIR.TAG."""
    trees = set()
    for executable in executables:
        parents = Path(executable).resolve().parents
        trees.add(next((parent for parent in parents if (parent / "CACHEDIR.TAG").is_file()),
                       parents[0]))
    return trees


def owned_by(uid, trees):
    """Every entry below `trees` (and the trees themselves) that `uid` owns."""
    found = set()
    for tree in trees:
        if os.lstat(tree).st_uid == uid:
            found.add(str(tree))
        for directory, directories, files in os.walk(tree):
            for name in (*directories, *files):
                path = os.path.join(directory, name)
                try:
                    if os.lstat(path).st_uid == uid:
                        found.add(path)
                except FileNotFoundError:
                    pass
    return found


def run_target(command, directory):
    """Run one test executable, forward its output, return (status, skip notices)."""
    notices, test = [], None
    with subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                          encoding="utf-8", errors="replace") as process:
        for line in process.stdout:
            print(line, end="", flush=True)
            header = OUTPUT_HEADER.match(line)
            if header:
                test = header.group(1)
            elif line.rstrip() in ("successes:", "failures:"):
                test = None  # the list of test names that follows is not output
            elif test and (SKIP_NOTICE.search(line) or NEEDS_ROOT.search(line)):
                notices.append(f"{test}: {line.strip()}")
        return process.wait(), notices


def run(arguments):
    if not sys.platform.startswith("linux"):
        return fail("the root-only test targets are Linux-only")
    arguments = list(arguments)
    open_build_tree = OWN_OPTION in arguments
    arguments = [argument for argument in arguments if argument != OWN_OPTION]
    separator = arguments.index("--") if "--" in arguments else len(arguments)
    cargo_arguments, harness_arguments = arguments[:separator], arguments[separator + 1:]
    if any(arg == "--no-run" or arg.startswith("--message-format") for arg in cargo_arguments):
        return fail("--no-run and --message-format are set by this script")
    sudo = root_command()
    if sudo is None:
        return fail("these tests skip without root, so they are not run without it: "
                    "run as root or as a user `sudo -n` accepts without a password")

    compile_command = [os.environ.get("CARGO", "cargo"), "test", *cargo_arguments,
                       "--no-run", "--message-format=json"]
    with subprocess.Popen(compile_command, cwd=ROOT, stdout=subprocess.PIPE, text=True,
                          encoding="utf-8", errors="replace") as compiler:
        tests, binaries = compiled(compiler.stdout)
        status = compiler.wait()
    if status:
        return status
    missing = [target for target in ROOT_TARGETS if target not in tests]
    if missing:
        return fail("this compilation does not build every root-only test target "
                    "(select the workspace): " + ", ".join(missing))

    executables = [*binaries, *(tests[target][0] for target in ROOT_TARGETS)]
    scratch = Path(tempfile.mkdtemp(prefix="maki-root-tests-", dir=SCRATCH_PARENT))
    scratch.chmod(0o755)
    opened, failed, skipped, left = [], [], [], []
    try:
        closed = closed_to_others([scratch, *executables])
        if closed and not open_build_tree:
            return fail("the fixture users cannot reach the scratch directory or the built "
                        "executables; closed to other users: " + ", ".join(map(str, closed))
                        + f" (chmod o+x them, or pass {OWN_OPTION} to do so for this run)")
        for entry in closed:
            mode = stat.S_IMODE(os.stat(entry).st_mode)
            if subprocess.call([*sudo, "chmod", "o+x", "--", str(entry)]):
                return fail(f"cannot open {entry} to other users")
            opened.append((entry, mode))

        # Compare ownership only for a caller who is not root itself.
        trees = set()
        if sudo:
            trees = {ROOT, *build_tree(executables)}
            trees = {tree for tree in trees if not any(other in tree.parents for other in trees)}
        before = owned_by(0, trees)
        environment = [f"PATH={os.environ.get('PATH', os.defpath)}", f"TMPDIR={scratch}"]
        environment += [f"{name}={os.environ[name]}"
                        for name in ("RUST_BACKTRACE", "RUST_TEST_THREADS") if name in os.environ]
        for target in ROOT_TARGETS:
            executable, package = tests[target]
            print(f"\nroot: {target}", flush=True)
            status, notices = run_target(
                [*sudo, "env", "-i", *environment, f"CARGO_MANIFEST_DIR={package}",
                 str(executable), "--show-output", *harness_arguments], package)
            if status:
                failed.append(target)
            skipped += [f"{target}: {notice}" for notice in notices]
        left = sorted(owned_by(0, trees) - before)
    finally:
        restored = [subprocess.call([*sudo, "chmod", f"{mode:o}", "--", str(entry)])
                    for entry, mode in reversed(opened)]
        removal = subprocess.call([*sudo, "rm", "-rf", "--", str(scratch)])

    print(f"\nroot-only tests: {len(ROOT_TARGETS) - len(failed)} of {len(ROOT_TARGETS)} "
          "targets passed as root", flush=True)
    print("still reported as skipped (see docs/testing.md):\n  "
          + "\n  ".join(skipped or ["nothing"]), flush=True)
    status = 0
    if failed:
        status = fail("failed as root: " + ", ".join(failed))
    unprivileged = [notice for notice in skipped if NEEDS_ROOT.search(notice)]
    if unprivileged:
        status = fail("ran as root, but a test reports that it needs root:\n  "
                      + "\n  ".join(unprivileged))
    if left:
        status = fail("the root run left entries owned by root, which later unprivileged "
                      "steps and the build cache cannot replace:\n  " + "\n  ".join(left[:20]))
    if removal or any(restored):
        status = fail(f"could not remove the scratch directory {scratch} or restore the "
                      "modes of " + ", ".join(str(entry) for entry, _ in opened))
    return status


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
