#!/usr/bin/env python3
"""Run cargo test with the native nbdkit cdylib from the same compilation.

Forward cargo-test options and optional harness arguments verbatim. On Linux,
first compile the identical test selection with --no-run and parse Cargo's
compiler-artifact messages. This preserves the toolchain, profile, target and
unified dependency features without depending on Cargo's internal cache layout.
Non-Linux runs need no native Linux plugin and invoke cargo test directly.
"""

import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "crates/maki-nbdkit/Cargo.toml"
PLUGIN_ENV = "MAKI_NBDKIT_TEST_PLUGIN"
PLUGIN_NAME = "libmaki_nbdkit.so"


def compiler_artifacts(lines):
    """Select only this workspace's non-test cdylib; preserve compiler diagnostics."""
    paths = set()
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
        target = event.get("target", {})
        if (event.get("reason") != "compiler-artifact"
                or target.get("name") != "maki_nbdkit"
                or "cdylib" not in target.get("crate_types", [])
                or event.get("profile", {}).get("test") is not False):
            continue
        manifest = event.get("manifest_path")
        if manifest is not None and Path(manifest).resolve() != MANIFEST.resolve():
            continue
        paths.update(Path(name) for name in event.get("filenames", [])
                     if Path(name).name == PLUGIN_NAME)
    return paths


def run(arguments, platform=None):
    platform = sys.platform if platform is None else platform
    command = [os.environ.get("CARGO", "cargo"), "test", *arguments]
    if not platform.startswith("linux"):
        return subprocess.call(command, cwd=ROOT)
    separator = arguments.index("--") if "--" in arguments else len(arguments)
    cargo_arguments = arguments[:separator]
    if any(arg == "--no-run" or arg.startswith("--message-format")
           for arg in cargo_arguments):
        print("run_cargo_tests.py controls --no-run and --message-format", file=sys.stderr)
        return 2
    if any(arg in ("-h", "--help") for arg in cargo_arguments):
        return subprocess.call(command, cwd=ROOT)
    compile_command = [command[0], "test", *cargo_arguments,
                       "--no-run", "--message-format=json"]
    environment = os.environ.copy()
    environment.pop(PLUGIN_ENV, None)
    with subprocess.Popen(compile_command, cwd=ROOT, env=environment,
                          stdout=subprocess.PIPE, text=True,
                          encoding="utf-8", errors="replace") as compiler:
        paths = compiler_artifacts(compiler.stdout)
        status = compiler.wait()
    if status:
        return status
    if len(paths) != 1:
        print(f"expected exactly one {PLUGIN_NAME} from this test compilation; "
              f"found {sorted(str(path) for path in paths)}", file=sys.stderr)
        return 1
    plugin = paths.pop()
    if not plugin.is_absolute() or not plugin.is_file():
        print(f"unusable compiler-reported native plugin: {plugin}", file=sys.stderr)
        return 1
    run_environment = environment.copy()
    run_environment[PLUGIN_ENV] = str(plugin)
    return subprocess.call(command, cwd=ROOT, env=run_environment)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
