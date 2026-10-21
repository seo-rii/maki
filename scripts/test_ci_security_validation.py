"""CI must reject vulnerable or informationally unsafe Rust dependencies."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"


class DependencyAuditContract(unittest.TestCase):
    def test_linux_ci_installs_a_pinned_auditor_and_denies_all_warnings(self):
        workflow = WORKFLOW.read_text()
        install = """      - name: install pinned RustSec auditor (Linux)
        if: runner.os == 'Linux'
        run: cargo install cargo-audit --version 0.22.1 --locked
"""
        audit = """      - name: RustSec dependency audit (Linux)
        if: runner.os == 'Linux'
        shell: bash
"""
        self.assertIn(install, workflow)
        self.assertIn(audit, workflow)
        self.assertLess(workflow.index(install), workflow.index(audit))

    def run_audit_step(self, fail_on=""):
        step = WORKFLOW.read_text().split("      - name: RustSec dependency audit (Linux)\n", 1)[1]
        step = step.split("      - name:", 1)[0]
        run = re.search(r"(?m)^        run: \|\n((?:          .*\n)+)", step)
        self.assertIsNotNone(run, "audit must have an executable shell block")
        script = "\n".join(line[10:] for line in run.group(1).splitlines())
        repo = WORKFLOW.parents[2]
        # Include a new vendor fixture so future standalone crates are covered.
        lockfiles = ["Cargo.lock", *sorted(str(path.relative_to(repo))
                                         for path in (repo / "vendor").glob("*/Cargo.lock")),
                     "vendor/new-fixture/Cargo.lock"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for lockfile in lockfiles:
                path = root / lockfile
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            binary = root / "bin"
            binary.mkdir()
            cargo = binary / "cargo"
            cargo.write_text("""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
if len(args) != 5 or args[:4] != ["audit", "--deny", "warnings", "--file"]:
    raise SystemExit("audit must retain --deny warnings and select a lockfile")
with open(os.environ["AUDIT_CALLS"], "a") as output:
    output.write(json.dumps(args[4]) + "\\n")
if not Path(args[4]).is_file():
    raise SystemExit(24)
if args[4] == os.environ["AUDIT_FAIL_ON"]:
    raise SystemExit(23)
""")
            cargo.chmod(0o700)
            calls = root / "audit-calls.jsonl"
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                       AUDIT_CALLS=str(calls), AUDIT_FAIL_ON=fail_on)
            result = subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=10)
            actual = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        return result, actual, lockfiles

    def test_audit_covers_root_and_every_standalone_vendor_lockfile(self):
        result, calls, lockfiles = self.run_audit_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["Cargo.lock", *sorted(lockfiles[1:])])

    def test_a_vendor_audit_failure_stops_before_later_lockfiles(self):
        result, calls, _ = self.run_audit_step(fail_on="vendor/bytes/Cargo.lock")
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(calls, ["Cargo.lock", "vendor/bytes/Cargo.lock"])


if __name__ == "__main__":
    unittest.main()
