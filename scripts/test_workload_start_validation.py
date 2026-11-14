"""Execute shipped first-write blocks with harmless local command fixtures."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("bash"), "Bash required for the documented commands")
class WorkloadStartTests(unittest.TestCase):
    def run_block(self, postgres, failure):
        document = ROOT / ("docs/deployment/postgres.md" if postgres
                           else "docs/getting-started/quickstart.md")
        marker = "pg_createcluster -d" if postgres else 'echo "hello from maki'
        block = next(part for part in re.findall(r"```bash\n(.*?)```", document.read_text(), re.S)
                     if marker in part)
        with tempfile.TemporaryDirectory(prefix="maki-first-write-") as temporary:
            root = Path(temporary)
            mountpoint = root / "unmounted-host-directory"
            mountpoint.mkdir()
            (mountpoint / ".maki-sentinel").write_text("fixture-volume\n")
            config = root / "attach.toml"
            config.write_text("init_sentinel = true\n")
            commands = root / "bin"
            commands.mkdir()
            # No systemd, helper, mount, DB, ownership or global sync action.
            for command in ("systemctl", "maki-attach", "findmnt", "install",
                            "pg_createcluster", "sync", "maki"):
                path = commands / command
                path.write_text('''#!/bin/sh
name=${0##*/}
printf '%s %s\\n' "$name" "$*" >> "$FIXTURE_CALLS"
case "$name $*" in
  "systemctl start "*) stage=start ;;
  "systemctl is-active --quiet maki@"*) stage=daemon ;;
  "systemctl is-active --quiet maki-attach@"*) stage=attach ;;
  "maki-attach verify "*) stage=verify ;;
  *) stage=other ;;
esac
if test "$stage" = "$FIXTURE_FAIL"; then exit 1; fi
if test "$name" = pg_createcluster; then touch "$FIXTURE_CLUSTER"; fi
exit 0
''')
                path.chmod(0o700)
            name = "postgres" if postgres else "demo"
            block = block.replace(f"/srv/{name}", str(mountpoint)).replace(
                f"/etc/maki/attach/{name}.toml", str(config))
            calls = root / "calls"
            cluster = root / "cluster"
            result = subprocess.run(
                ["bash", "-c", block], capture_output=True, text=True, timeout=5,
                env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                         FIXTURE_CALLS=str(calls), FIXTURE_CLUSTER=str(cluster),
                         FIXTURE_FAIL=failure),
            )
            created = cluster.exists() if postgres else (mountpoint / "hello.txt").exists()
            return result, created, calls.read_text().splitlines(), config.read_text()

    def test_each_failed_start_gate_prevents_first_write(self):
        for postgres in (False, True):
            for stage in ("start", "daemon", "attach", "verify"):
                with self.subTest(postgres=postgres, stage=stage):
                    result, created, calls, config = self.run_block(postgres, stage)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(created, calls)
                    self.assertFalse(any(line.startswith("install ") for line in calls), calls)
                    self.assertEqual(config, "init_sentinel = true\n")

    def test_successful_start_runs_identity_gate_before_data_creation(self):
        for postgres in (False, True):
            with self.subTest(postgres=postgres):
                result, created, calls, _ = self.run_block(postgres, "never")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(created)
                verify = next(i for i, line in enumerate(calls)
                              if line.startswith("maki-attach verify "))
                after = "install " if postgres else "sync "
                self.assertLess(verify, next(i for i, line in enumerate(calls)
                                            if line.startswith(after)))


if __name__ == "__main__":
    unittest.main()
