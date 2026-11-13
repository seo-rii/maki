"""Run the documented bootstrap with fake storage commands and private files.

All device/sysfs/config paths are relocated, block-type checks are replaced by
regular-file checks, and every privileged command is a mock. No NBD, LVM,
filesystem formatting, service mutation or root privilege is used.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
UUID = "12345678-1234-1234-1234-123456789abc"
PV = "111111-1111-1111-1111-1111-1111-111111"
VG = "222222-2222-2222-2222-2222-2222-222222"
LV = "333333-3333-3333-3333-3333-3333-333333"
MOCK = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["BOOTSTRAP_FIXTURE"])
scenario = os.environ["BOOTSTRAP_SCENARIO"]
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "commands.jsonl").open("a") as log:
    log.write(json.dumps([name, *args]) + "\n")
if scenario == "fail-" + name:
    sys.exit(42)
if name == "blockdev":
    active = (root / "connected").exists()
    print(4096 if scenario == "busy" or (scenario == "wrong-size" and active)
          else 8589934592 if active else 0)
elif name == "lsblk":
    if "TYPE" in args:
        print("disk\npart" if scenario == "partition" else "disk")
    elif scenario == "mounted":
        print("/somewhere")
elif name == "vgs":
    if "vg_name" in args:
        if scenario == "existing-vg":
            print("  vg_maki_demo")
    else:
        print(os.environ["BOOTSTRAP_VG"])
elif name == "lvs":
    if "vg_name,lv_name" in args:
        if scenario == "existing-lv":
            print(" vg_maki_demo data")
    else:
        print("bad" if scenario == "invalid-lv-uuid" else os.environ["BOOTSTRAP_LV"])
elif name == "pvs":
    print(os.environ["BOOTSTRAP_PV"])
elif name == "maki" and args[:2] == ["volume", "inspect"]:
    print("uuid: " + os.environ["BOOTSTRAP_UUID"])
elif name == "nbd-client":
    if "-d" in args:
        (root / "connected").unlink()
    else:
        identity = args[args.index("-identifier") + 1]
        (root / "connected").touch()
        (root / "sys/block/nbd0/backend").write_text(
            "foreign" if scenario == "foreign-backend" else identity)
elif name == "wipefs":
    if scenario == "signature":
        print("xfs")
elif name == "lvcreate":
    target = root / "dev/vg_maki_demo/data"
    target.parent.mkdir()
    target.symlink_to(root / "dev/dm-0")
    dm = root / "sys/class/block/dm-0"
    (dm / "dm").mkdir(parents=True)
    (dm / "slaves").mkdir()
    (dm / "dm/uuid").write_text("LVM-" +
        ("wrong" if scenario == "foreign-lv" else
         os.environ["BOOTSTRAP_VG"].replace("-", "") + os.environ["BOOTSTRAP_LV"].replace("-", "")))
    (dm / "slaves" / ("sda" if scenario == "foreign-pv" else "nbd0")).touch()
    if scenario == "replaced-backend":
        (root / "sys/block/nbd0/backend").write_text("foreign")
    elif scenario == "missing-backend":
        (root / "sys/block/nbd0/backend").unlink()
    elif scenario == "ambiguous-pv":
        (dm / "slaves/nbd1").touch()
elif name == "blkid":
    print(os.environ["BOOTSTRAP_UUID"])
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires Bash")
class ProvisioningContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = (ROOT / "docs/getting-started/first-volume.md").read_text()
        cls.program = re.search(r"bash <<'BASH'\n(.*?)\nBASH\n", text, re.S).group(1)

    def run_case(self, scenario):
        with tempfile.TemporaryDirectory(prefix="maki-bootstrap-") as directory:
            root = Path(directory)
            for path in ["bin", "dev", "etc/maki/attach", "run/maki-attach",
                         "sys/block/nbd0", "proc/sys/kernel/random", "srv"]:
                (root / path).mkdir(parents=True, exist_ok=True)
            (root / "dev/nbd0").touch()
            (root / "dev/dm-0").touch()
            (root / "proc/sys/kernel/random/uuid").write_text(UUID)
            if scenario == "existing-config":
                (root / "etc/maki/attach/demo.toml").write_text("preserved")
            if scenario == "existing-path":
                (root / "dev/vg_maki_demo").mkdir()
                (root / "dev/vg_maki_demo/data").touch()
            if scenario == "connected-zero-size":
                (root / "sys/block/nbd0/pid").write_text("1234")
            if scenario == "backend-zero-size":
                (root / "sys/block/nbd0/backend").write_text("foreign")
            commands = ["blockdev", "lsblk", "vgs", "lvs", "pvs", "maki", "systemctl",
                        "nbd-client", "wipefs", "pvcreate", "vgcreate", "lvcreate",
                        "mkfs.xfs", "blkid", "vgchange"]
            for name in commands:
                path = root / "bin" / name
                path.write_text(MOCK)
                path.chmod(0o700)
            # No root-owned directories or device nodes are touched. The only
            # altered tests are block-device type tests; control flow is intact.
            program = self.program.replace('[[ -b ', '[[ -f ')
            program = re.sub(r"/(?:dev|sys|etc|run|srv|proc)/",
                             lambda match: directory + match.group(), program)
            # Installation is confined to the fixture; don't request root ownership.
            program = program.replace("-o root -g root ", "")
            env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                       BOOTSTRAP_FIXTURE=directory, BOOTSTRAP_SCENARIO=scenario,
                       BOOTSTRAP_UUID=UUID, BOOTSTRAP_PV=PV, BOOTSTRAP_VG=VG, BOOTSTRAP_LV=LV)
            result = subprocess.run(["bash", "-c", program], env=env, capture_output=True,
                                    text=True, timeout=10)
            log = root / "commands.jsonl"
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            config = root / "etc/maki/attach/demo.toml"
            content = config.read_text() if config.exists() else None
            mode = config.stat().st_mode & 0o777 if config.exists() else None
            return result, calls, content, mode

    def test_success_pins_created_layout_and_formats_without_force(self):
        result, calls, content, mode = self.run_case("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        names = [call[0] for call in calls]
        self.assertEqual(names.count("mkfs.xfs"), 1)
        self.assertNotIn("-f", next(call for call in calls if call[0] == "mkfs.xfs"))
        self.assertEqual(names[-3:], ["blockdev", "nbd-client", "systemctl"])
        for identity in [UUID, PV, VG, LV]:
            self.assertIn(identity, content)
        self.assertEqual(mode, 0o600)

    def test_preflight_refuses_existing_resources_before_start(self):
        for scenario in ["existing-vg", "existing-lv", "existing-path", "existing-config",
                         "busy", "connected-zero-size", "backend-zero-size", "partition", "mounted",
                         "fail-vgs", "fail-lvs", "fail-blockdev", "fail-lsblk"]:
            with self.subTest(scenario=scenario):
                result, calls, content, _ = self.run_case(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse({"systemctl", "nbd-client", "pvcreate", "mkfs.xfs"}
                                 & {call[0] for call in calls}, result.stderr)
                self.assertEqual(content, "preserved" if scenario == "existing-config" else None)

    def test_failures_never_reach_formatting_or_cleanup(self):
        for scenario in ["fail-maki", "fail-systemctl", "fail-nbd-client", "wrong-size",
                         "foreign-backend", "signature", "fail-wipefs", "fail-pvcreate",
                         "fail-vgcreate", "fail-lvcreate", "fail-pvs", "invalid-lv-uuid",
                         "foreign-lv", "foreign-pv", "ambiguous-pv", "replaced-backend",
                         "missing-backend"]:
            with self.subTest(scenario=scenario):
                result, calls, content, _ = self.run_case(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("mkfs.xfs", [call[0] for call in calls], result.stderr)
                self.assertNotIn("vgchange", [call[0] for call in calls])
                self.assertFalse(any(call[:2] == ["nbd-client", "-d"] for call in calls))
                self.assertIsNone(content)
                if scenario.startswith("fail-"):
                    self.assertIn(scenario[5:], [call[0] for call in calls], result.stderr)

    def test_formatter_failure_does_not_publish_config_or_disconnect(self):
        result, calls, content, _ = self.run_case("fail-mkfs.xfs")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mkfs.xfs", [call[0] for call in calls])
        self.assertNotIn("vgchange", [call[0] for call in calls])
        self.assertIsNone(content)

    def test_quickstart_uses_the_shared_checked_procedure(self):
        text = (ROOT / "docs/getting-started/quickstart.md").read_text()
        self.assertIn("first-volume.md#1-provision-and-record-the-layout", text)
        blocks = re.findall(r"```bash\n(.*?)```", text, re.S)
        self.assertFalse(any(re.search(r"\b(pvcreate|vgcreate|lvcreate|mkfs\.xfs)\b", block)
                             for block in blocks))


if __name__ == "__main__":
    unittest.main()
