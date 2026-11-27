"""Run the documented bootstrap with fake storage commands and private files.

All device/sysfs/config paths are relocated, block-type checks are replaced by
regular-file checks, and every privileged command is a mock. No NBD, LVM,
filesystem formatting, service mutation or root privilege is used. A run that
stops is followed by further runs of the same block on the same fixture, as
the guide tells an operator to do.
"""

import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[1]
UUID = "12345678-1234-1234-1234-123456789abc"
PV = "111111-1111-1111-1111-1111-1111-111111"
VG = "222222-2222-2222-2222-2222-2222-222222"
LV = "333333-3333-3333-3333-3333-3333-333333"
# A VG of the same name that this run did not create, on its device, and
# one on another disk of the host.
OTHER_VG = "444444-4444-4444-4444-4444-4444-444444"
OTHER_DISK_VG = "555555-5555-5555-5555-5555-5555-555555"
BOOT = "99999999-8888-7777-6666-555555555555"
CONNECTION = "maki-bootstrap-" + UUID
# What a run records, below the fixture's root, before its first change to
# the host.
RECORD = "etc/maki/attach/demo.bootstrap"
MOCK = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ["BOOTSTRAP_FIXTURE"])
scenario = os.environ["BOOTSTRAP_SCENARIO"]
name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == "maki-attach":
    # The helper takes no lock and must not inherit the shell's: a child
    # holding the lock's descriptor keeps the lock after the shell exits.
    try:
        os.fstat(9)
    except OSError:
        pass
    else:
        sys.exit("maki-attach inherited the attach lock's descriptor")
entry = [name, *args]
if name in ("vgs", "lvs", "pvs", "pvcreate", "vgcreate", "lvcreate", "vgchange"):
    # Whether LVM was told not to warn about the descriptors it inherits.
    with (root / "lvm-environment.jsonl").open("a") as log:
        log.write(json.dumps([name, os.environ.get("LVM_SUPPRESS_FD_WARNINGS")]) + "\n")
if name == "sync":
    # Whether the record still exists when something is made durable.
    entry.append("record" if (root / "etc/maki/attach/demo.bootstrap").exists() else "no record")
with (root / "commands.jsonl").open("a") as log:
    log.write(json.dumps(entry) + "\n")
if scenario == "fail-" + name or scenario == "fail-" + "-".join([name, *args[:1]]):
    sys.exit(42)
backend = root / "sys/block/nbd0/backend"
# Another disk of the host holds a VG of the same name: an LVM command that
# names the VG without --devices for the NBD device acts on that one.
other_disk = (root / "other-disk-vg").exists()
on_device = "--devices" in args and args[args.index("--devices") + 1].endswith("/dev/nbd0")
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
        if scenario == "existing-vg" or other_disk:
            print("  vg_maki_demo")
    elif other_disk and not on_device:
        print(os.environ["BOOTSTRAP_OTHER_DISK_VG"])
    else:
        print(os.environ["BOOTSTRAP_OTHER_VG" if scenario == "other-vg" else "BOOTSTRAP_VG"])
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
elif name == "maki" and args[:1] == ["check"] and scenario == "racing-record":
    # A record appears while a fresh run checks the volume.
    (root / "etc/maki/attach/demo.bootstrap").write_text("someone else's\n")
elif name == "maki-attach":
    # The helper's provisioning verbs, not its volume lifecycle, with the
    # helper's rules: a connect refuses a device that shows a connection, a
    # disconnect does nothing for a device without one and refuses another
    # identifier's.
    assert args[0] in ("nbd-connect", "nbd-disconnect"), args
    assert args[args.index("--nbd-device") + 1].endswith("/dev/nbd0"), args
    identity = args[args.index("--identifier") + 1]
    if args[0] == "nbd-disconnect":
        if backend.exists():
            if backend.read_text() != identity:
                sys.exit("refusing to touch another identifier's connection")
            # An active mapping holds the device open, as anything else can.
            if any((root / "sys/block/nbd0/holders").iterdir()) or scenario == "busy-disconnect":
                # The kernel acknowledged it, but something has the device
                # open, so it still shows the connection.
                sys.exit("something still has the device open; run the command again")
            backend.unlink()
            (root / "connected").unlink()
    else:
        assert args[args.index("--socket") + 1].endswith("/run/maki/demo/nbd.sock"), args
        assert args[args.index("--block-size") + 1] == "4096", args
        assert not backend.exists(), "the device already shows a connection"
        (root / "connected").touch()
        backend.write_text("foreign" if scenario == "foreign-backend" else identity)
        if scenario == "unacknowledged-connect":
            # The kernel connected, but its answer was lost: the step failed
            # with its effect unknown.
            sys.exit("no answer to the connect request")
elif name == "wipefs":
    if scenario == "signature":
        print("xfs")
    elif (root / "export-signatures").exists():
        print((root / "export-signatures").read_text(), end="")
elif name == "pvcreate":
    # The export keeps what was written to it across connections.
    (root / "export-signatures").write_text("LVM2_member\n")
elif name == "vgchange":
    assert args[-2:] == ["-an", "vg_maki_demo"], args
    if other_disk and not on_device:
        (root / "other-disk-vg-deactivated").touch()
        sys.exit(0)
    # Deactivation removes the LV's mapping, its holder link and its path.
    shutil.rmtree(root / "dev/vg_maki_demo", ignore_errors=True)
    shutil.rmtree(root / "sys/class/block/dm-0", ignore_errors=True)
    (root / "sys/block/nbd0/holders/dm-0").unlink(missing_ok=True)
    if scenario == "racing-config":
        (root / "etc/maki/attach/demo.toml").write_text("someone else's")
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
    if scenario != "foreign-pv":
        # The active LV holds the device it maps.
        (root / "sys/block/nbd0/holders/dm-0").symlink_to(dm)
    if scenario == "replaced-backend":
        (root / "sys/block/nbd0/backend").write_text("foreign")
    elif scenario == "missing-backend":
        (root / "sys/block/nbd0/backend").unlink()
    elif scenario == "ambiguous-pv":
        (dm / "slaves/nbd1").touch()
elif name == "blkid":
    print(os.environ["BOOTSTRAP_UUID"])
elif name == "sync":
    target, = args
    if not os.path.exists(target):
        sys.exit(f"sync: {target}: No such file or directory")
    if scenario == "fail-config-sync" and target.endswith("/demo.toml.next"):
        sys.exit(f"sync: {target}: Input/output error")
'''

# One program under the names the quick start's creation block runs. It logs
# its command line, prints its stage and fails at the stage named by FAIL_AT;
# as `runuser` it accepts only `-u maki -- <command>` and runs the command.
QUICKSTART_TOOL = r'''#!@BASH@
name=${0##*/}
echo "$name $*" >> "$TOOL_LOG"
case "$name" in
    runuser)
        [[ "$1" == -u && "$2" == maki && "$3" == -- && $# -gt 3 ]] ||
            { echo "runuser: unexpected arguments: $*" >&2; exit 64; }
        shift 3
        exec "$@"
        ;;
    install) stage=install ;;
    maki) if [[ "$1" == volume ]]; then stage=$2; else stage=$1; fi ;;
esac
echo "$stage"
[[ "$stage" != "$FAIL_AT" ]] || exit 42
'''


# `rm` as the block runs it, for the race of a staged copy: once the block
# has removed the staged name BOOTSTRAP_RACE_NAME, another process takes it
# before the block writes it, with a symbolic link to a file elsewhere
# (BOOTSTRAP_RACE=symlink) or with a file of its own (file).
RACING_RM = r'''#!@BASH@
status=0
command -p rm "$@" || status=$?
if [[ $status == 0 && $# == 2 && $1 == -f && $2 == */etc/maki/attach/$BOOTSTRAP_RACE_NAME &&
      ! -e $BOOTSTRAP_FIXTURE/raced ]]; then
    touch "$BOOTSTRAP_FIXTURE/raced"
    case $BOOTSTRAP_RACE in
        symlink) ln -s "$BOOTSTRAP_FIXTURE/srv/victim" "$2" ;;
        file) printf 'made by another process\n' > "$2" ;;
    esac
fi
exit "$status"
'''

@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires Bash")
class ProvisioningContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = (ROOT / "docs/getting-started/first-volume.md").read_text()
        cls.program = re.search(r"bash <<'BASH'\n(.*?)\nBASH\n", text, re.S).group(1)

    def make_fixture(self, directory, scenario):
        root = Path(directory)
        for path in ["bin", "dev", "etc/maki/attach", "run/maki-attach",
                     "sys/block/nbd0/holders", "proc/sys/kernel/random", "srv"]:
            (root / path).mkdir(parents=True, exist_ok=True)
        (root / "dev/nbd0").touch()
        (root / "dev/nbd1").touch()
        (root / "dev/dm-0").touch()
        (root / "proc/sys/kernel/random/uuid").write_text(UUID)
        (root / "proc/sys/kernel/random/boot_id").write_text(BOOT + "\n")
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
                    "maki-attach", "wipefs", "pvcreate", "vgcreate", "lvcreate",
                    "mkfs.xfs", "blkid", "vgchange", "sync"]
        for name in commands:
            path = root / "bin" / name
            path.write_text(MOCK)
            path.chmod(0o700)

    def run_block(self, directory, scenario, program=None):
        """Run the guide's block once on the fixture; return its result and
        the commands this run called."""
        root = Path(directory)
        # No root-owned directories or device nodes are touched. The only
        # altered tests are block-device type tests; control flow is intact.
        program = (program or self.program).replace('[[ -b ', '[[ -f ')
        program = re.sub(r"/(?:dev|sys|etc|run|srv|proc)/",
                         lambda match: directory + match.group(), program)
        # Installation is confined to the fixture; don't request root ownership,
        # and expect the fixture's files to belong to the user running it.
        program = program.replace("-o root -g root ", "")
        program = program.replace(" == 0:", f" == {os.getuid()}:")
        env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                   BOOTSTRAP_FIXTURE=directory, BOOTSTRAP_SCENARIO=scenario,
                   BOOTSTRAP_UUID=UUID, BOOTSTRAP_PV=PV, BOOTSTRAP_VG=VG, BOOTSTRAP_LV=LV,
                   BOOTSTRAP_OTHER_VG=OTHER_VG, BOOTSTRAP_OTHER_DISK_VG=OTHER_DISK_VG)
        # Only the block may tell LVM what to suppress.
        env.pop("LVM_SUPPRESS_FD_WARNINGS", None)
        log = root / "commands.jsonl"
        before = len(log.read_text().splitlines()) if log.exists() else 0
        result = subprocess.run(["bash", "-c", program], env=env, capture_output=True,
                                text=True, timeout=10)
        # What the run prints names the fixture's paths as the guide does.
        result.stdout = result.stdout.replace(directory, "")
        result.stderr = result.stderr.replace(directory, "")
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, [[arg.replace(directory, "") for arg in call] for call in calls[before:]]

    @staticmethod
    def read_file(path, root):
        """The content of `path`, with the fixture's paths as the guide
        writes them, and its mode; or (None, None). What is not a regular
        file is named by its kind."""
        if not path.exists():
            return None, None
        mode = path.stat().st_mode
        if not stat.S_ISREG(mode):
            return "<fifo>" if stat.S_ISFIFO(mode) else "<other>", mode & 0o777
        return path.read_text().replace(str(root), ""), mode & 0o777

    def run_case(self, scenario):
        with tempfile.TemporaryDirectory(prefix="maki-bootstrap-") as directory:
            self.make_fixture(directory, scenario)
            result, calls = self.run_block(directory, scenario)
            content, mode = self.read_file(Path(directory) / "etc/maki/attach/demo.toml", directory)
            return result, calls, content, mode

    def run_again(self, first, *later, between=None):
        """Run the block with scenario `first`, then once more for each of
        `later` (a scenario, or a scenario and the block to run) on the same
        host; `between(root)` runs before each later run. Return each run's
        result and calls, the record after each run (content and mode), and
        what is left at the end: the attach configuration (content and mode)
        and the device's backend identifier and holders."""
        with tempfile.TemporaryDirectory(prefix="maki-bootstrap-") as directory:
            root = Path(directory)
            self.make_fixture(directory, first)
            runs, records = [], []
            for index, run in enumerate((first, *later)):
                scenario, program = (run, None) if isinstance(run, str) else run
                if index and between:
                    with between(root):
                        runs.append(self.run_block(directory, scenario, program))
                else:
                    runs.append(self.run_block(directory, scenario, program))
                records.append(self.read_file(root / RECORD, directory))
            backend = root / "sys/block/nbd0/backend"
            return runs, records, {
                "config": self.read_file(root / "etc/maki/attach/demo.toml", directory),
                "backend": backend.read_text() if backend.exists() else None,
                "holders": sorted(entry.name for entry in (root / "sys/block/nbd0/holders").iterdir()),
                "other disk deactivated": (root / "other-disk-vg-deactivated").exists(),
                "staged": sorted(entry.name for entry in (root / "etc/maki/attach").iterdir()
                                 if entry.name.endswith(".next")),
            }

    def test_lvm_is_told_not_to_warn_about_the_lock_descriptor(self):
        # Every LVM command inherits the attach lock's descriptor 9; LVM
        # closes its own copy, which leaves the lock held, and warns that it
        # "leaked" unless LVM_SUPPRESS_FD_WARNINGS is set (lvm(8)).
        self.assertLess(self.program.index("\nexport LVM_SUPPRESS_FD_WARNINGS=1\n"),
                        self.program.index("\nexec 9>>/run/maki-attach/attach.lock\n"))
        for runs in (("success",), ("fail-mkfs.xfs", "success")):
            with self.subTest(runs=runs), tempfile.TemporaryDirectory(prefix="maki-bootstrap-") as directory:
                self.make_fixture(directory, runs[0])
                for scenario in runs:
                    self.run_block(directory, scenario)
                log = Path(directory) / "lvm-environment.jsonl"
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertIn("vgchange", [name for name, _ in calls])
                self.assertEqual({value for _, value in calls}, {"1"}, calls)

    def test_success_pins_created_layout_and_formats_without_force(self):
        result, calls, content, mode = self.run_case("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [call for call in calls if call[0] != "sync"]
        names = [call[0] for call in calls]
        self.assertEqual(names.count("mkfs.xfs"), 1)
        self.assertNotIn("-f", next(call for call in calls if call[0] == "mkfs.xfs"))
        # The export is released in order: the VG's mapping of the device is
        # deactivated once it is shown to be this VG's, the connection is
        # disconnected, and only then is the daemon stopped.
        self.assertEqual(names[-5:], ["blockdev", "vgs", "vgchange", "maki-attach", "systemctl"])
        self.assertEqual(calls[-1], ["systemctl", "stop", "maki@demo.service"])
        self.assertEqual([call[1] for call in calls if call[0] == "maki-attach"],
                         ["nbd-connect", "nbd-disconnect"])
        self.assertNotIn("nbd-client", names)
        # Only the helper activates this VG: it is created with LVM's
        # autoactivation property off, and the new LV is still activated
        # for mkfs by plain activation, which ignores the property.
        vgcreate, = [call for call in calls if call[0] == "vgcreate"]
        self.assertIn("--setautoactivation", vgcreate)
        self.assertEqual(vgcreate[vgcreate.index("--setautoactivation") + 1], "n")
        self.assertEqual(vgcreate[-2:], ["vg_maki_demo", vgcreate[vgcreate.index("--devices") + 1]])
        lvcreate, = [call for call in calls if call[0] == "lvcreate"]
        self.assertFalse({"-an", "-aay", "--activate", "--setautoactivation"} & set(lvcreate), lvcreate)
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
                self.assertFalse({"systemctl", "maki-attach", "pvcreate", "mkfs.xfs"}
                                 & {call[0] for call in calls}, result.stderr)
                self.assertEqual(content, "preserved" if scenario == "existing-config" else None)

    def test_failures_never_reach_formatting_or_cleanup(self):
        for scenario in ["fail-maki", "fail-systemctl", "fail-maki-attach", "wrong-size",
                         "foreign-backend", "signature", "fail-wipefs", "fail-pvcreate",
                         "fail-vgcreate", "fail-lvcreate", "fail-pvs", "invalid-lv-uuid",
                         "foreign-lv", "foreign-pv", "ambiguous-pv", "replaced-backend",
                         "missing-backend"]:
            with self.subTest(scenario=scenario):
                result, calls, content, _ = self.run_case(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("mkfs.xfs", [call[0] for call in calls], result.stderr)
                self.assertNotIn("vgchange", [call[0] for call in calls])
                self.assertFalse(any(call[:2] == ["maki-attach", "nbd-disconnect"]
                                     for call in calls))
                self.assertIsNone(content)
                if scenario.startswith("fail-"):
                    self.assertIn(scenario[5:], [call[0] for call in calls], result.stderr)

    def test_formatter_failure_does_not_publish_config_or_disconnect(self):
        result, calls, content, _ = self.run_case("fail-mkfs.xfs")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mkfs.xfs", [call[0] for call in calls])
        self.assertNotIn("vgchange", [call[0] for call in calls])
        self.assertIsNone(content)

    # Where a run of the block stops once it has recorded itself (before its
    # first change to the host), and what the next run of the same block
    # does: each value says whether that next run finds an LVM mapping of
    # the device to deactivate before it disconnects.
    #
    # Stopped before the filesystem was recorded: the next run releases the
    # export and the daemon, removes the record and fails, since nothing can
    # be attached.
    UNFINISHED = {
        "fail-systemctl": False, "fail-maki-attach": False, "unacknowledged-connect": False,
        "wrong-size": False, "signature": False, "fail-wipefs": False,
        "fail-pvcreate": False, "fail-vgcreate": False, "fail-lvcreate": False,
        "fail-pvs": True, "invalid-lv-uuid": True, "foreign-pv": False,
        "ambiguous-pv": True, "fail-mkfs.xfs": True, "fail-blkid": True,
    }
    # Stopped after it: the next run finishes the bootstrap.
    FINISHED = {
        "fail-vgchange": True, "busy-disconnect": False,
        "fail-maki-attach-nbd-disconnect": False, "fail-systemctl-stop": False,
        "fail-config-sync": False,
    }
    # Stopped on something that is not this run's: the next run refuses it
    # too, and keeps the record.
    REFUSED = ["foreign-backend", "foreign-lv", "replaced-backend", "missing-backend",
               "racing-config"]
    # Stops after the LVM identities, and after the filesystem's, were read.
    LVM_READ = {"foreign-lv", "foreign-pv", "ambiguous-pv", "replaced-backend",
                "missing-backend", "fail-mkfs.xfs", "fail-blkid", "racing-config", *FINISHED}
    FS_READ = {"racing-config", *FINISHED}

    # What a stopped run says when running the block again continues from
    # its record, and only then.
    CONTINUES = "run this block again: it continues from the record"

    def release(self, mapped):
        """The commands of a run that releases the export."""
        return (["blockdev", "vgs", "vgchange"] if mapped else []) + ["maki-attach", "systemctl"]

    def assert_released(self, calls, mapped):
        calls = [call for call in calls if call[0] != "sync"]
        self.assertEqual([call[0] for call in calls], self.release(mapped), calls)
        disconnect = calls[-2]
        self.assertEqual(disconnect[:2], ["maki-attach", "nbd-disconnect"])
        # The connection is released under the identifier it was made with.
        self.assertEqual(disconnect[disconnect.index("--identifier") + 1], CONNECTION)
        self.assertEqual(calls[-1], ["systemctl", "stop", "maki@demo.service"])

    def test_a_run_that_changed_nothing_leaves_no_record(self):
        for scenario in ["existing-vg", "existing-lv", "existing-path", "existing-config",
                         "busy", "connected-zero-size", "backend-zero-size", "partition", "mounted",
                         "fail-vgs", "fail-lvs", "fail-blockdev", "fail-lsblk", "fail-maki"]:
            with self.subTest(scenario=scenario):
                runs, records, _ = self.run_again(scenario)
                (result, calls), = runs
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse({"systemctl", "maki-attach"} & {call[0] for call in calls})
                self.assertEqual(records, [(None, None)], result.stderr)

    def test_every_stop_after_the_first_change_is_recorded_and_printed(self):
        for scenario in [*self.UNFINISHED, *self.FINISHED, *self.REFUSED]:
            with self.subTest(scenario=scenario):
                runs, records, _ = self.run_again(scenario)
                (result, calls), = runs
                self.assertNotEqual(result.returncode, 0)
                record, mode = records[0]
                self.assertIsNotNone(record, result.stderr)
                self.assertEqual(mode, 0o600)
                lines = record.splitlines()
                self.assertIn(f"connection_id={CONNECTION}", lines)
                self.assertIn(f"volume_uuid={UUID}", lines)
                self.assertIn(f"boot_id={BOOT}", lines)
                # Each identity is recorded as soon as it has been read.
                for line in [f"pv_uuid={PV}", f"vg_uuid={VG}", f"lv_uuid={LV}"]:
                    self.assertEqual(line in lines, scenario in self.LVM_READ, (line, record))
                self.assertEqual(f"fs_uuid={UUID}" in lines, scenario in self.FS_READ, record)
                # The stopped run prints where its record is and what it holds,
                # and that running the block again continues from it.
                self.assertIn(RECORD, result.stderr)
                for line in lines:
                    self.assertIn(line, result.stderr)
                self.assertIn(self.CONTINUES, result.stderr)

    def test_the_next_run_releases_an_unfinished_bootstrap(self):
        _, _, expected, _ = self.run_case("success")
        for scenario, mapped in self.UNFINISHED.items():
            with self.subTest(scenario=scenario):
                runs, records, state = self.run_again(scenario, "success", "success")
                (_, first), (released, calls), (again, fresh) = runs
                self.assertNotEqual(released.returncode, 0)
                self.assert_released(calls, mapped)
                self.assertIn(RECORD, released.stderr)
                self.assertEqual(records[1], (None, None), released.stderr)
                # The removal of the record is made durable.
                self.assertEqual(calls[-1], ["sync", "/etc/maki/attach", "no record"])
                # Such a run may have formatted, or begun to: it recorded no
                # filesystem, and the export can hold one.
                self.assertIn("recorded no filesystem", released.stderr)
                self.assertNotIn("before it created the filesystem", released.stderr)
                self.assertIn("recreate", released.stderr)
                # Starting over is a new run, which refuses an export that the
                # stopped run had written to.
                if "pvcreate" in [call[0] for call in first] and scenario != "fail-pvcreate":
                    self.assertNotEqual(again.returncode, 0)
                    self.assertNotIn("pvcreate", [call[0] for call in fresh], again.stderr)
                    self.assertIsNone(state["config"][0])
                else:
                    self.assertEqual(again.returncode, 0, again.stderr)
                    self.assertIn(["maki-attach", "nbd-connect"], [call[:2] for call in fresh])
                    self.assertEqual(state["config"], (expected, 0o600))

    def test_the_next_run_finishes_a_formatted_bootstrap(self):
        _, _, expected, _ = self.run_case("success")
        for scenario, mapped in self.FINISHED.items():
            with self.subTest(scenario=scenario):
                runs, records, state = self.run_again(scenario, "success")
                (stopped, first), (finished, calls) = runs
                self.assertNotEqual(stopped.returncode, 0)
                connect, = [call for call in first if call[:2] == ["maki-attach", "nbd-connect"]]
                self.assertEqual(connect[connect.index("--identifier") + 1], CONNECTION)
                self.assertEqual(finished.returncode, 0, finished.stderr)
                # Nothing is created again: the record says what was.
                self.assert_released(calls, mapped)
                self.assertEqual(state["config"], (expected, 0o600))
                self.assertEqual(records[1], (None, None))
                self.assertIsNone(state["backend"])
                self.assertEqual(state["staged"], [])

    def test_a_disconnect_that_stays_busy_is_run_again_until_it_succeeds(self):
        _, _, expected, _ = self.run_case("success")
        runs, records, state = self.run_again("busy-disconnect", "busy-disconnect", "success")
        _, (second, calls), (third, _) = runs
        self.assertNotEqual(second.returncode, 0)
        # The disconnect is asked again, under the recorded identifier, and
        # nothing runs after it while the device still shows the connection.
        self.assertEqual([call[0] for call in calls], ["maki-attach"])
        self.assertEqual(calls[0][calls[0].index("--identifier") + 1], CONNECTION)
        self.assertEqual(records[1], records[0])
        self.assertIn(f"fs_uuid={UUID}", second.stderr)
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertEqual(state["config"], (expected, 0o600))
        self.assertEqual(records[2], (None, None))

    def test_the_next_run_refuses_what_it_cannot_attribute(self):
        # What the device shows after the stop, which the next run leaves as
        # it is: its backend identifier and its holders.
        left = {"foreign-backend": ("foreign", []), "foreign-lv": (CONNECTION, ["dm-0"]),
                "replaced-backend": ("foreign", ["dm-0"]), "missing-backend": (None, ["dm-0"]),
                "racing-config": (None, [])}
        self.assertEqual(set(left), set(self.REFUSED))
        for scenario in self.REFUSED:
            with self.subTest(scenario=scenario):
                runs, records, state = self.run_again(scenario, "success")
                (refused, calls) = runs[1]
                self.assertNotEqual(refused.returncode, 0)
                self.assertIsNotNone(records[0][0])
                self.assertEqual(records[1], records[0])
                self.assertEqual((state["backend"], state["holders"]), left[scenario])
                self.assertFalse({"vgchange", "pvcreate", "mkfs.xfs"} & {call[0] for call in calls})
                if scenario == "racing-config":
                    # A configuration that is not this run's is never replaced.
                    self.assertEqual(state["config"][0], "someone else's")
                else:
                    self.assertIsNone(state["config"][0])
                    self.assertNotIn("systemctl", [call[0] for call in calls])

    def test_the_next_run_deactivates_only_the_recorded_vg(self):
        # After the stop, a VG of the same name that this run did not create
        # is found on the device, and its mapping holds the device.
        @contextlib.contextmanager
        def replaced(root):
            (root / "sys/class/block/dm-0/dm/uuid").write_text(
                "LVM-" + OTHER_VG.replace("-", "") + LV.replace("-", ""))
            yield
        runs, records, state = self.run_again("fail-vgchange", "other-vg", between=replaced)
        (refused, calls) = runs[1]
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual([call[0] for call in calls], ["blockdev", "vgs"], refused.stderr)
        self.assertIsNotNone(records[1][0])
        self.assertEqual((state["backend"], state["holders"]), (CONNECTION, ["dm-0"]))

    def test_a_record_of_other_values_is_refused(self):
        others = {"volume": "other", "dev": "/dev/nbd1", "expected_bytes": "4294967296",
                  "block_size": "512", "vg": "vg_other", "lv": "other",
                  "mountpoint": "/srv/other", "attach_config": "/etc/maki/attach/other.toml"}
        for name, value in others.items():
            with self.subTest(name=name):
                line, = [line for line in self.program.splitlines()
                         if line.startswith(name + "=")]
                program = self.program.replace(line + "\n", f"{name}={value}\n")
                runs, records, _ = self.run_again("busy-disconnect", ("success", program))
                (refused, calls) = runs[1]
                self.assertNotEqual(refused.returncode, 0)
                self.assertEqual(calls, [])
                self.assertIn(f"was made with {name}=", refused.stderr)
                self.assertNotIn(self.CONTINUES, refused.stderr)
                self.assertEqual(records[1], records[0])

    def test_the_next_run_acts_only_on_the_vg_on_its_device(self):
        # After the stop, another disk with a VG of the same name appears; an
        # LVM command without --devices for the NBD device would act on it.
        @contextlib.contextmanager
        def other_disk(root):
            (root / "other-disk-vg").touch()
            yield
        _, _, expected, _ = self.run_case("success")
        runs, records, state = self.run_again("fail-vgchange", "success", between=other_disk)
        (finished, calls) = runs[1]
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assert_released(calls, True)
        self.assertFalse(state["other disk deactivated"])
        self.assertEqual(state["holders"], [])
        self.assertEqual(state["config"], (expected, 0o600))

    def test_a_restart_since_the_record_was_made_is_reported(self):
        # The restart ended the connection; then the device was free, or
        # another volume's attachment took it.
        def restarted(attached):
            @contextlib.contextmanager
            def between(root):
                (root / "proc/sys/kernel/random/boot_id").write_text(
                    "11111111-2222-3333-4444-555555555555\n")
                (root / "sys/block/nbd0/backend").unlink()
                (root / "connected").unlink()
                if attached:
                    (root / "sys/block/nbd0/backend").write_text("maki-" + UUID)
                yield
            return between
        _, _, expected, _ = self.run_case("success")
        for attached in (False, True):
            with self.subTest(attached=attached):
                runs, records, state = self.run_again("busy-disconnect", "success",
                                                      between=restarted(attached))
                (result, calls) = runs[1]
                self.assertIn("restarted", result.stderr)
                if attached:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(records[1], records[0])
                    self.assertEqual(state["backend"], "maki-" + UUID)
                    self.assertNotIn("systemctl", [call[0] for call in calls])
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(state["config"], (expected, 0o600))

    def test_a_value_that_would_break_the_record_is_refused_before_it(self):
        program = self.program.replace("mountpoint=/srv/demo\n",
                                       "mountpoint=$'/srv/demo\\nfs_uuid=" + UUID + "'\n")
        self.assertNotEqual(program, self.program)
        runs, records, state = self.run_again(("success", program))
        (result, calls), = runs
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mountpoint", result.stderr)
        self.assertFalse({"systemctl", "maki-attach"} & {call[0] for call in calls})
        self.assertEqual(records, [(None, None)])
        self.assertIsNone(state["config"][0])

    def test_a_record_that_cannot_be_read_is_refused_before_anything_runs(self):
        def damaged(edit):
            @contextlib.contextmanager
            def between(root):
                edit(root / RECORD)
                yield
            return between
        def rewrite(old, new):
            return lambda path: path.write_text(path.read_text().replace(old, new))
        def symlink(path):
            path.rename(path.with_name("copy"))
            path.symlink_to(path.with_name("copy"))
        def fifo(path):
            path.unlink()
            os.mkfifo(path, 0o600)
        edits = {
            "unreadable line": lambda path: path.write_text(path.read_text() + "junk\n"),
            "repeated name": lambda path: path.write_text(path.read_text() + "lv_uuid=" + LV + "\n"),
            "unknown name": lambda path: path.write_text(path.read_text() + "colour=blue\n"),
            "unterminated last line": lambda path: path.write_text(path.read_text()[:-1]),
            "empty": lambda path: path.write_text(""),
            # Each value the block writes first must be there: one that is
            # missing is refused as such, not by an unbound variable later.
            "missing volume UUID": rewrite(f"volume_uuid={UUID}\n", ""),
            "missing connection identifier": rewrite(f"connection_id={CONNECTION}\n", ""),
            "missing boot ID": rewrite(f"boot_id={BOOT}\n", ""),
            "group-readable": lambda path: path.chmod(0o640),
            "FIFO": fifo,
            "filesystem without VG UUID": rewrite(f"vg_uuid={VG}\n", ""),
            "filesystem without LV UUID": rewrite(f"lv_uuid={LV}\n", ""),
            "attach-record identifier": rewrite(f"connection_id={CONNECTION}",
                                                f"connection_id=maki-{UUID}"),
            "invalid volume UUID": rewrite(f"volume_uuid={UUID}", "volume_uuid=bad"),
            "invalid LVM UUID": rewrite(f"vg_uuid={VG}", "vg_uuid=bad"),
            "invalid filesystem UUID": rewrite(f"fs_uuid={UUID}", "fs_uuid=bad"),
            "filesystem without LVM UUIDs": rewrite(f"pv_uuid={PV}\n", ""),
            "symlink": symlink,
        }
        for name, edit in edits.items():
            with self.subTest(record=name):
                runs, records, state = self.run_again("busy-disconnect", "success",
                                                      between=damaged(edit))
                (refused, calls) = runs[1]
                self.assertNotEqual(refused.returncode, 0)
                self.assertEqual(calls, [], refused.stderr)
                self.assertIsNotNone(records[1][0])
                self.assertEqual(state["backend"], CONNECTION)
                self.assertIsNone(state["config"][0])
                # It says that it cannot continue, never that it would.
                self.assertIn("cannot be continued from", refused.stderr)
                self.assertNotIn(self.CONTINUES, refused.stderr)

    @unittest.skipUnless(os.geteuid() == 0, "giving the record another owner needs root")
    def test_a_record_another_user_owns_is_refused(self):
        @contextlib.contextmanager
        def given_away(root):
            os.chown(root / RECORD, 65534, 65534)
            yield
        runs, records, state = self.run_again("busy-disconnect", "success", between=given_away)
        (refused, calls) = runs[1]
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(calls, [], refused.stderr)
        self.assertIn("cannot be continued from", refused.stderr)
        self.assertEqual(state["backend"], CONNECTION)

    def test_a_record_of_another_owner_is_refused(self):
        # Without root the fixture cannot give the record another owner, so
        # the block expects another owner of it instead.
        program = self.program.replace(" == 0:600", f" == {os.getuid() + 1}:600")
        self.assertNotEqual(program, self.program)
        runs, records, state = self.run_again("busy-disconnect", ("success", program))
        (refused, calls) = runs[1]
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(calls, [], refused.stderr)
        self.assertIn("cannot be continued from", refused.stderr)
        self.assertEqual(records[1], records[0])
        self.assertEqual(state["backend"], CONNECTION)

    def test_the_next_run_takes_the_attach_lock_first(self):
        @contextlib.contextmanager
        def locked(root):
            with open(root / "run/maki-attach/attach.lock", "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
        runs, records, state = self.run_again("busy-disconnect", "success", between=locked)
        (refused, calls) = runs[1]
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIsNotNone(records[0][0])
        self.assertEqual(records[1], records[0])
        self.assertEqual(state["backend"], CONNECTION)
        # Another run holds the lock: this one says so, and does not present
        # the record as its own to continue from.
        self.assertIn("attach lock", refused.stderr)
        self.assertNotIn(self.CONTINUES, refused.stderr)

    def test_the_record_and_configuration_are_durable_before_they_are_relied_on(self):
        result, calls, _, _ = self.run_case("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        syncs = [call[1:] for call in calls if call[0] == "sync"]
        published = [["/etc/maki/attach/demo.bootstrap.next", "no record"],
                     ["/etc/maki/attach", "record"]]
        updated = [["/etc/maki/attach/demo.bootstrap.next", "record"],
                   ["/etc/maki/attach", "record"]]
        # Each copy of the record is synced under its staged name, then its
        # name: three copies, the first before the daemon is started. The
        # configuration and its name are synced while the record still
        # exists, and the record's removal is synced last.
        self.assertEqual(syncs, published + updated + updated + [
            ["/etc/maki/attach/demo.toml.next", "record"],
            ["/etc/maki/attach/demo.toml", "record"],
            ["/etc/maki/attach", "record"],
            ["/etc/maki/attach", "no record"],
        ])
        names = [call[0] for call in calls]
        self.assertLess(calls.index(["sync", "/etc/maki/attach", "record"]),
                        names.index("systemctl"))

    def test_leftover_staged_files_are_replaced_not_written_into(self):
        @contextlib.contextmanager
        def leftover(root):
            for name in ("demo.bootstrap.next", "demo.toml.next"):
                path = root / "etc/maki/attach" / name
                path.unlink(missing_ok=True)
                path.write_text("left by a killed run\n")
                path.chmod(0o644)
            yield
        _, _, expected, _ = self.run_case("success")
        # A run that starts with both staged names taken.
        with tempfile.TemporaryDirectory(prefix="maki-bootstrap-") as directory:
            self.make_fixture(directory, "success")
            with leftover(Path(directory)):
                result, _ = self.run_block(directory, "success")
            self.assertEqual(result.returncode, 0, result.stderr)
            content, mode = self.read_file(Path(directory) / "etc/maki/attach/demo.toml", directory)
            self.assertEqual((content, mode), (expected, 0o600))
            self.assertEqual(sorted(entry.name for entry in Path(directory, "etc/maki/attach").iterdir()),
                             ["demo.toml"])
        # A stop after the configuration was staged leaves its staged copy
        # and the mountpoint the run made; the next run accepts that
        # mountpoint and stages the configuration again.
        runs, records, state = self.run_again("fail-config-sync", "success", between=leftover)
        self.assertNotEqual(runs[0][0].returncode, 0)
        self.assertIn(f"fs_uuid={UUID}", records[0][0])
        self.assertEqual(runs[1][0].returncode, 0, runs[1][0].stderr)
        self.assertEqual(state["config"], (expected, 0o600))
        self.assertEqual(state["staged"], [])
        self.assertEqual(records[1], (None, None))

    def test_a_staged_name_taken_after_its_removal_is_never_written_through(self):
        # Each staged copy is written into a name the block has just
        # removed. Another process can take that name in between: a link
        # to a file elsewhere, or a file of its own. The write must refuse
        # both (`set -C`), never write through the link or into that file.
        for staged in ("demo.bootstrap.next", "demo.toml.next"):
            for taken in ("symlink", "file"):
                with self.subTest(staged=staged, taken=taken), \
                        tempfile.TemporaryDirectory(prefix="maki-bootstrap-") as directory:
                    root = Path(directory)
                    self.make_fixture(directory, "success")
                    victim = root / "srv/victim"
                    victim.write_text("another file\n")
                    rm = root / "bin/rm"
                    rm.write_text(RACING_RM.replace("@BASH@", shutil.which("bash")))
                    rm.chmod(0o700)
                    race = {"BOOTSTRAP_RACE_NAME": staged, "BOOTSTRAP_RACE": taken}
                    with mock.patch.dict(os.environ, race):
                        result, calls = self.run_block(directory, "success")
                    self.assertTrue((root / "raced").exists(), "the name was never removed")
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertIn("cannot overwrite existing file", result.stderr)
                    self.assertEqual(victim.read_text(), "another file\n")
                    if taken == "file":
                        self.assertEqual((root / "etc/maki/attach" / staged).read_text(),
                                         "made by another process\n")
                    self.assertFalse((root / "etc/maki/attach/demo.toml").exists())
                    if staged == "demo.bootstrap.next":
                        # The first copy: the run stops before its first
                        # change to the host, and leaves no record.
                        self.assertFalse((root / RECORD).exists())
                        self.assertFalse({"systemctl", "maki-attach"} & {call[0] for call in calls})
                    else:
                        # The record stays for the next run to continue from.
                        self.assertTrue((root / RECORD).exists())
                        self.assertIn(self.CONTINUES, result.stderr)

    def test_a_record_that_appears_during_a_fresh_run_is_never_replaced(self):
        runs, records, state = self.run_again("racing-record")
        (result, calls), = runs
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(records[0][0], "someone else's\n")
        self.assertFalse({"systemctl", "maki-attach"} & {call[0] for call in calls})
        self.assertNotIn(self.CONTINUES, result.stderr)

    def test_the_next_run_uses_only_the_mountpoint_it_made(self):
        def at_mountpoint(make):
            @contextlib.contextmanager
            def between(root):
                make(root, root / "srv/demo")
                yield
            return between
        def symlink(root, path):
            (root / "srv/elsewhere").mkdir(mode=0o755)
            path.symlink_to(root / "srv/elsewhere")
        def not_empty(root, path):
            path.mkdir(mode=0o700)
            (path / "data").touch()
        cases = {
            "symlink": symlink,
            "not empty": not_empty,
            "other mode": lambda root, path: path.mkdir(mode=0o755),
            "file": lambda root, path: path.touch(),
        }
        for name, make in cases.items():
            with self.subTest(mountpoint=name):
                with tempfile.TemporaryDirectory(prefix="maki-bootstrap-") as directory:
                    root = Path(directory)
                    self.make_fixture(directory, "busy-disconnect")
                    self.run_block(directory, "busy-disconnect")
                    make(root, root / "srv/demo")
                    elsewhere = root / "srv/elsewhere"
                    result, _ = self.run_block(directory, "success")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("mountpoint", result.stderr)
                    self.assertTrue((root / RECORD).exists())
                    self.assertFalse((root / "etc/maki/attach/demo.toml").exists())
                    if name == "symlink":
                        # What the link names is not taken over.
                        self.assertEqual(elsewhere.stat().st_mode & 0o777, 0o755)

    def test_a_configuration_symlink_is_refused_even_with_its_content(self):
        _, _, expected, _ = self.run_case("success")
        @contextlib.contextmanager
        def linked(root):
            target = root / "srv/attach.toml"
            target.write_text(expected.replace('mountpoint = "/srv/demo"',
                                               f'mountpoint = "{root}/srv/demo"'))
            (root / "etc/maki/attach/demo.toml").symlink_to(target)
            yield
        runs, records, state = self.run_again("fail-systemctl-stop", "success", between=linked)
        (refused, _) = runs[1]
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("Attach configuration already exists", refused.stderr)
        self.assertEqual(records[1], records[0])

    def test_quickstart_create_block_stops_at_each_failed_command(self):
        text = (ROOT / "docs/getting-started/quickstart.md").read_text()
        blocks = re.findall(r"```bash\n(.*?)```", text, re.S)
        block, = [block for block in blocks if "maki volume create" in block]
        commands = ["install", "create", "inspect", "check"]
        # The block runs as written, with only these programs to find: what
        # the package installs (`maki`) and what its dependencies bring
        # (`install` from coreutils, `runuser` from util-linux). A command
        # from any other package, such as sudo, is "command not found".
        with tempfile.TemporaryDirectory(prefix="maki-quickstart-") as directory:
            tools = Path(directory)
            bash = shutil.which("bash")
            for name in ("install", "maki", "runuser"):
                (tools / name).write_text(QUICKSTART_TOOL.replace("@BASH@", bash))
                (tools / name).chmod(0o700)
            for index, failed in enumerate([*commands, "none"]):
                with self.subTest(failed=failed):
                    log = tools / f"{failed}.log"
                    result = subprocess.run(
                        [bash, "-c", block], capture_output=True, text=True, timeout=5,
                        env={"PATH": directory, "FAIL_AT": failed, "TOOL_LOG": str(log)})
                    self.assertEqual(result.returncode, 0 if failed == "none" else 42, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), commands[:index + 1])
                    if index:
                        # The volume is created as the daemon user.
                        self.assertIn("runuser -u maki -- maki volume create "
                                      "/etc/maki/volumes/demo.toml", log.read_text().splitlines())

    def test_quickstart_uses_the_shared_checked_procedure(self):
        text = (ROOT / "docs/getting-started/quickstart.md").read_text()
        self.assertIn("first-volume.md#1-provision-and-record-the-layout", text)
        blocks = re.findall(r"```bash\n(.*?)```", text, re.S)
        self.assertFalse(any(re.search(r"\b(pvcreate|vgcreate|lvcreate|mkfs\.xfs)\b", block)
                             for block in blocks))


if __name__ == "__main__":
    unittest.main()
