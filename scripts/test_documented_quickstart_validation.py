"""CI runs the documented installation (Debian's, or RHEL's on EL9), quick
start and first-volume bootstrap as written: every block of the guides, in
order, in one root shell that stops at the first command that fails. These tests compose the program
from the guides and run its mechanics with stand-in blocks; nothing here
installs, attaches or runs as root."""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DRIVER = Path(__file__).with_name("documented_quickstart.py")
GUIDES = ROOT / "docs" / "getting-started"


def load_driver():
    spec = importlib.util.spec_from_file_location("documented_quickstart", DRIVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bash_blocks(text):
    # As the documentation tests read them.
    return re.findall(r"```bash\n(.*?)```", text, re.S)


class DocumentedSteps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()
        cls.steps = cls.driver.steps()
        cls.blocks = [block for _, block in cls.steps]

    def test_the_debian_install_steps_come_first(self):
        installation = (GUIDES / "installation-debian.md").read_text()
        section = installation.split("\n## Install the Maki package\n", 1)[1].split("\n## ", 1)[0]
        expected = bash_blocks(section)
        self.assertEqual(len(expected), 3)
        self.assertEqual(self.blocks[:3], expected)
        self.assertIn("apt install -y ./maki.deb\n", expected[0])
        self.assertIn("systemd-analyze verify maki@demo.service", expected[2])

    def test_every_quick_start_block_runs_in_order_with_the_bootstrap_at_step_4(self):
        quickstart = bash_blocks((GUIDES / "quickstart.md").read_text())
        self.assertGreaterEqual(len(quickstart), 9)
        self.assertEqual(self.blocks[3:], quickstart[:3] + [self.blocks[6]] + quickstart[3:])
        labels = [label for label, _ in self.steps]
        self.assertEqual(labels[6], "quickstart.md, 4. Provision LVM and XFS on the export: "
                                    "first-volume.md, 1. Provision and record the layout")
        self.assertTrue(labels[5].startswith("quickstart.md, 3. Create the volume, block 1"))
        self.assertTrue(labels[7].startswith("quickstart.md, 5. Review the attach configuration"))
        self.assertTrue(labels[-1].startswith("quickstart.md, 9. Clean up"))

    def test_the_bootstrap_is_the_block_the_provisioning_tests_run(self):
        text = (GUIDES / "first-volume.md").read_text()
        program = re.search(r"bash <<'BASH'\n(.*?)\nBASH\n", text, re.S).group(1)
        self.assertEqual(self.blocks[6], f"bash <<'BASH'\n{program}\nBASH\n")

    def test_the_volume_configuration_is_the_quick_starts(self):
        text = (GUIDES / "quickstart.md").read_text()
        [toml] = re.findall(r"```toml\n(.*?)```", text, re.S)
        self.assertEqual(self.driver.configuration(), toml)
        # Step 2 installs it from the directory the program runs in.
        self.assertIn("install -m 0640 -o root -g maki demo.toml /etc/maki/volumes/demo.toml\n",
                      self.blocks[4])

    @unittest.skipUnless(shutil.which("bash"), "the writer reads each block with Bash")
    def test_the_program_holds_each_block_verbatim_in_order(self):
        program = self.driver.program(self.steps)
        position = 0
        for label, block in self.steps:
            with self.subTest(label=label):
                found = program.find(block, position)
                self.assertGreaterEqual(found, position, "missing or out of order")
                position = found + len(block)

    def test_a_guide_without_its_steps_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            guides = Path(directory)
            for name in ("installation-debian.md", "quickstart.md", "first-volume.md"):
                shutil.copyfile(GUIDES / name, guides / name)
            quickstart = guides / "quickstart.md"
            text = quickstart.read_text()
            with mock.patch.multiple(self.driver, INSTALLATION=guides / "installation-debian.md",
                                              QUICKSTART=quickstart,
                                              FIRST_VOLUME=guides / "first-volume.md"):
                self.assertEqual(len(self.driver.steps()), len(self.steps))
                quickstart.write_text(text.replace("## 4. Provision LVM and XFS on the export",
                                                   "## 4. Provision the export"))
                with self.assertRaisesRegex(ValueError, "no section"):
                    self.driver.steps()
                quickstart.write_text(text.replace("## 4. Provision LVM and XFS on the export\n",
                                                   "## 4. Provision LVM and XFS on the export\n\n"
                                                   "```bash\ntrue\n```\n"))
                with self.assertRaisesRegex(ValueError, "block of its own"):
                    self.driver.steps()
                quickstart.write_text(text.replace("```toml", "```text"))
                with self.assertRaisesRegex(ValueError, "0 toml blocks"):
                    self.driver.configuration()

    @unittest.skipUnless(shutil.which("bash"), "the writer reads each block with Bash")
    def test_the_files_are_written_once(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "quickstart"
            with mock.patch("builtins.print"):
                self.assertEqual(self.driver.main([str(target)]), 0)
            self.assertEqual((target / "demo.toml").read_text(), self.driver.configuration())
            self.assertEqual((target / "quickstart.sh").read_text(), self.driver.program(self.steps))
        # What an earlier run left is evidence of that run: neither file is
        # ever replaced.
        for name in ("demo.toml", "quickstart.sh"):
            with self.subTest(existing=name), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)
                (target / name).write_text("an earlier run's\n")
                with self.assertRaises(FileExistsError), mock.patch("builtins.print"):
                    self.driver.main([str(target)])
                self.assertEqual((target / name).read_text(), "an earlier run's\n")


class RhelInstallation(unittest.TestCase):
    """On EL9 the RHEL 9 guide's repository and install steps come first; it
    sends its reader on to the same quick start."""

    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()

    def test_the_rhel_host_steps_come_first_and_then_the_same_quick_start(self):
        guide = (GUIDES / "installation-rhel.md").read_text()
        repositories = guide.split("\n## Repositories\n", 1)[1].split("\n## ", 1)[0]
        install = guide.split("\n## Install the Maki package\n", 1)[1].split("\n## ", 1)[0]
        expected = bash_blocks(repositories) + bash_blocks(install)
        self.assertEqual(len(expected), 4)
        self.assertIn("dnf repolist", expected[0])
        self.assertIn("dnf install -y ./maki.rpm\n", expected[1])
        self.assertIn("systemd-analyze verify maki@demo.service", expected[3])
        # Building the package is the build host's: not a step on the target.
        self.assertNotIn("build-rpm.py", "".join(expected))
        rhel = self.driver.steps("rhel")
        debian = self.driver.steps()
        self.assertEqual([block for _, block in rhel[:4]], expected)
        self.assertEqual(rhel[4:], debian[3:])
        self.assertEqual([label for label, _ in rhel[:4]],
                         ["installation-rhel.md, Repositories, block 1",
                          "installation-rhel.md, Install the Maki package, block 1",
                          "installation-rhel.md, Install the Maki package, block 2",
                          "installation-rhel.md, Install the Maki package, block 3"])
        self.assertEqual(self.driver.steps("debian"), debian)

    @unittest.skipUnless(shutil.which("bash"), "the writer reads each block with Bash")
    def test_the_program_names_the_package_its_install_step_installs(self):
        for installation, package in (("debian", "maki.deb"), ("rhel", "maki.rpm")):
            with self.subTest(installation=installation):
                program = self.driver.program(self.driver.steps(installation), installation)
                self.assertIn(f"# in the directory that holds {package} and demo.toml", program)
                self.assertIn(f"./{package}\n", program)

    @unittest.skipUnless(shutil.which("bash"), "the writer reads each block with Bash")
    def test_main_writes_the_rhel_program_when_asked(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "quickstart"
            with mock.patch("builtins.print"):
                self.assertEqual(self.driver.main(["--installation", "rhel", str(target)]), 0)
            self.assertEqual((target / "quickstart.sh").read_text(),
                             self.driver.program(self.driver.steps("rhel"), "rhel"))
            self.assertEqual((target / "demo.toml").read_text(), self.driver.configuration())

    @unittest.skipUnless(shutil.which("bash"), "the program runs in Bash")
    def test_the_install_step_stops_the_program_only_when_the_selinux_module_is_installed(self):
        # The block's status is the program's verdict on it: the module check
        # must succeed while nbdkit-selinux is absent, as the guide expects,
        # and fail if it is installed.
        label, block = self.driver.steps("rhel")[1]
        self.assertIn("rpm -q nbdkit-selinux", block)
        for installed in (False, True):
            with self.subTest(installed=installed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / "bin"
                binary.mkdir()
                (binary / "dnf").write_text("#!/bin/sh\nexit 0\n")
                if installed:
                    rpm = "#!/bin/sh\necho nbdkit-selinux-1.38.5-5.el9.noarch\nexit 0\n"
                else:
                    rpm = "#!/bin/sh\necho \"package $2 is not installed\"\nexit 1\n"
                (binary / "rpm").write_text(rpm)
                for name in ("dnf", "rpm"):
                    (binary / name).chmod(0o700)
                program = self.driver.program([(label, block), ("after", "touch after")], "rhel")
                result = subprocess.run(["bash", "-c", program], cwd=root, capture_output=True, text=True,
                                        env=dict(os.environ, PATH=f"{binary}{os.pathsep}{os.environ['PATH']}"),
                                        timeout=10)
                self.assertEqual(result.returncode == 0, not installed, result.stdout + result.stderr)
                self.assertEqual((root / "after").exists(), not installed)


@unittest.skipUnless(shutil.which("bash"), "requires Bash")
class UnguardedLists(unittest.TestCase):
    """set -e does not stop at a failed command in an && or || list that is
    not the last of its block, and the block's status is its last command's:
    the program would go on. The writer refuses && or || text at a block's
    own level before its last command, read from Bash's printing of the
    block (declare -f); a change of that layout shows here."""

    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()

    def test_a_list_before_the_last_command_is_refused(self):
        for block in ("false && true\ntouch after", "false || false\ntouch after",
                      "true\na && b; c", "{ a; } && b\nc",
                      # Inside a subshell set -e does not stop at it either.
                      "(\nset -e\na && b\nc\n)\nd"):
            with self.subTest(block=block):
                with self.assertRaises(ValueError) as raised:
                    self.driver.program([("block one", "true"), ("block two", block)])
                self.assertIn("block two has && or || at its own level before its last command",
                              str(raised.exception))

    def test_a_block_bash_cannot_read_is_refused_before_anything_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ran"
            for block in ("}\ntouch " + str(marker), "if true; then"):
                with self.subTest(block=block):
                    with self.assertRaisesRegex(ValueError, "Bash cannot read block two"):
                        self.driver.program([("block two", block)])
            self.assertFalse(marker.exists())

    def test_lists_that_end_their_block_or_never_run_at_its_level_are_accepted(self):
        for block in ("a && b && c", "a\nb || c", "f() {\n  a\n  b\n}\nc && d",
                      "bash <<'BASH'\na && b\nc || d\nBASH",
                      "python3 - <<PY\nx = 1 if a and b else 2\nPY\nok",
                      "if a; then\n  b\nfi\nc"):
            with self.subTest(block=block):
                self.driver.program([("block", block)])

    def test_any_list_text_at_the_blocks_level_before_its_last_command_is_refused(self):
        # The check matches && and || as text on the lines Bash prints at
        # the block's level: a condition, a test expression, quoted text or
        # a command substitution there is refused too, though set -e would
        # see its failure or there is none.
        for block in ("if a && b; then\n  c\nfi\nd", "while a || b; do\n  c\ndone\nd",
                      "[[ -n $x && -n $y ]] || exit 1\nd", "echo 'a && b'\nd", "x=$(a || b)\nd",
                      "false | cat && true\ntouch after"):
            with self.subTest(block=block):
                with self.assertRaises(ValueError):
                    self.driver.program([("block", block)])

    # Lists that Bash prints below a block's level: in the bodies of
    # compound commands, brace groups and functions. set -e does not stop at
    # their failure there either, and the program would go on.
    DEEPER = ("{\n  false && true\n  echo inner\n}\ntouch after",
              "if true; then\n  false && true\n  echo inner\nfi\ntouch after",
              "for i in 1; do\n  false && true\n  echo inner\ndone\ntouch after",
              "while true; do\n  false || break\ndone\ntouch after",
              "f() {\n  false && true\n  echo inner\n}\nf\ntouch after",
              "f() {\n  a || return 1\n  b\n}\nc && d",
              "case x in\n x) false && true\n echo inner;;\nesac\ntouch after",
              "{ findmnt /srv/demo || echo unmounted; }",
              "(\n  if a; then\n    b && c\n  fi\n  d\n)\ne")

    def test_lists_below_the_blocks_level_are_refused_at_every_depth(self):
        for block in self.DEEPER:
            with self.subTest(block=block):
                with self.assertRaises(ValueError) as raised:
                    self.driver.program([("block one", "true"), ("block two", block)])
                self.assertIn("block two has && or || below its own level", str(raised.exception))

    def test_only_the_lists_read_for_a_block_are_accepted_below_its_level(self):
        # An entry of the allow-list holds for its own block, by its label,
        # and for nothing else: the same text in another block is refused,
        # and so is another list beside it in its own.
        (label, line), *_ = sorted(self.driver.DEEPER_LISTS)
        _, block = next(step for step in self.driver.steps() if step[0] == label)
        self.driver.program([(label, block)])
        with self.assertRaisesRegex(ValueError, "below its own level"):
            self.driver.program([(label.replace("block 1", "block 2"), block)])
        with self.assertRaisesRegex(ValueError, "below its own level"):
            self.driver.program([(label, "f() {\n  a && b\n  c\n}\n" + block)])

    def test_a_negated_or_a_background_command_is_not_seen(self):
        # set -e's other exemptions are a known gap: the check reads only
        # && and ||, so these are accepted and a failure there lets the
        # program go on.
        for block in ("! true\ntouch after", "false &\ntouch after"):
            with self.subTest(block=block), tempfile.TemporaryDirectory() as directory:
                program = self.driver.program([("block", block)])
                result = subprocess.run(["bash", "-c", program], cwd=directory, capture_output=True,
                                        text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((Path(directory) / "after").exists())
                self.assertIn("every documented step succeeded", result.stdout)

    def test_the_allow_list_is_the_guides_lists_below_the_block_level(self):
        # Below a block's level (here-document bodies, which run in a shell
        # of their own under `set -euo pipefail`, left out) the guides hold
        # only wait_stopped's returns and the unmount check's alternative,
        # each its own handling, and the allow-list names exactly those: a
        # new one must be read and added, or the block reworded, and one the
        # guides no longer hold must go.
        bash = shutil.which("bash")
        deeper = []
        for label, block in self.driver.steps():
            printed = subprocess.run(
                [bash, "--noprofile", "--norc", "-c",
                 'eval "documented_block() {\n$1\n}" && declare -f documented_block', "bash",
                 self.driver.without_heredoc_bodies(block)],
                capture_output=True, text=True, check=True, timeout=10).stdout
            deeper += [(label, line.strip()) for line in printed.splitlines()
                       if line.startswith("     ") and ("&&" in line or "||" in line)]
        step7 = "quickstart.md, 7. Planned stop with a durability acknowledgement, block 1"
        self.assertEqual(deeper, [
            (step7, 'state=$(systemctl show -P ActiveState "$unit") || return 1;'),
            (step7, '[ -n "$pending" ] || return 0;'),
            (step7, 'findmnt /srv/demo || echo "unmounted"'),
        ])
        self.assertEqual(self.driver.DEEPER_LISTS, set(deeper))

    def test_the_guides_have_no_unguarded_list(self):
        # The program CI runs is written from them, so this is what CI runs.
        self.driver.program(self.driver.steps())


@unittest.skipUnless(shutil.which("bash"), "requires Bash")
class ProgramMechanics(unittest.TestCase):
    """The composed program with stand-in blocks."""

    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()

    def run_program(self, blocks):
        directory = tempfile.TemporaryDirectory(prefix="maki-documented-")
        self.addCleanup(directory.cleanup)
        program = self.driver.program([(f"block {name}", block) for name, block in blocks])
        result = subprocess.run(["bash", "-c", program], cwd=directory.name, capture_output=True,
                                text=True, timeout=10)
        return result, Path(directory.name)

    def test_every_block_runs_in_one_shell(self):
        result, root = self.run_program([
            ("one", "wait_for() { touch defined; }\nexport FROM_ONE=1\n"),
            ("two", 'wait_for && test "$FROM_ONE" = 1 && touch two'),
            ("three", "(\nset -euo pipefail\ntouch three\n)"),
        ])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((root / "defined").exists() and (root / "two").exists()
                        and (root / "three").exists())
        self.assertIn("==> [1/3] block one\n", result.stdout)
        self.assertIn("==> [3/3] block three\n", result.stdout)
        self.assertTrue(result.stdout.endswith("==> every documented step succeeded\n"))
        self.assertNotIn("stopped in", result.stderr)

    def test_the_first_failure_stops_the_program_and_names_its_step(self):
        cases = {
            # An && list that ends the block: set -e does not stop at it, the
            # block's status check does.
            "chain": "true && false && touch after-chain",
            # A command before the block's last.
            "sequence": "false\ntouch after-sequence",
            # Any stage of a pipeline, before the block's last command too.
            "pipeline": "false | cat\ntouch after-pipeline",
            "subshell": "(\nset -euo pipefail\nfalse\n)",
            "heredoc": "bash <<'BASH'\nexit 4\nBASH",
        }
        for name, block in cases.items():
            with self.subTest(case=name):
                result, root = self.run_program([("before", "touch before"), (name, block),
                                                 ("after", "touch later")])
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(f"stopped in [2/3] block {name} with status", result.stderr)
                self.assertTrue((root / "before").exists())
                self.assertFalse(any(root.glob("after*")) or (root / "later").exists())
                self.assertNotIn("every documented step succeeded", result.stdout)


# A stand-in for the bootstrap block, with the guide's behaviour: a run
# without a record starts over and records the layout, then the filesystem;
# a run with a record that names no filesystem releases the export, removes
# the record and fails; one that names it finishes. The knobs make it break
# the rules the program checks.
STAND_IN_BOOTSTRAP = r"""bash <<'BASH'
set -euo pipefail
volume=demo
dev=/dev/nbd0
record=@ROOT@/demo.bootstrap
echo run >> @ROOT@/log
if [[ -e $record ]]; then
    if ! grep -q '^fs_uuid=' "$record"; then
        [[ -n ${KEEP_RECORD:-} ]] || rm "$record"
        [[ -n ${KEEP_BACKEND:-} ]] || rm -f @ROOT@/sys/block/nbd0/backend
        echo released >> @ROOT@/log
        [[ -n ${RELEASE_SUCCEEDS:-} ]] && exit 0
        exit 1
    fi
else
    printf 'pv_uuid=1\n' > "$record"
    echo maki-bootstrap-1 > @ROOT@/sys/block/nbd0/backend
    if ! mkfs.xfs; then
        [[ -z ${NO_RECORD:-} ]] || rm "$record"
        [[ -n ${NO_STOP:-} ]] || exit 1
    fi
    printf 'fs_uuid=2\n' >> "$record"
fi
if ! vgchange; then
    [[ -n ${NO_STOP:-} ]] || exit 1
fi
rm -f "$record" @ROOT@/sys/block/nbd0/backend
echo created >> @ROOT@/log
BASH
"""
FAKE_TOOL = """#!/bin/sh
echo "${0##*/} $*" >> "$FIXTURE/log"
if [ "${0##*/}" = systemctl ]; then echo "${SYSTEMCTL_STATE:-inactive}"; fi
"""


@unittest.skipUnless(shutil.which("bash"), "requires Bash")
class StoppedBootstrap(unittest.TestCase):
    """--stop-once: the bootstrap's first run stops where a shim on PATH
    fails one command, and the same block runs again, as the first-volume
    guide's recovery notes say, before the rest of the quick start."""

    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()
        cls.steps = cls.driver.steps()
        cls.bootstrap = cls.steps[6][1]
        cls.creation = cls.steps[5][1]

    def test_the_bootstraps_values_and_the_guides_reset_are_read(self):
        self.assertEqual(self.driver.bootstrap_values(self.bootstrap),
                         {"volume": "demo", "dev": "/dev/nbd0",
                          "record": "/etc/maki/attach/demo.bootstrap"})
        self.assertEqual(self.driver.recovery_reset(), ("/var/lib/maki/demo", "maki@demo.service"))
        with tempfile.TemporaryDirectory() as directory:
            guide = Path(directory) / "first-volume.md"
            guide.write_text((GUIDES / "first-volume.md").read_text().replace(
                "remove `/var/lib/maki/demo`", "delete `/var/lib/maki/demo`"))
            with mock.patch.object(self.driver, "FIRST_VOLUME", guide), \
                    self.assertRaisesRegex(ValueError, "reset"):
                self.driver.recovery_reset()

    def test_the_bootstrap_runs_again_as_the_recovery_notes_say(self):
        for command, runs in (("mkfs.xfs", 3), ("vgchange", 2)):
            with self.subTest(command=command):
                program = self.driver.program(self.steps, stop_once=command)
                labels = re.findall(r"(?m)^step='\[\d+/\d+\] (.*)'$", program)
                self.assertEqual(len(labels), len(self.steps) + (runs - 1) + (2 if runs == 3 else 0))
                provision = self.driver.QUICKSTART.name + ", " + self.driver.PROVISION_STEP
                bootstrap_label = next(label for label, _ in self.steps if label.startswith(provision))
                expected = [f"{bootstrap_label} (run 1 of {runs}: {command} fails)",
                            f"{bootstrap_label} (run 2 of {runs}: continues from the record)"]
                if runs == 3:
                    expected += ["first-volume.md, Recovering from a failed bootstrap: remove "
                                 "/var/lib/maki/demo while maki@demo.service is stopped",
                                 self.steps[5][0] + " (again)", f"{bootstrap_label} (run 3 of 3)"]
                start = labels.index(expected[0])
                self.assertEqual(labels[start:start + len(expected)], expected)
                self.assertEqual(labels[:start], [label for label, _ in self.steps[:6]])
                self.assertEqual(labels[start + len(expected):], [label for label, _ in self.steps[7:]])
                # Each run is the block itself, and the creation block runs
                # again only after the reset.
                self.assertEqual(program.count(self.bootstrap), runs)
                self.assertEqual(program.count(self.creation), 2 if runs == 3 else 1)
                # Only the first run has the shim on its PATH.
                self.assertEqual(program.count('export PATH="$documented_shim:$PATH"'), 1)
                shim = program.index('export PATH="$documented_shim:$PATH"')
                self.assertLess(shim, program.index(self.bootstrap))
                self.assertLess(program.index('export PATH="$documented_path"'),
                                program.index(self.bootstrap, program.index(self.bootstrap) + 1))
                self.assertEqual("rm -rf -- /var/lib/maki/demo\n" in program, runs == 3)

    def run_stopped(self, command, **environment):
        directory = tempfile.TemporaryDirectory(prefix="maki-stopped-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "sys/block/nbd0").mkdir(parents=True)
        (root / "var/lib/maki/demo").mkdir(parents=True)
        (root / "bin").mkdir()
        for name in ("mkfs.xfs", "vgchange", "systemctl"):
            (root / "bin" / name).write_text(FAKE_TOOL)
            (root / "bin" / name).chmod(0o700)
        found = [(self.steps[5][0], "echo create >> " + str(root / "log")),
                 (self.steps[6][0], STAND_IN_BOOTSTRAP.replace("@ROOT@", str(root))),
                 ("after", "echo after >> " + str(root / "log"))]
        with mock.patch.object(self.driver, "SYSFS", str(root / "sys/block")), \
                mock.patch.object(self.driver, "recovery_reset",
                                  lambda: (str(root / "var/lib/maki/demo"), "maki@demo.service")):
            program = self.driver.program(found, stop_once=command)
        env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                   FIXTURE=str(root), **environment)
        result = subprocess.run(["bash", "-c", program], cwd=root, env=env, capture_output=True,
                                text=True, timeout=20)
        log = (root / "log").read_text().splitlines() if (root / "log").exists() else []
        return result, log, root

    def test_a_stop_before_the_filesystem_is_released_reset_and_started_over(self):
        result, log, root = self.run_stopped("mkfs.xfs")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(log, ["create", "run", "run", "released", "systemctl show -P ActiveState "
                               "maki@demo.service", "systemctl show -P ActiveState maki@demo.service",
                               "create", "run", "mkfs.xfs ", "vgchange ", "created", "after"])
        self.assertFalse((root / "var/lib/maki/demo").exists())
        self.assertIn("mkfs.xfs: failed once by documented_quickstart.py", result.stderr)
        self.assertIn("pv_uuid=1", result.stdout)
        self.assertIn("every documented step succeeded", result.stdout)

    def test_a_stop_after_the_filesystem_is_finished_by_the_next_run(self):
        result, log, root = self.run_stopped("vgchange")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(log, ["create", "run", "mkfs.xfs ", "run", "vgchange ", "created", "after"])
        self.assertTrue((root / "var/lib/maki/demo").exists())
        self.assertIn("vgchange: failed once by documented_quickstart.py", result.stderr)
        self.assertIn("fs_uuid=2", result.stdout)

    def test_a_run_that_breaks_the_recovery_notes_stops_the_program(self):
        cases = {
            ("mkfs.xfs", "NO_STOP"): "the bootstrap did not stop where mkfs.xfs failed",
            ("vgchange", "NO_STOP"): "the bootstrap did not stop where vgchange failed",
            ("mkfs.xfs", "NO_RECORD"): "the stopped bootstrap left no record",
            ("mkfs.xfs", "RELEASE_SUCCEEDS"): "must fail once it has released the export",
            ("mkfs.xfs", "KEEP_RECORD"): "kept its record",
            ("mkfs.xfs", "KEEP_BACKEND"): "still shows the connection maki-bootstrap-1",
            ("mkfs.xfs", "SYSTEMCTL_STATE"): "maki@demo.service is active, not stopped",
        }
        for (command, knob), message in cases.items():
            with self.subTest(command=command, knob=knob):
                result, log, root = self.run_stopped(
                    command, **{knob: "active" if knob == "SYSTEMCTL_STATE" else "1"})
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message, result.stderr)
                self.assertIn("stopped in [", result.stderr)
                self.assertNotIn("after", log)
                self.assertNotIn("every documented step succeeded", result.stdout)
                # Each stops before the reset: nothing is removed.
                self.assertTrue((root / "var/lib/maki/demo").exists())

    def test_the_writer_takes_the_command_to_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "stopped"
            with mock.patch("builtins.print"):
                self.assertEqual(self.driver.main(["--stop-once", "mkfs.xfs", str(target)]), 0)
            self.assertEqual((target / "quickstart.sh").read_text(),
                             self.driver.program(self.steps, stop_once="mkfs.xfs"))
            with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
                self.driver.main(["--stop-once", "lvcreate", str(Path(directory) / "other")])



if __name__ == "__main__":
    unittest.main()
