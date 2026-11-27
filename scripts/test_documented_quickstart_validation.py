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
        for block in ("a && b && c", "a\nb || c", "f() {\n  a || return 1\n  b\n}\nc && d",
                      "{ findmnt /srv/demo || echo unmounted; }",
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

    def test_lists_inside_compound_commands_groups_and_functions_are_not_seen(self):
        # A known gap: Bash prints these bodies deeper than the block's
        # level, which the check does not read, so it accepts them although
        # set -e does not stop at their failure and the program goes on. Nor
        # does it refuse set -e's other exemptions, a negated or a background
        # command. What the guides hold there is pinned below.
        for block in ("{\n  false && true\n  echo inner\n}\ntouch after",
                      "if true; then\n  false && true\n  echo inner\nfi\ntouch after",
                      "for i in 1; do\n  false && true\n  echo inner\ndone\ntouch after",
                      "f() {\n  false && true\n  echo inner\n}\nf\ntouch after",
                      "case x in\n x) false && true\n echo inner;;\nesac\ntouch after",
                      "! true\ntouch after", "false && true &\ntouch after"):
            with self.subTest(block=block), tempfile.TemporaryDirectory() as directory:
                program = self.driver.program([("block", block)])
                result = subprocess.run(["bash", "-c", program], cwd=directory, capture_output=True,
                                        text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((Path(directory) / "after").exists())
                self.assertIn("every documented step succeeded", result.stdout)

    def test_the_guides_lists_below_the_block_level_are_their_own_handling(self):
        # The gap above, for the guides as they are: below a block's level
        # (here-document bodies, which run in a shell of their own under
        # `set -euo pipefail`, left out) the only lists are wait_stopped's
        # returns and the unmount check's alternative. A new one must be
        # read and added here, or the block reworded.
        bash = shutil.which("bash")
        deeper = []
        for label, block in self.driver.steps():
            printed = subprocess.run(
                [bash, "--noprofile", "--norc", "-c",
                 'eval "documented_block() {\n$1\n}" && declare -f documented_block', "bash",
                 self.driver.without_heredoc_bodies(block)],
                capture_output=True, text=True, check=True, timeout=10).stdout
            deeper += [(label.split(",")[1].strip(), line.strip()) for line in printed.splitlines()
                       if line.startswith("     ") and ("&&" in line or "||" in line)]
        self.assertEqual(deeper, [
            ("7. Planned stop with a durability acknowledgement",
             'state=$(systemctl show -P ActiveState "$unit") || return 1;'),
            ("7. Planned stop with a durability acknowledgement", '[ -n "$pending" ] || return 0;'),
            ("7. Planned stop with a durability acknowledgement", 'findmnt /srv/demo || echo "unmounted"'),
        ])

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



if __name__ == "__main__":
    unittest.main()
