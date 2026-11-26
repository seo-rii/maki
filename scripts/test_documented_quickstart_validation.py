"""CI runs the documented installation, quick start and first-volume
bootstrap as written: every block of the guides, in order, in one root shell
that stops at the first command that fails. These tests compose the program
from the guides and run its mechanics with stand-in blocks; nothing here
installs, attaches or runs as root."""
import importlib.util
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
            # Inside an && list, which set -e does not stop.
            "chain": "true && false && touch after-chain",
            # A command before the block's last.
            "sequence": "false\ntouch after-sequence",
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
