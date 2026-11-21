"""Documented stop procedures must wait until every unit is really stopped.

`systemctl is-active` succeeds only for `active` and `reloading`, so a loop
that waits "while is-active" ends as soon as a unit is `deactivating` (nbdkit
is still flushing, checkpointing and holding the volume lock) or `failed`
(attach cleanup left a mount or mapping behind). An offline check, a
snapshot or `rm -rf` then runs too early. Waits must poll `ActiveState`
until `inactive` and stop on `failed`.
"""

from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).parents[1]
STOP_GUIDES = [
    ROOT / "docs" / "operations.md",
    ROOT / "docs" / "getting-started" / "quickstart.md",
    ROOT / "docs" / "deployment" / "postgres.md",
]


def bash_blocks(text):
    return re.findall(r"```bash\n(.*?)```", text, flags=re.S)


class StopWaitContract(unittest.TestCase):
    @unittest.skipUnless(shutil.which("bash"), "requires Bash")
    def test_rechecks_units_while_others_stop(self):
        for path in STOP_GUIDES:
            definition = re.search(r"^wait_stopped\(\) \{.*?^\}", path.read_text(), re.M | re.S)[0]
            script = """
tick=0
sleep() { tick=1; }
systemctl() {
    case "$tick:$4" in
        0:first) echo inactive ;;
        0:second) echo deactivating ;;
        1:first) echo failed ;;
        1:second) echo inactive ;;
    esac
}
""" + definition + "\nwait_stopped first second"
            with self.subTest(path=path):
                self.assertEqual(subprocess.run(["bash", "-c", script], capture_output=True,
                                                timeout=5).returncode, 1)

    def test_no_guide_waits_while_is_active(self):
        for path in [*STOP_GUIDES, *sorted((ROOT / "docs").rglob("*.md"))]:
            if "qualification" in path.parts:
                continue
            for block in bash_blocks(path.read_text()):
                self.assertNotRegex(
                    block,
                    r"while\s+systemctl\s+is-active",
                    f"{path.relative_to(ROOT)} waits while is-active",
                )

    def test_stop_guides_wait_for_inactive_and_stop_on_failed(self):
        for path in STOP_GUIDES:
            blocks = "\n".join(bash_blocks(path.read_text()))
            name = path.relative_to(ROOT)
            self.assertIn("systemctl show -P ActiveState", blocks, name)
            self.assertIn('!= inactive', blocks, name)
            self.assertIn('= failed', blocks, name)


if __name__ == "__main__":
    unittest.main()
