"""The RHEL 9 installation guide must match the RPM it installs.

It quotes the spec's static Requires, installs from BaseOS and AppStream
only, never installs the nbdkit metapackage (whose SELinux module would stop
systemd from starting nbdkit), calls the RPM builder only with options it
accepts, says that RHEL 9 is not qualified, and is linked from the pages
that list installation guides.
"""

import os
import pathlib
import re
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/getting-started/installation-rhel.md"
SPEC = ROOT / "packaging/rpm/maki.spec"
BUILDER = ROOT / "packaging/rpm/build-rpm.py"
RPM_README = ROOT / "packaging/rpm/README.md"
LINKED_FROM = ("README.md", "docs/README.md", "docs/status.md", "docs/deployment/support-matrix.md")


def bash_blocks(path):
    return re.findall(r"^```bash\n(.*?)^```", path.read_text(), re.M | re.S)


def commands(path):
    """Shell commands of the bash blocks, continuation lines joined."""
    joined = [block.replace("\\\n", " ") for block in bash_blocks(path)]
    return [line.strip() for block in joined for line in block.splitlines()
            if line.strip() and not line.strip().startswith("#")]


def static_requires():
    return [line.split(":", 1)[1].strip() for line in SPEC.read_text().splitlines()
            if line.startswith("Requires:")]


class RhelInstallationGuide(unittest.TestCase):
    def test_guide_and_package_readme_quote_the_spec_static_requires(self):
        expected = ", ".join(static_requires())
        self.assertIn("nbdkit-server", expected)
        for path in (GUIDE, RPM_README):
            with self.subTest(path=path.name):
                self.assertEqual(re.findall(r"^Requires: (.+)$", path.read_text(), re.M), [expected])

    def test_packages_come_from_baseos_and_appstream_only(self):
        dnf = [command for command in commands(GUIDE) if re.match(r"(?:sudo )?dnf\b", command)]
        self.assertTrue([command for command in dnf if " install " in f" {command} "], dnf)
        for command in dnf:
            with self.subTest(command=command):
                self.assertNotRegex(command, r"--enablerepo|config-manager|copr|epel")
        self.assertNotIn("epel-release", GUIDE.read_text())

    def test_the_nbdkit_metapackage_is_never_installed(self):
        for command in commands(GUIDE):
            if re.match(r"(?:sudo )?dnf .*\binstall\b", command):
                with self.subTest(command=command):
                    self.assertNotIn("nbdkit", re.split(r"\s+", command))
        self.assertIn("nbdkit-selinux", GUIDE.read_text())

    def test_rpm_builder_calls_use_options_it_accepts(self):
        usage = subprocess.run([sys.executable, "-B", str(BUILDER), "--help"], check=True,
                               capture_output=True, text=True).stdout
        accepted = set(re.findall(r"--[a-z][a-z-]*", usage))
        for path in (GUIDE, RPM_README):
            calls = [command for command in commands(path) if "packaging/rpm/build-rpm.py" in command]
            with self.subTest(path=path.name):
                self.assertEqual(len(calls), 1, calls)
                arguments = re.sub(r"\$\([^)]*\)", "", calls[0].split("build-rpm.py", 1)[1])
                used = set(re.findall(r"(?<![\w-])--[a-z][a-z-]*", arguments))
                self.assertTrue({"--release-dir", "--version", "--architecture", "--output"} <= used)
                self.assertEqual(sorted(used - accepted), [])
                self.assertNotIn("--no-autoreq", used, "an installed package keeps its requirements")

    def test_guide_says_rhel_9_is_not_qualified(self):
        text = GUIDE.read_text()
        self.assertIn("## Status: not qualified", text)
        for missing in ("enforcing", "attach", "kernel"):
            self.assertIn(missing, text.split("## What Maki needs", 1)[0])
        matrix = (ROOT / "docs/deployment/support-matrix.md").read_text()
        rows = [line for line in matrix.splitlines() if line.startswith("| RHEL 9")]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0].split("|")[2].strip(), "Not qualified")

    def test_guide_is_linked_where_installation_guides_are_listed(self):
        for name in LINKED_FROM:
            path = ROOT / name
            target = os.path.relpath(GUIDE, path.parent).replace(os.sep, "/")
            with self.subTest(page=name):
                self.assertTrue(f"]({target})" in path.read_text(), f"{name} does not link {target}")


if __name__ == "__main__":
    unittest.main()
