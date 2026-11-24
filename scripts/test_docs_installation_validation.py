"""The Debian guide installs Maki without nbd-client.

The privileged helper negotiates with the daemon's socket and connects the
kernel device over netlink itself, so neither the package nor the guide may
ask for nbd-client, and the guide quotes the package builder's dependencies
exactly.
"""

import ast
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/getting-started/installation-debian.md"


class NoNbdClient(unittest.TestCase):
    def test_no_step_of_the_guide_builds_or_installs_nbd_client(self):
        for block in re.findall(r"^```(?:bash|sh)\n(.*?)^```", GUIDE.read_text(), re.M | re.S):
            self.assertNotIn("nbd-client", block)
            self.assertNotIn("dpkg-buildpackage", block)

    def test_the_guide_says_a_source_built_nbd_client_is_no_longer_used(self):
        text = " ".join(GUIDE.read_text().split())
        self.assertNotIn("## nbd-client", GUIDE.read_text())
        self.assertIn("no longer used", text)
        self.assertIn("stay detachable", text)


class PackageDependencyQuote(unittest.TestCase):
    def test_guide_quotes_the_package_builder_static_depends(self):
        tree = ast.parse((ROOT / "packaging/debian/build-deb.py").read_text())
        static = [ast.literal_eval(node.value) for node in ast.walk(tree) if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "depends" for target in node.targets)]
        self.assertEqual(len(static), 1, "build-deb.py must assign its static Depends list once")
        quoted = re.findall(r"^Depends: (.+)$", GUIDE.read_text(), re.M)
        self.assertEqual(quoted, [", ".join(static[0])])


if __name__ == "__main__":
    unittest.main()
