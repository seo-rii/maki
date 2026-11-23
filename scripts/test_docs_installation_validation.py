"""Execute the Debian guide's nbd-client backport recipe against recording stubs.

Every command the recipe runs is a stub confined to a private directory, so no
package, download or host path is touched. The recipe must stop at its first
failed step, refuse a tarball that does not match the verified digest, and
install exactly the client package that its own build produced.
"""

import ast
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/getting-started/installation-debian.md"
TARBALL = b"synthetic nbd-3.27.1 release tarball\n"
STUBS = ("apt", "curl", "uupdate", "dpkg-buildpackage", "dpkg-parsechangelog", "dpkg", "mktemp")

STUB = r'''
import json, os, pathlib, sys, tempfile

name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ["RECIPE_ROOT"])
cwd = pathlib.Path.cwd()
call = {"tool": name, "args": args, "cwd": str(cwd)}


def finish(status=0, **fields):
    with open(root / "calls.jsonl", "a") as log:
        log.write(json.dumps(call | fields) + "\n")
    sys.exit(status)


if not cwd.resolve().is_relative_to(root.resolve()):
    finish(97, refused=f"{name} ran outside the fixture in {cwd}")
if os.environ.get("RECIPE_FAIL") in (name, " ".join([name, *args[:1]])):
    finish(1, failed=True)
if name == "mktemp":
    if args[:1] != ["-d"] or len(args) != 2 or not args[1].endswith("XXXXXX"):
        finish(98, refused="expected mktemp -d TEMPLATE")
    builds = root / "builds"
    builds.mkdir(exist_ok=True)
    created = tempfile.mkdtemp(prefix=pathlib.Path(args[1]).name.removesuffix("XXXXXX"), dir=builds)
    print(created)
    finish(created=created)
if name == "apt" and args == ["source", "nbd-client"]:
    (cwd / "nbd-3.24").mkdir()
if name == "curl":
    (cwd / args[-1].rsplit("/", 1)[1]).write_bytes(os.environ["RECIPE_TARBALL"].encode())
if name == "uupdate":
    if not (cwd / args[-1]).is_file():
        finish(2, refused="upstream tarball missing")
    changelog = cwd.parent / "nbd-3.27.1/debian/changelog"
    changelog.parent.mkdir(parents=True)
    changelog.write_text("nbd (1:3.27.1-1) UNRELEASED; urgency=medium\n")
if name == "dpkg-parsechangelog":
    version = (cwd / "debian/changelog").read_text().split("(", 1)[1].split(")", 1)[0]
    print(version)
if name == "dpkg" and args == ["--print-architecture"]:
    print(os.environ["RECIPE_ARCH"])
if name == "dpkg-buildpackage":
    if not (cwd / "debian/changelog").is_file():
        finish(2, refused="not a Debian source tree")
    built = []
    for package in ("nbd-client", "nbd-server"):
        built.append(cwd.parent / f"{package}_3.27.1-1_{os.environ['RECIPE_ARCH']}.deb")
        built[-1].write_bytes(f"{package} built in {cwd}\n".encode())
    finish(built=[str(path) for path in built])
finish()
'''


def backport_block():
    text = GUIDE.read_text()
    blocks = [block for block in re.findall(r"^```bash\n(.*?)^```", text, re.M | re.S)
              if "dpkg-buildpackage" in block]
    if len(blocks) != 1:
        raise AssertionError(f"expected one backport recipe in {GUIDE}, found {len(blocks)}")
    return blocks[0]


@unittest.skipUnless(shutil.which("bash") and shutil.which("sha256sum"), "requires Bash and sha256sum")
class NbdClientBackportRecipe(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        tools = self.root / "bin"
        tools.mkdir()
        for name in STUBS:
            (tools / name).write_text(f"#!{sys.executable} -I\n{STUB}")
            (tools / name).chmod(0o755)
        (tools / "sha256sum").symlink_to(shutil.which("sha256sum"))
        self.start = self.root / "start"
        self.start.mkdir()
        # Earlier builds' packages must never be installed by a new run.
        (self.root / "builds").mkdir()
        for stale in (self.root, self.root / "builds", self.start):
            (stale / "nbd-client_3.27.1-1_arm64.deb").write_text("stale package")
        self.environment = {
            "PATH": str(tools),
            "LANG": "C",
            "LC_ALL": "C",
            "RECIPE_ROOT": str(self.root),
            "RECIPE_ARCH": "arm64",
            "RECIPE_TARBALL": TARBALL.decode(),
            "NBD_TARBALL_SHA256": hashlib.sha256(TARBALL).hexdigest(),
        }

    def run_recipe(self, **overrides):
        environment = self.environment | {key: value for key, value in overrides.items() if value is not None}
        for key in [key for key, value in overrides.items() if value is None]:
            environment.pop(key, None)
        log = self.root / "calls.jsonl"
        log.unlink(missing_ok=True)
        result = subprocess.run([shutil.which("bash"), "-c", backport_block()], cwd=self.start,
                                env=environment, capture_output=True, text=True, timeout=60)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        for call in calls:
            self.assertNotIn("refused", call, f"{call}\n{result.stderr}")
        return result, calls

    @staticmethod
    def installed_packages(calls):
        return [os.path.realpath(argument) for call in calls if call["tool"] == "apt"
                for argument in call["args"] if argument.endswith(".deb")]

    def test_recipe_installs_exactly_the_client_package_it_built(self):
        directories = []
        for _ in range(2):
            result, calls = self.run_recipe()
            self.assertEqual(result.returncode, 0, result.stderr)
            created = [os.path.realpath(call["created"]) for call in calls if call["tool"] == "mktemp"]
            built = [os.path.realpath(path) for call in calls if call["tool"] == "dpkg-buildpackage"
                     for path in call["built"]]
            self.assertEqual(len(created), 1)
            client = [path for path in built if pathlib.Path(path).name.startswith("nbd-client_")]
            self.assertEqual(client, [os.path.join(created[0], "nbd-client_3.27.1-1_arm64.deb")])
            self.assertEqual(self.installed_packages(calls), client)
            directories.append(created[0])
        self.assertNotEqual(directories[0], directories[1], "each run builds in a new directory")

    def test_tarball_must_match_the_verified_digest_before_anything_is_built(self):
        for digest in (None, "", "0" * 64, hashlib.sha256(b"other tarball").hexdigest(),
                       hashlib.sha256(TARBALL).hexdigest() + "  extra"):
            with self.subTest(digest=digest):
                result, calls = self.run_recipe(NBD_TARBALL_SHA256=digest)
                self.assertNotEqual(result.returncode, 0)
                tools = [call["tool"] for call in calls]
                self.assertIn("curl", tools)
                self.assertNotIn("uupdate", tools)
                self.assertNotIn("dpkg-buildpackage", tools)
                self.assertEqual(self.installed_packages(calls), [])

    def test_a_failed_step_stops_the_recipe(self):
        for step in ("apt update", "apt build-dep", "mktemp", "apt source", "curl", "uupdate",
                     "dpkg-buildpackage", "dpkg-parsechangelog", "dpkg"):
            with self.subTest(step=step):
                result, calls = self.run_recipe(RECIPE_FAIL=step)
                self.assertNotEqual(result.returncode, 0)
                failed = [index for index, call in enumerate(calls) if call.get("failed")]
                self.assertEqual(failed, [len(calls) - 1], "nothing may run after a failed step")
                self.assertEqual(self.installed_packages(calls), [])


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
