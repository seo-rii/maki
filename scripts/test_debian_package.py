import hashlib
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER = ROOT / "packaging" / "debian" / "build-deb.py"


class DebianPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = pathlib.Path(self.temp.name)
        self.release = self.work / "release"
        self.release.mkdir()
        for name in ("maki", "maki-attach", "maki-check", "libmaki_nbdkit.so"):
            path = self.release / name
            path.write_bytes((f"artifact:{name}\n").encode())
            path.chmod(0o755)

    def build(self, name="maki.deb", version="0.1.0+test1"):
        output = self.work / name
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = "1789689600"
        subprocess.run(
            [
                "python3",
                str(BUILDER),
                "--release-dir",
                str(self.release),
                "--version",
                version,
                "--architecture",
                "amd64",
                "--output",
                str(output),
            ],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        return output

    def field(self, package, name):
        return subprocess.run(
            ["dpkg-deb", "--field", package, name],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def extract(self, package, name="root"):
        root = self.work / name
        subprocess.run(["dpkg-deb", "--extract", package, root], check=True)
        control = self.work / f"{name}-control"
        subprocess.run(["dpkg-deb", "--control", package, control], check=True)
        return root, control

    def test_package_owns_runtime_artifacts_but_not_live_configuration(self):
        package = self.build()
        self.assertEqual(self.field(package, "Package"), "maki")
        self.assertEqual(self.field(package, "Version"), "0.1.0+test1")
        self.assertEqual(self.field(package, "Architecture"), "amd64")
        dependencies = self.field(package, "Depends")
        self.assertIn("nbd-client (>= 1:3.27.0)", dependencies)
        for dependency in ("nbdkit", "lvm2", "xfsprogs", "systemd"):
            self.assertIn(dependency, dependencies)

        root, control = self.extract(package)
        expected = {
            "usr/bin/maki": self.release / "maki",
            "usr/bin/maki-attach": self.release / "maki-attach",
            "usr/bin/maki-check": self.release / "maki-check",
            "usr/lib/maki/maki-nbdkit.so": self.release / "libmaki_nbdkit.so",
        }
        for relative, source in expected.items():
            installed = root / relative
            self.assertEqual(installed.read_bytes(), source.read_bytes())
            self.assertTrue(installed.stat().st_mode & stat.S_IXUSR)

        for unit in ("maki@.service", "maki-attach@.service", "maki-recover@.service"):
            self.assertEqual(
                (root / "usr/lib/systemd/system" / unit).read_bytes(),
                (ROOT / "packaging/systemd" / unit).read_bytes(),
            )
        self.assertFalse((root / "etc/maki").exists())
        self.assertFalse((root / "etc/systemd/system").exists())

        postinst = (control / "postinst").read_text()
        subprocess.run(["sh", "-n", control / "postinst"], check=True)
        self.assertIn("systemd-sysusers", postinst)
        self.assertIn("systemd-tmpfiles", postinst)
        self.assertIn("daemon-reload", postinst)
        for unsafe_action in (" enable ", " start ", " restart ", " try-restart "):
            self.assertNotIn(unsafe_action, postinst)

    def test_build_is_reproducible_and_rejects_invalid_inputs(self):
        first = self.build("first.deb")
        second = self.build("second.deb")
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(digest(first), digest(second))

        (self.release / "maki-check").unlink()
        failed = subprocess.run(
            [
                "python3",
                str(BUILDER),
                "--release-dir",
                str(self.release),
                "--version",
                "0.1.0+test2",
                "--architecture",
                "amd64",
                "--output",
                str(self.work / "invalid.deb"),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("maki-check", failed.stderr)


if __name__ == "__main__":
    unittest.main()
