import hashlib
import os
import pathlib
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER = ROOT / "packaging" / "debian" / "build-deb.py"
RELEASE_NAMES = ("maki", "maki-attach", "maki-check", "libmaki_nbdkit.so")

ET_EXEC = 2
ET_DYN = 3
EM_386 = 0x03
EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7


def elf_stub(machine, e_type, elf_class=64, endian="little"):
    """A minimal ELF header (no sections) with the given identity fields."""
    order = "<" if endian == "little" else ">"
    ident = b"\x7fELF" + bytes([2 if elf_class == 64 else 1, 1 if endian == "little" else 2, 1, 0])
    ident += b"\0" * 8
    if elf_class == 64:
        header = struct.pack(
            f"{order}HHIQQQIHHHHHH",
            e_type, machine, 1, 0x1000, 0, 0, 0, 64, 56, 0, 64, 0, 0,
        )
    else:
        header = struct.pack(
            f"{order}HHIIIIIHHHHHH",
            e_type, machine, 1, 0x1000, 0, 0, 0, 52, 32, 0, 40, 0, 0,
        )
    return ident + header


def fake_systemctl(path, active_units=()):
    """A stand-in `systemctl` whose `list-units` prints the given unit names."""
    lines = "".join(f"echo '{unit} loaded active running Maki fixture'\n" for unit in active_units)
    path.write_text("#!/bin/sh\n" + lines + "exit 0\n")
    path.chmod(0o755)
    return path


class DebianPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = pathlib.Path(self.temp.name)
        self.release = self.work / "release"
        self.release.mkdir()
        self.write_release_files()

    def write_release_files(self, machine=EM_X86_64, elf_class=64, endian="little"):
        # Release artifacts are ELF images; the builder must check them
        # against the requested Debian architecture (R4-007).
        for name in RELEASE_NAMES:
            e_type = ET_DYN if name.endswith(".so") else ET_EXEC
            path = self.release / name
            path.write_bytes(
                elf_stub(machine, e_type, elf_class, endian) + f"artifact:{name}\n".encode()
            )
            path.chmod(0o755)

    def builder_command(self, name, version, architecture="amd64", extra=()):
        output = self.work / name
        return output, [
            "python3",
            str(BUILDER),
            "--release-dir",
            str(self.release),
            "--version",
            version,
            "--architecture",
            architecture,
            "--output",
            str(output),
            *extra,
        ]

    def build(self, name="maki.deb", version="0.1.0+test1", umask=None, architecture="amd64"):
        output, command = self.builder_command(name, version, architecture)
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = "1789689600"
        subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            preexec_fn=(lambda: os.umask(umask)) if umask is not None else None,
        )
        return output

    def build_failure(self, name, architecture="amd64", extra=()):
        _, command = self.builder_command(name, "0.1.0+test9", architecture, extra)
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.work / name).exists(), "a refused build must leave no package")
        return result.stderr

    def run_prerm(self, control, action, state_dir, systemctl, extra_args=()):
        environment = os.environ.copy()
        environment["MAKI_ATTACH_STATE_DIR"] = str(state_dir)
        environment["MAKI_SYSTEMCTL"] = str(systemctl)
        return subprocess.run(
            ["sh", str(control / "prerm"), action, *extra_args],
            env=environment,
            capture_output=True,
            text=True,
        )

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
        # No maintainer script may start, stop or restart a volume: the
        # operator owns the lifecycle (drain, then stop the target).
        for script in ("preinst", "postinst", "prerm", "postrm"):
            path = control / script
            if not path.exists():
                continue
            subprocess.run(["sh", "-n", path], check=True)
            text = path.read_text()
            for unsafe_action in (" enable ", " start ", " stop ", " restart ", " try-restart "):
                self.assertNotIn(unsafe_action, text, f"{script} must not run systemctl{unsafe_action}")

    # --- R4-003: removal must not orphan a live attachment -----------------

    def test_prerm_refuses_removal_while_a_volume_is_attached(self):
        package = self.build()
        _, control = self.extract(package, "prerm-record")
        self.assertTrue((control / "prerm").exists(), "the package needs a prerm script")
        self.assertTrue((control / "prerm").stat().st_mode & stat.S_IXUSR)

        state = self.work / "state"
        state.mkdir()
        (state / "pg.nbd").write_text("{}")
        idle_systemctl = fake_systemctl(self.work / "systemctl-idle")
        result = self.run_prerm(control, "remove", state, idle_systemctl)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("pg", result.stderr)
        self.assertIn("maki-workload@", result.stderr, "the message must name the stop procedure")

    def test_prerm_refuses_removal_while_a_maki_unit_is_active(self):
        package = self.build()
        _, control = self.extract(package, "prerm-unit")
        state = self.work / "state-empty"
        state.mkdir()
        busy_systemctl = fake_systemctl(self.work / "systemctl-busy", ["maki@pg.service"])
        result = self.run_prerm(control, "remove", state, busy_systemctl)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("maki@pg.service", result.stderr)

    def test_prerm_allows_idle_removal_and_never_blocks_an_upgrade(self):
        package = self.build()
        _, control = self.extract(package, "prerm-idle")
        idle_systemctl = fake_systemctl(self.work / "systemctl-idle2")
        busy_systemctl = fake_systemctl(self.work / "systemctl-busy2", ["maki-attach@pg.service"])

        empty = self.work / "state-idle"
        empty.mkdir()
        self.assertEqual(self.run_prerm(control, "remove", empty, idle_systemctl).returncode, 0)
        missing = self.work / "state-missing"
        self.assertEqual(self.run_prerm(control, "remove", missing, idle_systemctl).returncode, 0)

        # An upgrade keeps attachments running; the old helper detaches them
        # only through the operator's own maintenance procedure.
        busy = self.work / "state-busy"
        busy.mkdir()
        (busy / "pg.nbd").write_text("{}")
        upgrade = self.run_prerm(control, "upgrade", busy, busy_systemctl, ["0.1.0+next"])
        self.assertEqual(upgrade.returncode, 0, upgrade.stderr)
        self.assertEqual(
            self.run_prerm(control, "failed-upgrade", busy, busy_systemctl, ["0.1.0+next"]).returncode,
            0,
        )

    # --- R4-007: release artifacts must match the declared architecture ---

    def test_package_architecture_must_match_the_elf_binaries(self):
        # Reproduction: x86-64 artifacts requested as an arm64 package used
        # to build successfully.
        stderr = self.build_failure("wrong-arch.deb", architecture="arm64")
        self.assertIn("arm64", stderr)
        self.assertIn("x86-64", stderr.replace("x86_64", "x86-64").replace("amd64", "x86-64"))

        self.write_release_files(machine=EM_AARCH64)
        aarch64 = self.build("arm64.deb", architecture="arm64")
        self.assertEqual(self.field(aarch64, "Architecture"), "arm64")
        self.build_failure("aarch64-as-amd64.deb", architecture="amd64")

        self.write_release_files(machine=EM_386, elf_class=32)
        self.build_failure("i386-as-amd64.deb", architecture="amd64")
        i386 = self.build("i386.deb", architecture="i386")
        self.assertEqual(self.field(i386, "Architecture"), "i386")

    def test_release_files_must_be_elf_images_of_the_right_kind(self):
        (self.release / "maki-check").write_bytes(b"#!/bin/sh\necho not a binary\n")
        stderr = self.build_failure("text.deb")
        self.assertIn("maki-check", stderr)
        self.assertIn("ELF", stderr)

        self.write_release_files()
        (self.release / "libmaki_nbdkit.so").write_bytes(elf_stub(EM_X86_64, ET_EXEC))
        stderr = self.build_failure("exec-so.deb")
        self.assertIn("libmaki_nbdkit.so", stderr)
        self.assertIn("shared object", stderr)

        self.write_release_files()
        (self.release / "maki").write_bytes(elf_stub(EM_X86_64, e_type=1))  # ET_REL
        stderr = self.build_failure("rel-bin.deb")
        self.assertIn("maki", stderr)

    def test_unknown_debian_architecture_is_refused_before_building(self):
        stderr = self.build_failure("unknown-arch.deb", architecture="vax")
        self.assertIn("vax", stderr)

    @unittest.skipUnless(shutil.which("dpkg-shlibdeps"), "dpkg-shlibdeps unavailable")
    def test_shlibdeps_option_fails_closed_on_artifacts_it_cannot_analyse(self):
        # Header-only stubs have no dynamic section: the dependency scan
        # must fail the build rather than emit a package with a guessed
        # Depends line.
        stderr = self.build_failure("shlibdeps.deb", extra=["--shlibdeps"])
        self.assertIn("dpkg-shlibdeps", stderr)

    def test_build_is_reproducible_and_rejects_invalid_inputs(self):
        first = self.build("first.deb")
        second = self.build("second.deb")
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(digest(first), digest(second))

        (self.release / "maki-check").unlink()
        stderr = self.build_failure("invalid.deb")
        self.assertIn("maki-check", stderr)

    def test_build_succeeds_with_restrictive_caller_umask(self):
        package = self.build(umask=0o077)
        root, control = self.extract(package, "restrictive-umask")

        for directory in [root, control, *root.rglob("*"), *control.rglob("*")]:
            if directory.is_dir():
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)


if __name__ == "__main__":
    unittest.main()
