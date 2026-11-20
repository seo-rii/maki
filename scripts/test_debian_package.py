import gzip
import hashlib
import os
import pathlib
import re
import runpy
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
EM_ARM = 0x28
DF_1_PIE = 0x08000000


def elf_stub(machine, e_type, elf_class=64, endian="little", e_flags=0):
    """A minimal ELF header (no sections) with the given identity fields."""
    order = "<" if endian == "little" else ">"
    ident = b"\x7fELF" + bytes([2 if elf_class == 64 else 1, 1 if endian == "little" else 2, 1, 0])
    ident += b"\0" * 8
    if elf_class == 64:
        header = struct.pack(
            f"{order}HHIQQQIHHHHHH",
            e_type, machine, 1, 0x1000, 0, 0, e_flags, 64, 56, 0, 64, 0, 0,
        )
    else:
        header = struct.pack(
            f"{order}HHIIIIIHHHHHH",
            e_type, machine, 1, 0x1000, 0, 0, e_flags, 52, 32, 0, 40, 0, 0,
        )
    return ident + header


def elf_with_segments(machine, elf_class=64, endian="little", *, interpreter=False, flags_1=None,
                      extra_segments=(), e_type=ET_DYN):
    """ET_DYN fixture with program headers, deliberately without section headers."""
    order = "<" if endian == "little" else ">"
    header = bytearray(elf_stub(machine, e_type, elf_class, endian))
    segments = list(extra_segments)
    if interpreter:
        segments.append((3, b"/fixture/ld.so\0"))  # PT_INTERP
    if flags_1 is not None:
        dynamic_format = f"{order}{'qQ' if elf_class == 64 else 'iI'}"
        segments.append((2, struct.pack(dynamic_format, 0x6FFFFFFB, flags_1)
                         + struct.pack(dynamic_format, 0, 0)))  # DT_FLAGS_1, DT_NULL
    program_size = 56 if elf_class == 64 else 32
    struct.pack_into(f"{order}{'Q' if elf_class == 64 else 'I'}", header,
                     32 if elf_class == 64 else 28, len(header))
    struct.pack_into(f"{order}HH", header, 54 if elf_class == 64 else 42,
                     program_size, len(segments))
    programs = bytearray()
    payload = bytearray()
    for kind, contents in segments:
        offset = len(header) + program_size * len(segments) + len(payload)
        if elf_class == 64:
            programs.extend(struct.pack(f"{order}IIQQQQQQ", kind, 4, offset, 0, 0,
                                        len(contents), len(contents), 1))
        else:
            programs.extend(struct.pack(f"{order}IIIIIIII", kind, offset, 0, 0,
                                        len(contents), len(contents), 4, 1))
        payload.extend(contents)
    return header + programs + payload


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
        self.builder = BUILDER
        self.release = self.work / "release"
        self.release.mkdir()
        self.write_release_files()

    def write_release_files(self, machine=EM_X86_64, elf_class=64, endian="little", e_flags=0):
        # Release artifacts are ELF images; the builder must check them
        # against the requested Debian architecture (R4-007).
        for name in RELEASE_NAMES:
            e_type = ET_DYN if name.endswith(".so") else ET_EXEC
            path = self.release / name
            path.write_bytes(
                elf_stub(machine, e_type, elf_class, endian, e_flags) + f"artifact:{name}\n".encode()
            )
            path.chmod(0o755)

    def builder_command(self, name, version, architecture="amd64", extra=()):
        output = self.work / name
        return output, [
            "python3",
            str(self.builder),
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
        # Header-only ELF stubs cannot be scanned for native dependencies.
        output, command = self.builder_command(name, version, architecture, ["--no-shlibdeps"])
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

    def build_failure(self, name, architecture="amd64", extra=(), opt_out=True):
        extra = list(extra)
        if opt_out and "--shlibdeps" not in extra:
            extra.append("--no-shlibdeps")
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

    def test_checkout_extras_do_not_change_the_packaged_units_or_examples(self):
        checkout = self.work / "checkout"
        shutil.copytree(ROOT / "packaging", checkout / "packaging")
        shutil.copyfile(ROOT / "CHANGELOG.md", checkout / "CHANGELOG.md")
        self.builder = checkout / "packaging/debian/build-deb.py"
        clean = self.build("clean.deb")
        (checkout / "packaging/systemd/maki@.service~").write_text("editor backup")
        examples = checkout / "packaging/examples"
        (examples / "maki@.service.d/local.conf").write_text("local example")
        with_extras = self.build("extras.deb")
        self.assertEqual(hashlib.sha256(clean.read_bytes()).digest(),
                         hashlib.sha256(with_extras.read_bytes()).digest())
        root, _ = self.extract(with_extras)
        drop_in = pathlib.Path("maki@.service.d/20-memory-budget.conf")
        self.assertEqual((root / "usr/share/doc/maki/examples" / drop_in).read_bytes(),
                         (examples / drop_in).read_bytes())

    def test_vendored_license_inventory_uses_tracked_paths(self):
        repo = self.work / "checkout"
        source = repo / "vendor" / "example"
        source.mkdir(parents=True)
        script = repo / "packaging/debian/update-copyright.py"
        script.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "packaging/debian/update-copyright.py", script)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (source / "LICENSE").write_text("published")
        subprocess.run(["git", "-C", source, "add", "LICENSE"], check=True)
        (source / "LICENSE.bak").write_text("local backup")
        inventory = runpy.run_path(str(script))["notice_files"]
        self.assertEqual(inventory(source, "LICENSE", tracked=True), {source / "LICENSE"})
        with self.assertRaisesRegex(ValueError, "not tracked"):
            inventory(source, "LICENSE.bak", tracked=True)

    def test_installed_maintenance_contact_history_and_manuals(self):
        package = self.build()
        self.assertRegex(self.field(package, "Maintainer"), r".+ <[^@<> ]+@[^@<> ]+>$")
        root, _ = self.extract(package)
        docs = root / "usr/share/doc/maki"
        changelog = gzip.decompress((docs / "changelog.Debian.gz").read_bytes())
        self.assertIn(b"maki (0.1.0+test1)", changelog)
        self.assertEqual(gzip.decompress((docs / "NEWS.gz").read_bytes()), (ROOT / "CHANGELOG.md").read_bytes())
        for binary in ("maki", "maki-attach", "maki-check"):
            page = root / "usr/share/man/man8" / f"{binary}.8.gz"
            self.assertIn(f".TH {binary.upper()} 8".encode(), gzip.decompress(page.read_bytes()))

    def test_package_owns_runtime_artifacts_but_not_live_configuration(self):
        package = self.build()
        self.assertEqual(self.field(package, "Package"), "maki")
        self.assertEqual(self.field(package, "Version"), "0.1.0+test1")
        self.assertEqual(self.field(package, "Architecture"), "amd64")
        dependencies = self.field(package, "Depends")
        self.assertIn("nbd-client (>= 1:3.27.0)", dependencies)
        for dependency in ("nbdkit", "lvm2", "xfsprogs", "systemd", "kmod"):
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
        # operator owns the lifecycle (stop workloads, unmount, then drain).
        for script in ("preinst", "postinst", "prerm", "postrm"):
            path = control / script
            if not path.exists():
                continue
            subprocess.run(["sh", "-n", path], check=True)
            text = path.read_text()
            for unsafe_action in ("enable", "start", "stop", "restart", "try-restart"):
                self.assertNotRegex(
                    text,
                    rf'(?m)^\s*(?:systemctl|"\$systemctl_bin")\s+{unsafe_action}\b',
                    f"{script} must not run systemctl {unsafe_action}",
                )

    # --- R4-003: removal must not orphan a live attachment -----------------

    def test_installs_the_project_and_dependency_copyright_notice(self):
        root, _ = self.extract(self.build())
        notice = root / "usr/share/doc/maki/copyright"
        self.assertTrue(notice.is_file())
        self.assertFalse(notice.is_symlink())
        self.assertEqual(stat.S_IMODE(notice.stat().st_mode), 0o644)
        self.assertEqual(notice.read_bytes(), (ROOT / "packaging/debian/copyright").read_bytes())
        text = notice.read_text(encoding="utf-8")
        self.assertIn("https://github.com/seo-rii/maki", text)
        self.assertIn("/usr/share/common-licenses/Apache-2.0", text)
        self.assertIn((ROOT / "vendor/bytes/LICENSE").read_text().strip(), text)

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

    def test_review_f01_removal_guidance_unmounts_before_final_drain(self):
        package = self.build()
        _, control = self.extract(package, "prerm-stop-order")
        state = self.work / "state-stop-order"
        state.mkdir()
        (state / "pg.nbd").write_text("{}")
        result = self.run_prerm(control, "remove", state, fake_systemctl(self.work / "systemctl"))
        self.assertNotEqual(result.returncode, 0)
        message = result.stderr
        self.assertLess(message.index("stop workloads"), message.index("unmount/detach"))
        self.assertLess(message.index("unmount/detach"), message.index("final drain/checkpoint"))
        self.assertIn("while the daemon still accepts I/O", message)
        self.assertNotIn("maki drain <config>", message)

    def test_prerm_refuses_removal_while_a_maki_unit_is_active(self):
        package = self.build()
        _, control = self.extract(package, "prerm-unit")
        state = self.work / "state-empty"
        state.mkdir()
        busy_systemctl = fake_systemctl(self.work / "systemctl-busy", ["maki@pg.service"])
        result = self.run_prerm(control, "remove", state, busy_systemctl)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("maki@pg.service", result.stderr)

    def test_prerm_refuses_removal_while_a_recovery_unit_runs(self):
        # R5-015: maki-recover@ runs maki-attach from the package after a
        # daemon failure, and keeps doing so after the record is gone.
        package = self.build()
        _, control = self.extract(package, "prerm-recover")
        state = self.work / "state-recover"
        state.mkdir()
        recovering = self.work / "systemctl-recover"
        recovering.write_text(
            "#!/bin/sh\n"
            "for pattern in \"$@\"; do\n"
            "  [ \"$pattern\" = 'maki-recover@*.service' ] && "
            "echo 'maki-recover@pg.service loaded activating start Maki fixture'\n"
            "done\n"
            "exit 0\n"
        )
        recovering.chmod(0o755)
        result = self.run_prerm(control, "remove", state, recovering)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("maki-recover@pg.service", result.stderr)

    def test_prerm_fails_closed_when_systemd_cannot_be_queried(self):
        # A failed `systemctl list-units` proves nothing about the maki
        # units; treating its empty output as "idle" let removal proceed
        # under a live attachment.
        package = self.build()
        _, control = self.extract(package, "prerm-query-failure")
        state = self.work / "state-query"
        state.mkdir()
        broken = self.work / "systemctl-broken"
        broken.write_text("#!/bin/sh\necho 'Failed to connect to bus' >&2\nexit 1\n")
        broken.chmod(0o755)
        result = self.run_prerm(control, "remove", state, broken)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("systemd", result.stderr)
        # Upgrades stay exempt even then.
        upgrade = self.run_prerm(control, "upgrade", state, broken, ["0.1.0+next"])
        self.assertEqual(upgrade.returncode, 0, upgrade.stderr)

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

    def test_foreign_os_abi_is_rejected_for_each_release_file(self):
        for name in RELEASE_NAMES:
            with self.subTest(name=name):
                self.write_release_files()
                path = self.release / name
                image = bytearray(path.read_bytes())
                image[7] = 9  # ELFOSABI_FREEBSD
                path.write_bytes(image)
                error = self.build_failure("freebsd.deb")
                self.assertIn(name, error)
                self.assertIn("OS ABI", error)
        self.write_release_files()
        for path in self.release.iterdir():
            image = bytearray(path.read_bytes())
            image[7] = 3  # ELFOSABI_GNU
            path.write_bytes(image)
        self.build("gnu.deb")

    def test_mips64el_checks_the_float_abi_in_each_program_header_table(self):
        def flags(fp_abi, version=0):
            return struct.pack("<H6B4I", version, 64, 2, 2, 2, 0, fp_abi, 0, 0, 0, 0)

        def image(name, *records):
            return elf_with_segments(8, extra_segments=[(0x70000003, record) for record in records],
                                     e_type=ET_DYN if name.endswith(".so") else ET_EXEC)

        for name in RELEASE_NAMES:
            (self.release / name).write_bytes(image(name, flags(1)))
        self.build("hard.deb", architecture="mips64el")
        (self.release / "maki").write_bytes(image("maki", flags(0)))
        self.build("abi-independent.deb", architecture="mips64el")
        for name in RELEASE_NAMES:
            with self.subTest(name=name):
                (self.release / name).write_bytes(image(name, flags(3)))
                error = self.build_failure("soft.deb", architecture="mips64el")
                self.assertIn(name, error)
                self.assertIn("mips64el", error)
                (self.release / name).write_bytes(image(name, flags(1)))
        for records in ([], [flags(1)[:-1]], [flags(1, version=1)], [flags(1), flags(1)]):
            with self.subTest(records=records):
                (self.release / "maki").write_bytes(image("maki", *records))
                self.assertIn("mips64el", self.build_failure("invalid.deb", architecture="mips64el"))

    def test_riscv64_requires_lp64d_for_every_artifact(self):
        machine = 0xF3
        self.write_release_files(machine, e_flags=0x5)
        self.build("lp64d.deb", architecture="riscv64")
        for name in RELEASE_NAMES:
            for flags in (0x1, 0x2, 0x6):
                with self.subTest(artifact=name, flags=flags):
                    self.write_release_files(machine, e_flags=0x4)
                    kind = ET_DYN if name.endswith(".so") else ET_EXEC
                    (self.release / name).write_bytes(elf_stub(machine, kind, e_flags=flags))
                    error = self.build_failure("invalid.deb", architecture="riscv64")
                    self.assertIn(name, error)
                    self.assertIn("LP64D", error)

    def test_ppc64el_rejects_incompatible_abi_markers_on_every_artifact(self):
        # 0 is ABI-neutral; 2 denotes ELFv2. Higher flag bits are independent.
        for flags in (0, 2, 0x12):
            self.write_release_files(0x15, e_flags=flags)
            self.build(f"ppc64el-{flags}.deb", architecture="ppc64el")
        for name in RELEASE_NAMES:
            for flags in (1, 3):
                with self.subTest(artifact=name, flags=flags):
                    self.write_release_files(0x15, e_flags=2)
                    kind = ET_DYN if name.endswith(".so") else ET_EXEC
                    (self.release / name).write_bytes(elf_stub(0x15, kind, e_flags=flags))
                    error = self.build_failure("bad-ppc.deb", architecture="ppc64el")
                    self.assertIn(name, error)
                    self.assertIn("ELFv2", error)

    def test_loong64_requires_lp64d_for_every_artifact(self):
        machine = 0x102
        self.write_release_files(machine, e_flags=0x43)
        self.build("lp64d.deb", architecture="loong64")
        for name in RELEASE_NAMES:
            for flags in (0x40, 0x41, 0x42):
                with self.subTest(artifact=name, flags=flags):
                    self.write_release_files(machine, e_flags=0x43)
                    kind = ET_DYN if name.endswith(".so") else ET_EXEC
                    (self.release / name).write_bytes(elf_stub(machine, kind, e_flags=flags))
                    error = self.build_failure("invalid.deb", architecture="loong64")
                    self.assertIn(name, error)
                    self.assertIn("LP64D", error)

    def test_arm_packages_accept_matching_float_abi(self):
        # AAELF32: absent float flags imply the base PCS, just like FLOAT_SOFT.
        for architecture, flags in (("armhf", 0x05000400),
                                    ("armel", 0x05000200), ("armel", 0x05000000)):
            with self.subTest(architecture=architecture, flags=flags):
                self.write_release_files(EM_ARM, 32, e_flags=flags)
                package = self.build(f"{architecture}-{flags:x}.deb", architecture=architecture)
                self.assertEqual(self.field(package, "Architecture"), architecture)

    def test_every_arm_artifact_must_match_package_float_abi(self):
        for architecture, good, bad in (("armhf", 0x05000400, 0x05000200),
                                       ("armhf", 0x05000400, 0x05000000),
                                       ("armel", 0x05000200, 0x05000400)):
            for name in RELEASE_NAMES:
                with self.subTest(architecture=architecture, artifact=name, flags=bad):
                    self.write_release_files(EM_ARM, 32, e_flags=good)
                    kind = ET_DYN if name.endswith(".so") else ET_EXEC
                    (self.release / name).write_bytes(elf_stub(EM_ARM, kind, 32, e_flags=bad))
                    stderr = self.build_failure("wrong-arm-abi.deb", architecture=architecture)
                    self.assertIn(name, stderr)
                    self.assertIn("ABI", stderr)
                    self.assertIn(architecture, stderr)

    def test_arm_abi_flags_must_be_unambiguous_eabi5(self):
        for architecture in ("armhf", "armel"):
            for flags, reason in ((0x05000600, "conflicting"),
                                  (0x04000400, "version 5"), (0, "version 5")):
                with self.subTest(architecture=architecture, flags=flags):
                    self.write_release_files(EM_ARM, 32, e_flags=flags)
                    stderr = self.build_failure("invalid-arm-abi.deb", architecture=architecture)
                    self.assertIn(reason, stderr)

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

    def test_plugin_rejects_pie_markers_without_section_headers(self):
        for architecture, machine, elf_class, endian in (
            ("amd64", EM_X86_64, 64, "little"),
            ("i386", EM_386, 32, "little"),
            ("s390x", 0x16, 64, "big"),
        ):
            # Older PIE may have only PT_INTERP; static PIE has no interpreter.
            for markers in ({"interpreter": True}, {"flags_1": DF_1_PIE}):
                with self.subTest(architecture=architecture, markers=markers):
                    self.write_release_files(machine, elf_class, endian)
                    (self.release / "libmaki_nbdkit.so").write_bytes(
                        elf_with_segments(machine, elf_class, endian, **markers)
                    )
                    stderr = self.build_failure("pie-plugin.deb", architecture=architecture)
                    self.assertIn("libmaki_nbdkit.so", stderr)
                    self.assertIn("PIE", stderr)
                    self.assertNotIn("Traceback", stderr)

    def test_shared_plugin_and_cli_pie_metadata_remain_allowed(self):
        for architecture, machine, elf_class, endian in (
            ("amd64", EM_X86_64, 64, "little"),
            ("i386", EM_386, 32, "little"),
            ("s390x", 0x16, 64, "big"),
        ):
            with self.subTest(architecture=architecture):
                for name in RELEASE_NAMES:
                    plugin = name.endswith(".so")
                    (self.release / name).write_bytes(elf_with_segments(
                        machine, elf_class, endian,
                        interpreter=not plugin, flags_1=1 if plugin else DF_1_PIE,
                    ))
                package = self.build(f"shared-{architecture}.deb", architecture=architecture)
                self.assertEqual(self.field(package, "Architecture"), architecture)

    def test_cli_rejects_shared_libraries_and_missing_entry_points(self):
        for architecture, machine, elf_class, endian in (
            ("amd64", EM_X86_64, 64, "little"),
            ("i386", EM_386, 32, "little"),
            ("s390x", 0x16, 64, "big"),
        ):
            for name in RELEASE_NAMES[:-1]:
                with self.subTest(architecture=architecture, name=name):
                    self.write_release_files(machine, elf_class, endian)
                    (self.release / name).write_bytes(
                        elf_with_segments(machine, elf_class, endian, flags_1=1))
                    error = self.build_failure("shared-cli.deb", architecture=architecture)
                    self.assertIn(name, error)
                    self.assertIn("not a shared library", error)
                    zero_entry = elf_with_segments(machine, elf_class, endian,
                                                   interpreter=True, flags_1=DF_1_PIE)
                    order = "<" if endian == "little" else ">"
                    struct.pack_into(f"{order}{'Q' if elf_class == 64 else 'I'}", zero_entry, 24, 0)
                    (self.release / name).write_bytes(zero_entry)
                    error = self.build_failure("zero-entry.deb", architecture=architecture)
                    self.assertIn("entry point", error)

    def test_old_dynamic_and_static_pie_executables_are_allowed(self):
        for markers in ({"interpreter": True}, {"flags_1": DF_1_PIE}):
            with self.subTest(markers=markers):
                self.write_release_files()
                for name in RELEASE_NAMES[:-1]:
                    (self.release / name).write_bytes(elf_with_segments(EM_X86_64, **markers))
                self.build("pie-cli.deb")

    def test_interpreter_segment_must_hold_one_complete_absolute_path(self):
        good = b"/lib64/ld-linux-x86-64.so.2\0"
        for records in ([good, good], [b"ld.so\0"], [good[:-1]], [good + b"extra\0"], [b""]):
            with self.subTest(records=records):
                (self.release / "maki").write_bytes(elf_with_segments(
                    EM_X86_64, extra_segments=[(3, record) for record in records]))
                self.assertIn("PT_INTERP", self.build_failure("bad-interpreter.deb"))

    @unittest.skipUnless(shutil.which("cc") and shutil.which("dpkg-shlibdeps"),
                         "native Debian build tools required")
    def test_native_package_requires_the_declared_elf_interpreter_on_the_target(self):
        architecture = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        source = self.work / "fixture.c"
        source.write_text("int main(void) { return 0; }\n")
        for name in RELEASE_NAMES:
            options = ["-shared", "-fPIC"] if name.endswith(".so") else []
            subprocess.run(["cc", *options, str(source), "-o", self.release / name], check=True)
        good, command = self.builder_command("native.deb", "1", architecture)
        subprocess.run(command, check=True, capture_output=True)
        self.assertTrue(good.is_file())

        headers = subprocess.check_output(["readelf", "-lW", self.release / "maki"], text=True,
                                          env={**os.environ, "LC_ALL": "C"})
        loader = re.search(r"\[Requesting program interpreter: (.+?)\]", headers)[1]
        for suffix in ("/", "/."):
            with self.subTest(directory_only_suffix=suffix):
                subprocess.run(["cc", str(source), f"-Wl,--dynamic-linker,{loader}{suffix}",
                                "-o", self.release / "maki-check"], check=True)
                error = self.build_failure("directory-interpreter.deb", architecture=architecture, opt_out=False)
                self.assertIn("interpreter", error)

        private = self.work / "ld-private.so.2"
        for installed in (False, True):
            with self.subTest(private_loader_exists=installed):
                if installed:
                    private.symlink_to("/bin/true")
                subprocess.run(["cc", str(source), f"-Wl,--dynamic-linker,{private}",
                                "-o", self.release / "maki-check"], check=True)
                error = self.build_failure("build-host-only.deb", architecture=architecture, opt_out=False)
                self.assertIn("maki-check", error)
                self.assertIn("interpreter", error)

    @unittest.skipUnless(shutil.which("cc") and shutil.which("dpkg-shlibdeps"),
                         "native C compiler and dpkg-shlibdeps required")
    def test_native_shared_library_cli_is_rejected_before_packaging(self):
        source = self.work / "library.c"
        source.write_text("int harmless_fixture(void) { return 0; }\n")
        library = self.work / "library.so"
        subprocess.run(["cc", str(source), "-shared", "-fPIC", "-o", str(library)],
                       check=True, capture_output=True, text=True)
        shutil.copyfile(library, self.release / "maki")
        architecture = subprocess.run(["dpkg", "--print-architecture"], check=True,
                                      capture_output=True, text=True).stdout.strip()
        error = self.build_failure("native-shared-cli.deb", architecture=architecture,
                                   opt_out=False)
        self.assertIn("maki must", error)
        self.assertIn("executable", error)
        self.assertNotIn("dpkg-shlibdeps failed", error)

    def test_plugin_metadata_must_fit_in_the_file(self):
        valid = elf_with_segments(EM_X86_64, flags_1=1)
        bad_program_table = bytearray(valid)
        struct.pack_into("<Q", bad_program_table, 32, len(valid) + 1)
        for contents in (bad_program_table, valid[:-1]):
            with self.subTest(contents=bytes(contents).hex()):
                (self.release / "libmaki_nbdkit.so").write_bytes(contents)
                stderr = self.build_failure("truncated-plugin.deb")
                self.assertIn("libmaki_nbdkit.so", stderr)
                self.assertIn("truncated", stderr)
                self.assertNotIn("Traceback", stderr)

    @unittest.skipUnless(shutil.which("cc") and shutil.which("dpkg-shlibdeps"),
                         "native C compiler and dpkg-shlibdeps required")
    def test_native_pie_plugin_is_rejected_before_packaging(self):
        # The real dependency scanner accepts a PIE renamed as the plugin.
        # A filename or ET_DYN check alone therefore produces an unusable .deb.
        source = self.work / "pie.c"
        source.write_text('#include <stdio.h>\nint main(void) { puts("fixture"); return 0; }\n')
        executable = self.work / "pie"
        subprocess.run(["cc", str(source), "-fPIE", "-pie", "-rdynamic", "-o", str(executable)],
                       check=True, capture_output=True, text=True)
        for name in RELEASE_NAMES:
            shutil.copyfile(executable, self.release / name)
        architecture = subprocess.run(["dpkg", "--print-architecture"], check=True,
                                      capture_output=True, text=True).stdout.strip()
        stderr = self.build_failure("native-pie.deb", architecture=architecture, opt_out=False)
        self.assertIn("libmaki_nbdkit.so", stderr)
        self.assertIn("PIE", stderr)
        self.assertNotIn("dpkg-shlibdeps failed", stderr)

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

    def test_native_dependency_scan_is_on_by_default(self):
        # A package without its native Depends installs on a host whose libc
        # is too old and fails at run time, so the scan is not opt-in: a
        # plain build of stubs it cannot analyse (or on a host without
        # dpkg-shlibdeps) is refused and names the explicit opt-out.
        stderr = self.build_failure("default-scan.deb", extra=[], opt_out=False)
        self.assertIn("dpkg-shlibdeps", stderr)
        if shutil.which("dpkg-shlibdeps") is None:
            self.assertIn("--no-shlibdeps", stderr)

    def test_opting_out_of_the_scan_keeps_the_static_depends_and_warns(self):
        output, command = self.builder_command("opt-out.deb", "0.1.0+test1")
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = "1789689600"
        result = subprocess.run(
            [*command, "--no-shlibdeps"], cwd=ROOT, env=environment, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--no-shlibdeps", result.stderr)
        self.assertIn("native library dependencies", result.stderr)
        self.assertEqual(
            self.field(output, "Depends"),
            "nbd-client (>= 1:3.27.0), nbdkit, lvm2, xfsprogs, util-linux, systemd, kmod",
        )

    def test_unspecified_epoch_also_applies_to_archive_headers(self):
        output, command = self.builder_command("default-epoch.deb", "0.1.0+test1",
                                               extra=["--no-shlibdeps"])
        environment = os.environ.copy()
        environment.pop("SOURCE_DATE_EPOCH", None)
        subprocess.run(command, cwd=ROOT, env=environment, check=True, capture_output=True)
        with output.open("rb") as stream:
            self.assertEqual(stream.read(8), b"!<arch>\n")
            header = stream.read(60)
        self.assertEqual(int(header[16:28]), 0)

    def test_build_is_reproducible_and_rejects_invalid_inputs(self):
        first = self.build("first.deb")
        second = self.build("second.deb")
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(digest(first), digest(second))

        (self.release / "maki-check").unlink()
        stderr = self.build_failure("invalid.deb")
        self.assertIn("maki-check", stderr)

    def test_installed_size_accounts_for_staged_files_in_kib(self):
        package = self.build()
        size = int(self.field(package, "Installed-Size"))
        self.assertGreater(size, 0)
        with (self.release / "maki").open("ab") as executable:
            executable.write(b"x" * 2048)
        self.assertEqual(int(self.field(self.build(), "Installed-Size")), size + 2)

    def test_output_cannot_replace_a_required_release_input(self):
        alias = self.work / "release-alias"
        alias.symlink_to(self.release, target_is_directory=True)
        for name in RELEASE_NAMES:
            source = self.release / name
            original = source.read_bytes()
            for directory in (self.release, alias):
                with self.subTest(name=name, directory=directory):
                    _, command = self.builder_command(directory / name, "0.1.0", extra=["--no-shlibdeps"])
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("overwrite a release input", result.stderr)
                    self.assertEqual(source.read_bytes(), original)
        self.assertEqual(self.field(self.build("release/maki.deb"), "Package"), "maki")

    def test_rebuild_replaces_the_directory_entry_after_output_is_complete(self):
        output = self.work / "maki.deb"
        output.write_bytes(b"previous package")
        previous = self.work / "previous.deb"
        os.link(output, previous)
        self.build()
        self.assertEqual(previous.read_bytes(), b"previous package")
        self.assertEqual(self.field(output, "Package"), "maki")

    def test_build_succeeds_with_restrictive_caller_umask(self):
        package = self.build(umask=0o077)
        root, control = self.extract(package, "restrictive-umask")

        for directory in [root, control, *root.rglob("*"), *control.rglob("*")]:
            if directory.is_dir():
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)


if __name__ == "__main__":
    unittest.main()
