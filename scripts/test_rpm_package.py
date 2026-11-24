"""Contract of the RPM package for RHEL 9 (packaging/rpm).

The package must install what the Debian package installs, with the same
owners and modes, the same refusal to be removed under a live attachment,
and the same checks of the release artifacts. These tests need `rpm`,
`rpmbuild`, `rpm2cpio` and `cpio` (on Debian and Ubuntu: `apt install rpm
cpio`). The comparison with the Debian package also needs `dpkg-deb`; it is
skipped where that is missing (a RHEL host), unless
MAKI_TEST_REQUIRE_DPKG_DEB=1, which CI sets on Ubuntu.
"""

import gzip
import hashlib
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER = ROOT / "packaging" / "rpm" / "build-rpm.py"
DEB_BUILDER = ROOT / "packaging" / "debian" / "build-deb.py"
RELEASE_NAMES = ("maki", "maki-attach", "maki-check", "libmaki_nbdkit.so")
EPOCH = "1789689600"
VERSION = "0.1.0~rc+rev12.gitabcdef012345"
REQUIRE_DPKG_DEB = "MAKI_TEST_REQUIRE_DPKG_DEB"
STATIC_REQUIRES = ["nbdkit-server", "lvm2", "xfsprogs", "util-linux", "systemd >= 249", "kmod"]
DEBIAN_NBDKIT = "ExecStart=/usr/bin/nbdkit \\"
RPM_NBDKIT = "ExecStart=/usr/sbin/nbdkit \\"

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7
EM_PPC64 = 0x15
DF_1_PIE = 0x08000000


def elf_stub(machine, e_type, elf_class=64, endian="little", e_flags=0):
    """A minimal ELF header (no sections) with the given identity fields."""
    order = "<" if endian == "little" else ">"
    ident = b"\x7fELF" + bytes([2 if elf_class == 64 else 1, 1 if endian == "little" else 2, 1, 0])
    ident += b"\0" * 8
    if elf_class == 64:
        header = struct.pack(f"{order}HHIQQQIHHHHHH",
                             e_type, machine, 1, 0x1000, 0, 0, e_flags, 64, 56, 0, 64, 0, 0)
    else:
        header = struct.pack(f"{order}HHIIIIIHHHHHH",
                             e_type, machine, 1, 0x1000, 0, 0, e_flags, 52, 32, 0, 40, 0, 0)
    return ident + header


def elf_with_dynamic_flags(machine, flags_1):
    """ET_DYN with one PT_DYNAMIC segment holding DT_FLAGS_1, no sections."""
    header = bytearray(elf_stub(machine, ET_DYN))
    dynamic = struct.pack("<qQ", 0x6FFFFFFB, flags_1) + struct.pack("<qQ", 0, 0)
    struct.pack_into("<Q", header, 32, len(header))
    struct.pack_into("<HH", header, 54, 56, 1)
    offset = len(header) + 56
    program = struct.pack("<IIQQQQQQ", 2, 4, offset, 0, 0, len(dynamic), len(dynamic), 1)
    return bytes(header) + program + dynamic


def fake_systemctl(path, active_units=()):
    """A stand-in `systemctl` whose `list-units` prints the given unit names."""
    lines = "".join(f"echo '{unit} loaded active running Maki fixture'\n" for unit in active_units)
    path.write_text("#!/bin/sh\n" + lines + "exit 0\n")
    path.chmod(0o755)
    return path


def query(package, query_format):
    return subprocess.run(["rpm", "-qp", "--queryformat", query_format, str(package)],
                          check=True, capture_output=True, text=True).stdout


def requires(package):
    return subprocess.run(["rpm", "-qp", "--requires", str(package)],
                          check=True, capture_output=True, text=True).stdout.splitlines()


def scriptlet(package, tag):
    return query(package, f"%{{{tag}}}")


def payload(package, destination):
    """Unpack the payload as rpm would install it, without an rpm database."""
    destination.mkdir()
    archive = subprocess.run(["rpm2cpio", str(package)], check=True, capture_output=True).stdout
    subprocess.run(["cpio", "-idm", "--quiet", "--no-absolute-filenames"], input=archive,
                   cwd=destination, check=True)
    return destination


def tree(root):
    """Relative path -> (kind, mode, contents) of everything below root."""
    entries = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        kind = "dir" if stat.S_ISDIR(mode) else "file" if stat.S_ISREG(mode) else "other"
        contents = path.read_bytes() if kind == "file" else None
        entries[path.relative_to(root).as_posix()] = (kind, stat.S_IMODE(mode), contents)
    return entries


def busy_check(script, opening, closing):
    """The lines of the removal check between the exact `opening` and
    `closing` lines, without indentation."""
    lines = script.splitlines()
    start = lines.index(opening) + 1
    return [line.strip() for line in lines[start:lines.index(closing, start)]]


class RpmPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = pathlib.Path(self.temp.name)
        self.builder = BUILDER
        self.release = self.work / "release"
        self.release.mkdir()
        self.write_release_files()
        self.environment = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH)

    def write_release_files(self, machine=EM_X86_64, elf_class=64, endian="little", e_flags=0):
        for name in RELEASE_NAMES:
            e_type = ET_DYN if name.endswith(".so") else ET_EXEC
            path = self.release / name
            path.write_bytes(elf_stub(machine, e_type, elf_class, endian, e_flags)
                             + f"artifact:{name}\n".encode())
            path.chmod(0o755)

    def builder_command(self, name, version=VERSION, architecture="x86_64", extra=()):
        output = self.work / name
        return output, ["python3", "-B", str(self.builder), "--release-dir", str(self.release),
                        "--version", version, "--architecture", architecture,
                        "--output", str(output), *extra]

    def build(self, name="maki.rpm", version=VERSION, architecture="x86_64", extra=(), umask=None):
        # Header-only ELF stubs have no interpreter or libraries to depend on.
        output, command = self.builder_command(name, version, architecture, ["--no-autoreq", *extra])
        result = subprocess.run(command, cwd=ROOT, env=self.environment, capture_output=True, text=True,
                                preexec_fn=(lambda: os.umask(umask)) if umask is not None else None)
        self.assertEqual(result.returncode, 0, result.stderr)
        # rpm reports some spec errors (a changelog date it cannot parse) and
        # still writes a package.
        self.assertNotIn("error:", result.stderr)
        return output

    def build_failure(self, name, version=VERSION, architecture="x86_64", extra=(), opt_out=True):
        extra = list(extra)
        if opt_out and "--autoreq" not in extra:
            extra.append("--no-autoreq")
        _, command = self.builder_command(name, version, architecture, extra)
        result = subprocess.run(command, cwd=ROOT, env=self.environment, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.work / name).exists(), "a refused build must leave no package")
        self.assertNotIn("Traceback", result.stderr)
        return result.stderr

    def run_preun(self, package, argument, state_dir, systemctl):
        script = self.work / "preun.sh"
        script.write_text(scriptlet(package, "PREUN"))
        environment = dict(os.environ, MAKI_ATTACH_STATE_DIR=str(state_dir),
                           MAKI_SYSTEMCTL=str(systemctl))
        return subprocess.run(["sh", str(script), str(argument)], env=environment,
                              capture_output=True, text=True)

    # --- what the package declares and installs -------------------------

    def test_package_declares_the_el9_runtime_and_no_nbd_client(self):
        package = self.build()
        self.assertEqual(query(package, "%{NAME} %{VERSION} %{RELEASE} %{ARCH}"),
                         f"maki {VERSION} 1 x86_64")
        self.assertRegex(query(package, "%{PACKAGER}"), r".+ <[^@<> ]+@[^@<> ]+>$")
        declared = requires(package)
        for dependency in STATIC_REQUIRES:
            self.assertIn(dependency, declared)
        self.assertFalse([entry for entry in declared if entry.split()[0].startswith("nbd")
                          and entry.split()[0] != "nbdkit-server"], declared)
        provides = query(package, "[%{PROVIDES}\n]").split()
        self.assertIn("maki(x86-64)", provides)
        self.assertFalse([name for name in provides if ".so" in name], provides)

    def sysusers_entries(self):
        """What packaging/sysusers.d/maki.conf creates, as `user(name)` and
        `group(name)`: the names rpm's sysusers generator gives a package
        that ships such a file on EL9 (`u` creates the user and its group,
        `g` a group, `m` names a user and a group)."""
        entries = set()
        for line in (ROOT / "packaging/sysusers.d/maki.conf").read_text().splitlines():
            fields = line.split()
            if fields[:1] == ["u"]:
                entries |= {f"user({fields[1]})", f"group({fields[1]})"}
            elif fields[:1] == ["g"]:
                entries.add(f"group({fields[1]})")
            elif fields[:1] == ["m"]:
                entries |= {f"user({fields[1]})", f"group({fields[2]})"}
        return sorted(entries)

    def host_with_a_sysusers_generator(self):
        """An environment in which rpmbuild has a sysusers dependency
        generator, as on a host with systemd-rpm-macros (every RHEL 9 host
        with systemd; the minimal container image has none). The stand-in
        prints provides no package declares, so that its output shows."""
        home = self.work / "generator-home"
        attributes = home / "fileattrs"
        attributes.mkdir(parents=True)
        system = pathlib.Path(subprocess.check_output(["rpm", "--eval", "%{_fileattrsdir}"], text=True).strip())
        for attribute in system.glob("*.attr"):
            shutil.copyfile(attribute, attributes / attribute.name)
        # rpm takes the generators' names from the files of this directory
        # and their commands from macros.
        (attributes / "sysusers.attr").write_text("")
        generator = home / "sysusers.prov"
        generator.write_text("#!/bin/sh\ncat > /dev/null\necho 'user(from-the-build-host)'\n"
                             "echo 'group(from-the-build-host)'\n")
        generator.chmod(0o755)
        (home / ".rpmmacros").write_text(
            f"%_fileattrsdir {attributes}\n%__sysusers_provides {generator}\n"
            "%__sysusers_path ^/usr/lib/sysusers\\.d/.*\\.conf$\n")
        return dict(self.environment, HOME=str(home))

    def test_package_provides_the_user_and_groups_it_creates(self):
        # Other packages may require the user or a group (`Requires:
        # user(maki)`, `group(maki-admin)`); the names are those of EL9's own
        # packages, each declared once and for every version.
        expected = self.sysusers_entries()
        self.assertEqual(expected, ["group(maki)", "group(maki-admin)", "user(maki)"])
        package = self.build()
        provided = [line.split("\t") for line in
                    query(package, "[%{PROVIDENAME}\t%{PROVIDEFLAGS:depflags}\t%{PROVIDEVERSION}\n]").splitlines()]
        accounts = [entry for entry in provided if entry[0].startswith(("user(", "group("))]
        self.assertEqual(sorted(name for name, _, _ in accounts), expected)
        for name, flags, version in accounts:
            self.assertEqual((flags.strip(), version.strip()), ("", ""), name)

    def test_provides_do_not_depend_on_the_build_hosts_dependency_generators(self):
        # A RHEL 9 host has rpm's sysusers generator (systemd-rpm-macros),
        # the release workflow's container has not: the published package
        # lacked the provides a package built on a host carried.
        plain = self.build("plain.rpm")
        self.environment = self.host_with_a_sysusers_generator()
        with_generator = self.build("generator.rpm")
        self.assertEqual(query(with_generator, "[%{PROVIDES}\n]"), query(plain, "[%{PROVIDES}\n]"))
        self.assertEqual(hashlib.sha256(with_generator.read_bytes()).hexdigest(),
                         hashlib.sha256(plain.read_bytes()).hexdigest())
        # The stand-in generator does run for a spec that leaves it on.
        checkout = self.work / "checkout"
        shutil.copytree(ROOT / "packaging", checkout / "packaging")
        for name in ("CHANGELOG.md", "LICENSE"):
            shutil.copyfile(ROOT / name, checkout / name)
        spec = checkout / "packaging/rpm/maki.spec"
        switch = "%global __sysusers_provides %{nil}\n"
        self.assertEqual(spec.read_text().count(switch), 1)
        spec.write_text(spec.read_text().replace(switch, ""))
        self.builder = checkout / "packaging/rpm/build-rpm.py"
        control = query(self.build("control.rpm"), "[%{PROVIDENAME}\n]").splitlines()
        self.assertIn("user(from-the-build-host)", control)
        self.assertIn("group(from-the-build-host)", control)

    def test_package_conflicts_with_the_nbdkit_selinux_module(self):
        # nbdkit-selinux labels /usr/sbin/nbdkit nbdkit_exec_t, which the
        # targeted policy lets systemd neither execute nor transition from.
        # Only the nbdkit metapackage requires the module, and only where
        # selinux-policy-targeted is installed: with the module alone refused
        # and Maki protected, `dnf install --allowerasing nbdkit` satisfies
        # the metapackage by replacing the host's SELinux policy.
        self.assertEqual(sorted(query(self.build(), "[%{CONFLICTS}\n]").split()), ["nbdkit", "nbdkit-selinux"])
        self.assertEqual(set(query(self.build(), "[%{CONFLICTVERSION}\n]").split()), set(),
                         "every version of both is refused")

    def test_dnf_is_told_not_to_remove_the_package(self):
        # A failing %preun keeps Maki, but rpm goes on with the rest of the
        # transaction: `dnf remove maki` under an attachment erased
        # nbdkit-server, lvm2, xfsprogs and kmod as unused dependencies, and
        # `dnf --allowerasing` installed what conflicts with Maki beside it.
        # dnf refuses a transaction that removes a protected package, or one
        # of its dependencies, before it changes anything.
        package = self.build()
        installed = payload(package, self.work / "root") / "etc/dnf/protected.d/maki.conf"
        self.assertEqual(installed.read_bytes(), (ROOT / "packaging/rpm/dnf-protected.conf").read_bytes())
        # As dnf reads a protected.d file: a package name per line, blank
        # lines and lines that start with `#` skipped.
        names = [line.strip() for line in installed.read_text().splitlines()
                 if line.strip() and not line.strip().startswith("#")]
        self.assertEqual(names, [query(package, "%{NAME}")])
        self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o644)
        # The file is what an operator finds behind dnf's refusal.
        for needed in ("rpm -e maki", "maki-workload@", "dnf autoremove"):
            self.assertIn(needed, installed.read_text())
        flags = dict(line.split("\t") for line in
                     query(package, "[%{FILENAMES}\t%{FILEFLAGS:fflags}\n]").splitlines())
        # %config(noreplace), like systemd's own entry: an administrator's
        # edit is kept by upgrades.
        self.assertEqual({name: value for name, value in flags.items() if "c" in value},
                         {"/etc/dnf/protected.d/maki.conf": "cn"})

    def test_package_owns_runtime_artifacts_but_not_live_configuration(self):
        package = self.build()
        root = payload(package, self.work / "root")
        expected = {
            "usr/bin/maki": "maki",
            "usr/bin/maki-attach": "maki-attach",
            "usr/bin/maki-check": "maki-check",
            "usr/lib/maki/maki-nbdkit.so": "libmaki_nbdkit.so",
        }
        for relative, source in expected.items():
            installed = root / relative
            # Byte for byte: no stripping, debuginfo split or build-id links.
            self.assertEqual(installed.read_bytes(), (self.release / source).read_bytes())
        self.assertFalse((root / "usr/lib/.build-id").exists())
        for unit in ("maki-attach@.service", "maki-recover@.service", "maki-workload@.target"):
            self.assertEqual((root / "usr/lib/systemd/system" / unit).read_bytes(),
                             (ROOT / "packaging/systemd" / unit).read_bytes())
        for kind in ("sysusers.d", "tmpfiles.d"):
            self.assertEqual((root / "usr/lib" / kind / "maki.conf").read_bytes(),
                             (ROOT / "packaging" / kind / "maki.conf").read_bytes())
        # Nothing below /etc/maki, which belongs to the operator; the one
        # file outside /usr is dnf's.
        self.assertEqual(sorted(path.relative_to(root).as_posix() for path in (root / "etc").rglob("*")
                                if not path.is_dir()), ["etc/dnf/protected.d/maki.conf"])

    def test_daemon_unit_runs_the_distribution_nbdkit_by_absolute_path(self):
        root = payload(self.build(), self.work / "root")
        installed = (root / "usr/lib/systemd/system/maki@.service").read_text().split("\n")
        source = (ROOT / "packaging/systemd/maki@.service").read_text().split("\n")
        self.assertEqual(len(installed), len(source))
        changed = [(old, new) for old, new in zip(source, installed) if old != new]
        self.assertEqual(changed, [(DEBIAN_NBDKIT, RPM_NBDKIT)])

    def test_a_unit_without_exactly_one_debian_nbdkit_start_is_refused(self):
        checkout = self.work / "checkout"
        for directory in ("packaging",):
            shutil.copytree(ROOT / directory, checkout / directory)
        for name in ("CHANGELOG.md", "LICENSE"):
            shutil.copyfile(ROOT / name, checkout / name)
        self.builder = checkout / "packaging/rpm/build-rpm.py"
        unit = checkout / "packaging/systemd/maki@.service"
        original = unit.read_text()
        self.build("checkout.rpm")
        for changed in (original.replace(DEBIAN_NBDKIT, "ExecStart=nbdkit \\"),
                        original.replace(DEBIAN_NBDKIT, RPM_NBDKIT),
                        original.replace(DEBIAN_NBDKIT, DEBIAN_NBDKIT + "\n" + DEBIAN_NBDKIT),
                        original + "ExecStartPre=/usr/bin/true\nExecStart=/usr/bin/true\n"):
            with self.subTest(changed=changed[-80:]):
                unit.write_text(changed)
                self.assertIn("ExecStart", self.build_failure("changed-unit.rpm"))

    def test_files_are_root_owned_with_the_debian_modes(self):
        package = self.build()
        listing = query(package, "[%{FILENAMES}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t"
                                 "%{FILEGROUPNAME}\t%{FILEFLAGS:fflags}\n]")
        entries = {}
        for line in listing.splitlines():
            name, mode, user, group, flags = line.split("\t")
            entries[name] = (int(mode, 8), flags)
            self.assertEqual((user, group), ("root", "root"), name)
        for name, (mode, _) in entries.items():
            expected = (0o40755 if stat.S_ISDIR(mode) else
                        0o100755 if name.startswith("/usr/bin/") or name.endswith(".so") else 0o100644)
            self.assertEqual(mode, expected, name)
        # Only Maki's own directories: /usr/bin and friends belong to the
        # distribution's filesystem and systemd packages.
        self.assertEqual(sorted(name for name, (mode, _) in entries.items() if stat.S_ISDIR(mode)), [
            "/usr/lib/maki",
            "/usr/share/doc/maki",
            "/usr/share/doc/maki/examples",
            "/usr/share/doc/maki/examples/maki-workload.service.d",
            "/usr/share/doc/maki/examples/maki@.service.d",
            "/usr/share/licenses/maki",
        ])
        # License files survive an installation without documentation.
        for name in ("/usr/share/doc/maki/copyright", "/usr/share/licenses/maki/LICENSE"):
            self.assertIn("l", entries[name][1], name)
        for name, (mode, flags) in entries.items():
            if stat.S_ISREG(mode) and name.startswith(("/usr/share/man/", "/usr/share/doc/maki/examples/")):
                self.assertIn("d", flags, name)

    def test_installed_history_manuals_and_license_texts(self):
        root = payload(self.build(), self.work / "root")
        docs = root / "usr/share/doc/maki"
        self.assertEqual(gzip.decompress((docs / "NEWS.gz").read_bytes()),
                         (ROOT / "CHANGELOG.md").read_bytes())
        self.assertEqual((docs / "copyright").read_bytes(),
                         (ROOT / "packaging/debian/copyright").read_bytes())
        # The Debian notice refers to /usr/share/common-licenses for the
        # Apache-2.0 text; RHEL has no such directory, so the RPM ships it.
        self.assertEqual((root / "usr/share/licenses/maki/LICENSE").read_bytes(),
                         (ROOT / "LICENSE").read_bytes())
        for binary in ("maki", "maki-attach", "maki-check"):
            page = root / "usr/share/man/man8" / f"{binary}.8.gz"
            self.assertEqual(gzip.decompress(page.read_bytes()),
                             (ROOT / "packaging/debian/man" / f"{binary}.8").read_bytes())
        changelog = query(self.build("changelog.rpm"), "[%{CHANGELOGTEXT}\n]")
        self.assertIn("release artifacts", changelog)

    # --- maintainer scripts ----------------------------------------------

    def test_scriptlets_create_users_and_directories_and_never_touch_a_service(self):
        package = self.build()
        post = scriptlet(package, "POSTIN")
        self.assertIn("systemd-sysusers /usr/lib/sysusers.d/maki.conf", post)
        self.assertIn("systemd-tmpfiles --create /usr/lib/tmpfiles.d/maki.conf", post)
        self.assertIn("daemon-reload", post)
        self.assertIn("daemon-reload", scriptlet(package, "POSTUN"))
        self.assertRegex(scriptlet(package, "POSTUN"), r'"\$1" -eq 0', "reload only on erase")
        for tag in ("PREIN", "POSTIN", "PREUN", "POSTUN", "PRETRANS", "POSTTRANS"):
            text = scriptlet(package, tag)
            if text == "(none)":
                continue
            self.assertEqual(query(package, f"%{{{tag}PROG}}"), "/bin/sh", tag)
            path = self.work / f"{tag}.sh"
            path.write_text(text)
            subprocess.run(["sh", "-n", str(path)], check=True)
            for unsafe_action in ("enable", "start", "stop", "restart", "try-restart"):
                self.assertNotRegex(
                    text, rf'(?m)^\s*(?:systemctl|"\$systemctl_bin")\s+{unsafe_action}\b',
                    f"{tag} must not run systemctl {unsafe_action}")

    def test_preun_refuses_removal_while_a_volume_is_attached(self):
        package = self.build()
        state = self.work / "state"
        state.mkdir()
        (state / "pg.nbd").write_text("{}")
        result = self.run_preun(package, 0, state, fake_systemctl(self.work / "systemctl-idle"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("pg", result.stderr)
        message = result.stderr
        self.assertIn("maki-workload@", message, "the message must name the stop procedure")
        self.assertLess(message.index("stop workloads"), message.index("unmount/detach"))
        self.assertLess(message.index("unmount/detach"), message.index("final drain/checkpoint"))

    def test_preun_refuses_removal_while_a_maki_unit_is_active_or_recovering(self):
        package = self.build()
        state = self.work / "state-empty"
        state.mkdir()
        for unit in ("maki@pg.service", "maki-attach@pg.service", "maki-recover@pg.service",
                     "maki-workload@pg.target"):
            with self.subTest(unit=unit):
                result = self.run_preun(package, 0, state,
                                        fake_systemctl(self.work / f"systemctl-{unit}", [unit]))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(unit, result.stderr)

    def test_preun_fails_closed_when_systemd_cannot_be_queried(self):
        package = self.build()
        state = self.work / "state-query"
        state.mkdir()
        broken = self.work / "systemctl-broken"
        broken.write_text("#!/bin/sh\necho 'Failed to connect to bus' >&2\nexit 1\n")
        broken.chmod(0o755)
        result = self.run_preun(package, 0, state, broken)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("systemd", result.stderr)
        self.assertEqual(self.run_preun(package, 1, state, broken).returncode, 0)

    def test_preun_allows_idle_removal_and_never_blocks_an_upgrade(self):
        package = self.build()
        idle = fake_systemctl(self.work / "systemctl-idle")
        busy_systemctl = fake_systemctl(self.work / "systemctl-busy", ["maki-attach@pg.service"])
        empty = self.work / "state-idle"
        empty.mkdir()
        self.assertEqual(self.run_preun(package, 0, empty, idle).returncode, 0)
        self.assertEqual(self.run_preun(package, 0, self.work / "state-missing", idle).returncode, 0)
        busy = self.work / "state-busy"
        busy.mkdir()
        (busy / "pg.nbd").write_text("{}")
        # rpm runs the old package's %preun with 1 when an upgrade replaces it.
        upgrade = self.run_preun(package, 1, busy, busy_systemctl)
        self.assertEqual(upgrade.returncode, 0, upgrade.stderr)

    # --- release artifacts -------------------------------------------------

    def test_package_architecture_must_match_the_elf_binaries(self):
        stderr = self.build_failure("wrong-arch.rpm", architecture="aarch64")
        self.assertIn("aarch64", stderr)
        self.assertIn("x86-64", stderr)
        self.write_release_files(machine=EM_AARCH64)
        aarch64 = self.build("aarch64.rpm", architecture="aarch64")
        self.assertEqual(query(aarch64, "%{ARCH}"), "aarch64")
        self.build_failure("aarch64-as-x86_64.rpm", architecture="x86_64")
        self.write_release_files(machine=0x16, endian="big")
        self.assertEqual(query(self.build("s390x.rpm", architecture="s390x"), "%{ARCH}"), "s390x")

    def test_unknown_architectures_and_debian_names_are_refused(self):
        for architecture in ("amd64", "i686", "armv7hl", "noarch", "vax"):
            with self.subTest(architecture=architecture):
                self.assertIn(architecture, self.build_failure("unknown.rpm", architecture=architecture))

    def test_ppc64le_requires_elfv2_or_an_abi_neutral_marker(self):
        for flags in (0, 2):
            self.write_release_files(EM_PPC64, e_flags=flags)
            self.build(f"ppc64le-{flags}.rpm", architecture="ppc64le")
        self.write_release_files(EM_PPC64, e_flags=1)
        self.assertIn("ELFv2", self.build_failure("elfv1.rpm", architecture="ppc64le"))

    def test_the_debian_builder_artifact_checks_apply(self):
        # The checks are the Debian builder's; these cases show they are wired in.
        (self.release / "maki-check").write_bytes(b"#!/bin/sh\necho not a binary\n")
        self.assertIn("maki-check", self.build_failure("text.rpm"))
        self.write_release_files()
        image = bytearray((self.release / "maki").read_bytes())
        image[7] = 9  # ELFOSABI_FREEBSD
        (self.release / "maki").write_bytes(image)
        error = self.build_failure("freebsd.rpm")
        self.assertIn("OS ABI", error)
        self.assertNotIn("Debian", error)
        self.write_release_files()
        (self.release / "libmaki_nbdkit.so").write_bytes(elf_with_dynamic_flags(EM_X86_64, DF_1_PIE))
        error = self.build_failure("pie-plugin.rpm")
        self.assertIn("PIE", error)
        self.assertTrue(error.startswith("build-rpm: "), error)
        self.write_release_files()
        (self.release / "maki").write_bytes(elf_with_dynamic_flags(EM_X86_64, 1))
        self.assertIn("not a shared library", self.build_failure("shared-cli.rpm"))
        self.write_release_files()
        (self.release / "maki-attach").unlink()
        self.assertIn("maki-attach", self.build_failure("missing.rpm"))

    @unittest.skipUnless(shutil.which("cc"), "a C compiler is required")
    def test_native_package_requires_the_loader_owner_and_its_libraries(self):
        source = self.work / "fixture.c"
        source.write_text("int main(void) { return 0; }\n")
        for name in RELEASE_NAMES:
            # A soname would make rpm provide the plugin as a library.
            options = ["-shared", "-fPIC", f"-Wl,-soname,{name}"] if name.endswith(".so") else []
            subprocess.run(["cc", *options, str(source), "-o", str(self.release / name)], check=True)
        headers = subprocess.check_output(["readelf", "-lW", str(self.release / "maki")], text=True,
                                          env=dict(os.environ, LC_ALL="C"))
        loader = re.search(r"\[Requesting program interpreter: (.+?)\]", headers)[1]
        owner = subprocess.run(["rpm", "-qf", "--queryformat", "%{NAME}", loader],
                               capture_output=True, text=True)
        architecture = subprocess.check_output(["rpm", "--eval", "%{_arch}"], text=True).strip()
        output, command = self.builder_command("native.rpm", architecture=architecture)
        result = subprocess.run(command, cwd=ROOT, env=self.environment, capture_output=True, text=True)
        if owner.returncode:
            # Not an RPM host (or a loader no package owns): refuse rather
            # than build a package whose loader nothing provides.
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("interpreter", result.stderr)
            self.assertFalse(output.exists())
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
            declared = requires(output)
            self.assertIn(owner.stdout, declared)
            self.assertTrue(any(entry.startswith("libc.so.6") for entry in declared), declared)
            provides = query(output, "[%{PROVIDES}\n]").split()
            self.assertFalse([name for name in provides if ".so" in name], provides)
        private = self.work / "ld-private.so.2"
        private.symlink_to("/bin/true")
        subprocess.run(["cc", str(source), f"-Wl,--dynamic-linker,{private}",
                        "-o", str(self.release / "maki-check")], check=True)
        error = self.build_failure("private-loader.rpm", architecture=architecture, opt_out=False)
        self.assertIn("interpreter", error)
        if not owner.returncode:
            self.assertIn(f"maki-check interpreter '{private}'", error)

    def test_opting_out_of_automatic_requirements_keeps_the_static_requires_and_warns(self):
        output, command = self.builder_command("opt-out.rpm", extra=["--no-autoreq"])
        result = subprocess.run(command, cwd=ROOT, env=self.environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--no-autoreq", result.stderr)
        self.assertIn("native library dependencies", result.stderr)
        declared = [entry for entry in requires(output)
                    if not entry.startswith("rpmlib(") and entry != "/bin/sh"]
        self.assertEqual(sorted(set(declared)),
                         sorted(set(STATIC_REQUIRES + ["systemd", "coreutils", "gawk"])))

    # --- version, reproducibility and output -------------------------------

    def test_versions_rpm_cannot_express_are_refused(self):
        for version in ("", "1.0-1", "1:1.0", "1 0", "~rc1", "1.0/../x", "1.0\n"):
            with self.subTest(version=version):
                self.assertIn("version", self.build_failure("bad-version.rpm", version=version))
        for release in ("", "1-2", "a b"):
            with self.subTest(release=release):
                self.assertIn("release", self.build_failure("bad-release.rpm",
                                                            extra=["--release", release]))

    def test_candidate_versions_keep_their_order_in_rpm(self):
        # docs/releasing.md: descendants increase, candidates sort below the
        # final workspace version.
        ordered = ["0.1.0~rc+rev9.gitbbbbbbbbbbbb", "0.1.0~rc+rev10.gitaaaaaaaaaaaa", "0.1.0",
                   "0.1.1~rc+rev11.gitcccccccccccc"]
        for older, newer in zip(ordered, ordered[1:]):
            with self.subTest(older=older, newer=newer):
                compared = subprocess.check_output(
                    ["rpm", "--eval", f'%{{lua: print(rpm.vercmp("{older}", "{newer}"))}}'], text=True)
                self.assertEqual(compared.strip(), "-1")
        self.assertEqual(query(self.build("final.rpm", version="0.1.0"), "%{VERSION}"), "0.1.0")

    def test_build_is_reproducible(self):
        first = self.build("first.rpm")
        second = self.build("second.rpm")
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(digest(first), digest(second))
        self.assertEqual(query(first, "%{BUILDTIME} %{BUILDHOST}"), f"{EPOCH} reproducible")
        times = set(query(first, "[%{FILEMTIMES}\n]").split())
        self.assertEqual(times, {EPOCH})

    def test_source_date_epoch_must_be_given_and_datable_by_rpm(self):
        # The build time, file times and the changelog entry come from it.
        # rpm refuses a changelog year before 1990 ("bad date") and still
        # writes a package without the entry, so such an epoch, and a build
        # without one, is refused before rpmbuild runs.
        for index, value in enumerate((None, "", "soon", "-1", "0", "631151999")):
            with self.subTest(value=value):
                self.environment = dict(os.environ)
                self.environment.pop("SOURCE_DATE_EPOCH", None)
                if value is not None:
                    self.environment["SOURCE_DATE_EPOCH"] = value
                self.assertIn("SOURCE_DATE_EPOCH", self.build_failure(f"epoch-{index}.rpm"))
        self.environment["SOURCE_DATE_EPOCH"] = "631152000"  # 1990-01-01T00:00:00Z
        package = self.build("1990.rpm")
        self.assertIn("* Mon Jan 01 1990 ", query(package, "[* %{CHANGELOGTIME:day} %{CHANGELOGNAME}\n]"))
        self.assertEqual(query(package, "%{BUILDTIME}"), "631152000")

    def test_output_cannot_replace_a_required_release_input(self):
        for name in RELEASE_NAMES:
            original = (self.release / name).read_bytes()
            with self.subTest(name=name):
                _, command = self.builder_command(self.release / name, extra=["--no-autoreq"])
                result = subprocess.run(command, env=self.environment, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("overwrite a release input", result.stderr)
                self.assertEqual((self.release / name).read_bytes(), original)
        self.assertEqual(query(self.build("release/maki.rpm"), "%{NAME}"), "maki")

    def test_rebuild_replaces_the_directory_entry_after_output_is_complete(self):
        output = self.work / "maki.rpm"
        output.write_bytes(b"previous package")
        previous = self.work / "previous.rpm"
        os.link(output, previous)
        self.build()
        self.assertEqual(previous.read_bytes(), b"previous package")
        self.assertEqual(query(output, "%{NAME}"), "maki")

    def test_build_succeeds_with_restrictive_caller_umask(self):
        package = self.build(umask=0o077)
        for line in query(package, "[%{FILEMODES:octal} %{FILENAMES}\n]").splitlines():
            mode, name = line.split(" ", 1)
            self.assertIn(int(mode, 8) & 0o777, (0o755, 0o644), name)


@unittest.skipUnless(shutil.which("dpkg-deb") or os.environ.get(REQUIRE_DPKG_DEB) == "1",
                     "dpkg-deb is required to compare with the Debian package")
class SameFilesAsTheDebianPackage(unittest.TestCase):
    """Both packages are built from the same artifacts and checkout."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        work = pathlib.Path(cls.temp.name)
        release = work / "release"
        release.mkdir()
        for name in RELEASE_NAMES:
            (release / name).write_bytes(elf_stub(EM_X86_64, ET_DYN if name.endswith(".so") else ET_EXEC)
                                         + f"artifact:{name}\n".encode())
            (release / name).chmod(0o755)
        environment = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH)
        common = ["--release-dir", str(release), "--version", VERSION]
        cls.deb = work / "maki.deb"
        cls.rpm = work / "maki.rpm"
        subprocess.run(["python3", "-B", str(DEB_BUILDER), *common, "--architecture", "amd64",
                        "--output", str(cls.deb), "--no-shlibdeps"],
                       env=environment, check=True, capture_output=True)
        subprocess.run(["python3", "-B", str(BUILDER), *common, "--architecture", "x86_64",
                        "--output", str(cls.rpm), "--no-autoreq"],
                       env=environment, check=True, capture_output=True)
        cls.deb_root = work / "deb"
        subprocess.run(["dpkg-deb", "--extract", str(cls.deb), str(cls.deb_root)], check=True)
        cls.deb_control = work / "deb-control"
        subprocess.run(["dpkg-deb", "--control", str(cls.deb), str(cls.deb_control)], check=True)
        cls.rpm_root = payload(cls.rpm, work / "rpm")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_both_packages_install_the_same_files_with_the_same_modes(self):
        deb = {name: entry for name, entry in tree(self.deb_root).items() if entry[0] == "file"}
        rpm = {name: entry for name, entry in tree(self.rpm_root).items() if entry[0] == "file"}
        # Format-specific records: Debian's changelog of the package itself;
        # RHEL has no /usr/share/common-licenses for the notice to point to,
        # and dnf, unlike apt, goes on with a removal that %preun refused.
        self.assertEqual(sorted(set(deb) - set(rpm)), ["usr/share/doc/maki/changelog.Debian.gz"])
        self.assertEqual(sorted(set(rpm) - set(deb)),
                         ["etc/dnf/protected.d/maki.conf", "usr/share/licenses/maki/LICENSE"])
        unit = "usr/lib/systemd/system/maki@.service"
        for name in sorted(set(deb) & set(rpm)):
            with self.subTest(name=name):
                deb_kind, deb_mode, deb_bytes = deb[name]
                rpm_kind, rpm_mode, rpm_bytes = rpm[name]
                self.assertEqual(deb_mode, rpm_mode)
                if name == unit:
                    deb_bytes = deb_bytes.replace(DEBIAN_NBDKIT.encode(), RPM_NBDKIT.encode())
                self.assertEqual(deb_bytes, rpm_bytes)

    def test_both_packages_record_root_ownership(self):
        listing = subprocess.run(["dpkg-deb", "--contents", str(self.deb)], check=True,
                                 capture_output=True, text=True).stdout
        self.assertEqual({line.split()[1] for line in listing.splitlines()}, {"root/root"})
        owners = set(query(self.rpm, "[%{FILEUSERNAME}:%{FILEGROUPNAME}\n]").split())
        self.assertEqual(owners, {"root:root"})

    def test_both_packages_refuse_removal_with_the_same_check(self):
        prerm = (self.deb_control / "prerm").read_text()
        preun = scriptlet(self.rpm, "PREUN")
        rpm = busy_check(preun, 'if [ "$1" -eq 0 ]; then', "fi")
        self.assertGreater(len(rpm), 20)
        self.assertEqual(rpm, busy_check(prerm, "    remove|deconfigure)", "        ;;"))

    def test_both_packages_declare_the_same_runtime_components(self):
        depends = subprocess.run(["dpkg-deb", "--field", str(self.deb), "Depends"], check=True,
                                 capture_output=True, text=True).stdout.strip()
        # Debian names nbdkit `nbdkit`; RHEL 9's /usr/sbin/nbdkit is in
        # nbdkit-server. nbd-client is not used on either.
        deb = {entry.split()[0] for entry in depends.split(", ") if not entry.startswith("nbd-client")}
        rpm = {entry.split()[0] for entry in STATIC_REQUIRES}
        self.assertEqual({"nbdkit-server" if name == "nbdkit" else name for name in deb}, rpm)


if __name__ == "__main__":
    unittest.main()
