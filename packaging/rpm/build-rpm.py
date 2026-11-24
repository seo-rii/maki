#!/usr/bin/env python3
"""Build a deterministic RPM package for RHEL 9 from Maki release artifacts."""

import argparse
import importlib.util
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = ROOT / "packaging/rpm/maki.spec"
PACKAGER = "Maki Developers <me@seorii.page>"


def load_debian_builder():
    """The Debian builder owns the artifact table and the ELF checks; the RPM
    installs the same files and refuses the same artifacts."""
    path = ROOT / "packaging/debian/build-deb.py"
    spec = importlib.util.spec_from_file_location("maki_build_deb", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DEB = load_debian_builder()

# RPM architecture -> the Debian architecture with the same ELF identity.
# These are the architectures RHEL 9 is built for.
RPM_ARCHITECTURES = {
    "x86_64": "amd64",
    "aarch64": "arm64",
    "ppc64le": "ppc64el",
    "s390x": "s390x",
}
# rpm refuses '-' (it separates the release) and ':' (the epoch) in a version.
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~^]*")
# The checked-in unit names Debian's nbdkit. RHEL 9 installs nbdkit as
# /usr/sbin/nbdkit (package nbdkit-server). The unit keeps an absolute path:
# systemd resolves a bare name through /usr/local/sbin and /usr/local/bin
# first, so a binary there would receive the volume's crypto credential.
DEBIAN_NBDKIT = "ExecStart=/usr/bin/nbdkit \\"
RPM_NBDKIT = "ExecStart=/usr/sbin/nbdkit \\"
# The license text the Debian notice points to under /usr/share/common-licenses.
LICENSE = "usr/share/licenses/maki/LICENSE"
# rpm refuses a changelog year before 1990 ("bad date in %changelog") and still
# writes the package, without the entry.
OLDEST_CHANGELOG = 631152000  # 1990-01-01T00:00:00Z
DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def fail(message):
    raise SystemExit(f"build-rpm: {message}")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--release", default="1",
                        help="the RPM release of this version (default 1)")
    parser.add_argument("--architecture", required=True,
                        help="RPM architecture: " + ", ".join(RPM_ARCHITECTURES))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--autoreq",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="let rpm add the binaries' shared-library requirements and require "
        "the build host package that owns their ELF interpreter (default; fails "
        "the build if the interpreter is not a packaged loader). --no-autoreq "
        "keeps only the static Requires and is meant for test fixtures, not for "
        "packages that will be installed",
    )
    return parser.parse_args()


def from_debian_builder(function, *arguments):
    """Run one of the Debian builder's checks and report its refusal as ours."""
    try:
        return function(*arguments)
    except SystemExit as refusal:
        message = str(refusal.code)
        fail(message[len("build-deb: "):] if message.startswith("build-deb: ") else message)


def validate_release_files(args):
    machine, elf_class, endian = DEB.ELF_ARCHITECTURES[RPM_ARCHITECTURES[args.architecture]]
    interpreters = {}
    for source_name in DEB.RELEASE_FILES:
        path = args.release_dir / source_name
        if not path.is_file() or path.is_symlink():
            fail(f"required regular file is missing: {source_name}")
        with path.open("rb") as handle:
            ident = handle.read(8)
        if len(ident) == 8 and ident[:4] == b"\x7fELF" and ident[7] not in (0, 3):
            fail(f"{source_name} declares ELF OS ABI {ident[7]}, incompatible with Linux")
        e_type, e_machine, file_class, file_endian, e_flags = from_debian_builder(DEB.inspect_elf, path)
        if (e_machine, file_class, file_endian) != (machine, elf_class, endian):
            fail(
                f"{source_name} is {DEB.describe(e_machine, file_class, file_endian)} but the "
                f"package architecture is {args.architecture} "
                f"({DEB.describe(machine, elf_class, endian)})"
            )
        if args.architecture == "ppc64le" and e_flags & DEB.EF_PPC64_ABI not in (0, 2):
            fail(f"{source_name} must be ABI-neutral or use ELFv2 for ppc64le")
        entry_point, interpreter, pie = from_debian_builder(
            DEB.inspect_loader, path, file_class, file_endian, args.architecture)
        if source_name in DEB.SHARED_OBJECTS:
            if e_type != DEB.ET_DYN:
                fail(f"{source_name} must be an ELF shared object (ET_DYN), found type {e_type}")
            from_debian_builder(DEB.validate_shared_object, path, interpreter, pie)
        elif e_type not in (DEB.ET_EXEC, DEB.ET_DYN):
            fail(f"{source_name} must be an ELF executable (ET_EXEC or PIE), found type {e_type}")
        else:
            from_debian_builder(DEB.validate_executable, path, e_type, entry_point, interpreter, pie)
            if interpreter:
                interpreters.setdefault(interpreter, source_name)
    return interpreters


def loader_dependencies(interpreters):
    """rpm's ELF dependency generator reads DT_NEEDED but not PT_INTERP, so a
    private loader path would still yield an installable package. Require the
    package that owns each loader in this build host's RPM database."""
    owners = set()
    for spelling, source in interpreters.items():
        query = subprocess.run(["rpm", "-qf", "--queryformat", "%{NAME}\\n", spelling],
                               capture_output=True, text=True)
        names = set(query.stdout.split())
        # The kernel opens the original spelling; a directory-only suffix on a
        # valid loader is an error even though rpm may normalize it away.
        if (query.returncode or len(names) != 1
                or not os.path.isfile(spelling) or not os.access(spelling, os.X_OK)):
            fail(f"{source} interpreter {spelling!r} is not a packaged runtime loader on "
                 "this build host (build the package on the target distribution)")
        owners.update(names)
    return owners


def validate(args):
    if not args.release_dir.is_dir():
        fail(f"release directory does not exist: {args.release_dir}")
    if args.output.name in DEB.RELEASE_FILES:
        output_parent = args.output.parent.resolve()
        if output_parent.is_dir() and output_parent.samefile(args.release_dir):
            fail(f"output would overwrite a release input: {args.output}")
    for name, value in (("version", args.version), ("release", args.release)):
        if not VERSION.fullmatch(value):
            fail(f"invalid RPM {name} {value!r}: use letters, digits and . _ + ~ ^, "
                 "starting with a letter or digit")
    if args.architecture not in RPM_ARCHITECTURES:
        fail(f"unknown RPM architecture {args.architecture!r}: expected one of "
             + ", ".join(RPM_ARCHITECTURES))
    interpreters = validate_release_files(args)
    if shutil.which("rpmbuild") is None:
        fail("building the package requires rpmbuild (package rpm-build)")
    if not args.autoreq:
        print(
            "build-rpm: warning: --no-autoreq: Requires omits the binaries' native "
            "library dependencies",
            file=sys.stderr,
        )
    if "SOURCE_DATE_EPOCH" not in os.environ:
        fail("set SOURCE_DATE_EPOCH to the source's timestamp (for example the commit time): "
             "the build time, the file times and the changelog entry come from it")
    try:
        epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    except ValueError:
        fail("SOURCE_DATE_EPOCH must be an integer")
    if epoch < OLDEST_CHANGELOG:
        fail(f"SOURCE_DATE_EPOCH must not be before 1990-01-01 ({OLDEST_CHANGELOG}): rpm "
             "cannot date a changelog entry earlier")
    owners = loader_dependencies(interpreters) if args.autoreq else set()
    return epoch, owners


def daemon_unit():
    unit = (ROOT / "packaging/systemd/maki@.service").read_text(encoding="utf-8")
    lines = unit.split("\n")
    if [line for line in lines if line.startswith("ExecStart=")] != [DEBIAN_NBDKIT]:
        fail(f"maki@.service must have exactly one ExecStart=, the line {DEBIAN_NBDKIT!r}")
    return "\n".join(RPM_NBDKIT if line == DEBIAN_NBDKIT else line for line in lines)


def create_tree(package_root, args):
    """Stage the files the Debian package installs, at the same paths."""
    for source_name, installed_name in DEB.RELEASE_FILES.items():
        DEB.install_file(args.release_dir / source_name, package_root / installed_name, 0o755)
    units = package_root / "usr/lib/systemd/system"
    for unit in DEB.SYSTEMD_UNITS:
        DEB.install_file(ROOT / "packaging/systemd" / unit, units / unit, 0o644)
    DEB.write_file(units / "maki@.service", daemon_unit(), 0o644)
    DEB.install_file(ROOT / "packaging/sysusers.d/maki.conf",
                     package_root / "usr/lib/sysusers.d/maki.conf", 0o644)
    DEB.install_file(ROOT / "packaging/tmpfiles.d/maki.conf",
                     package_root / "usr/lib/tmpfiles.d/maki.conf", 0o644)
    for example in DEB.EXAMPLE_FILES:
        DEB.install_file(ROOT / "packaging/examples" / example,
                         package_root / "usr/share/doc/maki/examples" / example, 0o644)
    DEB.install_file(ROOT / "packaging/debian/copyright",
                     package_root / "usr/share/doc/maki/copyright", 0o644)
    DEB.install_file(ROOT / "LICENSE", package_root / LICENSE, 0o644)
    DEB.install_gzip((ROOT / "CHANGELOG.md").read_bytes(), package_root / "usr/share/doc/maki/NEWS.gz")
    for name in ("maki", "maki-attach", "maki-check"):
        page = ROOT / "packaging/debian/man" / f"{name}.8"
        DEB.install_gzip(page.read_bytes(), package_root / "usr/share/man/man8" / f"{name}.8.gz")


def changelog_date(epoch):
    moment = time.gmtime(epoch)
    return f"{DAYS[moment.tm_wday]} {MONTHS[moment.tm_mon - 1]} {moment.tm_mday:02d} {moment.tm_year}"


def build(stage, top, args, epoch, owners):
    defines = {
        "_topdir": str(top),
        "maki_version": args.version,
        "maki_release": args.release,
        "maki_stage": str(stage),
        "maki_autoreq": "1" if args.autoreq else "0",
        "maki_changelog_date": changelog_date(epoch),
        # Reproducible headers and payload: the build time and every file
        # time come from SOURCE_DATE_EPOCH, and the host name is fixed.
        "use_source_date_epoch_as_buildtime": "1",
        "clamp_mtime_to_source_date_epoch": "1",
        "_buildhost": "reproducible",
    }
    if owners:
        defines["maki_loader_requires"] = ", ".join(sorted(owners))
    command = ["rpmbuild", "-bb", "--quiet", "--target", args.architecture]
    for name, value in defines.items():
        command += ["--define", f"{name} {value}"]
    command.append(str(SPEC))
    subprocess.run(command, env={**os.environ, "SOURCE_DATE_EPOCH": str(epoch), "LC_ALL": "C"},
                   check=True)
    built = top / "RPMS" / args.architecture / f"maki-{args.version}-{args.release}.{args.architecture}.rpm"
    if not built.is_file():
        fail(f"rpmbuild did not write {built.name}")
    return built


def main():
    args = parse_args()
    epoch, owners = validate(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="maki-rpm-") as temporary:
        work = pathlib.Path(temporary)
        stage = work / "root"
        stage.mkdir(mode=0o755)
        create_tree(stage, args)
        DEB.normalize_directory_permissions(stage)
        DEB.normalize_timestamps(stage, epoch)
        built = build(stage, work / "rpmbuild", args, epoch, owners)
        with tempfile.TemporaryDirectory(prefix=".maki-rpm-", dir=args.output.parent) as staging:
            temporary_output = pathlib.Path(staging) / "maki.rpm"
            shutil.copyfile(built, temporary_output)
            temporary_output.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
            temporary_output.replace(args.output)
    print(args.output)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        fail(f"command failed with exit {error.returncode}: {error.cmd}")
