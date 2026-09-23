#!/usr/bin/env python3
"""Build a deterministic Debian package from Maki release artifacts."""

import argparse
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
RELEASE_FILES = {
    "maki": "usr/bin/maki",
    "maki-attach": "usr/bin/maki-attach",
    "maki-check": "usr/bin/maki-check",
    "libmaki_nbdkit.so": "usr/lib/maki/maki-nbdkit.so",
}
SHARED_OBJECTS = {"libmaki_nbdkit.so"}

# ELF identity a Debian architecture's binaries must carry:
# (e_machine, ELF class, byte order). The builder refuses an artifact that
# does not match the requested `--architecture` (R4-007: an x86-64 file used
# to become a "valid" arm64 package).
ELF_ARCHITECTURES = {
    "amd64": (0x3E, 64, "little"),
    "arm64": (0xB7, 64, "little"),
    "i386": (0x03, 32, "little"),
    "armhf": (0x28, 32, "little"),
    "armel": (0x28, 32, "little"),
    "ppc64el": (0x15, 64, "little"),
    "s390x": (0x16, 64, "big"),
    "riscv64": (0xF3, 64, "little"),
    "mips64el": (0x08, 64, "little"),
    "loong64": (0x102, 64, "little"),
}
ELF_MACHINE_NAMES = {
    0x03: "x86 (i386)",
    0x08: "MIPS",
    0x15: "PowerPC64",
    0x16: "IBM S/390",
    0x28: "ARM",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
    0x102: "LoongArch",
}
ET_REL, ET_EXEC, ET_DYN = 1, 2, 3


def fail(message):
    raise SystemExit(f"build-deb: {message}")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--shlibdeps",
        action="store_true",
        help="compute native library dependencies of the release artifacts with "
        "dpkg-shlibdeps and add them to Depends (fails the build if the scan fails)",
    )
    return parser.parse_args()


def inspect_elf(path):
    """Return (e_type, e_machine, class, byte order) of an ELF file, or fail."""
    with path.open("rb") as handle:
        header = handle.read(64)
    if len(header) < 52 or header[:4] != b"\x7fELF":
        fail(f"{path.name} is not an ELF image")
    elf_class = {1: 32, 2: 64}.get(header[4])
    endian = {1: "little", 2: "big"}.get(header[5])
    if elf_class is None or endian is None:
        fail(f"{path.name} has an unsupported ELF class or byte order")
    if elf_class == 64 and len(header) < 64:
        fail(f"{path.name} has a truncated ELF64 header")
    order = "<" if endian == "little" else ">"
    e_type, e_machine = struct.unpack(f"{order}HH", header[16:20])
    return e_type, e_machine, elf_class, endian


def describe(e_machine, elf_class, endian):
    name = ELF_MACHINE_NAMES.get(e_machine, f"machine 0x{e_machine:x}")
    return f"{name}, {elf_class}-bit {endian}-endian"


def validate_release_files(args):
    expected = ELF_ARCHITECTURES.get(args.architecture)
    if expected is None:
        fail(
            f"unknown Debian architecture {args.architecture!r}: add its ELF machine "
            "identity to ELF_ARCHITECTURES before packaging for it"
        )
    machine, elf_class, endian = expected
    for source_name in RELEASE_FILES:
        path = args.release_dir / source_name
        if not path.is_file() or path.is_symlink():
            fail(f"required regular file is missing: {source_name}")
        e_type, e_machine, file_class, file_endian = inspect_elf(path)
        if (e_machine, file_class, file_endian) != (machine, elf_class, endian):
            fail(
                f"{source_name} is {describe(e_machine, file_class, file_endian)} but the "
                f"package architecture is {args.architecture} "
                f"({describe(machine, elf_class, endian)})"
            )
        if source_name in SHARED_OBJECTS:
            if e_type != ET_DYN:
                fail(f"{source_name} must be an ELF shared object (ET_DYN), found type {e_type}")
        elif e_type not in (ET_EXEC, ET_DYN):
            fail(f"{source_name} must be an ELF executable (ET_EXEC or PIE), found type {e_type}")


def shared_library_dependencies(package_root):
    """`dpkg-shlibdeps` needs a source tree with debian/control; give it a
    minimal one and read the substvar it prints with -O."""
    binaries = [package_root / installed for installed in RELEASE_FILES.values()]
    with tempfile.TemporaryDirectory(prefix="maki-shlibdeps-") as temporary:
        source = pathlib.Path(temporary)
        write_file(
            source / "debian/control",
            "Source: maki\nMaintainer: Maki Developers\n\nPackage: maki\nArchitecture: any\n",
            0o644,
        )
        result = subprocess.run(
            ["dpkg-shlibdeps", "-O", *(str(binary) for binary in binaries)],
            cwd=source,
            capture_output=True,
            text=True,
        )
    if result.returncode:
        fail(
            "dpkg-shlibdeps failed to analyse the release artifacts; refusing to guess "
            f"native dependencies:\n{result.stderr.strip()}"
        )
    for line in result.stdout.splitlines():
        if line.startswith("shlibs:Depends="):
            value = line.split("=", 1)[1].strip()
            return [entry.strip() for entry in value.split(",") if entry.strip()]
    fail("dpkg-shlibdeps printed no shlibs:Depends line")


def install_file(source, destination, mode):
    if not source.is_file() or source.is_symlink():
        fail(f"required regular file is missing: {source.name}")
    # Release binaries were validated in validate_release_files.
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def write_file(path, contents, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    path.chmod(mode)


def validate(args):
    if not args.release_dir.is_dir():
        fail(f"release directory does not exist: {args.release_dir}")
    version = subprocess.run(
        ["dpkg", "--validate-version", args.version],
        capture_output=True,
        text=True,
    )
    if version.returncode:
        fail(version.stderr.strip() or "invalid Debian version")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.architecture):
        fail(f"invalid Debian architecture: {args.architecture}")
    validate_release_files(args)
    if args.shlibdeps and shutil.which("dpkg-shlibdeps") is None:
        fail("--shlibdeps requires dpkg-shlibdeps (package dpkg-dev)")
    try:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    except ValueError:
        fail("SOURCE_DATE_EPOCH must be an integer")
    if epoch < 0:
        fail("SOURCE_DATE_EPOCH must not be negative")
    return epoch


def create_tree(package_root, args):
    for source_name, installed_name in RELEASE_FILES.items():
        install_file(
            args.release_dir / source_name,
            package_root / installed_name,
            0o755,
        )

    for source in sorted((ROOT / "packaging/systemd").iterdir()):
        if source.is_file():
            install_file(source, package_root / "usr/lib/systemd/system" / source.name, 0o644)
    install_file(
        ROOT / "packaging/sysusers.d/maki.conf",
        package_root / "usr/lib/sysusers.d/maki.conf",
        0o644,
    )
    install_file(
        ROOT / "packaging/tmpfiles.d/maki.conf",
        package_root / "usr/lib/tmpfiles.d/maki.conf",
        0o644,
    )
    for source in sorted((ROOT / "packaging/examples").rglob("*")):
        if source.is_file():
            relative = source.relative_to(ROOT / "packaging/examples")
            install_file(source, package_root / "usr/share/doc/maki/examples" / relative, 0o644)

    depends = ["nbd-client (>= 1:3.27.0)", "nbdkit", "lvm2", "xfsprogs", "util-linux", "systemd"]
    if args.shlibdeps:
        for entry in shared_library_dependencies(package_root):
            if entry not in depends:
                depends.append(entry)
    control = f"""Package: maki
Version: {args.version}
Section: admin
Priority: optional
Architecture: {args.architecture}
Maintainer: Maki Developers
Depends: {", ".join(depends)}
Description: encrypted block storage daemon and recovery controller
 Maki exposes encrypted backing storage through nbdkit and provides a
 fail-closed privileged helper for NBD, LVM, XFS, and workload recovery.
"""
    postinst = """#!/bin/sh
set -e
if [ "$1" = configure ]; then
    systemd-sysusers /usr/lib/sysusers.d/maki.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/maki.conf
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
    fi
fi
exit 0
"""
    # Removal refuses while any volume is attached (R4-003): the helper the
    # lifecycle needs for cleanup is part of this package, so removing it
    # under a live attachment would leave the operator without a normal
    # detach path. Upgrades are deliberately exempt: the operator detaches
    # with the old helper as part of the documented maintenance procedure,
    # and a running attachment must never be stopped by a package script.
    prerm = """#!/bin/sh
set -e
case "$1" in
    remove|deconfigure)
        state_dir="${MAKI_ATTACH_STATE_DIR:-/run/maki-attach}"
        systemctl_bin="${MAKI_SYSTEMCTL:-systemctl}"
        busy=""
        for record in "$state_dir"/*.nbd; do
            if [ -e "$record" ]; then
                busy="$busy attachment-record:$(basename "$record" .nbd)"
            fi
        done
        if [ -n "${MAKI_SYSTEMCTL:-}" ] || [ -d /run/systemd/system ]; then
            units=$("$systemctl_bin" list-units --plain --no-legend \\
                --state=active,activating,reloading,deactivating \\
                'maki@*.service' 'maki-attach@*.service' 'maki-workload@*.target' \\
                2>/dev/null | awk '{print $1}' || true)
            for unit in $units; do
                busy="$busy unit:$unit"
            done
        fi
        if [ -n "$busy" ]; then
            echo "maki: refusing to remove the package while volumes are attached:$busy" >&2
            echo "maki: for each volume run 'maki drain <config>' after the workload has" \\
                "quiesced, deactivate its lifecycle target maki-workload@<volume>.target," \\
                "wait for maki-attach@ and maki@ to become inactive, and retry the removal" >&2
            exit 1
        fi
        ;;
esac
exit 0
"""
    postrm = """#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
    fi
fi
exit 0
"""
    write_file(package_root / "DEBIAN/control", control, 0o644)
    write_file(package_root / "DEBIAN/postinst", postinst, 0o755)
    write_file(package_root / "DEBIAN/prerm", prerm, 0o755)
    write_file(package_root / "DEBIAN/postrm", postrm, 0o755)


def normalize_timestamps(root, epoch):
    paths = sorted(root.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for path in paths + [root]:
        os.utime(path, (epoch, epoch), follow_symlinks=False)


def normalize_directory_permissions(root):
    root.chmod(0o755)
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)


def main():
    args = parse_args()
    epoch = validate(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="maki-deb-") as temporary:
        package_root = pathlib.Path(temporary) / "root"
        package_root.mkdir(mode=0o755)
        (package_root / "DEBIAN").mkdir(mode=0o755)
        create_tree(package_root, args)
        normalize_directory_permissions(package_root)
        normalize_timestamps(package_root, epoch)
        temporary_output = pathlib.Path(temporary) / "maki.deb"
        subprocess.run(
            [
                "dpkg-deb",
                "--build",
                "--root-owner-group",
                str(package_root),
                str(temporary_output),
            ],
            check=True,
        )
        shutil.copyfile(temporary_output, args.output)
        args.output.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    print(args.output)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        fail(f"command failed with exit {error.returncode}: {error.cmd}")
