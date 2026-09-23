#!/usr/bin/env python3
"""Build a deterministic Debian package from Maki release artifacts."""

import argparse
import os
import pathlib
import re
import shutil
import stat
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


def fail(message):
    raise SystemExit(f"build-deb: {message}")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    return parser.parse_args()


def install_file(source, destination, mode):
    if not source.is_file() or source.is_symlink():
        fail(f"required regular file is missing: {source.name}")
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

    control = f"""Package: maki
Version: {args.version}
Section: admin
Priority: optional
Architecture: {args.architecture}
Maintainer: Maki Developers
Depends: nbd-client (>= 1:3.27.0), nbdkit, lvm2, xfsprogs, util-linux, systemd
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
