#!/usr/bin/env python3
"""Refresh the checked-in Debian notice from the release crates' locked sources."""

import collections
import json
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("maki", "maki-attach", "maki-check", "maki-nbdkit")
TARGETS = (
    "x86_64-unknown-linux-gnu", "i686-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "armv7-unknown-linux-gnueabihf", "arm-unknown-linux-gnueabi", "powerpc64le-unknown-linux-gnu",
    "s390x-unknown-linux-gnu", "riscv64gc-unknown-linux-gnu", "mips64el-unknown-linux-gnuabi64",
    "loongarch64-unknown-linux-gnu",
)
NOTICE = re.compile(r"(?:licen[sc]e|copying|copyright|notice|unlicense)(?:[.-][\w.-]+)?", re.I)
HEADER = """Maki
Upstream authors: Maki Developers
Source: https://github.com/seo-rii/maki
Contact: https://github.com/seo-rii/maki/issues

Maki's own source is distributed under the Apache License, Version 2.0.
Debian systems provide the full text in /usr/share/common-licenses/Apache-2.0.

Third-party components retain their respective licenses. The entries below
collect the notices in the locked Cargo dependencies of the packaged binaries
and plugin across the Debian Linux targets. Identical texts are printed once.
"""


def cargo(*args):
    return subprocess.check_output(["cargo", *args, "--locked"], text=True, cwd=ROOT)


def notice_files(source, license_file, *, tracked):
    if tracked:
        # Path patches share the working tree with local notes and build
        # products. Only tracked files can accompany the source release.
        names = subprocess.check_output(["git", "ls-files", "-z", "--", "."], cwd=source)
        candidates = {source / os.fsdecode(name) for name in names.split(b"\0") if name}
    else:
        candidates = (Path(directory) / name for directory, _, names in os.walk(source)
                      for name in names if NOTICE.fullmatch(name))
    notices = {path for path in candidates if NOTICE.fullmatch(path.name)}
    if license_file:
        declared = source / license_file
        if tracked and declared not in candidates:
            raise ValueError(f"declared license file is not tracked: {declared}")
        notices.add(declared)
    return notices


def render():
    selection = [arg for package in PACKAGES for arg in ("-p", package)]
    platforms = [arg for target in TARGETS for arg in ("--target", target)]
    tree = cargo("tree", "--edges", "normal", "--prefix", "none", "--format", "{p}",
                 *selection, *platforms)
    versions = {tuple(line.split()[:2]) for line in tree.splitlines()}
    metadata = json.loads(cargo("metadata", "--format-version", "1"))
    texts = collections.defaultdict(list)
    for package in metadata["packages"]:
        name, version = package["name"], package["version"]
        if (name, "v" + version) not in versions or package["id"] in metadata["workspace_members"]:
            continue
        source = Path(package["manifest_path"]).parent
        files = notice_files(source, package["license_file"],
                             tracked=package["source"] is None and source.is_relative_to(ROOT))
        if not files:
            raise ValueError(f"Review the license notice for {name} {version}")
        for path in sorted(files):
            body = "\n".join(line.rstrip() for line in path.read_text(encoding="utf-8").splitlines()).strip()
            texts[body].append(f"{name} {version} — {path.relative_to(source).as_posix()}")
    blocks = []
    for body, entries in sorted(texts.items(), key=lambda item: min(item[1])):
        blocks.append("\n".join(sorted(entries)) + "\n\n" + body)
    return HEADER + "\n" + ("\n\n" + "-" * 72 + "\n\n").join(blocks) + "\n"


if __name__ == "__main__":
    (ROOT / "packaging/debian/copyright").write_text(render(), encoding="utf-8")
