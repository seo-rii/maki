#!/usr/bin/env python3
"""Fail when a Markdown file links to a repository path that does not exist.

Documentation is reorganized by reader task, so relative links move. This check
checks every `[text](path)` link in tracked and nonignored new Markdown files.
Only byte-identical vendor documents recorded in vendor/upstream.json may
reference package-internal paths omitted from the published archive. Missing
published files/directories and links in edited or project documents still fail.
External URLs, mail links and pure in-page anchors are not checked; heading
anchors inside other files are not verified either.

Usage: python3 -B scripts/check_docs_links.py [repository-root]
"""

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

LINK = re.compile(r"(?<!\\)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def candidate_markdown(root):
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others",
         "--exclude-standard", "-z", "--", "*.md", "**/*.md"],
        capture_output=True,
        check=True,
    )
    names = {name for name in listing.stdout.decode("utf-8").split("\0") if name}
    return sorted(root / name for name in names)


def omitted_archive_reference(root, document, content, target, packages):
    """Accept only an unchanged archive's unpublished package-local target."""
    parts = document.relative_to(root).parts
    if len(parts) < 3 or parts[0] != "vendor":
        return False
    files = packages.get(parts[1], {}).get("upstream_files", {})
    document_name = pathlib.PurePosixPath(*parts[2:]).as_posix()
    if files.get(document_name) != hashlib.sha256(content).hexdigest():
        return False
    archive_root = root / "vendor" / parts[1]
    try:
        requested = pathlib.Path(os.path.abspath(target)).relative_to(archive_root).as_posix()
        resolved = target.resolve().relative_to(archive_root.resolve()).as_posix()
    except ValueError:
        return False
    # Inventories list files, not directories. A missing directory containing
    # published files is lost packaged content, not an omitted source path.
    # Check the requested name too: a dangling symlink must not disguise a
    # missing published file as an unrelated unpublished target.
    return all(
        name not in files and not any(path.startswith(name + "/") for path in files)
        for name in (requested, resolved)
    )


def broken_links(root):
    inventory = root / "vendor/upstream.json"
    packages = (
        json.loads(inventory.read_text(encoding="utf-8"))["packages"]
        if inventory.exists() else {}
    )
    broken = []
    for path in candidate_markdown(root):
        content = path.read_bytes()
        text = content.decode("utf-8")
        in_fence = False
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for match in LINK.finditer(line):
                target = match.group(1)
                if target.startswith(SKIP_PREFIXES):
                    continue
                file_part = target.split("#", 1)[0]
                if not file_part:
                    continue
                target_path = path.parent / file_part
                if not target_path.exists() and not omitted_archive_reference(
                    root, path, content, target_path, packages
                ):
                    relative = path.relative_to(root).as_posix()
                    broken.append(f"{relative}:{number}: {target}")
    return broken


def main(argv):
    root = pathlib.Path(argv[1] if len(argv) > 1 else ".").resolve()
    broken = broken_links(root)
    for entry in broken:
        print(f"broken link: {entry}")
    if broken:
        print(f"{len(broken)} broken Markdown link(s)")
        return 1
    print("all checked Markdown links are valid (original archive omissions permitted)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
