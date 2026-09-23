#!/usr/bin/env python3
"""Fail when a Markdown file links to a repository path that does not exist.

Documentation is reorganized by reader task, so relative links move. This check
keeps every `[text](path)` link in tracked Markdown files pointing at a real
file or directory. External URLs, mail links and pure in-page anchors are not
checked; heading anchors inside other files are not verified either.

Usage: python3 -B scripts/check_docs_links.py [repository-root]
"""

import pathlib
import re
import subprocess
import sys

LINK = re.compile(r"(?<!\\)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def tracked_markdown(root):
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.md", "**/*.md"],
        capture_output=True,
        check=True,
    )
    names = {name for name in listing.stdout.decode("utf-8").split("\0") if name}
    return sorted(root / name for name in names)


def broken_links(root):
    broken = []
    for path in tracked_markdown(root):
        text = path.read_text(encoding="utf-8")
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
                resolved = (path.parent / file_part).resolve()
                if not resolved.exists():
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
    print("all Markdown links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
