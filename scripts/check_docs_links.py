#!/usr/bin/env python3
"""Fail when a Markdown file links to a repository path or anchor that does not exist.

Documentation is reorganized by reader task, so relative links move. This check
checks every `[text](path)` link in tracked and nonignored new Markdown files.
Only byte-identical vendor documents recorded in vendor/upstream.json may
reference package-internal paths omitted from the published archive. Missing
published files/directories and links in edited or project documents still fail.
External URLs and mail links are not checked.

A fragment, in-page (`#anchor`) or on another Markdown file (`other.md#anchor`),
must name exactly a heading slug as GitHub computes it, or an explicit
`<a id="...">`/`<a name="...">` anchor of that document. Fragments on other
targets (source files, directories) and on omitted archive targets are not
checked.

Usage: python3 -B scripts/check_docs_links.py [repository-root]
"""

import hashlib
import html
import json
import os
import pathlib
import re
import string
import subprocess
import sys
import unicodedata
import urllib.parse

LINK = re.compile(r"(?<!\\)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:")
ATX_HEADING = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$")
ATX_CLOSING = re.compile(r"(?:^|[ \t]+)#+$")
SETEXT_UNDERLINE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
# Lines that cannot continue a paragraph into a setext heading: indented
# code, block quotes, ATX headings, tables, HTML blocks and list items.
NOT_PARAGRAPH = re.compile(r"^(?: {4}|\t| {0,3}(?:[>#|<]|[-+*](?:[ \t]|$)|\d{1,9}[.)](?:[ \t]|$)))")
HTML_ANCHOR = re.compile(
    r"<a\s(?:[^>]*?\s)?(?:id|name)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", re.IGNORECASE
)
HTML_TAG = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>")
AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^<>\s]*)>")
BACKTICKS = re.compile(r"`+")
ASCII_PUNCTUATION = frozenset(string.punctuation)


def candidate_markdown(root):
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others",
         "--exclude-standard", "-z", "--", "*.md", "**/*.md"],
        capture_output=True,
        check=True,
    )
    names = {name for name in listing.stdout.decode("utf-8").split("\0") if name}
    return sorted(root / name for name in names)


def unfenced_lines(text):
    """Yield (line number, line) for every line outside fenced code blocks."""
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield number, line


def closing_bracket(text, start):
    """Index of the `]` matching the `[` at `start`, or -1."""
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def closing_parenthesis(text, start):
    """Index of the `)` closing the `(` at `start`, or -1."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def inline_text(raw):
    """Reduce inline Markdown to its rendered text as (character, literal) pairs.

    Code span contents and backslash-escaped characters are literal: they are
    never emphasis delimiters or entity references.
    """
    out = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == "\\" and index + 1 < len(raw) and raw[index + 1] in ASCII_PUNCTUATION:
            out.append((raw[index + 1], True))
            index += 2
            continue
        if char == "`":
            opening = BACKTICKS.match(raw, index).group(0)
            closing = next(
                (run for run in BACKTICKS.finditer(raw, index + len(opening))
                 if run.group(0) == opening),
                None,
            )
            if closing is None:
                out.extend((tick, True) for tick in opening)
                index += len(opening)
                continue
            content = raw[index + len(opening):closing.start()]
            if len(content) > 1 and content[0] == content[-1] == " " and content.strip():
                content = content[1:-1]
            out.extend((code, True) for code in content)
            index = closing.end()
            continue
        if char == "[" or (char == "!" and raw[index + 1:index + 2] == "["):
            opening = index if char == "[" else index + 1
            close = closing_bracket(raw, opening)
            if close != -1 and raw[close + 1:close + 2] == "(":
                end = closing_parenthesis(raw, close + 1)
                if end != -1:
                    # A link contributes its text; an image's alt text is an
                    # attribute, not part of the heading's text.
                    if char == "[":
                        out.extend(inline_text(raw[opening + 1:close]))
                    index = end + 1
                    continue
        if char == "<":
            autolink = AUTOLINK.match(raw, index)
            if autolink:
                out.extend((link, True) for link in autolink.group(1))
                index = autolink.end()
                continue
            tag = HTML_TAG.match(raw, index)
            if tag:
                index = tag.end()
                continue
        out.append((char, False))
        index += 1
    return out


def heading_text(raw):
    """The text GitHub renders for a heading's inline content."""
    pairs = inline_text(raw)
    kept = []
    index = 0
    while index < len(pairs):
        char, literal = pairs[index]
        if char == "_" and not literal:
            # A run of `_` delimits emphasis unless it sits inside a word
            # (snake_case); escaped and code underscores are literal.
            end = index
            while end < len(pairs) and pairs[end] == ("_", False):
                end += 1
            before = pairs[index - 1][0] if index else " "
            after = pairs[end][0] if end < len(pairs) else " "
            if before.isalnum() and after.isalnum():
                kept.extend(pairs[index:end])
            index = end
            continue
        kept.append((char, literal))
        index += 1
    # Entity references are decoded outside code spans and escapes only.
    rendered = []
    plain = []
    for char, literal in kept:
        if literal:
            rendered.append(html.unescape("".join(plain)))
            plain = []
            rendered.append(char)
        else:
            plain.append(char)
    rendered.append(html.unescape("".join(plain)))
    return "".join(rendered).strip()


def github_slug(text):
    """GitHub's heading slug (github-slugger): lowercase, remove every
    character that is not a letter, mark, number, connector punctuation,
    space or hyphen, then turn each space into a hyphen without collapsing
    runs ("a — b" becomes "a--b")."""
    kept = [
        char for char in text.lower()
        if char in " -" or unicodedata.category(char)[0] in "LMN"
        or unicodedata.category(char) == "Pc"
    ]
    return "".join(kept).replace(" ", "-")


def document_anchors(text):
    """Every anchor GitHub defines for a Markdown document."""
    headings = []
    paragraph = []
    for number, line in unfenced_lines(text):
        atx = ATX_HEADING.match(line)
        if atx:
            headings.append(ATX_CLOSING.sub("", atx.group(2) or ""))
            paragraph = []
            continue
        if paragraph and paragraph[-1][0] == number - 1 and SETEXT_UNDERLINE.match(line):
            headings.append("\n".join(content for _, content in paragraph))
            paragraph = []
            continue
        if not line.strip() or NOT_PARAGRAPH.match(line):
            paragraph = []
            continue
        if paragraph and paragraph[-1][0] != number - 1:
            paragraph = []
        paragraph.append((number, line.strip()))

    anchors = set()
    occurrences = {}
    for heading in headings:
        base = github_slug(heading_text(heading))
        slug = base
        while slug in occurrences:
            occurrences[base] += 1
            slug = f"{base}-{occurrences[base]}"
        occurrences[slug] = 0
        anchors.add(slug)
    for _, line in unfenced_lines(text):
        for match in HTML_ANCHOR.finditer(line):
            anchors.add(match.group(1) if match.group(1) is not None else match.group(2))
    return anchors


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
    anchor_cache = {}

    def anchors_of(document):
        key = document.resolve()
        if key not in anchor_cache:
            anchor_cache[key] = document_anchors(key.read_bytes().decode("utf-8"))
        return anchor_cache[key]

    broken = []
    for path in candidate_markdown(root):
        content = path.read_bytes()
        text = content.decode("utf-8")
        relative = path.relative_to(root).as_posix()
        for number, line in unfenced_lines(text):
            for match in LINK.finditer(line):
                target = match.group(1)
                if target.startswith(SKIP_PREFIXES):
                    continue
                file_part, _, fragment = target.partition("#")
                target_path = path.parent / file_part if file_part else path
                if not target_path.exists():
                    if not omitted_archive_reference(
                        root, path, content, target_path, packages
                    ):
                        broken.append(f"{relative}:{number}: {target}")
                    continue
                fragment = urllib.parse.unquote(fragment)
                if (
                    fragment
                    and target_path.is_file()
                    and target_path.suffix.lower() == ".md"
                    and fragment not in anchors_of(target_path)
                ):
                    broken.append(f"{relative}:{number}: {target} (missing anchor)")
    return broken


def main(argv):
    root = pathlib.Path(argv[1] if len(argv) > 1 else ".").resolve()
    broken = broken_links(root)
    for entry in broken:
        print(f"broken link: {entry}")
    if broken:
        print(f"{len(broken)} broken Markdown link(s)")
        return 1
    print("all checked Markdown links and anchors are valid "
          "(original archive omissions permitted)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
