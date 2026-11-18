#!/usr/bin/env python3
"""Fail when a Markdown file links to a repository path or anchor that does not exist.

Documentation is reorganized by reader task, so relative links move. This check
checks every `[text](path)` link in tracked and nonignored new Markdown files.
Only byte-identical vendor documents recorded in vendor/upstream.json may
reference package-internal paths omitted from the published archive. Missing
published files/directories and links in edited or project documents still fail.
External URLs and mail links are not checked.

Reference-style links are checked too. Every link reference definition
(`[label]: path#anchor "title"`) that GitHub recognizes (CommonMark: it starts
a paragraph, inside a block quote or list item too, and is not a `[^footnote]`
definition) must name an existing target and anchor, like an inline link, even
when its label is unused or repeated. A full or collapsed reference
(`[text][label]`, `[label][]`) whose label no definition of the same document
matches (case-insensitively, whitespace collapsed) is reported: GitHub renders
it as literal bracketed text. An undefined shortcut (`[label]`) is ordinary
text and is not reported. Multi-line titles and full reference labels are not parsed,
and indented code blocks are not distinguished from list-item content.

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
FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
BACKTICKS = re.compile(r"`+")
ASCII_PUNCTUATION = frozenset(string.punctuation)
# A link label: at most 999 characters, no unescaped brackets.
LINK_LABEL = re.compile(r"\[((?:[^\\\[\]]|\\.){0,999})\]")
# Block-quote markers, then at most one list-item marker, before a block.
QUOTE_MARKER = re.compile(r" {0,3}>[ \t]?")
LIST_MARKER = re.compile(r" {0,3}(?:[-+*]|\d{1,9}[.)])(?:[ \t]+|$)")
CONTAINER_PREFIX = re.compile(rf"^((?:{QUOTE_MARKER.pattern})*)({LIST_MARKER.pattern})?")
THEMATIC_BREAK = re.compile(r"^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$")


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
    fence = None
    list_indents = []
    last_depth = 0
    for number, line in enumerate(text.splitlines(), start=1):
        # CommonMark counts block indentation in columns, with four-column tab stops.
        columns = line.expandtabs(4)
        if fence is not None:
            marker, quote_depth, list_indent = fence
            pos = 0
            for _ in range(quote_depth):
                quote = QUOTE_MARKER.match(columns, pos)
                if quote is None:
                    break
                pos = quote.end()
            else:
                content = columns[pos:]
                if not content.strip() or content.startswith(" " * list_indent):
                    close = FENCE.fullmatch(content[list_indent:])
                    if (close and close[1][0] == marker[0] and len(close[1]) >= len(marker)
                            and not close[2].strip(" \t")):
                        fence = None
                    continue
            # A fence inside a quote or list item ends with its container.
            fence = None
        prefix = CONTAINER_PREFIX.match(columns)
        depth = prefix[1].count(">")
        body = columns[prefix.end(1):]
        if last_depth != depth:
            list_indents.clear()
        last_depth = depth
        indent = len(body) - len(body.lstrip(" "))
        if body.strip():
            while list_indents and list_indents[-1] > indent:
                list_indents.pop()
        list_indent = list_indents[-1] if list_indents else 0
        item = LIST_MARKER.match(body, list_indent)
        if item:
            list_indent = item.end()
            list_indents.append(list_indent)
        match = FENCE.fullmatch(body[list_indent:])
        if match and not (match[1][0] == "`" and "`" in match[2]):
            fence = match[1], depth, list_indent
            continue
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


def label_key(label):
    """A link label as CommonMark matches it: trimmed, internal whitespace
    collapsed to one space, Unicode case-folded."""
    return re.sub(r"[ \t\r\n]+", " ", label.strip(" \t\r\n")).casefold()


def valid_label(label):
    return bool(label.strip(" \t\r\n"))


def unescape(raw):
    """Resolve backslash escapes of ASCII punctuation and entity references."""
    parts = []
    plain = []
    index = 0
    while index < len(raw):
        if raw[index] == "\\" and raw[index + 1:index + 2] in ASCII_PUNCTUATION:
            parts.append(html.unescape("".join(plain)))
            plain = []
            parts.append(raw[index + 1])
            index += 2
            continue
        plain.append(raw[index])
        index += 1
    parts.append(html.unescape("".join(plain)))
    return "".join(parts)


def link_destination(text, start):
    """The raw link destination at `text[start:]` and its end, or None."""
    if text.startswith("<", start):
        index = start + 1
        while index < len(text):
            if text[index] == "\\":
                index += 2
                continue
            if text[index] == ">":
                return text[start + 1:index], index + 1
            if text[index] == "<":
                return None
            index += 1
        return None
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\" and text[index + 1:index + 2] in ASCII_PUNCTUATION:
            index += 2
            continue
        if char in " \t" or ord(char) < 0x20 or char == "\x7f":
            break
        if char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                break
            depth -= 1
        index += 1
    if index == start or depth:
        return None
    return text[start:index], index


def inline_destination(line, opening):
    """Parse the destination and optional title after a link label's `(`."""
    start = opening + 1
    while line[start:start + 1] in (" ", "\t"):
        start += 1
    if line[start:start + 1] == ")":
        return "", start + 1
    parsed = link_destination(line, start)
    if parsed is None:
        return None
    destination, end = parsed
    tail = end
    while line[tail:tail + 1] in (" ", "\t"):
        tail += 1
    if tail > end and line[tail:tail + 1] in ('"', "'", "("):
        tail = link_title_end(line, tail)
        if tail == -1:
            return None
        while line[tail:tail + 1] in (" ", "\t"):
            tail += 1
    if line[tail:tail + 1] == ")":
        return destination, tail + 1
    return None


def inline_destinations(line, masked, depth):
    """Find link and image targets on this line, carrying open labels within the paragraph."""
    targets = []
    index = 0
    while index < len(masked):
        char = masked[index]
        index += 1
        if char == "\\":
            index += 1
        elif char == "[":
            depth += 1
        elif char == "]" and depth:
            depth -= 1
            if masked[index:index + 1] == "(":
                parsed = inline_destination(line, index)
                if parsed is not None:
                    destination, index = parsed
                    targets.append(unescape(destination))
    return targets, depth


def link_title_end(text, start):
    """The end of a complete link title at `text[start:]`, or -1."""
    closer = {'"': '"', "'": "'", "(": ")"}.get(text[start:start + 1])
    if closer is None:
        return -1
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == closer:
            return index + 1
        if closer == ")" and text[index] == "(":
            return -1
        index += 1
    return -1


def title_only(text):
    """Whether `text` is one complete link title and nothing else."""
    stripped = text.strip(" \t")
    return bool(stripped) and link_title_end(stripped, 0) == len(stripped)


def continuation(lines, index, number):
    """Line `index` without block-quote markers if it directly follows line
    `number`, else None."""
    if index >= len(lines) or lines[index][0] != number + 1:
        return None
    line = lines[index][1]
    return line[CONTAINER_PREFIX.match(line).end(1):]


def parse_definition(content, lines, index):
    """Parse a link reference definition that starts `content` (line `index`).

    Returns (lines consumed, destination line, label key, destination) or None.
    """
    match = re.match(r"[ \t]*" + LINK_LABEL.pattern + ":", content)
    if not match or not valid_label(match.group(1)) or match.group(1).startswith("^"):
        return None
    number = lines[index][0]
    rest = content[match.end():]
    consumed = 1
    if not rest.strip(" \t"):
        rest = continuation(lines, index + 1, number)
        if rest is None or not rest.strip(" \t"):
            return None
        consumed = 2
    destination_line = lines[index + consumed - 1][0]
    parsed = link_destination(rest, len(rest) - len(rest.lstrip(" \t")))
    if parsed is None:
        return None
    destination, end = parsed
    after = rest[end:]
    if after.strip(" \t"):
        # A title must be separated by whitespace and end the line.
        if after[:1] not in (" ", "\t") or not title_only(after):
            return None
    else:
        title = continuation(lines, index + consumed, destination_line)
        if title is not None and title_only(title):
            consumed += 1
    return consumed, destination_line, label_key(match.group(1)), unescape(destination)


def reference_definitions(text):
    """Link reference definitions GitHub recognizes, outside code fences.

    Returns (first line, last line, destination line, label key, destination)
    tuples in document order. A definition starts a paragraph: it follows a
    blank line, a heading, a thematic break, a fence or another definition,
    or opens a block quote or list item. A line continuing a paragraph is
    text. The destination may be on the next line, and a title on the line
    after it; a title must end on the line it starts on. `[^label]:` starts
    a footnote, not a link.
    """
    lines = list(unfenced_lines(text))
    definitions = []
    in_paragraph = False
    previous_number = None
    previous_quoted = False
    index = 0
    while index < len(lines):
        number, line = lines[index]
        if previous_number != number - 1:
            in_paragraph = False  # a fenced block ended the paragraph
        prefix = CONTAINER_PREFIX.match(line)
        quoted = bool(prefix.group(1))
        opens_container = bool(prefix.group(2)) or (quoted and not previous_quoted)
        block = line[prefix.end(1):]
        content = line[prefix.end():]
        previous_number, previous_quoted = number, quoted
        definition = None
        if not in_paragraph or opens_container:
            definition = parse_definition(content, lines, index)
        if definition is not None:
            consumed, destination_line, label, destination = definition
            last = lines[index + consumed - 1][0]
            definitions.append((number, last, destination_line, label, destination))
            previous_number = last
            in_paragraph = False
            index += consumed
            continue
        in_paragraph = not (
            not content.strip()
            or ATX_HEADING.match(block)
            or THEMATIC_BREAK.match(block)
            or (in_paragraph and SETEXT_UNDERLINE.match(block))
        )
        index += 1
    return definitions


def mask_inline_literals(line):
    """Mask code spans and link destinations/titles while preserving offsets and link delimiters."""
    out = []
    depth = 0
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\":
            out.append(line[index:index + 2])
            index += 2
            continue
        if char == "[":
            depth += 1
        elif char == "]" and depth:
            depth -= 1
            if line[index + 1:index + 2] == "(":
                parsed = inline_destination(line, index + 1)
                if parsed is not None:
                    # Backticks in a destination or title do not start code.
                    end = parsed[1]
                    out.append("](" + " " * (end - index - 3) + ")")
                    index = end
                    continue
        if char == "`":
            opening = BACKTICKS.match(line, index).group(0)
            closing = next(
                (run for run in BACKTICKS.finditer(line, index + len(opening))
                 if run.group(0) == opening),
                None,
            )
            if closing is None:
                out.append(opening)
                index += len(opening)
            else:
                out.append(" " * (closing.end() - index))
                index = closing.end()
            continue
        out.append(char)
        index += 1
    return "".join(out)


def inline_lines(text, definition_lines):
    """Mask code spans across soft line breaks within the same paragraph."""
    paragraph = []
    quote_depth = 0

    def masked_lines():
        masked = mask_inline_literals("\n".join(line for _, line in paragraph))
        start = 0
        depth = 0
        for number, line in paragraph:
            view = masked[start:start + len(line)]
            targets, depth = inline_destinations(line, view, depth)
            yield number, line, view, targets
            start += len(line) + 1

    for number, line in unfenced_lines(text):
        prefix = CONTAINER_PREFIX.match(line)
        depth = prefix[1].count(">")
        content = line[prefix.end():]
        single = bool(ATX_HEADING.match(content) or THEMATIC_BREAK.match(content)
                      or SETEXT_UNDERLINE.match(content) or content.lstrip().startswith("|"))
        if (not content.strip() or number in definition_lines or single or prefix[2]
                or depth != quote_depth or (paragraph and number != paragraph[-1][0] + 1)):
            yield from masked_lines()
            paragraph.clear()
        if content.strip() and number not in definition_lines:
            paragraph.append((number, line))
            if single:
                yield from masked_lines()
                paragraph.clear()
        quote_depth = depth
    yield from masked_lines()


def undefined_references(line, masked, labels):
    """Full (`[text][label]`) and collapsed (`[label][]`) references on
    `line` whose label `labels` does not define, as written.

    Link text is scanned too, so an undefined reference nested in another
    one (an image inside a link) is found; a label and an inline link's
    destination are not link text. A label that is followed by another
    label or an inline destination may be the text of the next construct
    (CommonMark retries from there), so it is not reported on its own.
    """
    found = []
    skip = {}  # start of a label or destination -> its end
    index = 0
    while index < len(masked):
        if index in skip:
            index = skip[index]
            continue
        if masked[index] == "\\":
            index += 2
            continue
        close = closing_bracket(masked, index) if masked[index] == "[" else -1
        index += 1
        if close == -1:
            continue
        if masked[close + 1:close + 2] == "(":
            parsed = inline_destination(line, close + 1)
            if parsed is not None:
                skip[close + 1] = parsed[1]
            continue
        reference = LINK_LABEL.match(masked, close + 1)
        if reference is None:
            continue
        if reference.group(1):
            label = line[reference.start(1):reference.end(1)]
        elif LINK_LABEL.fullmatch(masked, index - 1, close + 1):
            label = line[index:close]
        else:
            continue
        if not valid_label(label) or label.startswith("^"):
            continue
        if label_key(label) not in labels:
            if masked[reference.end():reference.end() + 1] in ("[", "("):
                continue
            found.append(line[index - 1:reference.end()])
        skip[close + 1] = reference.end()
    return found


def inline_text(raw, labels=frozenset()):
    """Reduce inline Markdown to its rendered text as (character, literal) pairs.

    Code span contents and backslash-escaped characters are literal: they are
    never emphasis delimiters or entity references. `labels` holds the
    document's defined reference labels: a reference to one renders as a link.
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
                parsed = inline_destination(raw, close + 1)
                if parsed is not None:
                    # A link contributes its text; an image's alt text is an
                    # attribute, not part of the heading's text.
                    if char == "[":
                        out.extend(inline_text(raw[opening + 1:close], labels))
                    index = parsed[1]
                    continue
            if close != -1 and labels:
                # A full reference uses its own label; a collapsed (`[]`)
                # or shortcut reference uses its text. An undefined full
                # label leaves the brackets literal (CommonMark).
                reference = LINK_LABEL.match(raw, close + 1)
                if reference and reference.group(1):
                    label = reference.group(1)
                else:
                    label = raw[opening + 1:close]
                if label_key(label) in labels:
                    if char == "[":
                        out.extend(inline_text(raw[opening + 1:close], labels))
                    index = reference.end() if reference else close + 1
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


def heading_text(raw, labels=frozenset()):
    """The text GitHub renders for a heading's inline content."""
    pairs = inline_text(raw, labels)
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
    definitions = reference_definitions(text)
    labels = frozenset(definition[3] for definition in definitions)
    # A definition is not paragraph text, so it never becomes a setext heading.
    definition_lines = {
        number for first, last, _, _, _ in definitions for number in range(first, last + 1)
    }
    headings = []
    paragraph = []
    for number, line in unfenced_lines(text):
        if number in definition_lines:
            paragraph = []
            continue
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
        base = github_slug(heading_text(heading, labels))
        slug = base
        while slug in occurrences:
            occurrences[base] += 1
            slug = f"{base}-{occurrences[base]}"
        occurrences[slug] = 0
        anchors.add(slug)
    for _, _, masked, _ in inline_lines(text, definition_lines):
        for match in HTML_ANCHOR.finditer(masked):
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

    def target_problem(path, content, target):
        """Why `target`, linked from `path`, is broken, or None."""
        if not target or target.startswith(SKIP_PREFIXES):
            return None
        file_part, _, fragment = target.partition("#")
        file_part = file_part.partition("?")[0]
        target_path = path.parent / urllib.parse.unquote(file_part) if file_part else path
        if not target_path.exists():
            if omitted_archive_reference(root, path, content, target_path, packages):
                return None
            return target
        fragment = urllib.parse.unquote(fragment)
        if (
            fragment
            and target_path.is_file()
            and target_path.suffix.lower() == ".md"
            and fragment not in anchors_of(target_path)
        ):
            return f"{target} (missing anchor)"
        return None

    broken = []
    for path in candidate_markdown(root):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() and not path.is_file():
            broken.append(f"{relative}: invalid Markdown symlink target")
            continue
        try:
            content = path.read_bytes()
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            continue  # the indexed file was deleted or replaced by a directory
        text = content.decode("utf-8")
        definitions = reference_definitions(text)
        labels = frozenset(definition[3] for definition in definitions)
        problems = [
            (number, target_problem(path, content, destination))
            for _, _, number, _, destination in definitions
        ]
        definition_lines = {n for first, last, *_ in definitions for n in range(first, last + 1)}
        for number, line, masked, targets in inline_lines(text, definition_lines):
            problems.extend(
                (number, target_problem(path, content, destination))
                for destination in targets
            )
            problems.extend(
                (number, f"{reference} (undefined reference)")
                for reference in undefined_references(line, masked, labels)
            )
        broken.extend(
            f"{relative}:{number}: {problem}"
            for number, problem in sorted(problems, key=lambda entry: entry[0])
            if problem is not None
        )
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
