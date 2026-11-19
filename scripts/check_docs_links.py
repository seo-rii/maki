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

from bisect import bisect_right
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
from typing import NamedTuple

SKIP_PREFIXES = ("http://", "https://", "mailto:", "//")
ATX_HEADING = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$")
ATX_CLOSING = re.compile(r"(?:^|[ \t]+)#+$")
SETEXT_UNDERLINE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
# Lines that cannot continue a paragraph into a setext heading: indented
# code, block quotes, ATX headings, tables, HTML blocks and list items.
NOT_PARAGRAPH = re.compile(r"^(?: {4}|\t| {0,3}(?:[>#|<]|[-+*](?:[ \t]|$)|\d{1,9}[.)](?:[ \t]|$)))")
HTML_ATTR = re.compile(r"""([A-Za-z_:][\w.:-]*)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+))?""", re.ASCII)
HTML_OPEN = rf"<(?P<tag>[A-Za-z][A-Za-z0-9-]*)(?P<attrs>(?:\s+{HTML_ATTR.pattern})*)\s*/?>"
HTML_CLOSE = re.compile(r"</[A-Za-z][A-Za-z0-9-]*\s*>")
HTML_TAG = re.compile(rf"(?:{HTML_OPEN}|{HTML_CLOSE.pattern})", re.ASCII)
# CommonMark HTML blocks ending at the matching close tag or at a blank line.
RAW_ELEMENT = re.compile(r"<(pre|script|style|textarea)(?=\s|>|$)", re.IGNORECASE)
BLOCK_ELEMENT = re.compile(
    r"</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|"
    r"dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|"
    r"h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|"
    r"optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|"
    r"tr|track|ul)(?=\s|/?>|$)", re.IGNORECASE)
HTML_TOKENS = re.compile(
    r"<!--.*?(?:-->|$)|<!\[CDATA\[.*?(?:\]\]>|$)|<\?.*?(?:\?>|$)|"
    r"<(?P<raw>script|style|textarea)(?=[\s>]).*?(?:</(?P=raw)>|$)|"
    rf"{HTML_OPEN}", re.IGNORECASE | re.DOTALL | re.ASCII)
AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^<>\s]*)>")
FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
BACKTICKS = re.compile(r"`+")
ASCII_PUNCTUATION = frozenset(string.punctuation)
# A link label: at most 999 characters, no unescaped brackets.
LINK_LABEL = re.compile(r"\[((?:[^\\\[\]]|\\.){0,999})\]")
# Container margins are consumed in nesting order before classifying a block.
QUOTE_MARKER = re.compile(r" {0,3}>[ \t]?")
BLOCK_LIST_MARKER = re.compile(r" {0,3}(?:[-+*]|\d{1,9}[.)])( +|$)")
THEMATIC_BREAK = re.compile(r"^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$")


def candidate_markdown(root):
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others",
         "--exclude-standard", "-z", "--", ":(icase)*.md"],
        capture_output=True,
        check=True,
    )
    names = {name for name in os.fsdecode(listing.stdout).split("\0") if name}
    return sorted(root / name for name in names)


class SourceLine(NamedTuple):
    number: int
    content: str
    container_changed: bool
    raw_html: bool


def document_lines(text):
    """Strip container margins and distinguish Markdown from literal blocks."""
    # Each open container is a block quote (None) or a list item's continuation
    # indentation in columns. Preserve their order for lists inside quotes and
    # quotes inside lists. A literal block cannot continue beyond its container.
    containers = []
    block = None
    html_end = None
    in_paragraph = False
    for number, line in enumerate(text.splitlines(), start=1):
        columns = line.expandtabs(4)
        pos = 0
        changed = False
        for index, indent in enumerate(containers):
            if indent is None:
                quote = QUOTE_MARKER.match(columns, pos)
                if quote:
                    pos = quote.end()
                    continue
            elif columns.startswith(" " * indent, pos):
                pos += indent
                continue
            elif not columns[pos:].strip():
                pos = len(columns)
                continue
            del containers[index:]
            changed = True
            in_paragraph = False
            html_end = None
            block = None
            break

        content = columns[pos:]
        if html_end is not None:
            if html_end or content.strip():
                yield SourceLine(number, content, changed, True)
                if html_end and html_end in content.lower():
                    html_end = None
                continue
            html_end = None
        if block is not None:
            close = FENCE.fullmatch(content)
            if (close and close[1][0] == block[0] and len(close[1]) >= len(block)
                    and not close[2].strip(" \t")):
                block = None
            continue

        before_markers = pos
        while pos < len(columns):
            quote = QUOTE_MARKER.match(columns, pos)
            if quote:
                containers.append(None)
                pos = quote.end()
                continue
            if THEMATIC_BREAK.fullmatch(columns[pos:]):
                break
            item = BLOCK_LIST_MARKER.match(columns, pos)
            if not item:
                break
            marker_end = item.start(1)
            padding = item.end(1) - marker_end
            # Five or more spaces introduce indented item content. An empty
            # item still needs one column after its marker on the next line.
            width = padding if 1 <= padding <= 4 and item.end() < len(columns) else 1
            containers.append(marker_end - pos + width)
            pos = marker_end + width

        changed = changed or pos != before_markers
        if changed:
            in_paragraph = False
        content = columns[pos:]
        # Only the container margin uses expanded tab stops. Keep literal tabs
        # in the body (e.g. code spans and link labels).
        if "\t" in line:
            column = 0
            offset = 0
            while column < pos and offset < len(line):
                column += 4 - column % 4 if line[offset] == "\t" else 1
                offset += 1
            content = " " * (column - pos) + line[offset:]
        stripped = content.lstrip(" ")
        if len(content) - len(stripped) <= 3 and stripped.startswith("<"):
            raw = RAW_ELEMENT.match(stripped)
            if raw:
                html_end = f"</{raw[1].lower()}>"
            elif stripped.startswith("<!--"):
                html_end = "-->"
            elif stripped.startswith("<?"):
                html_end = "?>"
            elif stripped.startswith("<![CDATA["):
                html_end = "]]>"
            elif re.match(r"<![A-Z]", stripped):
                html_end = ">"
            elif BLOCK_ELEMENT.match(stripped) or (
                    not in_paragraph and HTML_TAG.fullmatch(stripped.rstrip())):
                html_end = ""
            if html_end is not None:
                in_paragraph = False
                yield SourceLine(number, content, changed, True)
                if html_end and html_end in stripped.lower():
                    html_end = None
                continue
        match = FENCE.fullmatch(content)
        if match and not (match[1][0] == "`" and "`" in match[2]):
            block = match[1]
            in_paragraph = False
            continue
        yield SourceLine(number, content, changed, False)
        in_paragraph = bool(content.strip() and not ATX_HEADING.match(content)
                            and not THEMATIC_BREAK.match(content)
                            and not (in_paragraph and SETEXT_UNDERLINE.match(content)))


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
            if text[index] in "<\n":
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
    while line[start:start + 1] in (" ", "\t", "\n"):
        start += 1
    if line[start:start + 1] == ")":
        return "", start + 1
    parsed = link_destination(line, start)
    if parsed is None:
        return None
    destination, end = parsed
    tail = end
    while line[tail:tail + 1] in (" ", "\t", "\n"):
        tail += 1
    if tail > end and line[tail:tail + 1] in ('"', "'", "("):
        tail = link_title_end(line, tail)
        if tail == -1:
            return None
        while line[tail:tail + 1] in (" ", "\t", "\n"):
            tail += 1
    if line[tail:tail + 1] == ")":
        return destination, tail + 1
    return None


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
    if (index >= len(lines) or lines[index].number != number + 1
            or lines[index].container_changed):
        return None
    return lines[index].content


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
    lines = [line for line in document_lines(text) if not line.raw_html]
    definitions = []
    in_paragraph = False
    previous_number = None
    index = 0
    while index < len(lines):
        number, content, opens_container, _ = lines[index]
        if previous_number != number - 1 or opens_container:
            in_paragraph = False
        previous_number = number
        definition = None
        if not in_paragraph:
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
            or ATX_HEADING.match(content)
            or THEMATIC_BREAK.match(content)
            or (in_paragraph and SETEXT_UNDERLINE.match(content))
        )
        index += 1
    return definitions


def mask_inline_literals(line, targets):
    """Mask literals and record link destinations with their offsets in this paragraph."""
    out = []
    depth = 0
    index = 0
    while index < len(line):
        char = line[index]
        if line.startswith("<!--", index):
            end = line.find("-->", index + 4)
            if end != -1:
                end += 3
                out.append(" " * (end - index))
                index = end
                continue
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
                    target_start = index + 2
                    while line[target_start:target_start + 1] in (" ", "\t", "\n"):
                        target_start += 1
                    targets.append((target_start, unescape(parsed[0])))
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
    def masked_lines():
        if not paragraph:
            return
        targets = []
        masked = mask_inline_literals("\n".join(line for _, line in paragraph), targets)
        starts = []
        start = 0
        for _, line in paragraph:
            starts.append(start)
            start += len(line) + 1
        per_line = [[] for _ in paragraph]
        for offset, destination in targets:
            per_line[bisect_right(starts, offset) - 1].append(destination)
        for (number, line), start, found in zip(paragraph, starts, per_line):
            yield number, line, masked[start:start + len(line)], found

    for number, content, changed, raw_html in document_lines(text):
        single = bool(ATX_HEADING.match(content) or THEMATIC_BREAK.match(content)
                      or SETEXT_UNDERLINE.match(content) or content.lstrip().startswith("|"))
        if (not content.strip() or raw_html or number in definition_lines or single or changed
                or (paragraph and number != paragraph[-1][0] + 1)):
            yield from masked_lines()
            paragraph.clear()
        if content.strip() and not raw_html and number not in definition_lines:
            paragraph.append((number, content))
            if single:
                yield from masked_lines()
                paragraph.clear()
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
        if raw.startswith("<!--", index):
            end = raw.find("-->", index + 4)
            if end != -1:
                index = end + 3
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
    raw_blocks = []
    for number, line, changed, raw_html in document_lines(text):
        if changed:
            paragraph = []
        if raw_html:
            if not raw_blocks or changed or raw_blocks[-1][-1][0] != number - 1:
                raw_blocks.append([])
            raw_blocks[-1].append((number, line))
        if raw_html or number in definition_lines:
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

    def collect_html(source):
        # Skip literal HTML text and comments before looking at real start
        # tags. A quoted attribute can itself contain markup-shaped text.
        for token in HTML_TOKENS.finditer(source):
            if (token["tag"] or "").lower() != "a":
                continue
            for attribute in HTML_ATTR.finditer(token["attrs"]):
                value = attribute[2]
                if value is not None and attribute[1].lower() in ("id", "name"):
                    if value[0] in ("'", '"'):
                        value = value[1:-1]
                    anchors.add(html.unescape(value))

    for lines in raw_blocks:
        collect_html("\n".join(line for _, line in lines))
    for _, _, masked, _ in inline_lines(text, definition_lines):
        collect_html(masked)
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
        if not target or target.lower().startswith(SKIP_PREFIXES):
            return None
        file_part, _, fragment = target.partition("#")
        file_part = file_part.partition("?")[0]
        decoded = urllib.parse.unquote(file_part)
        if file_part.startswith("/"):
            target_path = root / decoded.lstrip("/")
        else:
            target_path = path.parent / decoded if decoded else path
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
