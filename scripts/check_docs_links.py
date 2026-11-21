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
text and is not reported. Multi-line titles and full reference labels are not parsed.

A fragment, in-page (`#anchor`) or on another Markdown file (`other.md#anchor`),
must name exactly a heading slug as GitHub computes it, or an explicit
`<a id="...">`/`<a name="...">` anchor of that document. In GitHub source view
(`?plain=1`), line references address a source line or a range of lines. Fragments on other
targets (source files, directories) and on omitted archive targets are not
checked.

Usage: python3 -B scripts/check_docs_links.py [repository-root]
"""

from bisect import bisect_right
import codecs
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

URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
ENTITY = re.compile(r"&(?:#[xX][0-9A-Fa-f]{1,6}|#[0-9]{1,7}|[A-Za-z][A-Za-z0-9]+);")
ATX_HEADING = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$")
ATX_CLOSING = re.compile(r"(?:^|[ \t]+)#+$")
SETEXT_UNDERLINE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
CODE_INDENT = re.compile(r"^(?: {4}| {0,3}\t)")
HTML_ATTR = re.compile(r"""([A-Za-z_:][\w.:-]*)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+))?""", re.ASCII)
HTML_OPEN = rf"<(?P<tag>[A-Za-z][A-Za-z0-9-]*)(?P<attrs>(?:\s+{HTML_ATTR.pattern})*)\s*/?>"
HTML_CLOSE = re.compile(r"</[A-Za-z][A-Za-z0-9-]*\s*>")
HTML_TAG = re.compile(rf"(?:{HTML_OPEN}|{HTML_CLOSE.pattern})", re.ASCII)
# CommonMark type 1 HTML blocks end at any of the four closing tags.
RAW_ELEMENT = re.compile(r"<(pre|script|style|textarea)(?=\s|>|$)", re.IGNORECASE)
RAW_ELEMENT_ENDS = ("</pre>", "</script>", "</style>", "</textarea>")
BLOCK_ELEMENT = re.compile(
    r"</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|"
    r"dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|"
    r"h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|"
    r"optgroup|option|p|param|section|source|summary|table|tbody|td|tfoot|th|thead|title|"
    r"tr|track|ul)(?=\s|/?>|$)", re.IGNORECASE)
INLINE_SPECIAL = re.compile(r"<!--.*?-->|<!\[CDATA\[.*?\]\]>|<\?.*?\?>|<![A-Z]+(?:\s+[^>]*)?>", re.DOTALL)
HTML_ATTRIBUTE_ENTITY = re.compile(r"&(?:#[xX][0-9a-fA-F]+;?|#[0-9]+;?|[A-Za-z][A-Za-z0-9]*;?)")
HTML_TOKENS = re.compile(
    r"<!--.*?(?:-->|$)|<!\[CDATA\[.*?(?:\]\]>|$)|<\?.*?(?:\?>|$)|"
    r"<(?P<raw>script|style|textarea)(?=[\s>]).*?(?:</(?P=raw)>|$)|"
    rf"{HTML_OPEN}", re.IGNORECASE | re.DOTALL | re.ASCII)
AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^<>\s]*)>")
BARE_LINK_START = re.compile(r"(?<![A-Za-z])(?i:https?|ftp)://|(?<![^ \t\r\n*_~(])www\.")
BARE_LINK_TAIL = re.compile(r"[^ \t\r\n\v\f<]*")
FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
BACKTICKS = re.compile(r"`+")
ASCII_PUNCTUATION = frozenset(string.punctuation)
# A link label: at most 999 characters, no unescaped brackets.
LINK_LABEL = re.compile(r"\[((?:[^\\\[\]]|\\.){0,999})\]")
# Container margins are consumed in nesting order before classifying a block.
QUOTE_MARKER = re.compile(r" {0,3}>[ \t]?")
BLOCK_LIST_MARKER = re.compile(r" {0,3}(?:[-+*]|[0-9]{1,9}[.)])( +|$)")
FOOTNOTE_MARKER = re.compile(r" {0,3}\[\^[^\] \t\r\n\x00]+\]:[ \t]*")
FOOTNOTE_CONTAINER = object()
THEMATIC_BREAK = re.compile(r"^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$")


def candidate_files(root):
    git = ["git", "-C", str(root), "ls-files", "-z"]
    tracked = subprocess.check_output([*git, "-t", "--stage"])
    untracked = subprocess.check_output([*git, "--others", "--exclude-standard"])
    candidates = {root / os.fsdecode(name) for name in untracked.split(b"\0") if name}
    skipped = {}
    for entry in tracked.split(b"\0"):
        if entry:
            metadata, name = entry.split(b"\t", 1)
            path = root / os.fsdecode(name)
            tag, mode, oid, stage = metadata.split()
            if tag == b"S" and stage == b"0" and not os.path.lexists(path):
                skipped[path] = (mode, oid)
                candidates.add(path)
            elif path.is_symlink() or path.is_file() or (mode == b"160000" and path.is_dir()):
                candidates.add(path)
    return candidates, skipped


class SourceLine(NamedTuple):
    number: int
    content: str
    container_changed: bool
    raw_html: bool
    lazy: bool = False


def html_block_end(content, in_paragraph):
    """Return closing strings, an empty tuple for a blank line, or None."""
    stripped = content.lstrip(" ")
    if len(content) - len(stripped) > 3 or not stripped.startswith("<"):
        return None
    if RAW_ELEMENT.match(stripped):
        return RAW_ELEMENT_ENDS
    if stripped.startswith("<!--"):
        return ("-->",)
    if stripped.startswith("<?"):
        return ("?>",)
    if stripped.startswith("<![CDATA["):
        return ("]]>",)
    if re.match(r"<![A-Z]", stripped):
        return (">",)
    if BLOCK_ELEMENT.match(stripped) or (not in_paragraph and HTML_TAG.fullmatch(stripped.rstrip(" \t"))):
        return ()
    return None


def opening_fence(content):
    match = FENCE.fullmatch(content)
    if match and not (match[1][0] == "`" and "`" in match[2]):
        return match[1]
    return None


def document_lines(text):
    """Strip container margins and distinguish Markdown from literal blocks."""
    # None denotes a block quote. List items store their continuation width,
    # and footnotes have a fixed four-column margin and their own blank-line rule.
    containers = []
    block = None
    html_end = None
    in_paragraph = False
    for number, line in enumerate(re.split(r"\r\n|[\r\n]", text.removeprefix("\ufeff")), start=1):
        columns = line.expandtabs(4)
        pos = 0
        changed = False
        lazy = False
        for index, container in enumerate(containers):
            indent = 4 if container is FOOTNOTE_CONTAINER else container
            if indent is None:
                quote = QUOTE_MARKER.match(columns, pos)
                if quote:
                    pos = quote.end()
                    continue
            elif columns.startswith(" " * indent, pos):
                pos += indent
                continue
            elif not columns[pos:].strip(" \t") and (container is not FOOTNOTE_CONTAINER or not line):
                pos = len(columns)
                continue
            rest = columns[pos:]
            if (in_paragraph and rest.strip(" \t") and not QUOTE_MARKER.match(rest)
                    and not BLOCK_LIST_MARKER.match(rest) and not FOOTNOTE_MARKER.match(rest)
                    and not ATX_HEADING.match(rest)
                    and not THEMATIC_BREAK.fullmatch(rest) and not opening_fence(rest)
                    and html_block_end(rest, True) is None):
                # A paragraph can continue without repeating list indentation
                # or a quote marker. Such a line cannot be a setext underline.
                lazy = True
                break
            del containers[index:]
            changed = True
            in_paragraph = False
            html_end = None
            block = None
            break

        content = columns[pos:]
        if html_end == () and not content.strip(" \t"):
            html_end = None
        if block is not None:
            close = FENCE.fullmatch(content)
            if (close and close[1][0] == block[0] and len(close[1]) >= len(block)
                    and not close[2].strip(" \t")):
                block = None
            continue

        before_markers = pos
        while html_end is None and not lazy and pos < len(columns):
            quote = QUOTE_MARKER.match(columns, pos)
            if quote:
                containers.append(None)
                pos = quote.end()
                continue
            footnote = FOOTNOTE_MARKER.match(columns, pos)
            if footnote:
                containers.append(FOOTNOTE_CONTAINER)
                pos = footnote.end()
                continue
            if THEMATIC_BREAK.fullmatch(columns[pos:]):
                break
            item = BLOCK_LIST_MARKER.match(columns, pos)
            if not item:
                break
            marker_end = item.start(1)
            marker = columns[pos:marker_end].strip()
            if in_paragraph and not changed and pos == before_markers:
                if item.end() == len(columns) or (marker[0].isdigit() and int(marker[:-1]) != 1):
                    break
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
        if html_end is None:
            html_end = html_block_end(content, in_paragraph)
        if html_end is not None:
            in_paragraph = False
            yield SourceLine(number, content, changed, True)
            lowered = content.lower()
            if any(end in lowered for end in html_end):
                html_end = None
            continue
        block = opening_fence(content)
        if block:
            in_paragraph = False
            continue
        # Indented code can start after a block boundary, but cannot
        # interrupt an open paragraph, including one inside a container.
        if not in_paragraph and CODE_INDENT.match(content):
            continue
        yield SourceLine(number, content, changed, False, lazy)
        in_paragraph = bool(content.strip(" \t") and not ATX_HEADING.match(content)
                            and not THEMATIC_BREAK.match(content)
                            and not (in_paragraph and not lazy and SETEXT_UNDERLINE.match(content)))


def table_cells(line):
    cells = re.split(r"(?<!\\)\|", line.strip(" \t"))
    if cells and not cells[0]:
        cells.pop(0)
    if cells and not cells[-1]:
        cells.pop()
    return [cell.strip(" \t").replace(r"\|", "|") for cell in cells]


def block_lines(text):
    """Pair each source line with its rendered cells when it belongs to a GFM table."""
    lines = list(document_lines(text))
    width = 0
    after_table = False
    for index, line in enumerate(lines):
        value = line.content
        if line.container_changed or not index or line.number != lines[index - 1].number + 1:
            width = 0
            after_table = False
        indented = CODE_INDENT.match(value)
        if (width or after_table) and (not value.strip(" \t") or indented):
            # A blank ends the table. Four columns start a literal code block,
            # including when the first such line follows a table row directly.
            width = 0
            after_table = True
            continue
        after_table = False
        if line.raw_html or ATX_HEADING.match(value) or THEMATIC_BREAK.fullmatch(value):
            width = 0
        if width:
            yield line, table_cells(value)[:width]
            continue
        if (not line.raw_html and value.strip(" \t") and not indented
                and not ATX_HEADING.match(value) and not THEMATIC_BREAK.fullmatch(value)
                and index + 1 < len(lines)):
            divider = lines[index + 1]
            if (divider.number == line.number + 1 and not divider.container_changed
                    and not divider.raw_html and re.fullmatch(r" {0,3}[:|\-][:| \t-]*", divider.content)
                    and ("|" in divider.content or ":" in divider.content)):
                cells = table_cells(value)
                markers = table_cells(divider.content)
                if cells and len(cells) == len(markers) and all(
                        re.fullmatch(r":?-+:?", marker) for marker in markers):
                    width = len(cells)
                    yield line, cells
                    continue
        yield line, None


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


def markdown_entities(text):
    def decode(match):
        entity = match.group()
        if entity[1] == "#":
            digits = entity[2:-1]
            code = int(digits[1:], 16) if digits.startswith(("x", "X")) else int(digits)
            return chr(code) if 0 < code <= 0x10FFFF and not 0xD800 <= code <= 0xDFFF else "\ufffd"
        return html.entities.html5.get(entity[1:], entity)
    return ENTITY.sub(decode, text)


def html_attribute_value(value):
    def decode(match):
        token = match.group()[1:]
        if token.startswith("#"):
            return html.unescape(match.group())
        if not token.endswith(";") and value[match.end():match.end() + 1] == "=":
            return match.group()
        # An unrecognised suffix of ASCII letters or digits prevents a
        # semicolonless named reference from being consumed in an attribute.
        return html.entities.html5.get(token, match.group())
    return HTML_ATTRIBUTE_ENTITY.sub(decode, value)


def unescape(raw):
    """Resolve backslash escapes of ASCII punctuation and entity references."""
    parts = []
    plain = []
    index = 0
    while index < len(raw):
        if raw[index] == "\\" and raw[index + 1:index + 2] in ASCII_PUNCTUATION:
            parts.append(markdown_entities("".join(plain)))
            plain = []
            parts.append(raw[index + 1])
            index += 2
            continue
        plain.append(raw[index])
        index += 1
    parts.append(markdown_entities("".join(plain)))
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
    lines = [line for line, cells in block_lines(text) if not line.raw_html and cells is None]
    definitions = []
    in_paragraph = False
    previous_number = None
    index = 0
    while index < len(lines):
        number, content, opens_container, _, lazy = lines[index]
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
            not content.strip(" \t")
            or ATX_HEADING.match(content)
            or THEMATIC_BREAK.match(content)
            or (in_paragraph and not lazy and SETEXT_UNDERLINE.match(content))
        )
        index += 1
    return definitions


def bare_host_char(char):
    # GFM permits symbols and combining marks in a host. ASCII punctuation
    # and Unicode punctuation are delimiters unless the host rule allows them.
    return (not char.isspace() and char not in ASCII_PUNCTUATION
            and not unicodedata.category(char).startswith("P"))


def bare_link_end(text, start):
    """End of a GFM extended URL autolink, excluding trailing prose punctuation."""
    prefix = BARE_LINK_START.match(text, start)
    if prefix is None:
        return start
    www = prefix[0] == "www."
    host_start = start if www else prefix.end()
    if host_start == len(text) or not bare_host_char(text[host_start]):
        return start
    host_end = host_start + 1
    while host_end < len(text) and (text[host_end] in "._-" or bare_host_char(text[host_end])):
        host_end += 1
    if any("_" in label for label in text[host_start:host_end].rsplit(".", 2)[-2:]):
        return start
    end = BARE_LINK_TAIL.match(text, host_end).end()
    extra_closing = text.count(")", start, end) - text.count("(", start, end)
    while end > start:
        last = text[end - 1]
        if last == ")" and extra_closing > 0:
            extra_closing -= 1
        elif last == ";":
            name = end - 1
            while name > start and text[name - 1] in string.ascii_letters:
                name -= 1
            if start < name < end - 1 and text[name - 1] == "&":
                end = name - 1
                continue
        elif last not in "?!.,:*_~'\"":
            break
        end -= 1
    return end


def scan_inline_paragraph(line, labels):
    """Mask literals and record link destinations with their offsets in this paragraph."""
    out = []
    targets = []
    html_tags = []
    link_spans = {}
    bare_links = {}
    brackets = []
    last_link = -1
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\":
            out.append(line[index:index + 2])
            index += 2
            continue
        if char == "<":
            special = INLINE_SPECIAL.match(line, index)
            if special:
                out.append(" " * len(special.group()))
                index = special.end()
                continue
            autolink = AUTOLINK.match(line, index)
            if autolink:
                out.append(" " * len(autolink.group()))
                index = autolink.end()
                continue
            tag = HTML_TAG.match(line, index)
            if tag:
                html_tags.append(tag.group())
                out.append(" " * len(tag.group()))
                index = tag.end()
                continue
        if not brackets and char in "hHfFw":
            end = bare_link_end(line, index)
            if end > index:
                bare_links[index] = end
                out.append(" " * (end - index))
                index = end
                continue
        if line.startswith("![", index):
            brackets.append((index + 1, (len(targets), len(html_tags))))
            out.append("![")
            index += 2
            continue
        if char == "[":
            brackets.append((index, None))
        elif char == "]" and brackets:
            opening, image_scope = brackets.pop()
            if image_scope is None and opening < last_link:
                out.append(char)
                index += 1
                continue
            parsed = (inline_destination(line, index + 1)
                      if line[index + 1:index + 2] == "(" else None)
            reference = LINK_LABEL.match(line, index + 1)
            label = reference[1] if reference and reference[1] else line[opening + 1:index]
            if parsed is not None or label_key(label) in labels:
                end = parsed[1] if parsed else reference.end() if reference else index + 1
                link_spans[opening] = (index, end, image_scope is not None)
                if image_scope is None:
                    last_link = opening
                else:
                    # An image description renders as alt text. Links and
                    # HTML tags within it do not create separate targets.
                    target_count, html_count = image_scope
                    del targets[target_count:]
                    del html_tags[html_count:]
                if parsed is not None:
                    end = parsed[1]
                    target_start = index + 2
                    while line[target_start:target_start + 1] in (" ", "\t", "\n"):
                        target_start += 1
                    targets.append((target_start, unescape(parsed[0])))
                    out.append("](" + " " * (end - index - 3) + ")")
                    index = end
                    continue
                if reference:
                    out.append(line[index:reference.end()])
                    index = reference.end()
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
    return "".join(out), targets, html_tags, link_spans, bare_links


def inline_paragraphs(text, definition_lines):
    """Group inline content across soft breaks within the same paragraph."""
    paragraph = []
    for source, cells in block_lines(text):
        number, content, changed, raw_html, lazy = source
        if cells is not None:
            if paragraph:
                yield paragraph
                paragraph = []
            for cell in cells:
                yield [(number, cell)]
            continue
        single = bool(ATX_HEADING.match(content) or THEMATIC_BREAK.match(content)
                      or (not lazy and SETEXT_UNDERLINE.match(content)))
        if (not content.strip(" \t") or raw_html or number in definition_lines or single or changed
                or (paragraph and number != paragraph[-1][0] + 1)):
            if paragraph:
                yield paragraph
                paragraph = []
        if content.strip(" \t") and not raw_html and number not in definition_lines:
            paragraph.append((number, content))
            if single:
                yield paragraph
                paragraph = []
    if paragraph:
        yield paragraph


def inline_lines(text, definition_lines, labels):
    for paragraph in inline_paragraphs(text, definition_lines):
        masked, targets, _, spans, _ = scan_inline_paragraph("\n".join(line for _, line in paragraph), labels)
        if any(image for _, _, image in spans.values()):
            visible = list(masked)
            for opening, (close, _, image) in spans.items():
                if image:
                    visible[opening + 1:close] = " " * (close - opening - 1)
            masked = "".join(visible)
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
    """Render heading text within one Markdown inline scope."""
    _, _, _, links, bare_links = scan_inline_paragraph(raw, labels)
    out = []
    marker_offsets = {}
    index = 0
    while index < len(raw):
        if index in bare_links:
            end = bare_links[index]
            out.extend(raw[index:end])
            index = end
            continue
        char = raw[index]
        if char == "\\" and index + 1 < len(raw) and raw[index + 1] in ASCII_PUNCTUATION:
            out.append(raw[index + 1])
            index += 2
            continue
        if char == "&":
            entity = ENTITY.match(raw, index)
            if entity:
                out.extend(markdown_entities(entity.group()))
                index = entity.end()
                continue
        if char == "`":
            opening = BACKTICKS.match(raw, index).group(0)
            closing = next(
                (run for run in BACKTICKS.finditer(raw, index + len(opening))
                 if run.group(0) == opening),
                None,
            )
            if closing is None:
                out.extend(opening)
                index += len(opening)
                continue
            content = raw[index + len(opening):closing.start()].replace("\n", " ")
            if len(content) > 1 and content[0] == content[-1] == " " and content.strip(" "):
                content = content[1:-1]
            out.extend(content)
            index = closing.end()
            continue
        if char == "!" and index + 1 in links and links[index + 1][2]:
            index = links[index + 1][1]
            continue
        if index in links:
            close, end, _ = links[index]
            out.extend(inline_text(raw[index + 1:close], labels))
            index = end
            continue
        if char == "<":
            special = INLINE_SPECIAL.match(raw, index)
            if special:
                index = special.end()
                continue
            autolink = AUTOLINK.match(raw, index)
            if autolink:
                out.extend(autolink.group(1))
                index = autolink.end()
                continue
            tag = HTML_TAG.match(raw, index)
            if tag:
                index = tag.end()
                continue
        if char == "\n":
            # Spaces before a prose line break are absent from rendered text.
            # Inside a code span they were already consumed as literal text.
            before_break = index
            while before_break and raw[before_break - 1] in " \t":
                out.pop()
                before_break -= 1
        if char in "_*":
            marker_offsets[len(out)] = index
        out.append(char)
        index += 1
    delimiters = emphasis_delimiters(raw, marker_offsets)
    return "".join(char for index, char in enumerate(out) if index not in delimiters)


def emphasis_delimiters(raw, marker_offsets):
    """Pair runs in this scope using their neighbors in the Markdown source."""
    def punctuation(char):
        return char in ASCII_PUNCTUATION or unicodedata.category(char).startswith("P")

    openers = []
    consumed = set()
    next_run = 0
    for index, start in marker_offsets.items():
        if index < next_run:
            continue
        marker = raw[start]
        end = index + 1
        while (marker_offsets.get(end) == start + end - index
               and raw[marker_offsets[end]] == marker):
            end += 1
        next_run = end
        source_end = start + end - index
        before = raw[start - 1] if start else " "
        after = raw[source_end] if source_end < len(raw) else " "
        left = not after.isspace() and (not punctuation(after) or before.isspace() or punctuation(before))
        right = not before.isspace() and (not punctuation(before) or after.isspace() or punctuation(after))
        can_open = left and (marker == "*" or not right or punctuation(before))
        can_close = right and (marker == "*" or not left or punctuation(after))
        remaining = index
        if can_close:
            for pos in range(len(openers) - 1, -1, -1):
                first, last, length, closes = openers[pos]
                if raw[marker_offsets[first]] != marker:
                    continue
                if ((can_open or closes) and (length + end - index) % 3 == 0
                        and length % 3 != 0):
                    continue
                count = min(last - first, end - remaining)
                consumed.update(range(last - count, last))
                consumed.update(range(remaining, remaining + count))
                remaining += count
                del openers[pos:]
                if first < last - count:
                    openers.append((first, last - count, length, closes))
                if remaining == end:
                    break
        if can_open and remaining < end:
            openers.append((remaining, end, end - index, can_close))
    return consumed


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
    for source, cells in block_lines(text):
        number, line, changed, raw_html, lazy = source
        if cells is not None:
            paragraph = []
            continue
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
        if not lazy and paragraph and paragraph[-1][0] == number - 1 and SETEXT_UNDERLINE.match(line):
            headings.append("\n".join(content for _, content in paragraph))
            paragraph = []
            continue
        if not line.strip(" \t") or THEMATIC_BREAK.fullmatch(line):
            paragraph = []
            continue
        if paragraph and paragraph[-1][0] != number - 1:
            paragraph = []
        paragraph.append((number, line.lstrip(" \t")))

    anchors = set()
    occurrences = {}
    for heading in headings:
        base = github_slug(inline_text(heading, labels).strip())
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
            seen = set()
            for attribute in HTML_ATTR.finditer(token["attrs"]):
                name = attribute[1].lower()
                if name in seen or name not in ("id", "name"):
                    continue
                seen.add(name)
                value = attribute[2]
                if value is not None:
                    if value[0] in ("'", '"'):
                        value = value[1:-1]
                    anchors.add(html_attribute_value(value))

    for lines in raw_blocks:
        collect_html("\n".join(line for _, line in lines))
    for paragraph in inline_paragraphs(text, definition_lines):
        _, _, tags, _, _ = scan_inline_paragraph("\n".join(line for _, line in paragraph), labels)
        for tag in tags:
            collect_html(tag)
    return anchors


def omitted_archive_reference(root, document, content, target, resolved, packages):
    """Accept only an unchanged archive's unpublished package-local target."""
    parts = document.relative_to(root).parts
    if len(parts) < 3 or parts[0] != "vendor":
        return False
    files = packages.get(parts[1], {}).get("upstream_files", {})
    document_name = pathlib.PurePosixPath(*parts[2:]).as_posix()
    if files.get(document_name) != hashlib.sha256(content).hexdigest():
        return False
    archive_root = root / "vendor" / parts[1]
    if not (target.is_relative_to(archive_root) and resolved.is_relative_to(archive_root)):
        return False
    # Inventories list files, not directories. A missing directory containing
    # published files is lost packaged content, not an omitted source path.
    # Check the requested name too: a dangling symlink must not disguise a
    # missing published file as an unrelated unpublished target.
    return all(
        name not in files and not any(path.startswith(name + "/") for path in files)
        for name in (target.relative_to(archive_root).as_posix(), resolved.relative_to(archive_root).as_posix())
    )


def checkout_url_path(root, document, file_part):
    """Resolve URL segments before mapping the destination into the checkout."""
    if not file_part:
        return document, False
    base = root if file_part.startswith("/") else document.parent
    parts = [os.fsencode(name) for name in base.relative_to(root).parts]
    for raw in file_part.removeprefix("/").split("/"):
        segment = urllib.parse.unquote_to_bytes(raw)
        if segment == b"..":
            if not parts:
                return None  # the URL left this repository
            parts.pop()
        elif segment != b".":
            parts.append(segment)  # an empty segment can also be removed by a later ".."
    directory = segment in (b"", b".", b"..")
    try:
        names = [os.fsdecode(part) for part in parts if part]
    except UnicodeDecodeError:
        return None
    # An encoded slash inside a surviving segment cannot name a checkout file.
    if any(pathlib.Path(name).name != name for name in names):
        return None
    return root.joinpath(*names), directory


def broken_links(root):
    root = root.resolve()
    candidates, skipped = candidate_files(root)

    def contents(path):
        if path in skipped:
            return subprocess.check_output(["git", "-C", str(root), "cat-file", "blob", skipped[path][1]])
        return path.read_bytes()

    anchor_cache = {}
    line_counts = {}
    encoding_errors = {}
    directories = {root}
    symlinks = {}
    for candidate in candidates:
        directories.update(parent for parent in candidate.parents if parent.is_relative_to(root))
        if candidate in skipped:
            mode, _ = skipped[candidate]
            if mode == b"120000":
                symlinks[candidate] = os.fsdecode(contents(candidate))
            elif mode == b"160000":
                directories.add(candidate)
        elif candidate.is_symlink():
            symlinks[candidate] = os.readlink(candidate)
        elif candidate.is_dir():
            directories.add(candidate)
    published = candidates | directories

    def resolve_target(path):
        """Follow checkout symlinks, preserving a dangling target's repository path."""
        if not path.is_relative_to(root):
            return None
        pending = list(reversed(path.relative_to(root).parts))
        current = root
        hops = 0
        while pending:
            part = pending.pop()
            if current in published and current not in directories:
                return None
            if current not in published and part in (".", ".."):
                return None
            current = current.parent if part == ".." else current / part
            if not current.is_relative_to(root):
                return None
            if current in symlinks:
                link = symlinks[current]
                target = pathlib.Path(link)
                hops += 1
                if target.is_absolute() or hops > 40:
                    return None
                # Path.parts strips a final slash or dot, which requires a directory.
                if os.path.basename(link) in ("", "."):
                    pending.append(".")
                pending.extend(reversed(target.parts))
                current = current.parent
        return current

    inventory = resolve_target(root / "vendor/upstream.json")
    packages = {}
    if inventory in candidates and inventory not in directories:
        packages = json.loads(contents(inventory))["packages"]

    def decode_document(path, content):
        encoding = "utf-16" if content.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8"
        try:
            text = content.decode(encoding)
        except UnicodeDecodeError as error:
            relative = path.relative_to(root).as_posix()
            encoding_errors[path] = f"{relative}: invalid {encoding} at byte {error.start}"
            return None
        line_counts[path] = text.count("\n") + bool(text and not text.endswith("\n"))
        return text

    def target_problem(path, content, target):
        """Why `target`, linked from `path`, is broken, or None."""
        if not target or target.startswith("//") or URI_SCHEME.match(target):
            return None
        file_part, _, fragment = target.partition("#")
        file_part, _, query = file_part.partition("?")
        checkout = checkout_url_path(root, path, file_part)
        if checkout is None:
            return target
        target_path, directory = checkout
        resolved = resolve_target(target_path)
        if resolved is None:
            return target
        if resolved not in published:
            if omitted_archive_reference(root, path, content, target_path, resolved, packages):
                return None
            return target
        if directory and resolved not in directories:
            return target
        fragment = urllib.parse.unquote(fragment)
        if fragment and resolved not in directories and target_path.suffix.lower() == ".md":
            if resolved in encoding_errors:
                return None
            span = re.fullmatch(r"L([1-9][0-9]*)(?:-L([1-9][0-9]*))?", fragment)
            if span and ("plain", "1") in urllib.parse.parse_qsl(query):
                if resolved not in line_counts:
                    if decode_document(resolved, contents(resolved)) is None:
                        return None
                count = line_counts[resolved]
                first, last = span[1], span[2] or span[1]
                if len(first) <= len(last) <= len(str(count)) and int(first) <= int(last) <= count:
                    return None
                return f"{target} (missing line)"
            if resolved not in anchor_cache:
                text = decode_document(resolved, contents(resolved))
                if text is None:
                    return None
                anchor_cache[resolved] = document_anchors(text)
            if fragment not in anchor_cache[resolved]:
                return f"{target} (missing anchor)"
        return None

    broken = []
    for path in sorted(path for path in candidates if path.name.lower().endswith(".md")):
        if path in encoding_errors:
            continue
        relative = path.relative_to(root).as_posix()
        resolved = resolve_target(path)
        if resolved not in candidates or resolved in directories:
            if path in symlinks:
                broken.append(f"{relative}: invalid Markdown symlink target")
            continue
        try:
            content = contents(resolved)
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            continue  # the indexed file was deleted or replaced by a directory
        text = decode_document(path, content)
        if text is None:
            continue
        definitions = reference_definitions(text)
        labels = frozenset(definition[3] for definition in definitions)
        problems = [
            (number, target_problem(path, content, destination))
            for _, _, number, _, destination in definitions
        ]
        definition_lines = {n for first, last, *_ in definitions for n in range(first, last + 1)}
        for number, line, masked, targets in inline_lines(text, definition_lines, labels):
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
    return broken + [encoding_errors[path] for path in sorted(encoding_errors)]


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
