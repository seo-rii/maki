"""Project links remain checked without rewriting preserved crate documents."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.check_docs_links import broken_links


class DocumentationLinks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)

    def write(self, name, content, tracked=True):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
        if tracked:
            subprocess.run(
                ["git", "-C", str(self.root), "add", "--", name], check=True
            )
        return path

    def archive(self, document="README.md", content="[Contributing](CONTRIBUTING.md)\n",
                extra_files=None):
        path = self.write(f"vendor/hyper/{document}", content)
        files = {document: hashlib.sha256(path.read_bytes()).hexdigest()}
        files.update(extra_files or {})
        self.write("vendor/upstream.json", json.dumps({
            "schema": 1,
            "packages": {"hyper": {"upstream_files": files}},
        }))
        return path

    def test_unchanged_archive_may_reference_an_omitted_source_file(self):
        self.archive()
        self.assertEqual(broken_links(self.root), [])

    def test_nested_archive_reference_uses_the_package_relative_path(self):
        self.archive("guide/README.md", "[Contributing](../CONTRIBUTING.md#setup)\n")
        self.assertEqual(broken_links(self.root), [])

    def test_original_document_hash_uses_raw_crlf_bytes(self):
        self.archive(content="[Contributing](CONTRIBUTING.md)\r\n")
        self.assertEqual(broken_links(self.root), [])

    def test_new_untracked_project_document_is_checked(self):
        self.write("draft.md", "[Broken](missing.md)\n", tracked=False)
        self.assertEqual(broken_links(self.root), ["draft.md:1: missing.md"])

    def test_ignored_untracked_document_is_not_a_commit_candidate(self):
        self.write(".gitignore", "scratch/\n")
        self.write("scratch/draft.md", "[Broken](missing.md)\n", tracked=False)
        self.assertEqual(broken_links(self.root), [])

    def test_tracked_document_is_checked_even_if_its_path_is_ignored(self):
        self.write("draft.md", "[Broken](missing.md)\n")
        self.write(".gitignore", "draft.md\n")
        self.assertEqual(broken_links(self.root), ["draft.md:1: missing.md"])

    def test_project_and_vendor_guide_links_are_not_exempt(self):
        self.archive()
        self.write("README.md", "[Broken](missing.md)\n")
        self.write("vendor/README.md", "[Broken](missing.md)\n")
        self.assertEqual(broken_links(self.root), [
            "README.md:1: missing.md", "vendor/README.md:1: missing.md",
        ])

    def test_edited_archive_document_loses_its_exception(self):
        path = self.archive()
        path.write_text("[Changed](missing.md)\n", encoding="utf-8")
        self.assertEqual(broken_links(self.root), ["vendor/hyper/README.md:1: missing.md"])

    def test_unrecorded_vendor_document_is_checked(self):
        self.archive()
        self.write("vendor/hyper/maki-notes.md", "[Broken](missing.md)\n")
        self.assertEqual(broken_links(self.root), [
            "vendor/hyper/maki-notes.md:1: missing.md",
        ])

    def test_missing_published_target_is_still_an_error(self):
        self.archive(extra_files={"CONTRIBUTING.md": "0" * 64})
        self.assertEqual(broken_links(self.root), [
            "vendor/hyper/README.md:1: CONTRIBUTING.md",
        ])

    def test_missing_published_directory_is_still_an_error(self):
        self.archive(content="[Guide](guide/)\n",
                     extra_files={"guide/chapter.md": "0" * 64})
        self.assertEqual(broken_links(self.root), ["vendor/hyper/README.md:1: guide/"])

    def test_dangling_symlink_cannot_hide_a_missing_published_target(self):
        self.archive(content="[License](LICENSE)\n", extra_files={"LICENSE": "0" * 64})
        (self.root / "vendor/hyper/LICENSE").symlink_to("missing-license")
        self.assertEqual(broken_links(self.root), [
            "vendor/hyper/README.md:1: LICENSE",
        ])

    def test_archive_exception_cannot_escape_its_package(self):
        self.archive(content="[Outside](../missing.md)\n")
        self.assertEqual(broken_links(self.root), [
            "vendor/hyper/README.md:1: ../missing.md",
        ])

    def test_fence_closer_must_match_marker_length_and_have_no_info(self):
        self.write("README.md", "````md\n```\n~~~\n````example\n"
                   "[sample](inside.md)\n`````\n[real](outside.md)\n")
        self.assertEqual(broken_links(self.root), ["README.md:7: outside.md"])

    def test_fences_end_at_the_list_item_or_quote_boundary(self):
        self.write("README.md", "10. example\n    ````md\n    [sample](inside.md)\n"
                   "    ```\n    ````\n[outside](one.md)\n\n"
                   "> - ~~~\n>   [sample](inside.md)\n> [outside](two.md)\n\n"
                   "- example\n  ```\n  [sample](inside.md)\n> [outside](three.md)\n")
        self.assertEqual(broken_links(self.root),
                         ["README.md:6: one.md", "README.md:10: two.md", "README.md:15: three.md"])

    def test_multiline_code_masks_links_references_and_anchors_only_in_its_paragraph(self):
        self.write("README.md", 'Text ``example `\n[shown](inside.md) [x][label] <a id="inside">\n'
                   'end`` [real](outside.md)\n\n[anchor](#inside)\n'
                   'Unmatched `tick\n\n[another](after.md) `literal\n')
        self.assertEqual(broken_links(self.root),
                         ["README.md:3: outside.md", "README.md:5: #inside (missing anchor)",
                          "README.md:8: after.md"])

    def test_backticks_and_brackets_in_a_destination_or_title_do_not_change_later_links(self):
        self.write("file`with).md", "# OK\n")
        self.write("README.md", """[ok](<file`with).md> 'title [x][label] <a id="hidden">') [bad](lost.md) `code`
[query](<file%60with%29.md?plain=1#ok>) [anchor](#hidden)
""")
        self.assertEqual(broken_links(self.root), ["README.md:1: lost.md",
                                                   "README.md:2: #hidden (missing anchor)"])

    def test_inline_code_is_not_a_link_or_an_html_anchor(self):
        self.write("README.md", '`<a id="sample"> [sample](inside.md)`\n[real](#sample)\n')
        self.assertEqual(broken_links(self.root), ["README.md:2: #sample (missing anchor)"])

    def test_inline_destinations_with_spaces_parentheses_and_titles(self):
        self.write("User Guide.md", "## here\n")
        self.write("right(one).md", "# yes\n")
        self.write("README.md", "[guide](User%20Guide.md#here)\n[guide](<User Guide.md>)\n"
                   "[guide](right(one).md 'title')\n[item](<Missing Guide.md>)\n"
                   "[![image](missing.png)](right(one).md)\n")
        self.assertEqual(broken_links(self.root),
                         ["README.md:4: Missing Guide.md", "README.md:5: missing.png"])

    def test_wrapped_label_retains_its_destination_and_report_line(self):
        self.write("guide#one%.md", "# Start\n")
        self.write("README.md", "[a wrapped\nlabel](guide%23one%25.md#start) and [a second\n"
                   "label](missing.md)\n\n[unmatched\n\nclosing](not-a-link.md)\n")
        self.assertEqual(broken_links(self.root), ["README.md:3: missing.md"])

    def test_unstaged_deletion_still_reports_links_to_the_removed_document(self):
        self.write("old.md", "# Old\n").unlink()
        self.write("README.md", "[old](old.md)\n")
        self.assertEqual(broken_links(self.root), ["README.md:1: old.md"])

    def test_dangling_markdown_symlink_is_reported_even_without_inbound_links(self):
        self.write("missing.md", "# Former file\n").unlink()
        (self.root / "guide.md").symlink_to("missing.md")
        self.write("README.md", "[other](no.md)\n")
        self.assertEqual(broken_links(self.root),
                         ["README.md:1: no.md", "guide.md: invalid Markdown symlink target"])

    def test_replacing_a_tracked_file_with_a_directory_checks_its_new_documents(self):
        old = self.write("old.md", "# Former file\n")
        old.unlink()
        self.write("old.md/new.md", "[missing](target.md)\n", tracked=False)
        self.assertEqual(broken_links(self.root), ["old.md/new.md:1: target.md"])

    def test_regular_link_filtering_and_locations_are_preserved(self):
        self.write("target.md", "# Present\n\n## Heading\n")
        self.write("README.md", """[Present](target.md#heading)
[Directory](.)
[Web](https://example.invalid/missing.md)
[Mail](mailto:test@example.invalid)
[Heading](#heading)
```text
[Example](missing.md)
```
~~~text
[Example](missing.md)
~~~
[Broken](missing.md#heading)
## Heading
""")
        self.assertEqual(broken_links(self.root), ["README.md:12: missing.md#heading"])


class DocumentationAnchors(unittest.TestCase):
    """Fragments must name a heading slug (GitHub's algorithm) or an explicit anchor."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
        subprocess.run(["git", "-C", str(self.root), "add", "--", name], check=True)

    def broken(self, headings, links):
        """Check `links` (one per line) against a target whose body is `headings`."""
        self.write("docs/target.md", headings)
        self.write("README.md", "".join(f"[link]({link})\n" for link in links))
        return [entry.split(": ", 1)[1] for entry in broken_links(self.root)]

    def test_cross_file_anchor_must_name_a_heading_exactly(self):
        self.assertEqual(self.broken("# Present\n\n## Other heading\n", [
            "docs/target.md#present",
            "docs/target.md#other-heading",
            "docs/target.md#missing",
            "docs/target.md#Present",
        ]), [
            "docs/target.md#missing (missing anchor)",
            "docs/target.md#Present (missing anchor)",
        ])

    def test_in_page_anchor_must_name_a_heading(self):
        self.write("README.md", "# Title\n\n[Here](#title)\n[Top](#)\n[Nowhere](#nope)\n")
        self.assertEqual(broken_links(self.root), ["README.md:5: #nope (missing anchor)"])

    def test_cross_directory_anchor_resolves_relative_to_the_linking_document(self):
        self.write("docs/guide.md", "# Guide\n\n[Back](../README.md#readme-title)\n"
                                    "[Wrong](../README.md#guide)\n")
        self.write("README.md", "# README title\n")
        self.assertEqual(broken_links(self.root), [
            "docs/guide.md:4: ../README.md#guide (missing anchor)",
        ])

    def test_punctuation_is_removed_and_each_space_becomes_a_hyphen(self):
        heading = "# Correctness and recovery review — 2026-10-12\n"
        self.assertEqual(self.broken(heading, [
            "docs/target.md#correctness-and-recovery-review--2026-10-12",
            "docs/target.md#correctness-and-recovery-review-2026-10-12",
        ]), ["docs/target.md#correctness-and-recovery-review-2026-10-12 (missing anchor)"])
        self.assertEqual(self.broken(
            "## Q&A: what's new? (v2.0) / §20 → done!\n",
            ["docs/target.md#qa-whats-new-v20--20--done"],
        ), [])

    def test_duplicate_headings_get_numeric_suffixes(self):
        self.assertEqual(self.broken("# Setup\n## Setup\n### Setup\n", [
            "docs/target.md#setup",
            "docs/target.md#setup-1",
            "docs/target.md#setup-2",
            "docs/target.md#setup-3",
        ]), ["docs/target.md#setup-3 (missing anchor)"])

    def test_inline_markup_in_headings_is_reduced_to_its_text(self):
        self.assertEqual(self.broken(
            "## The `max_bytes` setting\n"
            "## See [the guide](https://example.invalid/guide) first\n"
            "## *Emphasis*, __strong__ and snake_case\n"
            "## Closing hashes ##\n"
            "## Escaped \\_name\\_ and <b>tags</b> &amp; entities\n",
            [
                "docs/target.md#the-max_bytes-setting",
                "docs/target.md#see-the-guide-first",
                "docs/target.md#emphasis-strong-and-snake_case",
                "docs/target.md#closing-hashes",
                "docs/target.md#escaped-_name_-and-tags--entities",
            ],
        ), [])

    def test_explicit_html_anchors_are_accepted(self):
        self.assertEqual(self.broken(
            '<a id="custom-id"></a>\n\nText <a name="legacy">here</a>.\n',
            ["docs/target.md#custom-id", "docs/target.md#legacy", "docs/target.md#text"],
        ), ["docs/target.md#text (missing anchor)"])

    def test_fenced_headings_and_anchors_are_not_anchors(self):
        self.assertEqual(self.broken(
            "```text\n# Not a heading\n<a id=\"fenced\"></a>\n```\n~~~\n## Nor this\n~~~\n",
            ["docs/target.md#not-a-heading", "docs/target.md#fenced", "docs/target.md#nor-this"],
        ), [
            "docs/target.md#not-a-heading (missing anchor)",
            "docs/target.md#fenced (missing anchor)",
            "docs/target.md#nor-this (missing anchor)",
        ])

    def test_setext_headings_are_anchors_but_thematic_breaks_are_not(self):
        self.assertEqual(self.broken(
            "Introduction\n------------\n\nWhy This?\n=========\n\n"
            "- a list item\n---\n\nParagraph\n\n---\n",
            [
                "docs/target.md#introduction",
                "docs/target.md#why-this",
                "docs/target.md#--a-list-item",
                "docs/target.md#a-list-item",
                "docs/target.md#paragraph",
            ],
        ), [
            "docs/target.md#--a-list-item (missing anchor)",
            "docs/target.md#a-list-item (missing anchor)",
            "docs/target.md#paragraph (missing anchor)",
        ])

    def test_hashes_without_a_space_do_not_start_a_heading(self):
        self.assertEqual(self.broken("#hashtag\n####### seven\n", [
            "docs/target.md#hashtag",
            "docs/target.md#-seven",
        ]), [
            "docs/target.md#hashtag (missing anchor)",
            "docs/target.md#-seven (missing anchor)",
        ])

    def test_percent_encoded_fragment_is_decoded(self):
        self.assertEqual(self.broken("# Café\n", [
            "docs/target.md#caf%C3%A9",
            "docs/target.md#café",
        ]), [])

    def test_fragments_of_non_markdown_targets_are_not_checked(self):
        self.write("src/lib.rs", "fn main() {}\n")
        self.assertEqual(self.broken("# Target\n", ["src/lib.rs#L1", "docs/"]), [])

    def test_missing_target_with_anchor_is_reported_once_as_a_missing_file(self):
        self.assertEqual(self.broken("# Target\n", ["docs/missing.md#target"]),
                         ["docs/missing.md#target"])

    def test_omitted_archive_target_keeps_its_exception_and_its_anchor_unchecked(self):
        path = self.root / "vendor/hyper/README.md"
        self.write("vendor/hyper/README.md", "[Contributing](CONTRIBUTING.md#setup)\n")
        self.write("vendor/upstream.json", json.dumps({
            "schema": 1,
            "packages": {"hyper": {"upstream_files": {
                "README.md": hashlib.sha256(path.read_bytes()).hexdigest(),
            }}},
        }))
        self.assertEqual(broken_links(self.root), [])

    def test_anchor_in_an_unchanged_archive_document_is_checked_when_its_target_exists(self):
        self.write("vendor/hyper/guide.md", "# Guide\n")
        path = self.root / "vendor/hyper/README.md"
        self.write("vendor/hyper/README.md", "[Guide](guide.md#guide)\n[Bad](guide.md#nope)\n")
        self.write("vendor/upstream.json", json.dumps({
            "schema": 1,
            "packages": {"hyper": {"upstream_files": {
                "README.md": hashlib.sha256(path.read_bytes()).hexdigest(),
                "guide.md": hashlib.sha256(b"# Guide\n").hexdigest(),
            }}},
        }))
        self.assertEqual(broken_links(self.root), [
            "vendor/hyper/README.md:2: guide.md#nope (missing anchor)",
        ])


class DocumentationReferenceLinks(unittest.TestCase):
    """Reference definitions (`[label]: target "title"`) are links too.

    GitHub renders `[text][label]`, `[label][]` and `[label]` through the
    document's own definitions (CommonMark): labels match case-insensitively
    with whitespace collapsed, and a full or collapsed reference whose label
    has no definition is shown as literal bracketed text.
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        self.write("docs/target.md", "# Present\n")

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
        subprocess.run(["git", "-C", str(self.root), "add", "--", name], check=True)
        return path

    def test_definition_targets_must_exist(self):
        self.write("README.md", "See [present][ok] and [gone][].\n\n"
                                "[ok]: docs/target.md\n"
                                "[gone]: docs/missing.md\n"
                                "[dir]: docs/\n")
        self.assertEqual(broken_links(self.root), ["README.md:4: docs/missing.md"])

    def test_definition_anchors_must_name_a_heading(self):
        self.write("README.md", "# Title\n\n[a] [b] [c] [d]\n\n"
                                "[a]: docs/target.md#present\n"
                                "[b]: docs/target.md#absent\n"
                                "[c]: #title\n"
                                "[d]: #nope\n")
        self.assertEqual(broken_links(self.root), [
            "README.md:6: docs/target.md#absent (missing anchor)",
            "README.md:8: #nope (missing anchor)",
        ])

    def test_definition_syntax_variants_are_recognized(self):
        self.write("README.md", "\n".join([
            "[angle]: <docs/missing-angle.md>",
            '[double]: docs/missing-double.md "Title"',
            "[single]: docs/missing-single.md 'Title'",
            "[paren]: docs/missing-paren.md (Title)",
            "   [indented]: docs/missing-indented.md",
            "[next-line]:",
            "  docs/missing-next-line.md",
            '  "title on its own line"',
            "[escaped]: docs/missing\\_escaped.md",
            "",
            "> [quoted]: docs/missing-quoted.md",
            "",
            "- [listed]: docs/missing-listed.md",
            "",
        ]))
        self.assertEqual(broken_links(self.root), [
            "README.md:1: docs/missing-angle.md",
            "README.md:2: docs/missing-double.md",
            "README.md:3: docs/missing-single.md",
            "README.md:4: docs/missing-paren.md",
            "README.md:5: docs/missing-indented.md",
            "README.md:7: docs/missing-next-line.md",
            "README.md:9: docs/missing_escaped.md",
            "README.md:11: docs/missing-quoted.md",
            "README.md:13: docs/missing-listed.md",
        ])

    def test_lines_github_does_not_treat_as_definitions_are_not_checked(self):
        self.write("README.md", "\n".join([
            "```text",
            "[fenced]: missing-fenced.md",
            "```",
            "[note]: see the next section",
            "",
            '[bad-title]: missing-bad-title.md "unterminated',
            "",
            '[trailing]: missing-trailing.md "Title" text',
            "",
            "A paragraph line",
            "[continuation]: missing-continuation.md",
            "",
            "[empty]: <>",
            "[web]: https://example.invalid/missing.md",
            "[mail]: mailto:test@example.invalid",
            "[^footnote]: missing-footnote.md is footnote text",
            "",
        ]))
        self.assertEqual(broken_links(self.root), [])

    def test_undefined_full_and_collapsed_references_are_reported(self):
        self.write("README.md", "\n".join([
            "[Text][defined] and [Defined][] resolve.",
            "[Text][missing] does not.",
            "Neither does [missing][].",
            "Nor ![an image][missing-image].",
            "An undefined shortcut [like this] is ordinary text.",
            "- [x] a task item and [an inline link](docs/target.md).",
            "`[code][span]` and \\[escaped][] are not references.",
            "[inline][label](docs/target.md) has an inline link after it.",
            "Footnotes[^1] are not links.",
            "[![badge][missing-badge]][defined] nests an undefined image.",
            "[A link](https://example.invalid/?q[0][1]) has brackets in its URL.",
            "[foo][bar][defined]: `[bar][defined]` is the link, `[foo]` text.",
            "",
            "[defined]: docs/target.md",
            "[^1]: The footnote.",
            "",
        ]))
        self.assertEqual(broken_links(self.root), [
            "README.md:2: [Text][missing] (undefined reference)",
            "README.md:3: [missing][] (undefined reference)",
            "README.md:4: [an image][missing-image] (undefined reference)",
            "README.md:10: [badge][missing-badge] (undefined reference)",
        ])

    def test_labels_match_case_insensitively_with_whitespace_collapsed(self):
        self.write("README.md", "\n".join([
            "[a][FOO BAR] [b][ foo   bar ] [Foo Bar][] [c][ẞ] [d][other]",
            "",
            "[Foo  Bar]: docs/target.md",
            "[SS]: docs/target.md",
            "",
        ]))
        self.assertEqual(broken_links(self.root), [
            "README.md:1: [d][other] (undefined reference)",
        ])

    def test_definitions_are_scoped_to_their_document(self):
        self.write("docs/other.md", "[elsewhere]: target.md\n")
        self.write("README.md", "[text][elsewhere]\n")
        self.assertEqual(broken_links(self.root), [
            "README.md:1: [text][elsewhere] (undefined reference)",
        ])

    def test_every_definition_is_checked_even_a_duplicate_label(self):
        self.write("README.md", "[text][dup]\n\n"
                                "[dup]: docs/target.md\n"
                                "[DUP]: docs/missing.md\n")
        self.assertEqual(broken_links(self.root), ["README.md:4: docs/missing.md"])

    def test_reference_links_in_headings_contribute_their_text_to_the_slug(self):
        self.write("docs/target.md", "\n".join([
            "## See [the guide][g] first",
            "## Use [Shortcut] now",
            "## Read [Collapsed][] too",
            "## Literal [undefined][nothing] text",
            "",
            "[g]: https://example.invalid/guide",
            "[shortcut]: https://example.invalid/shortcut",
            "[collapsed]: https://example.invalid/collapsed",
            "",
        ]))
        self.write("README.md", "\n".join([
            "[a](docs/target.md#see-the-guide-first)",
            "[b](docs/target.md#use-shortcut-now)",
            "[c](docs/target.md#read-collapsed-too)",
            "[d](docs/target.md#literal-undefinednothing-text)",
            "",
        ]))
        self.assertEqual(broken_links(self.root), [
            "docs/target.md:4: [undefined][nothing] (undefined reference)",
        ])

    def test_unchanged_archive_definitions_keep_the_omission_exception(self):
        self.write("vendor/hyper/guide.md", "# Guide\n")
        path = self.write("vendor/hyper/README.md", "[examples] [guide] [bad]\n\n"
                                                    "[examples]: examples/\n"
                                                    "[guide]: guide.md#guide\n"
                                                    "[bad]: guide.md#nope\n")
        self.write("vendor/upstream.json", json.dumps({
            "schema": 1,
            "packages": {"hyper": {"upstream_files": {
                "README.md": hashlib.sha256(path.read_bytes()).hexdigest(),
                "guide.md": hashlib.sha256(b"# Guide\n").hexdigest(),
            }}},
        }))
        self.assertEqual(broken_links(self.root), [
            "vendor/hyper/README.md:5: guide.md#nope (missing anchor)",
        ])


if __name__ == "__main__":
    unittest.main()
