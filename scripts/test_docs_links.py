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


if __name__ == "__main__":
    unittest.main()
