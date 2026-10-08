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
        self.write("target.md", "# Present\n")
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
""")
        self.assertEqual(broken_links(self.root), ["README.md:12: missing.md#heading"])


if __name__ == "__main__":
    unittest.main()
