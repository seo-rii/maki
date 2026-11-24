"""Statements in the maintained documents that a file in the tree decides.

A refusal a guide quotes is a string in the sources, the tier table of the
testing guide describes steps of the workflow, a layout lists directories,
and the release pages describe what the release workflow tags. Each test
reads both sides, so that neither changes alone.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def prose(path):
    """A document's text with every run of whitespace as one space."""
    return " ".join((ROOT / path).read_text().split())


def rust_strings(path):
    """A Rust source's text with string continuations joined."""
    return re.sub(r"\\\n\s*", "", (ROOT / path).read_text())


class DocumentTest(unittest.TestCase):
    """Assertions on whole documents that name the document, not its text."""

    def has(self, text, phrase, where):
        self.assertTrue(phrase in text, f"{where} does not contain {phrase!r}")

    def lacks(self, text, phrase, where):
        self.assertFalse(phrase in text, f"{where} contains {phrase!r}")


class QuotedRefusals(DocumentTest):
    """The refusals the rollback guide quotes for an interrupted creation."""

    GUIDE = "docs/rollback-protection.md"
    # The message and the source that returns it.
    REFUSALS = (
        ("remote enrollment requires an empty backing",
         "crates/maki-backing/src/rollback/remote.rs"),
        ("remote witness already enrolled or occupied",
         "crates/maki-backing/src/rollback/remote.rs"),
        ("rollback enrollment requires empty backing and witness directories",
         "crates/maki-backing/src/rollback.rs"),
    )

    def test_each_refusal_of_volume_create_is_quoted_as_the_source_returns_it(self):
        guide = prose(self.GUIDE)
        for message, source in self.REFUSALS:
            with self.subTest(message=message):
                self.has(rust_strings(source), f'"{message}"', source)
                self.has(guide, f"`{message}`", self.GUIDE)

    def test_the_refusal_of_a_claimed_authority_is_told_apart_from_the_backing_check(self):
        # `create_remote` asks the authority before it looks at the backing
        # root, so a creation that stopped after its claim is answered by
        # the authority's state, never by the backing check.
        source = rust_strings("crates/maki-backing/src/rollback/remote.rs")
        create = source[source.index("pub fn create_remote("):]
        self.assertLess(create.index("remote witness already enrolled or occupied"),
                        create.index("initialize_remote_root("))
        guide = prose(self.GUIDE)
        occupied = "`remote witness already enrolled or occupied`"
        self.has(guide, occupied, self.GUIDE)
        at = guide.index(occupied)
        sentence = guide[guide.rindex(". ", 0, at):guide.index(". ", at)]
        before, after = sentence.split(occupied)
        self.assertIn("`remote enrollment requires an empty backing`", before)
        self.assertIn("unclaimed", before)
        self.assertIn("claimed the authority", after)


class LogFilterWarning(DocumentTest):
    """What the `MAKI_LOG` fallback warning carries."""

    WARNING = "MAKI_LOG is not a valid filter"

    def test_the_documents_say_the_warning_gives_a_reason_and_never_the_value(self):
        for sink in ("crates/maki-core/src/logging.rs", "crates/maki-privileged/src/logging.rs"):
            source = rust_strings(sink)
            self.has(source, f'"{self.WARNING}; ', sink)
            self.has(source, "fn invalid_filter_diagnostics_never_expose_selector_values", sink)
        for document in ("docs/operations.md", "docs/testing.md"):
            with self.subTest(document=document):
                text = prose(document)
                self.has(text, f"`{self.WARNING}`", document)
                self.lacks(text, "naming the value", document)


class CiTierTable(unittest.TestCase):
    """The tier table of the testing guide against the workflow's steps."""

    def formatting_steps(self):
        """{job: condition of its `cargo fmt` step} for the two matrix jobs."""
        jobs = dict(re.findall(r"(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)", WORKFLOW.read_text()))
        found = {}
        for job in ("pr", "latest-stable"):
            self.assertRegex(jobs[job], r"os: \[ubuntu-latest, windows-latest\]")
            step, = re.findall(r"(?m)^      - name: ([^\n]+)\n((?:        [^\n]*\n)*?)        run: cargo fmt --all --check\n",
                               jobs[job])
            found[job] = step[1].strip()
        return found

    def test_rows_of_jobs_that_format_on_linux_only_say_so(self):
        rows = dict(re.findall(r"(?m)^\| (Baseline|Compatibility) \|[^|]*\|[^|]*\| ([^|]*) \|$",
                               (ROOT / "docs/testing.md").read_text()))
        self.assertEqual(set(rows), {"Baseline", "Compatibility"})
        conditions = self.formatting_steps()
        for row, job in (("Baseline", "pr"), ("Compatibility", "latest-stable")):
            with self.subTest(row=row):
                self.assertEqual(conditions[job], "if: runner.os == 'Linux'")
                self.assertIn("formatting on Ubuntu", rows[row])
                self.assertNotRegex(rows[row], r"^Formatting\b",
                                    "formatting does not run on Windows")


class Layouts(unittest.TestCase):
    """The directory listings of SPEC §11 and the README."""

    def test_the_specification_lists_every_packaging_directory(self):
        spec = (ROOT / "SPEC.md").read_text()
        section = spec[spec.index("# 11. Project Layout"):spec.index("# 12. ")]
        tree = section[section.index("packaging/"):section.index("```", section.index("packaging/"))]
        listed = re.findall(r"(?m)^ +[├└]── ([\w.-]+)/$", tree)
        present = sorted(entry.name for entry in (ROOT / "packaging").iterdir() if entry.is_dir())
        self.assertEqual(sorted(listed), present)

    def test_the_readme_names_both_package_builders(self):
        row, = re.findall(r"(?m)^\| `packaging/` \| ([^|]*) \|$", (ROOT / "README.md").read_text())
        for builder, name in (("debian/build-deb.py", "Debian"), ("rpm/build-rpm.py", "RPM")):
            self.assertTrue((ROOT / "packaging" / builder).is_file())
            self.assertIn(name, row)


class ReleaseCandidates(DocumentTest):
    """The release workflow tags candidates, so no page may deny a tag."""

    def test_no_document_says_there_is_no_tagged_release(self):
        workflow = RELEASE_WORKFLOW.read_text()
        self.has(workflow, "--prerelease", "release.yml")
        self.has(workflow, "v<workspace version>-rc.<n>", "release.yml")
        version, = re.findall(r'(?ms)^\[workspace\.package\]\n.*?^version = "([^"]+)"$',
                              (ROOT / "Cargo.toml").read_text())
        for document in ("SECURITY.md", "CHANGELOG.md", "README.md", "docs/status.md"):
            with self.subTest(document=document):
                self.lacks(prose(document), "no tagged release", document)
        for document in ("SECURITY.md", "CHANGELOG.md", "docs/status.md"):
            with self.subTest(document=document):
                self.has(prose(document).lower(), "no final release", document)
                self.has(prose(document), f"`v{version}-rc.<n>`", document)


if __name__ == "__main__":
    unittest.main()
