"""Statements in the maintained documents that a file in the tree decides.

A refusal a guide quotes is a string in the sources, the tier table of the
testing guide describes steps of the workflow, a layout lists directories,
the release pages describe what the release workflow tags, and a command a
guide runs must exist on a host that has only the package's dependencies.

Each test reads the source and the document. Two compare structures and hold
what they say: the directories SPEC §11 lists against `packaging/`, and the
commands of the guides against the forms `DaemonUserCommands` names. The
others pin prose by an exact phrase, present or absent. They keep a quoted
message equal to the string its source returns and keep a corrected sentence
from being put back as it was; a page that says the same false thing in
other words passes, and so does a false statement no phrase was written for.
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


FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")


def code_of(markdown):
    """(lines of the fenced blocks, inline code spans outside them) of a Markdown text."""
    lines, prose, fence = [], [], None
    for line in markdown.splitlines():
        marker, stripped = FENCE.match(line), line.strip()
        if fence is None:
            if marker:
                fence = marker.group(1)
            else:
                prose.append(line)
        elif stripped.startswith(fence) and not stripped.strip(fence[0]):
            fence = None  # the same marker, at least as long, and nothing else
        else:
            lines.append(line)
    # A span may wrap with its paragraph; a stray backtick ends with it.
    spans = [" ".join(span.group(2).split())
             for paragraph in re.split(r"\n[ \t]*\n", "\n".join(prose))
             for span in CODE_SPAN.finditer(" ".join(paragraph.split()))]
    return lines, spans


# `sudo` as a command word and the words up to the end of its command.
SUDO = re.compile(r"(?<![\w./-])sudo(?![\w.-])([^\n|;&`]*)")
# sudo's own options that take a value: the word after one is not the command.
SUDO_VALUE_FLAGS = "CDghpRrTtU"
SUDO_VALUE_OPTIONS = ("--chdir", "--chroot", "--close-from", "--command-timeout", "--group",
                      "--host", "--other-user", "--prompt", "--role", "--type")


def sudo_selects_a_user(words):
    """Whether sudo's own options, the words before its command, name a user."""
    words = iter(words)
    for word in words:
        if word == "--" or not word.startswith("-"):
            return False  # the command starts here: `sudo journalctl -u unit`
        if word.startswith("--"):
            if word.split("=")[0] == "--user":
                return True
            if word in SUDO_VALUE_OPTIONS:
                next(words, None)
            continue
        for position, flag in enumerate(word[1:], 1):
            if flag == "u":
                return True
            if flag in SUDO_VALUE_FLAGS:
                if position == len(word) - 1:
                    next(words, None)  # its value is the next word
                break
    return False


def sudo_user_switches(line):
    """Each `sudo` of a line that runs its command as a user it names."""
    return [found.group(0).strip() for found in SUDO.finditer(line)
            if sudo_selects_a_user(found.group(1).split())]


# `runuser` as a command word, and the one form the guides give it.
RUNUSER = re.compile(r"(?<![\w./-])runuser(?![\w.-])")
RUNUSER_FORM = re.compile(r"(?<![\w./-])runuser -u (maki|maki-witness) -- \S")


def runuser_commands(text, markdown=True):
    """The commands of a page that run `runuser`.

    In Markdown a command is a line of a fenced block that names the program
    outside a shell comment, or an inline code span that starts with it. The
    word in prose, in a table or alone in a code span is a mention. A manual
    page marks no code, so each of its lines that names the program counts.
    """
    if not markdown:
        return [line.replace("\\-", "-").strip() for line in text.splitlines()
                if RUNUSER.search(line)]
    lines, spans = code_of(text)
    commands = [line.split(" #")[0].strip() for line in lines if not line.lstrip().startswith("#")]
    return ([command for command in commands if RUNUSER.search(command)]
            + [span for span in spans if span.startswith("runuser ")])


def runuser_users(command):
    """The accounts a command reaches, or None when one of its `runuser` has another form."""
    users = RUNUSER_FORM.findall(command)
    return users if len(users) == len(RUNUSER.findall(command)) else None


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


class DaemonUserCommands(DocumentTest):
    """How the guides, which run as root, run a command as another user.

    Neither package depends on sudo, and a minimal Debian 12 or RHEL 9
    installation has none; `runuser` comes with util-linux, which both
    packages require. No guide may have sudo select a user, wherever the
    option stands among sudo's own (`sudo -u maki`, `sudo -H -u maki`,
    `sudo --user=maki`); sudo used to become root is left alone. Every
    `runuser` command must name the daemon user or the witness account and
    end its options with `--`. `su` is not checked: util-linux ships it as
    well, so it is not a program a host may lack.
    """

    maxDiff = None

    def guides(self):
        """Every maintained guide; dated reports and records keep their text."""
        pages = [ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "CONTRIBUTING.md", ROOT / "SPEC.md"]
        pages += sorted((ROOT / "docs").rglob("*.md"))
        pages += sorted((ROOT / "packaging").rglob("*.md")) + sorted((ROOT / "packaging").rglob("*.8"))
        pages += sorted((ROOT / "examples").rglob("*.md"))
        return [page for page in pages
                if "qualification" not in page.parts and not page.name.startswith("review-")]

    def test_no_guide_switches_user_through_sudo(self):
        guides = self.guides()
        for expected in ("docs/getting-started/quickstart.md", "docs/operations.md",
                         "docs/deployment/postgres.md", "docs/rollback-protection.md",
                         "docs/remote-witness-service.md", "README.md"):
            self.assertIn(ROOT / expected, guides)
        # Prose and code alike; a manual page writes its hyphens as `\\-`.
        found = [f"{page.relative_to(ROOT)}:{number}: {line.strip()}"
                 for page in guides
                 for number, line in enumerate(page.read_text().splitlines(), 1)
                 if sudo_user_switches(line.replace("\\-", "-"))]
        self.assertEqual(found, [], "use `runuser -u <user> -- <command>`")

    def test_sudo_is_judged_by_its_own_options_and_not_by_those_of_its_command(self):
        for line in ("sudo -u maki maki volume create /etc/maki/volumes/demo.toml",
                     "sudo -H -u maki maki check demo.toml --deep",
                     "sudo -Hu maki true",
                     "sudo -umaki true",
                     "sudo --user=maki true",
                     "sudo --user maki true",
                     "sudo -g maki -u maki true",
                     "sudo -n -- true && sudo -iu maki-witness",
                     "the daemon user (`sudo -H -u maki`), but",
                     "install -d /var/lib/maki/demo; sudo -u maki true"):
            with self.subTest(line=line):
                self.assertEqual(len(sudo_user_switches(line)), 1)
        for line in ("sudo journalctl -u maki@demo.service",
                     "sudo maki-attach verify --volume pg",
                     "sudo systemctl --user status",
                     "sudo -n true",
                     "sudo -g maki true",
                     "sudo -- id -u",
                     "same as root or with passwordless `sudo`. A new test -u that",
                     "pseudo -u maki"):
            with self.subTest(line=line):
                self.assertEqual(sudo_user_switches(line), [])

    def test_every_runuser_command_names_the_user_and_ends_its_options(self):
        users = set()
        for page in self.guides():
            for command in runuser_commands(page.read_text(), markdown=page.suffix == ".md"):
                with self.subTest(page=str(page.relative_to(ROOT)), command=command):
                    reached = runuser_users(command)
                    self.assertIsNotNone(reached, "use `runuser -u <user> -- <command>`")
                    users.update(reached)
        # The daemon user in the volume guides, the witness account in its own.
        self.assertEqual(users, {"maki", "maki-witness"})

    def test_a_mention_of_runuser_is_no_command_and_a_malformed_command_is_found(self):
        page = "\n".join((
            "`runuser` comes with util-linux; runuser needs no password as root.",
            "",
            "| Package | Programs the guides use |",
            "|---|---|",
            "| util-linux | `runuser`, `mount` and /etc/pam.d/runuser |",
            "",
            "Run it as the daemon user (`runuser -u maki -- …`), or give the whole",
            "command to the witness account (`runuser -u maki-witness --",
            "maki-witness init /var/lib/maki-witness/volume`).",
            "",
            "   ```bash",
            "   # runuser, not sudo: the packages do not depend on sudo",
            "   install -d -o maki /x &&",
            "       runuser -u maki -- maki volume create demo.toml  # as the daemon user",
            "   ```",
        ))
        commands = runuser_commands(page)
        self.assertEqual(commands, [
            "runuser -u maki -- maki volume create demo.toml",
            "runuser -u maki -- …",
            "runuser -u maki-witness -- maki-witness init /var/lib/maki-witness/volume",
        ])
        self.assertEqual([runuser_users(command) for command in commands],
                         [["maki"], ["maki"], ["maki-witness"]])
        for malformed in ("as that user (`runuser -u maki maki check demo.toml`), but",
                          "`runuser maki -- true`",
                          "```\nrunuser -u postgres -- true\n```",
                          "```bash\nrunuser -u maki -- true && runuser -l maki\n```"):
            with self.subTest(malformed=malformed):
                commands = runuser_commands(malformed)
                self.assertEqual(len(commands), 1)
                self.assertIsNone(runuser_users(commands[0]))
        # A manual page: every line that names the program, hyphens unescaped.
        self.assertEqual(runuser_commands(".B runuser \\-u maki \\-\\- maki check\n", markdown=False),
                         [".B runuser -u maki -- maki check"])
        self.assertIsNone(runuser_users(runuser_commands("runuser maki\n", markdown=False)[0]))

    def test_both_packages_require_the_package_that_ships_runuser(self):
        deb = (ROOT / "packaging/debian/build-deb.py").read_text()
        depends, = re.findall(r"(?m)^    depends = \[([^\]]*)\]$", deb)
        self.assertIn('"util-linux"', depends)
        spec = (ROOT / "packaging/rpm/maki.spec").read_text()
        self.assertRegex(spec, r"(?m)^Requires:\s+util-linux$")


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


class HelperAndWitnessStatements(DocumentTest):
    """What the helper's man page and the witness guide say its code does."""

    MAN = "packaging/debian/man/maki-attach.8"

    def test_the_run_as_root_hint_comes_with_the_state_files_and_the_gates_configuration(self):
        # `state::named` adds the hint to a refusal for a caller that is not
        # the files' owner; it is the one place the hint is written.
        sources = sorted((ROOT / "crates/maki-privileged/src").rglob("*.rs"))
        sources += sorted((ROOT / "bins/maki-attach/src").rglob("*.rs"))
        sources = [path for path in sources if not path.name.endswith("_tests.rs")
                   and not path.name.startswith("review_")]
        hinted = [path.relative_to(ROOT).as_posix() for path in sources
                  if "; run this command as root" in rust_strings(path.relative_to(ROOT))]
        self.assertEqual(hinted, ["crates/maki-privileged/src/state.rs"])
        callers = {}
        for path in sources:
            text = rust_strings(path.relative_to(ROOT))
            calls = re.findall(r"(?<![\w:.])named\(\s*(\"[^\"]*\"|\w+)", text)
            if calls:
                callers[path.relative_to(ROOT).as_posix()] = calls
        # The state directory, its lock and its records, and the attachment
        # file `verify` reads (`gate_config`); the other commands read theirs
        # through `config::load` or `exec::load_trusted_config`, which do not.
        self.assertEqual(sorted(callers), ["crates/maki-privileged/src/state.rs",
                                           "crates/maki-privileged/src/workload_verify.rs"])
        self.assertEqual(callers["crates/maki-privileged/src/workload_verify.rs"],
                         ['"attach config"'])
        man = prose(self.MAN)
        self.lacks(man, "or its lock names that path, and says to run the command as root", self.MAN)
        self.lacks(man, "one about the state directory or its lock also says", self.MAN)
        self.has(man, "one about the state directory, its lock or the attachment file that .B verify "
                      "reads also says to run the command as root", self.MAN)

    def test_the_block_size_bound_is_the_kernel_page_size(self):
        config = rust_strings("crates/maki-privileged/src/config.rs")
        check = config[config.index("pub fn check_device_block_size"):]
        self.has(check[:check.index("\n}")], "_SC_PAGESIZE", "check_device_block_size")
        self.has(rust_strings("bins/maki-attach/src/main.rs"),
                 'check_device_block_size("--block-size"', "maki-attach main.rs")
        self.has(prose(self.MAN), "a power of two from 512 up to the kernel's page size", self.MAN)

    def test_a_changed_witness_state_is_refused_first_as_invalid(self):
        def flat(path):
            return " ".join(rust_strings(path).split())
        store = flat("crates/maki-backing/src/remote_witness.rs")
        self.has(store, "fn invalid(message: &'static str) -> io::Error { "
                        "io::Error::new(io::ErrorKind::InvalidData, message) }", "remote_witness.rs")
        self.has(store, 'invalid("remote witness changed while locked")', "remote_witness.rs")
        wire = flat("crates/maki-witness/src/lib.rs")
        self.has(wire, "io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => "
                       "WireError::InvalidRequest", "maki-witness lib.rs")
        self.has(wire, 'WireError::InvalidRequest => invalid("witness request rejected")',
                 "maki-witness lib.rs")
        self.has(wire, "fn invalid(message: &'static str) -> io::Error { "
                       "io::Error::new(io::ErrorKind::InvalidInput, message) }", "maki-witness lib.rs")
        session = flat("crates/maki-backing/src/rollback/remote.rs")
        stops = session[session.index("fn stops_session("):]
        self.has(stops[:stops.index("fn ", 3)], "Self::Remote(_) => matches!( error.kind(), "
                 "io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput", "stops_session")
        guide = prose("docs/remote-witness-service.md")
        self.lacks(guide, "stops decoding while `serve` holds its lock also makes it answer "
                          "unavailable until a restart", "remote-witness-service.md")
        self.has(guide, "makes it refuse the next request as invalid", "remote-witness-service.md")

if __name__ == "__main__":
    unittest.main()
