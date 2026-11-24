"""Contract of the release workflow (.github/workflows/release.yml).

It is run by hand from main and publishes only a release candidate,
v<workspace version>-rc.<n>, as a GitHub pre-release; it refuses before
building a tag or ref it must not publish; only its publish job may write;
the Debian bundle comes from prepare_release.py in Debian 12 and the RPM
from build-rpm.py in CentOS Stream 9, both from the dispatched commit with
its whole history; every asset is checked against SHA-256 sums; the release
is created as a draft with the runner's gh and published only once every
asset is there, so a failure leaves no tag; and the notes say what each
asset is, that nothing is signed and that the release is not qualified.

The publish steps are run against a stand-in `gh` that keeps releases and
tags the way GitHub does (a draft has no tag until it is published).
"""

import hashlib
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
HELPER = ROOT / "scripts" / "release_assets.py"
TEMPLATE = ROOT / ".github" / "release-notes.md"
RPM_BUILDER = ROOT / "packaging" / "rpm" / "build-rpm.py"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
OTHER = "fedcba9876543210fedcba9876543210fedcba98"
VERSION = "0.1.0~rc+rev7.git0123456789ab"
REPOSITORY = "seo-rii/maki"
ALLOWED_ACTIONS = {"actions/checkout@v4", "actions/upload-artifact@v4", "actions/download-artifact@v4"}


def body(text, after):
    return text.split(after, 1)[1]


def jobs():
    """Each job's body, by name."""
    text = body(WORKFLOW.read_text(), "\njobs:\n")
    return dict(re.findall(r"(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)", text))


def steps(job):
    """(name or action, body) of each step, comments removed."""
    text = "".join(line for line in job.splitlines(keepends=True) if not line.lstrip().startswith("#"))
    found = re.findall(r"(?ms)^      - (?:name: ([^\n]+)|uses: ([^\n]+))\n(.*?)(?=^      - |\Z)", text)
    return [(name or uses, rest) for name, uses, rest in found]


def run_script(step):
    """The `run` block of a step as the runner's shell receives it."""
    block = re.search(r"(?m)^        run: \|\n((?:          .*\n|\n)+)", step)
    if block:
        return "".join(line[10:] + "\n" for line in block.group(1).splitlines())
    line = re.search(r"(?m)^        run: (.+)$", step)
    assert line is not None, step
    return line.group(1) + "\n"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_bundle(directory, files, manifest):
    directory.mkdir(parents=True)
    for name, contents in files.items():
        (directory / name).write_bytes(contents)
    (directory / "manifest.json").write_text(json.dumps(manifest))
    names = sorted([*files, "manifest.json"])
    (directory / "SHA256SUMS").write_text("".join(f"{sha256(directory / name)}  {name}\n" for name in names))


def cargo_toml(directory, version="0.1.0"):
    path = directory / "Cargo.toml"
    path.write_text(f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{version}"\n')
    return path


def helper(*arguments, cwd=None, environment=None):
    return subprocess.run([sys.executable, "-B", str(HELPER), *arguments], cwd=cwd, env=environment,
                          capture_output=True, text=True)


class Workflow(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()
        self.jobs = jobs()

    def step(self, job, name):
        return dict(steps(self.jobs[job]))[name]

    def test_it_runs_only_when_dispatched_with_a_required_tag(self):
        trigger = self.text.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
        self.assertEqual(re.findall(r"(?m)^  (\w+):", trigger), ["workflow_dispatch"])
        self.assertEqual(re.findall(r"(?m)^      (\w+):$", trigger), ["tag"])
        tag = trigger.split("      tag:\n", 1)[1]
        self.assertIn("        required: true\n", tag)
        self.assertIn("        type: string\n", tag)

    def test_only_the_publish_job_may_write(self):
        self.assertIn("\npermissions:\n  contents: read\n\n", self.text)
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                granted = re.findall(r"(?m)^    permissions:\n((?:      .*\n)+)", job)
                self.assertEqual(granted, ["      contents: write\n"] if name == "publish" else [])
        self.assertEqual(self.text.count(": write"), 1)

    def test_runs_are_serialised_and_every_job_is_bounded(self):
        self.assertIn("\nconcurrency:\n  group: release\n  cancel-in-progress: false\n", self.text)
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                self.assertRegex(job, r"(?m)^    timeout-minutes: \d+$")
                self.assertNotRegex(job, r"(?m)^    (?:if|continue-on-error):")

    def test_every_run_step_uses_bash(self):
        # In a container job a step without `shell:` runs under `sh -e`, which
        # is dash in debian:12: `set -o pipefail` is an illegal option there
        # (the first release run failed so). Every step runs under bash.
        self.assertIn("\ndefaults:\n  run:\n    shell: bash\n", self.text)
        self.assertNotRegex(self.text, r"(?m)^\s+shell: (?!bash$)")

    def test_jobs_containers_and_order(self):
        self.assertEqual(list(self.jobs), ["check", "deb", "rpm", "publish"])
        expected = {"check": None, "deb": "debian:12", "rpm": "quay.io/centos/centos:stream9", "publish": None}
        for name, image in expected.items():
            with self.subTest(job=name):
                self.assertIn("    runs-on: ubuntu-latest\n", self.jobs[name])
                containers = re.findall(r"(?m)^    container: (\S+)$", self.jobs[name])
                self.assertEqual(containers, [image] if image else [])
        self.assertIn("    needs: check\n", self.jobs["deb"])
        self.assertIn("    needs: check\n", self.jobs["rpm"])
        self.assertIn("    needs: [check, deb, rpm]\n", self.jobs["publish"])

    def test_only_first_party_actions_and_the_baseline_toolchain(self):
        baseline = re.findall(r"uses: (dtolnay/rust-toolchain@[\w.]+)", CI.read_text().split("\n  pr:\n")[1])[0]
        used = set(re.findall(r"(?m)^\s+- uses: (\S+)$", self.text))
        self.assertEqual(used - ALLOWED_ACTIONS, {baseline})
        self.assertNotRegex(self.text.lower(), r"release-action|action-gh-release|create-release|upload-release")
        self.assertNotIn("rust-cache", self.text, "release artifacts must not be built from a shared cache")
        for job in ("deb", "rpm"):
            self.assertIn(baseline, [name for name, _ in steps(self.jobs[job])])

    def test_inputs_reach_shell_steps_only_through_the_environment(self):
        for name, job in self.jobs.items():
            for step_name, step in steps(job):
                if "run:" in step:
                    with self.subTest(job=name, step=step_name):
                        self.assertNotIn("${{", run_script(step))
        self.assertEqual(set(re.findall(r"\$\{\{ inputs\.(\w+) \}\}", self.text)), {"tag"})
        for line in re.findall(r"(?m)^.*\$\{\{ inputs\.tag \}\}.*$", self.text):
            self.assertEqual(line.strip(), "TAG: ${{ inputs.tag }}")

    def test_every_checkout_is_the_dispatched_commit_and_the_builds_have_its_history(self):
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                checkout = dict(steps(job))["actions/checkout@v4"]
                self.assertIn("          ref: ${{ github.sha }}\n", checkout)
                if name in ("deb", "rpm"):
                    self.assertIn("          fetch-depth: 0\n", checkout)

    def test_the_check_job_refuses_before_anything_is_built(self):
        names = [name for name, _ in steps(self.jobs["check"])]
        self.assertEqual(names, ["actions/checkout@v4", "tag, workspace version and ref",
                                 "no release and no tag of that name"])
        self.assertEqual(run_script(self.step("check", "tag, workspace version and ref")),
                         'python3 -B scripts/release_assets.py check-tag --tag "$TAG" --ref "$GITHUB_REF"\n')

    def test_container_builds_trust_the_runner_owned_workspace_before_git_runs(self):
        for job in ("deb", "rpm"):
            with self.subTest(job=job):
                names = [name for name, _ in steps(self.jobs[job])]
                trust = names.index("root in the runner-owned workspace")
                self.assertEqual(trust, names.index("actions/checkout@v4") + 1)
                self.assertEqual(run_script(self.step(job, "root in the runner-owned workspace")),
                                 'git config --global --add safe.directory "$GITHUB_WORKSPACE"\n')
                self.assertLess(names.index("actions/checkout@v4"), trust)
                self.assertLess(0, names.index("actions/checkout@v4"), "git is installed before the checkout")

    def test_deb_job_builds_the_candidate_bundle_and_checks_it(self):
        install = run_script(self.step("deb", "build dependencies"))
        for package in ("build-essential", "dpkg-dev", "python3", "git", "curl", "ca-certificates"):
            self.assertRegex(install, rf"(?<![\w-]){re.escape(package)}(?![\w-])")
        bundle = run_script(self.step("deb", "release candidate bundle"))
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"\n', bundle)
        self.assertIn("python3 -B scripts/prepare_release.py --output dist/deb\n", bundle)
        verify = run_script(self.step("deb", "verify the bundle"))
        self.assertIn("(cd dist/deb && sha256sum --check --strict SHA256SUMS)\n", verify)
        upload = self.step("deb", "actions/upload-artifact@v4")
        for line in ("name: deb", "path: dist/deb", "if-no-files-found: error"):
            self.assertIn(f"          {line}\n", upload)

    def test_rpm_job_packages_the_same_candidate_version(self):
        build = run_script(self.step("rpm", "packaged binaries"))
        self.assertIn('cargo build --release --locked --target "$host" -p maki -p maki-attach -p maki-check '
                      '-p maki-nbdkit\n', build)
        bundle = run_script(self.step("rpm", "RPM bundle"))
        self.assertIn('version="$(python3.11 -B scripts/prepare_release.py --print-version)"\n', bundle)
        self.assertIn('SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" python3 -B packaging/rpm/build-rpm.py', bundle)
        builder = bundle.split("packaging/rpm/build-rpm.py", 1)[1].split("\n\n", 1)[0]
        self.assertIn('--version "$version"', builder)
        self.assertIn('--release-dir "target/$host/release"', builder)
        self.assertNotIn("--no-autoreq", bundle, "the published RPM keeps its native requirements")
        self.assertIn('python3 -B scripts/release_assets.py rpm-manifest --package "$package" --version "$version"',
                      bundle)
        verify = run_script(self.step("rpm", "verify the bundle"))
        self.assertIn("(cd dist/rpm && sha256sum --check --strict SHA256SUMS)\n", verify)
        upload = self.step("rpm", "actions/upload-artifact@v4")
        for line in ("name: rpm", "path: dist/rpm", "if-no-files-found: error"):
            self.assertIn(f"          {line}\n", upload)

    def test_publish_assembles_checks_and_creates_a_draft_pre_release_first(self):
        names = [name for name, _ in steps(self.jobs["publish"])]
        self.assertEqual(names, ["actions/checkout@v4", "actions/download-artifact@v4",
                                 "actions/download-artifact@v4", "assets and notes", "publish",
                                 "what a failed publication left"])
        assemble = run_script(self.step("publish", "assets and notes"))
        self.assertIn("--template .github/release-notes.md --output dist/release --notes dist/notes.md", assemble)
        self.assertIn("(cd dist/release && sha256sum --check --strict SHA256SUMS)\n", assemble)
        publish = self.step("publish", "publish")
        self.assertIn("          GH_TOKEN: ${{ github.token }}\n", publish)
        script = run_script(publish)
        self.assertIn('gh release create "$TAG" --draft --prerelease --latest=false --target "$GITHUB_SHA"', script)
        self.assertLess(script.index("gh release create"), script.index("release_assets.py uploaded"))
        self.assertLess(script.index("release_assets.py uploaded"), script.index('gh release edit "$TAG" --draft=false'))
        self.assertIn("        if: failure()\n", self.step("publish", "what a failed publication left"))


@unittest.skipUnless(shutil.which("bash"), "the steps run in bash on the runners")
class PublishSteps(unittest.TestCase):
    """The check job's existence step and the publish steps against a stand-in gh."""

    FAKE_GH = r'''
import json, os, pathlib, sys
state_path = pathlib.Path(os.environ["FAKE_GH_STATE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
with open(os.environ["FAKE_GH_CALLS"], "a") as log:
    log.write(json.dumps(args) + "\n")
def save():
    state_path.write_text(json.dumps(state))
def find(tag):
    return [release for release in state["releases"] if release["tag_name"] == tag]
if os.environ.get("GH_TOKEN") != "token":
    sys.exit("fake gh: no token")
if args[0] == "api":
    path = args[1]
    prefix = f"repos/{os.environ['GITHUB_REPOSITORY']}/"
    assert path.startswith(prefix), path
    path = path[len(prefix):]
    if path == "releases?per_page=100":
        assert "--paginate" in args
        releases = [{key: release[key] for key in ("tag_name", "draft", "prerelease")}
                    for release in state["releases"]]
        print(json.dumps(releases[:1]))
        print(json.dumps(releases[1:]))
    elif path.startswith("git/matching-refs/tags/"):
        tag = path[len("git/matching-refs/tags/"):]
        print(json.dumps([ref for ref in state["refs"] if ref["ref"].startswith(f"refs/tags/{tag}")]))
    else:
        sys.exit(f"fake gh: unexpected api {path}")
elif args[:2] == ["release", "create"]:
    tag = args[2]
    options = args[3:]
    files = [argument for argument in options if os.path.isfile(argument) and argument.startswith("dist/release/")]
    release = {"tag_name": tag, "draft": "--draft" in options, "prerelease": "--prerelease" in options,
               "target": options[options.index("--target") + 1], "assets": []}
    state["releases"].append(release)
    for index, name in enumerate(files):
        if state.get("fail") == "upload" and index == 1:
            save()
            sys.exit("HTTP 502: upload failed")
        asset = os.path.basename(name)
        if state.get("fail") == "rename":
            asset = asset.replace("-rc.", "-rc_")
        release["assets"].append({"name": asset, "size": os.path.getsize(name), "state": "uploaded"})
    save()
elif args[:2] == ["release", "view"]:
    matching = find(args[2])
    if not matching:
        sys.exit("release not found")
    assert args[3:] == ["--json", "assets"], args
    print(json.dumps({"assets": matching[0]["assets"]}))
elif args[:2] == ["release", "edit"]:
    assert args[3:] == ["--draft=false"], args
    release = find(args[2])[0]
    release["draft"] = False
    sha = OTHER if state.get("fail") == "wrong-tag" else release["target"]
    state["refs"].append({"ref": f"refs/tags/{release['tag_name']}", "object": {"sha": sha, "type": "commit"}})
    save()
elif args[:2] == ["release", "delete"]:
    assert args[3:] == ["--yes"], args
    matching = find(args[2])
    if not matching:
        sys.exit("release not found")
    state["releases"].remove(matching[0])
    save()
else:
    sys.exit(f"fake gh: unexpected {args}")
'''.replace("OTHER", repr(OTHER))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-release-steps-")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(HELPER, self.root / "scripts" / "release_assets.py")
        tools = self.root / "bin"
        tools.mkdir()
        (tools / "gh").write_text(f"#!{sys.executable}\n{self.FAKE_GH}")
        (tools / "gh").chmod(0o755)
        release = self.root / "dist" / "release"
        release.mkdir(parents=True)
        for name in ("maki-0.1.0-rc.1-debian12-amd64.deb", "maki-0.1.0-rc.1-el9-x86_64.rpm", "SHA256SUMS"):
            (release / name).write_bytes(f"asset {name}\n".encode())
        (self.root / "dist" / "notes.md").write_text("notes\n")
        self.state = self.root / "state.json"
        self.calls = self.root / "calls.jsonl"
        self.summary = self.root / "summary.md"
        self.environment = {
            "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}", "GH_TOKEN": "token", "TAG": "v0.1.0-rc.1",
            "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_SHA": COMMIT, "GITHUB_STEP_SUMMARY": str(self.summary),
            "FAKE_GH_STATE": str(self.state), "FAKE_GH_CALLS": str(self.calls),
        }
        self.publish_job = dict(steps(jobs()["publish"]))

    def github(self, releases=(), refs=(), fail=None):
        self.state.write_text(json.dumps({"releases": list(releases), "refs": list(refs), "fail": fail}))

    def run_step(self, script):
        return subprocess.run(["bash", "-e", "-c", script], cwd=self.root, env=self.environment,
                              capture_output=True, text=True, timeout=60)

    def gh_calls(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def published(self):
        return json.loads(self.state.read_text())

    def publish(self):
        result = self.run_step(run_script(self.publish_job["publish"]))
        cleanup = self.run_step(run_script(self.publish_job["what a failed publication left"])) \
            if result.returncode else None
        return result, cleanup

    def test_a_free_tag_is_published_as_a_pre_release_at_the_dispatched_commit(self):
        self.github(releases=[{"tag_name": "v0.1.0-rc.10", "draft": False, "prerelease": True}],
                    refs=[{"ref": "refs/tags/v0.1.0-rc.10", "object": {"sha": OTHER}}])
        result, _ = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        create = [call for call in self.gh_calls() if call[:2] == ["release", "create"]]
        self.assertEqual(len(create), 1)
        self.assertEqual(create[0][:9], ["release", "create", "v0.1.0-rc.1", "--draft", "--prerelease",
                                         "--latest=false", "--target", COMMIT, "--title"])
        self.assertEqual(sorted(os.path.basename(path) for path in create[0] if path.startswith("dist/release/")),
                         sorted(path.name for path in (self.root / "dist/release").iterdir()))
        state = self.published()
        release = [entry for entry in state["releases"] if entry["tag_name"] == "v0.1.0-rc.1"][0]
        self.assertEqual((release["draft"], release["prerelease"]), (False, True))
        self.assertIn({"ref": "refs/tags/v0.1.0-rc.1", "object": {"sha": COMMIT, "type": "commit"}}, state["refs"])

    def test_a_taken_tag_or_release_is_refused_before_anything_is_created(self):
        for name, releases, refs in (
            ("published", [{"tag_name": "v0.1.0-rc.1", "draft": False, "prerelease": True}], []),
            ("draft", [{"tag_name": "v0.1.0-rc.1", "draft": True, "prerelease": True}], []),
            ("tag", [], [{"ref": "refs/tags/v0.1.0-rc.1", "object": {"sha": OTHER}}]),
        ):
            with self.subTest(taken=name):
                self.calls.unlink(missing_ok=True)
                self.github(releases=releases, refs=refs)
                result, cleanup = self.publish()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refusing to publish", result.stderr)
                self.assertFalse([call for call in self.gh_calls() if call[0] == "release"])
                self.assertEqual(cleanup.returncode, 0)
                self.assertIn("Nothing was created", cleanup.stderr)
                self.assertEqual(self.published()["releases"], releases, "what existed is left alone")
                check = self.run_step(run_script(dict(steps(jobs()["check"]))["no release and no tag of that name"]))
                self.assertNotEqual(check.returncode, 0)
                self.assertIn("is taken", check.stderr)
        self.github()
        check = self.run_step(run_script(dict(steps(jobs()["check"]))["no release and no tag of that name"]))
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_an_interrupted_upload_leaves_no_release_and_no_tag(self):
        for failure in ("upload", "rename"):
            with self.subTest(failure=failure):
                self.calls.unlink(missing_ok=True)
                (self.root / "dist" / "draft-requested").unlink(missing_ok=True)
                self.github(fail=failure)
                result, cleanup = self.publish()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse([call for call in self.gh_calls() if call[:2] == ["release", "edit"]],
                                 "an incomplete draft must never be published")
                self.assertEqual(cleanup.returncode, 0, cleanup.stderr)
                self.assertIn(["release", "delete", "v0.1.0-rc.1", "--yes"], self.gh_calls())
                self.assertEqual(self.published()["releases"], [])
                self.assertEqual(self.published()["refs"], [])
                self.assertIn("Deleted the incomplete draft release", self.summary.read_text())

    def test_a_published_release_with_the_wrong_tag_is_reported_not_deleted(self):
        self.github(fail="wrong-tag")
        result, cleanup = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected a pre-release and the tag at", result.stderr)
        self.assertFalse([call for call in self.gh_calls() if call[:2] == ["release", "delete"]])
        self.assertEqual(cleanup.returncode, 0)
        report = self.summary.read_text()
        self.assertIn("release prerelease, tag " + OTHER, report)
        self.assertIn("gh release delete v0.1.0-rc.1 --cleanup-tag --yes", report)
        self.assertIn("git push --delete origin v0.1.0-rc.1", report)


class TagCheck(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = pathlib.Path(temporary.name)

    def check(self, tag, ref="refs/heads/main", version="0.1.0"):
        return helper("check-tag", "--tag", tag, "--ref", ref,
                      "--cargo-toml", str(cargo_toml(self.directory, version)))

    def test_release_candidates_of_the_workspace_version_are_accepted(self):
        for tag, version, number in (("v0.1.0-rc.1", "0.1.0", 1), ("v0.1.0-rc.12", "0.1.0", 12),
                                     ("v2.3.4-rc.7", "2.3.4", 7)):
            with self.subTest(tag=tag):
                result = self.check(tag, version=version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"workspace_version={version}\nrelease_candidate={number}\n")

    def test_the_repository_version_is_what_is_checked(self):
        result = helper("check-tag", "--tag", "v0.1.0-rc.1", "--ref", "refs/heads/main")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_other_tags_are_refused(self):
        for tag in ("v0.1.1-rc.1", "v0.2.0-rc.1", "0.1.0-rc.1", "v0.1.0-rc.0", "v0.1.0-rc.01", "v0.1.0-rc1",
                    "v0.1.0-rc.", "v0.1.0-beta.1", "v0.1.0-rc.1-1", "v0.1.0-rc.1 ", " v0.1.0-rc.1",
                    "v0.1.0-rc.1\n", "v0.1.0-rc.1/x", "refs/tags/v0.1.0-rc.1", "v0.1.0+rc.1", "v0.1", ""):
            with self.subTest(tag=tag):
                result = self.check(tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr.startswith("release-assets: "), result.stderr)

    def test_a_final_release_is_refused_while_production_approval_is_pending(self):
        result = self.check("v0.1.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("production approval is pending", result.stderr)
        self.assertIn("v0.1.0-rc.<n>", result.stderr)

    def test_only_main_may_publish(self):
        for ref in ("refs/heads/feature", "refs/tags/v0.1.0-rc.1", "refs/pull/1/merge", "main",
                    "refs/heads/main2", "refs/heads/main/x"):
            with self.subTest(ref=ref):
                result = self.check("v0.1.0-rc.1", ref=ref)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("from main only", result.stderr)


class Assembly(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = pathlib.Path(temporary.name)
        self.cargo = cargo_toml(self.work)
        self.deb_name = f"maki_{VERSION}_amd64.deb"
        self.source_name = f"maki-{VERSION}-source.tar.gz"
        self.rpm_name = f"maki-{VERSION}-1.x86_64.rpm"
        self.deb_files = {self.deb_name: b"debian package\n", self.source_name: b"source archive\n"}
        self.rpm_files = {self.rpm_name: b"rpm package\n"}
        self.deb_manifest = {
            "workspace_version": "0.1.0",
            "source": {"commit": COMMIT, "filename": self.source_name,
                       "sha256": hashlib.sha256(b"source archive\n").hexdigest()},
            "build_host": {"distribution": {"id": "debian", "version_id": "12", "version_codename": "bookworm"},
                           "architecture": "amd64"},
            "package": {"filename": self.deb_name, "version": VERSION,
                        "sha256": hashlib.sha256(b"debian package\n").hexdigest()},
        }
        self.rpm_manifest = {
            "source": {"commit": COMMIT},
            "build_host": {"distribution": {"id": "centos", "version_id": "9", "name": "CentOS Stream"},
                           "dist": ".el9", "architecture": "x86_64"},
            "package": {"filename": self.rpm_name, "version": VERSION, "release": "1",
                        "sha256": hashlib.sha256(b"rpm package\n").hexdigest()},
        }

    def assemble(self, tag="v0.1.0-rc.1", commit=COMMIT, name="out"):
        deb, rpm = self.work / f"{name}-deb", self.work / f"{name}-rpm"
        if not deb.exists():
            write_bundle(deb, self.deb_files, self.deb_manifest)
            write_bundle(rpm, self.rpm_files, self.rpm_manifest)
        output, notes = self.work / f"{name}-release", self.work / f"{name}-notes.md"
        result = helper("assemble", "--tag", tag, "--commit", commit, "--repository", REPOSITORY,
                        "--deb-bundle", str(deb), "--rpm-bundle", str(rpm), "--template", str(TEMPLATE),
                        "--output", str(output), "--notes", str(notes), "--cargo-toml", str(self.cargo))
        return result, output, notes, deb, rpm

    def test_assets_get_release_names_and_one_checksum_list(self):
        result, output, notes, deb, rpm = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = {
            "maki-0.1.0-rc.1-debian12-amd64.deb": deb / self.deb_name,
            "maki-0.1.0-rc.1-debian12-amd64-manifest.json": deb / "manifest.json",
            "maki-0.1.0-rc.1-source.tar.gz": deb / self.source_name,
            "maki-0.1.0-rc.1-el9-x86_64.rpm": rpm / self.rpm_name,
            "maki-0.1.0-rc.1-el9-x86_64-manifest.json": rpm / "manifest.json",
        }
        self.assertEqual(sorted(path.name for path in output.iterdir()), sorted([*expected, "SHA256SUMS"]))
        for name, source in expected.items():
            self.assertEqual((output / name).read_bytes(), source.read_bytes(), name)
            self.assertRegex(name, r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
        self.assertEqual(result.stdout.split(), [str(output / name) for name in sorted(expected)]
                         + [str(output / "SHA256SUMS")])
        if shutil.which("sha256sum"):
            check = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=output,
                                   capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        listed = [line.split("  ", 1)[1] for line in (output / "SHA256SUMS").read_text().splitlines()]
        self.assertEqual(listed, sorted(expected))

    def test_the_notes_say_what_each_asset_is_and_what_the_release_is_not(self):
        result, output, notes, _, _ = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)
        text = notes.read_text()
        blob = f"https://github.com/{REPOSITORY}/blob/v0.1.0-rc.1/"
        for required in (
            "pre-release", "not production-qualified", "not signed", "SHA256SUMS",
            "sha256sum --check --ignore-missing SHA256SUMS",
            f"`maki-0.1.0-rc.1-debian12-amd64.deb` | Debian package for Debian 12 (bookworm), amd64",
            "`maki-0.1.0-rc.1-el9-x86_64.rpm` | RPM package for RHEL 9 and its rebuilds, x86_64",
            "`maki-0.1.0-rc.1-source.tar.gz` | The exact committed source of `" + COMMIT + "`",
            f"`{VERSION}`", f"`{VERSION}-1`",
            f"[`{COMMIT}`](https://github.com/{REPOSITORY}/commit/{COMMIT})",
            blob + "docs/status.md", blob + "docs/deployment/support-matrix.md",
            blob + "docs/getting-started/installation-debian.md",
            blob + "docs/getting-started/installation-rhel.md", blob + "CHANGELOG.md",
            "apt install ./maki-0.1.0-rc.1-debian12-amd64.deb", "dnf install ./maki-0.1.0-rc.1-el9-x86_64.rpm",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        self.assertNotIn("$", text.replace("```bash", ""), "every placeholder is filled")
        self.assertNotIn("Unreleased", text, "the changelog is linked, not pasted")
        for name in (path.name for path in output.iterdir()):
            self.assertIn(f"`{name}`", text)

    def test_inconsistent_bundles_are_refused(self):
        cases = {
            "tampered package": None,
            "other commit": lambda: self.rpm_manifest["source"].__setitem__("commit", OTHER),
            "other version": lambda: self.rpm_manifest["package"].__setitem__("version", VERSION + ".1"),
            "other workspace version": lambda: self.deb_manifest.__setitem__("workspace_version", "0.2.0"),
            "extra file": lambda: self.deb_files.__setitem__("notes.txt", b"extra\n"),
            "second package": lambda: self.rpm_files.__setitem__("maki-other-1.x86_64.rpm", b"rpm\n"),
            "renamed package": lambda: self.rpm_manifest["package"].__setitem__("filename", "maki.rpm"),
            "unsafe asset name": lambda: self.deb_manifest["build_host"]["distribution"].__setitem__("id", "deb+ian"),
            "missing dist": lambda: self.rpm_manifest["build_host"].__setitem__("dist", ""),
        }
        for index, (name, change) in enumerate(cases.items()):
            with self.subTest(case=name):
                self.setUp()
                if change is None:
                    # Changed after its bundle's SHA256SUMS was written.
                    deb = self.work / f"case{index}-deb"
                    write_bundle(deb, self.deb_files, self.deb_manifest)
                    write_bundle(self.work / f"case{index}-rpm", self.rpm_files, self.rpm_manifest)
                    (deb / self.deb_name).write_bytes(b"tampered after hashing\n")
                else:
                    change()
                result, output, notes, _, _ = self.assemble(name=f"case{index}")
                self.assertNotEqual(result.returncode, 0, name)
                self.assertTrue(result.stderr.startswith("release-assets: "), result.stderr)
                self.assertFalse(notes.exists())

    def test_the_dispatched_commit_and_tag_must_match_the_bundles(self):
        result, *_ = self.assemble(commit=OTHER, name="commit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("commit", result.stderr)
        for tag in ("v0.1.0", "v0.2.0-rc.1"):
            with self.subTest(tag=tag):
                result, *_ = self.assemble(tag=tag, name=f"tag-{tag}")
                self.assertNotEqual(result.returncode, 0)

    def test_an_existing_output_is_refused(self):
        result, output, notes, *_ = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)
        again, *_ = self.assemble()
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("already exists", again.stderr)


class ReleaseState(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = pathlib.Path(temporary.name)

    def state(self, pages, refs, tag="v0.1.0-rc.1"):
        releases = self.work / "releases.json"
        releases.write_text("\n".join(json.dumps(page) for page in pages))
        (self.work / "refs.json").write_text(json.dumps(refs))
        result = helper("state", "--tag", tag, "--releases", str(releases), "--refs", str(self.work / "refs.json"))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_releases_of_every_page_and_exact_tags_count(self):
        rc10 = {"ref": "refs/tags/v0.1.0-rc.10", "object": {"sha": OTHER}}
        self.assertEqual(self.state([[], []], [rc10]), "release=none\ntag=none\n")
        page = [{"tag_name": "v0.1.0-rc.10", "draft": False, "prerelease": True}]
        for entry, expected in (({"draft": True, "prerelease": True}, "draft"),
                                ({"draft": False, "prerelease": True}, "prerelease"),
                                ({"draft": False, "prerelease": False}, "release")):
            with self.subTest(entry=entry):
                second = [{"tag_name": "v0.1.0-rc.1", **entry}]
                self.assertEqual(self.state([page, second], []), f"release={expected}\ntag=none\n")
        tag = {"ref": "refs/tags/v0.1.0-rc.1", "object": {"sha": COMMIT}}
        self.assertEqual(self.state([page], [rc10, tag]), f"release=none\ntag={COMMIT}\n")

    def test_uploaded_assets_must_match_by_name_and_size(self):
        assets = self.work / "assets"
        assets.mkdir()
        (assets / "a.deb").write_bytes(b"12345")
        (assets / "SHA256SUMS").write_bytes(b"12")
        view = self.work / "view.json"
        for listed, accepted in (
            ([{"name": "a.deb", "size": 5, "state": "uploaded"}, {"name": "SHA256SUMS", "size": 2}], True),
            ([{"name": "a.deb", "size": 5}], False),
            ([{"name": "a.deb", "size": 4}, {"name": "SHA256SUMS", "size": 2}], False),
            ([{"name": "a.deb", "size": 5, "state": "starter"}, {"name": "SHA256SUMS", "size": 2}], False),
            ([{"name": "a.deb", "size": 5}, {"name": "SHA256SUMS", "size": 2}, {"name": "x", "size": 1}], False),
        ):
            with self.subTest(listed=listed):
                view.write_text(json.dumps({"assets": listed}))
                result = helper("uploaded", "--view", str(view), "--assets", str(assets))
                self.assertEqual(result.returncode == 0, accepted, result.stderr)


class RpmManifest(unittest.TestCase):
    """Builds a fixture RPM: needs rpm and rpmbuild, as scripts/test_rpm_package.py does."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = pathlib.Path(temporary.name)
        release = self.work / "release"
        release.mkdir()
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
        for name in ("maki", "maki-attach", "maki-check", "libmaki_nbdkit.so"):
            e_type = 3 if name.endswith(".so") else 2
            header = struct.pack("<HHIQQQIHHHHHH", e_type, 0x3E, 1, 0x1000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
            (release / name).write_bytes(ident + header)
        self.bundle = self.work / "bundle"
        self.bundle.mkdir()
        self.package = self.bundle / f"maki-{VERSION}-1.x86_64.rpm"
        subprocess.run([sys.executable, "-B", str(RPM_BUILDER), "--release-dir", str(release), "--version", VERSION,
                        "--architecture", "x86_64", "--output", str(self.package), "--no-autoreq"],
                       env=dict(os.environ, SOURCE_DATE_EPOCH="1789689600"), check=True, capture_output=True)
        tools = self.work / "bin"
        tools.mkdir()
        for name, output in (("rustc", "rustc 1.94.0 (fixture)\nhost: x86_64-unknown-linux-gnu"),
                             ("cargo", "cargo 1.94.0 (fixture)")):
            (tools / name).write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n")
            (tools / name).chmod(0o755)
        self.environment = dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}")

    def manifest(self, version=VERSION, commit=COMMIT):
        return helper("rpm-manifest", "--package", str(self.package), "--version", version, "--commit", commit,
                      environment=self.environment)

    def test_the_bundle_records_the_package_and_checks_out(self):
        result = self.manifest()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(path.name for path in self.bundle.iterdir()),
                         sorted([self.package.name, "manifest.json", "SHA256SUMS"]))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        self.assertEqual(manifest["source"], {"commit": COMMIT})
        self.assertEqual(manifest["package"]["filename"], self.package.name)
        self.assertEqual(manifest["package"]["version"], VERSION)
        self.assertEqual(manifest["package"]["release"], "1")
        self.assertEqual(manifest["package"]["sha256"], sha256(self.package))
        self.assertIn("nbdkit-server", manifest["package"]["requires"])
        self.assertEqual(manifest["package"]["conflicts"], ["nbdkit-selinux"])
        self.assertEqual(manifest["build_host"]["architecture"], "x86_64")
        self.assertIn("rustc 1.94.0", manifest["toolchain"]["rustc"])
        if shutil.which("sha256sum"):
            check = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=self.bundle,
                                   capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_a_mismatched_version_a_short_commit_or_a_crowded_directory_is_refused(self):
        for arguments in ({"version": VERSION + ".1"}, {"commit": COMMIT[:12]}):
            with self.subTest(arguments=arguments):
                result = self.manifest(**arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.bundle / "manifest.json").exists())
        (self.bundle / "stray").write_text("x")
        result = self.manifest()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only the RPM", result.stderr)


class Documentation(unittest.TestCase):
    def test_releasing_describes_publication_and_cleanup(self):
        text = (ROOT / "docs" / "releasing.md").read_text()
        section = text.split("\n## Publishing a pre-release\n", 1)[1].split("\n## ", 1)[0]
        for required in ("workflow_dispatch", ".github/workflows/release.yml", "--prerelease", "not signed",
                         "gh release delete", "--cleanup-tag", "git push --delete origin", "SHA256SUMS"):
            with self.subTest(required=required):
                self.assertIn(required, section)
        self.assertIn("releasing.md#publishing-a-pre-release", (ROOT / "docs" / "status.md").read_text())


if __name__ == "__main__":
    unittest.main()
