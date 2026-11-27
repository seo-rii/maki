"""Exercise the native runner's artifact fragment without privileged
operations: the release build from the source snapshot, and the prebuilt
artifacts that --prebuilt names, which the booted-host jobs take from the
package."""
import hashlib
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("privileged-linux-validation.sh")
FRAGMENT_START = 'readonly build_target_dir="$run_dir/target"'
FRAGMENT_END = 'pass "release binaries and plugin_init export"'


def artifact_fragment():
    """The runner's lines that select, check and hash its three artifacts."""
    script = SCRIPT.read_text()
    start = script.index(FRAGMENT_START)
    return script[start:script.index(FRAGMENT_END, start) + len(FRAGMENT_END)]


def fragment(source, start, end):
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


@unittest.skipUnless(all(shutil.which(tool) for tool in ("cargo", "rustc", "nm")),
                     "Cargo, rustc and nm required")
class NativeArtifactPath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fragment = artifact_fragment()
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = pathlib.Path(temporary.name)
        cls.repo = cls.root / "fixture"
        cls.repo.mkdir()
        (cls.repo / "Cargo.toml").write_text(
            '[workspace]\nmembers=["maki","maki-attach","maki-nbdkit"]\nresolver="2"\n')
        for name in ("maki", "maki-attach", "maki-nbdkit"):
            directory = cls.repo / name
            (directory / "src").mkdir(parents=True)
            text = f'[package]\nname="{name}"\nversion="0.0.0"\nedition="2021"\n'
            if name == "maki-nbdkit":
                text += '[lib]\ncrate-type=["cdylib"]\n'
                (directory / "src/lib.rs").write_text(
                    '#[no_mangle]\npub extern "C" fn plugin_init() {}\n')
            else:
                (directory / "src/main.rs").write_text('fn main() { println!("STALE"); }\n')
            (directory / "Cargo.toml").write_text(text)
        cls.environment = os.environ.copy()
        cls.environment.pop("CARGO_BUILD_TARGET", None)
        cls.environment.update(CARGO_TARGET_DIR=str(cls.repo / "target"),
                               CARGO_BUILD_BUILD_DIR=str(cls.root / "stale-build"),
                               CARGO_BUILD_JOBS="2")
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=cls.repo,
                       env=cls.environment, check=True, capture_output=True)
        subprocess.run(["cargo", "build", "--release", "--locked"], cwd=cls.repo,
                       env=cls.environment, check=True, capture_output=True)
        for name in ("maki", "maki-attach"):
            (cls.repo / name / "src/main.rs").write_text('fn main() { println!("FRESH"); }\n')
        (cls.repo / "maki-nbdkit/src/lib.rs").write_text(
            '#[no_mangle]\npub extern "C" fn plugin_init() {}\n'
            '#[no_mangle]\npub extern "C" fn maki_fresh_artifact() {}\n')
        (cls.repo / ".cargo").mkdir()
        (cls.repo / ".cargo/config.toml").write_text(
            '[build]\ntarget-dir="configured-target"\n')

    def check_artifacts(self, *, override_directory=False, override_target=False):
        run_dir = self.root / self._testMethodName
        run_dir.mkdir()
        environment = dict(self.environment, REPO_ROOT=str(self.repo), run_dir=str(run_dir))
        environment.pop("CARGO_TARGET_DIR", None)
        if override_directory:
            environment["CARGO_TARGET_DIR"] = str(self.root / "environment-target")
        if override_target:
            # The runner must select the native host instead of inheriting this.
            environment["CARGO_BUILD_TARGET"] = "invalid-cross-target"
        setup = ('set -euo pipefail\nlog() { :; }\npass() { :; }\n'
                 'die() { echo "$*" >&2; exit 1; }\nprebuilt_dir=""\n')
        program = (setup + self.fragment + '\n"$maki_bin"\n"$attach_bin"\n'
                   'nm -D --defined-only "$plugin_path" | grep -q maki_fresh_artifact\n')
        result = subprocess.run(["bash", "-c", program], cwd=self.repo,
                                env=environment, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["FRESH", "FRESH"],
                         "validation must execute the artifacts it just built")
        stale = subprocess.check_output([str(self.repo / "target/release/maki")], text=True)
        self.assertEqual(stale.strip(), "STALE", "the fixture retains a tempting stale artifact")

    def test_cargo_environment_override_cannot_select_stale_artifacts(self):
        self.check_artifacts(override_directory=True)

    def test_cargo_config_override_cannot_select_stale_artifacts(self):
        self.check_artifacts()

    def test_cross_target_override_does_not_change_native_validation(self):
        self.check_artifacts(override_target=True)


@unittest.skipUnless(all(shutil.which(tool) for tool in ("bash", "cc", "nm")), "Bash, a C compiler and nm")
class PrebuiltArtifactPath(unittest.TestCase):
    """--prebuilt DIR: the run copies DIR's artifacts into its own directory,
    checks and hashes the copies, and never builds."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-prebuilt-")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.prebuilt = self.root / "prebuilt"
        self.prebuilt.mkdir()
        for name in ("maki", "maki-attach"):
            (self.prebuilt / name).write_text(f"#!/bin/sh\necho PREBUILT {name}\n")
            (self.prebuilt / name).chmod(0o755)
        self.plugin('void plugin_init(void) {}\n')
        # Building is refused: a call to Cargo or rustc fails the run.
        self.tools = self.root / "bin"
        self.tools.mkdir()
        for tool in ("cargo", "rustc"):
            (self.tools / tool).write_text(f'#!/bin/sh\necho "{tool} called" >&2\nexit 99\n')
            (self.tools / tool).chmod(0o755)

    def plugin(self, source):
        (self.root / "plugin.c").write_text(source)
        subprocess.run(["cc", "-shared", "-fPIC", "-o", str(self.prebuilt / "libmaki_nbdkit.so"),
                        str(self.root / "plugin.c")], check=True, capture_output=True)

    def run_fragment(self, after=""):
        run_dir = self.root / "run"
        run_dir.mkdir(exist_ok=True)
        setup = ('set -euo pipefail\nlog() { :; }\npass() { echo "PASS: $*"; }\n'
                 'die() { echo "$*" >&2; exit 1; }\n'
                 f'prebuilt_dir="{self.prebuilt}"\nrun_dir="{run_dir}"\nREPO_ROOT="{self.root}"\n')
        environment = dict(os.environ, PATH=f"{self.tools}{os.pathsep}{os.environ['PATH']}")
        return subprocess.run(["bash", "-c", setup + artifact_fragment() + "\n" + after], cwd=self.root,
                              env=environment, text=True, capture_output=True, timeout=30), run_dir

    def test_the_run_executes_and_hashes_its_own_copies_and_never_builds(self):
        result, run_dir = self.run_fragment(
            # A change in the given directory after the copy does not reach the run.
            'echo "#!/bin/sh" > "$prebuilt_dir/maki"\n'
            '"$maki_bin"\n"$attach_bin"\necho "$maki_bin $attach_bin $plugin_path"\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("called", result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[:3], ["PASS: release binaries and plugin_init export",
                                     "PREBUILT maki", "PREBUILT maki-attach"])
        copies = run_dir / "target" / "prebuilt"
        self.assertEqual(lines[3].split(), [str(copies / "maki"), str(copies / "maki-attach"),
                                            str(copies / "libmaki_nbdkit.so")])
        self.assertEqual((copies / "maki").stat().st_mode & 0o777, 0o755)
        self.assertEqual((copies / "libmaki_nbdkit.so").stat().st_mode & 0o777, 0o644)
        recorded = dict(reversed(line.split()) for line in (run_dir / "artifact-sha256").read_text().splitlines())
        for name in ("maki", "maki-attach", "libmaki_nbdkit.so"):
            self.assertEqual(recorded[name], hashlib.sha256((copies / name).read_bytes()).hexdigest())
        self.assertEqual((run_dir / "artifact-origin").read_text(), f"prebuilt {self.prebuilt}\n")

    def test_a_prebuilt_plugin_without_plugin_init_is_refused(self):
        self.plugin('void not_the_entry_point(void) {}\n')
        result, _run_dir = self.run_fragment()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("plugin_init is not exported", result.stderr)

    def run_script(self, *arguments):
        return subprocess.run(["bash", str(SCRIPT), *arguments], cwd=self.root, text=True,
                              capture_output=True, timeout=30)

    def test_the_option_names_a_directory_that_holds_all_three_artifacts(self):
        # Named by its absolute path, also when given relative to the
        # current directory: that is what the worker and its records get.
        for given in (str(self.prebuilt), "prebuilt", "./prebuilt/"):
            with self.subTest(given=given):
                result = self.run_script("--preflight", "--device", "/dev/nbd15", "--prebuilt", given)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"Artifacts:  prebuilt in {self.prebuilt.resolve()}\n", result.stdout)
        self.assertIn("Artifacts:  built from the source snapshot\n",
                      self.run_script("--preflight", "--device", "/dev/nbd15").stdout)
        (self.prebuilt / "libmaki_nbdkit.so").unlink()
        result = self.run_script("--preflight", "--device", "/dev/nbd15", "--prebuilt", str(self.prebuilt))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no libmaki_nbdkit.so", result.stderr)
        for arguments in (("--prebuilt",), ("--prebuilt", str(self.root / "missing"))):
            with self.subTest(arguments=arguments):
                result = self.run_script("--preflight", "--device", "/dev/nbd15", *arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("--prebuilt", result.stderr)
        usage = self.run_script("--help").stdout
        self.assertIn("[--prebuilt DIR]", usage)
        self.assertIn("  --prebuilt DIR ", usage)

    def test_cargo_and_rustc_are_required_only_to_build(self):
        source = SCRIPT.read_text()
        required = fragment(source, "required_commands=(", "missing_commands() {")
        for prebuilt, expected in (("", True), (str(self.prebuilt), False)):
            with self.subTest(prebuilt=prebuilt):
                listed = subprocess.run(
                    ["bash", "-c", f'set -euo pipefail\nprebuilt_dir="{prebuilt}"\ndiscard=false\n'
                                   f'{required}\nprintf "%s\\n" "${{required_commands[@]}}"'],
                    text=True, capture_output=True, check=True).stdout.split()
                self.assertEqual("cargo" in listed, expected)
                self.assertEqual("rustc" in listed, expected)
                for tool in ("git", "python3", "nbdkit", "nm", "sudo"):
                    self.assertIn(tool, listed)

    @unittest.skipUnless(shutil.which("git"), "git")
    def test_the_launcher_passes_the_resolved_directory_to_its_worker(self):
        launcher = fragment(SCRIPT.read_text(), "prepare_source_snapshot() {",
                            '[[ "$background" == false ]] || die "--run-dir')
        for prebuilt in ("", str(self.prebuilt)):
            with self.subTest(prebuilt=prebuilt), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                repo = root / "repo"
                (repo / "scripts").mkdir(parents=True)
                for name in ("qualification_source.py", "prepare_release.py"):
                    shutil.copyfile(SCRIPT.with_name(name), repo / "scripts" / name)
                worker = repo / "scripts/privileged-linux-validation.sh"
                worker.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/../../arguments"\n')
                worker.chmod(0o755)
                for arguments in (["init", "-q"], ["add", "."],
                                  ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                                   "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"]):
                    subprocess.run(["git", "-C", str(repo), *arguments], check=True, capture_output=True)
                setup = (f'set -euo pipefail\nrun_dir=""\ndevice=/dev/nbd15\nconfirmed_device="$device"\n'
                         f'install_missing=false\ndiscard=false\nkill_daemon=true\nwork_root=""\n'
                         f'background=false\nprebuilt_dir="{prebuilt}"\nsudo() {{ :; }}\n')
                result = subprocess.run(["bash", "-c", setup + launcher], capture_output=True, text=True,
                                        timeout=15, env=dict(os.environ, REPO_ROOT=str(repo),
                                                             log_root=str(root / "logs")))
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = (root / "logs/maki-privileged-validation.latest/arguments").read_text().split()
                if prebuilt:
                    self.assertEqual(arguments[arguments.index("--prebuilt") + 1], prebuilt)
                else:
                    self.assertNotIn("--prebuilt", arguments)


if __name__ == "__main__":
    unittest.main()
