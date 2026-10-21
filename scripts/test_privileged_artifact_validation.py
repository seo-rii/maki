"""Exercise the native runner's build fragment without privileged operations."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(all(shutil.which(tool) for tool in ("cargo", "rustc", "nm")),
                     "Cargo, rustc and nm required")
class NativeArtifactPath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = pathlib.Path(__file__).with_name("privileged-linux-validation.sh").read_text()
        start = script.index('log "building release binaries and nbdkit plugin"')
        end_marker = 'pass "release binaries and plugin_init export"'
        cls.fragment = script[start:script.index(end_marker, start) + len(end_marker)]
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
                 'die() { echo "$*" >&2; exit 1; }\n')
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


if __name__ == "__main__":
    unittest.main()
