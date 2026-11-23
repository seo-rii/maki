"""Probe: Cargo profile/C-toolchain environment overrides reach the candidate build but not its manifest."""
import json, sys, unittest
sys.path.insert(0, "/home/user/wt/audit4")
from scripts import test_release_preparation as base


class ProfileEnvironmentProbe(base.ReleasePreparationTests):
    def test_profile_overrides_are_not_recorded(self):
        overrides = {
            "CARGO_PROFILE_RELEASE_PANIC": "abort",          # disables the plugin's catch_unwind boundary
            "CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS": "true",
            "CARGO_PROFILE_RELEASE_OPT_LEVEL": "0",
            "CC": "clang", "CFLAGS": "-O0",                 # aws-lc-sys / ring build scripts
        }
        self.environment.update(overrides)
        # The fixture cargo records its environment so we can prove it saw the overrides.
        cargo = self.tools / "cargo"
        cargo.write_text(cargo.read_text().replace(
            "'epoch': os.environ['SOURCE_DATE_EPOCH']}",
            "'epoch': os.environ['SOURCE_DATE_EPOCH'], 'env': {k: os.environ.get(k) for k in "
            + repr(sorted(overrides)) + "}}"))
        output, _ = self.prepare()
        manifest = json.loads((output / "manifest.json").read_text())
        seen = json.loads(self.cargo_trace.read_text())["env"]
        print("\ncargo build saw:", seen)
        print("manifest compiler_environment:", manifest["build"]["compiler_environment"])
        print("manifest package_environment:", manifest["build"]["package_environment"])
        self.assertEqual(seen, overrides)
        recorded = json.dumps(manifest)
        missing = [key for key in overrides if key not in recorded]
        print("overrides absent from manifest:", missing)
        self.assertEqual(missing, [], "build inputs that changed the artifact are missing from the manifest")


if __name__ == "__main__":
    unittest.main(defaultTest="ProfileEnvironmentProbe.test_profile_overrides_are_not_recorded")
