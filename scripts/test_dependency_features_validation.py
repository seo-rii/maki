"""Production builds must not enable test-only dependency features."""

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).parents[1]


def manifest(path):
    return tomllib.loads((ROOT / path).read_text())


class TokioFeatureContract(unittest.TestCase):
    def test_workspace_tokio_omits_test_util(self):
        # `test-util` makes the runtime clock pausable and is meant for
        # tests only; through the workspace dependency it reached every
        # production build, including the nbdkit plugin.
        features = manifest("Cargo.toml")["workspace"]["dependencies"]["tokio"]["features"]
        self.assertNotIn("test-util", features)

    def test_crates_with_paused_clock_tests_request_test_util_as_dev_dependency(self):
        for crate in sorted((ROOT / "crates").iterdir()):
            tests = list(crate.glob("tests/*.rs")) + list(crate.glob("src/**/*.rs"))
            paused = any(
                "start_paused" in text or "time::pause" in text or "time::advance" in text
                for text in (path.read_text() for path in tests)
            )
            if not paused:
                continue
            dev = manifest(crate.relative_to(ROOT) / "Cargo.toml").get("dev-dependencies", {})
            tokio = dev.get("tokio", {})
            self.assertIn(
                "test-util",
                tokio.get("features", []) if isinstance(tokio, dict) else [],
                f"{crate.name} uses tokio's paused clock in tests",
            )


if __name__ == "__main__":
    unittest.main()
