"""Every workspace target that `cargo doc` documents has its own output directory."""

import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).parents[1]
NOT_DOCUMENTED = {"test", "bench", "example", "custom-build"}


def documented_targets(metadata):
    """Yield (output directory, owner) for every target `cargo doc` documents.

    rustdoc writes a crate to `doc/<crate name>`, its name with `-` replaced
    by `_`. Cargo documents each library, and each binary that does not set
    `doc = false`, except a binary named like its own package's library.
    """
    for package in metadata["packages"]:
        targets = package["targets"]
        libraries = {
            target["name"].replace("-", "_")
            for target in targets
            if not set(target["kind"]) & (NOT_DOCUMENTED | {"bin"})
        }
        for target in targets:
            kinds = set(target["kind"])
            if kinds & NOT_DOCUMENTED or not target.get("doc", True):
                continue
            directory = target["name"].replace("-", "_")
            if "bin" in kinds and directory in libraries:
                continue
            yield directory, f"{'/'.join(sorted(kinds))} target {target['name']!r} of {package['name']}"


def collisions(metadata):
    owners = {}
    found = []
    for directory, owner in documented_targets(metadata):
        if directory in owners:
            found.append((directory, owners[directory], owner))
        owners.setdefault(directory, owner)
    return found


def package(name, *targets):
    return {"name": name, "targets": [
        {"name": target, "kind": [kind], **({"doc": doc} if doc is not None else {})}
        for target, kind, doc in targets
    ]}


class DocOutputContract(unittest.TestCase):
    def test_workspace_targets_document_into_distinct_directories(self):
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            cwd=ROOT, text=True))
        self.assertIn("maki_witness", {d for d, _ in documented_targets(metadata)})
        self.assertEqual(collisions(metadata), [])

    def test_a_binary_named_like_another_packages_library_collides(self):
        metadata = {"packages": [
            package("tool-cli", ("tool", "bin", None)),
            package("tool", ("tool", "lib", None), ("tool", "test", None)),
        ]}
        self.assertEqual(len(collisions(metadata)), 1)
        metadata["packages"][0] = package("tool-cli", ("tool", "bin", False))
        self.assertEqual(collisions(metadata), [])

    def test_a_binary_named_like_its_own_library_is_not_documented(self):
        metadata = {"packages": [
            package("tool", ("tool", "lib", None), ("tool", "bin", None)),
        ]}
        self.assertEqual(list(documented_targets(metadata)), [("tool", "lib target 'tool' of tool")])


if __name__ == "__main__":
    unittest.main()
