"""Dependency changes must not silently remove the plaintext-erasure patches."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.check_vendor_erasure import check


class VendorErasureContract(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "vendor").mkdir()
        upstream = {"schema": 1, "packages": {}}
        patches = {"schema": 1, "packages": {}}
        self.metadata = {"packages": []}
        manifest = "[patch.crates-io]\n"
        lock = "version = 4\n"
        for name, version in (
            ("serde_json", "1.0.151"), ("rustls", "0.23.45"),
            ("bytes", "1.12.1"), ("hyper", "1.11.1"),
            ("tungstenite", "0.26.2"),
        ):
            path = self.root / "vendor" / name
            path.mkdir()
            text = f'[package]\nname = "{name}"\nversion = "{version}"\n'
            (path / "Cargo.toml").write_text(text)
            original = {"Cargo.toml": hashlib.sha256(text.encode()).hexdigest()}
            upstream["packages"][name] = {
                "version": version, "crate_sha256": "0" * 64, "upstream_files": original
            }
            patches["packages"][name] = {"files": {}}
            manifest += f'{name} = {{ path = "vendor/{name}" }}\n'
            lock += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
            self.metadata["packages"].append({
                "name": name, "version": version, "source": None,
                "manifest_path": str(path / "Cargo.toml"), "id": name,
            })
        self.metadata["resolve"] = {"nodes": [
            {"id": "serde_json", "features": ["default", "std"]},
            {"id": "rustls", "features": ["ring", "std", "tls12"]},
        ]}
        (self.root / "Cargo.toml").write_text(manifest)
        (self.root / "Cargo.lock").write_text(lock)
        (self.root / "vendor/upstream.json").write_text(json.dumps(upstream))
        (self.root / "vendor/patches.json").write_text(json.dumps(patches))
        (self.root / "vendor/test-ca-provenance.json").write_text(json.dumps({"files": {}}))

    def test_known_local_dependencies_pass(self):
        self.assertEqual(check(self.root, self.metadata), [])

    def test_unrecorded_source_edit_is_rejected(self):
        (self.root / "vendor/rustls/Cargo.toml").write_text("changed")
        self.assertTrue(check(self.root, self.metadata))

    def test_transport_source_inventory_cannot_be_removed(self):
        path = self.root / "vendor/upstream.json"
        record = json.loads(path.read_text())
        del record["packages"]["bytes"]
        path.write_text(json.dumps(record))
        self.assertTrue(check(self.root, self.metadata))

    def test_transport_patch_cannot_be_bypassed_transitively(self):
        package = next(p for p in self.metadata["packages"] if p["name"] == "bytes")
        package["source"] = "registry"
        self.assertTrue(check(self.root, self.metadata))

    def test_second_registry_version_is_rejected(self):
        self.metadata["packages"].append({
            "name": "rustls", "version": "0.23.46", "source": "registry", "id": "other"
        })
        self.assertTrue(check(self.root, self.metadata))

    def test_reviewed_float_roundtrip_feature_is_allowed(self):
        for features in (["std", "float_roundtrip"],
                         ["std", "raw_value", "float_roundtrip"],
                         ["std", "arbitrary_precision", "float_roundtrip"],
                         ["std", "raw_value", "arbitrary_precision", "float_roundtrip"]):
            with self.subTest(features=features):
                self.metadata["resolve"]["nodes"][0]["features"] = features
                self.assertEqual(check(self.root, self.metadata), [])

    def test_reviewed_raw_value_feature_is_allowed(self):
        self.metadata["resolve"]["nodes"][0]["features"].append("raw_value")
        self.assertEqual(check(self.root, self.metadata), [])

    def test_reviewed_arbitrary_precision_feature_is_allowed(self):
        for features in (["std", "arbitrary_precision"],
                         ["std", "raw_value", "arbitrary_precision"]):
            with self.subTest(features=features):
                self.metadata["resolve"]["nodes"][0]["features"] = features
                self.assertEqual(check(self.root, self.metadata), [])

    def test_dependency_patch_removal_is_rejected(self):
        (self.root / "Cargo.toml").write_text("[patch.crates-io]\n")
        self.assertTrue(check(self.root, self.metadata))

    def test_public_test_fixture_changes_are_rejected(self):
        path = self.root / "vendor/test-ca"
        path.mkdir()
        (path / "certificate.der").write_bytes(b"changed public fixture")
        (self.root / "vendor/test-ca-provenance.json").write_text(json.dumps({
            "files": {"test-ca/certificate.der": {"sha256": "0" * 64}}
        }))
        self.assertTrue(check(self.root, self.metadata))


if __name__ == "__main__":
    unittest.main()
