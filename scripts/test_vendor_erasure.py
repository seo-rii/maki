"""Dependency changes must not silently remove the plaintext-erasure patches."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.check_vendor_erasure import check, resolve


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
            ("serde_json", "1.0.151"), ("rustls", "0.23.46"),
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
            {"id": "bytes", "features": ["default", "std"]},
            {"id": "hyper", "features": ["client", "http1", "http2"]},
            {"id": "tungstenite", "features": ["handshake", "__rustls-tls"]},
        ]}
        (self.root / "Cargo.toml").write_text(manifest)
        (self.root / "Cargo.lock").write_text(lock)
        (self.root / "vendor/upstream.json").write_text(json.dumps(upstream))
        (self.root / "vendor/patches.json").write_text(json.dumps(patches))
        (self.root / "vendor/test-ca-provenance.json").write_text(json.dumps({"files": {}}))

    def features(self, name):
        return next(node for node in self.metadata["resolve"]["nodes"]
                    if node["id"] == name)["features"]

    def test_known_local_dependencies_pass(self):
        self.assertEqual(check(self.root, self.metadata), [])

    def test_current_workspace_features_are_reviewed(self):
        for name, features in (
            ("bytes", ["default", "std"]),
            ("hyper", ["client", "default", "http1", "http2", "server"]),
            ("rustls", ["aws-lc-rs", "aws_lc_rs", "log", "logging", "ring", "std", "tls12"]),
            ("serde_json", ["default", "raw_value", "std"]),
            ("tungstenite", ["__rustls-tls", "data-encoding", "handshake", "http",
                             "httparse", "rustls", "rustls-pki-types", "sha1"]),
        ):
            self.features(name)[:] = features
        self.assertEqual(check(self.root, self.metadata), [])

    def test_unreviewed_feature_is_rejected(self):
        for name, feature in (
            ("serde_json", "preserve_order"), ("serde_json", "unbounded_depth"),
            ("rustls", "brotli"), ("bytes", "serde"), ("hyper", "ffi"),
            ("tungstenite", "native-tls"), ("tungstenite", "rustls-tls-webpki-roots"),
        ):
            with self.subTest(name=name, feature=feature):
                features = self.features(name)
                features.append(feature)
                errors = check(self.root, self.metadata)
                features.remove(feature)
                self.assertTrue(any(name in error and feature in error for error in errors),
                                errors)

    def test_missing_resolve_section_is_rejected(self):
        for resolve in (None, {}, {"nodes": []}):
            with self.subTest(resolve=resolve):
                self.metadata["resolve"] = resolve
                self.assertTrue(check(self.root, self.metadata))
        del self.metadata["resolve"]
        self.assertTrue(check(self.root, self.metadata))

    def test_patched_package_missing_from_resolve_is_rejected(self):
        nodes = self.metadata["resolve"]["nodes"]
        nodes[:] = [node for node in nodes if node["id"] != "tungstenite"]
        self.assertTrue(check(self.root, self.metadata))

    def test_nested_target_directory_is_inventoried(self):
        path = self.root / "vendor/rustls/src/target"
        path.mkdir(parents=True)
        (path / "unrecorded.rs").write_text("// unreviewed source\n")
        self.assertTrue(check(self.root, self.metadata))

    def test_top_level_build_directory_is_ignored(self):
        path = self.root / "vendor/rustls/target/debug"
        path.mkdir(parents=True)
        (path / "build-output").write_text("local build artifact\n")
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
            "name": "rustls", "version": "0.23.47", "source": "registry", "id": "other"
        })
        self.assertTrue(check(self.root, self.metadata))

    def test_reviewed_float_roundtrip_feature_is_allowed(self):
        for features in (["std", "float_roundtrip"],
                         ["std", "raw_value", "float_roundtrip"],
                         ["std", "arbitrary_precision", "float_roundtrip"],
                         ["std", "raw_value", "arbitrary_precision", "float_roundtrip"]):
            with self.subTest(features=features):
                self.features("serde_json")[:] = features
                self.assertEqual(check(self.root, self.metadata), [])

    def test_reviewed_raw_value_feature_is_allowed(self):
        self.features("serde_json").append("raw_value")
        self.assertEqual(check(self.root, self.metadata), [])

    def test_reviewed_arbitrary_precision_feature_is_allowed(self):
        for features in (["std", "arbitrary_precision"],
                         ["std", "raw_value", "arbitrary_precision"]):
            with self.subTest(features=features):
                self.features("serde_json")[:] = features
                self.assertEqual(check(self.root, self.metadata), [])

    def test_dependency_patch_removal_is_rejected(self):
        (self.root / "Cargo.toml").write_text("[patch.crates-io]\n")
        self.assertTrue(check(self.root, self.metadata))

    def test_public_fixture_roots_require_a_provenance_entry_for_each_file(self):
        vendor = self.root / "vendor"
        records = {}
        for directory in ("test-ca", "rustls/src/testdata", "fuzz/corpus/message", "rustls-provider-test/tests"):
            path = vendor / directory / "new.bin"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"new public fixture")
            rel = path.relative_to(vendor).as_posix()
            records[rel] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            self.assertIn(f"rustls: public test fixture missing from provenance: {rel}",
                          check(self.root, self.metadata))
        (vendor / "test-ca-provenance.json").write_text(json.dumps({"files": records}))
        # rustls/src/testdata is also covered by the package's source inventory.
        patches = json.loads((vendor / "patches.json").read_text())
        patches["packages"]["rustls"]["files"]["src/testdata/new.bin"] = records["rustls/src/testdata/new.bin"]["sha256"]
        (vendor / "patches.json").write_text(json.dumps(patches))
        self.assertEqual(check(self.root, self.metadata), [])

    def test_public_test_fixture_changes_are_rejected(self):
        path = self.root / "vendor/test-ca"
        path.mkdir()
        (path / "certificate.der").write_bytes(b"changed public fixture")
        (self.root / "vendor/test-ca-provenance.json").write_text(json.dumps({
            "files": {"test-ca/certificate.der": {"sha256": "0" * 64}}
        }))
        self.assertTrue(check(self.root, self.metadata))


class WorkspaceFeatureResolution(unittest.TestCase):
    """Optional workspace features cannot enable unreviewed patched features."""

    # One reviewed and one unreviewed feature of each patched package.
    PACKAGES = {
        "serde_json": ("1.0.151", "raw_value", "unbounded_depth"),
        "rustls": ("0.23.46", "tls12", "brotli"),
        "bytes": ("1.12.1", "std", "serde"),
        "hyper": ("1.11.1", "http2", "ffi"),
        "tungstenite": ("0.26.2", "handshake", "native-tls"),
    }

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def resolve_workspace(self, optional, helper_features=()):
        """Resolve a path-only copy of Maki's layout through the contract.

        The patched packages are excluded from the workspace, as in Maki, and
        the member enables `optional` only through its non-default `extra`
        feature, optionally by way of an optional, excluded `helper` package.
        """
        root = Path(tempfile.mkdtemp(dir=self.directory.name))
        upstream = {"schema": 1, "packages": {}}
        patches = {"schema": 1, "packages": {}}
        dependencies = patch = ""
        for name, (version, reviewed, unreviewed) in self.PACKAGES.items():
            files = {
                "Cargo.toml": (f'[package]\nname = "{name}"\nversion = "{version}"\n'
                               f'edition = "2021"\n\n[features]\n{reviewed} = []\n'
                               f'{unreviewed} = []\n'),
                "src/lib.rs": "",
            }
            for rel, text in files.items():
                (root / "vendor" / name / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / "vendor" / name / rel).write_text(text)
            upstream["packages"][name] = {
                "version": version, "crate_sha256": "0" * 64,
                "upstream_files": {rel: hashlib.sha256(text.encode()).hexdigest()
                                   for rel, text in files.items()},
            }
            patches["packages"][name] = {"files": {}}
            dependencies += f'{name} = {{ path = "../vendor/{name}" }}\n'
            patch += f'{name} = {{ path = "vendor/{name}" }}\n'
        excluded = [f"vendor/{name}" for name in self.PACKAGES] + ["helper"]
        (root / "Cargo.toml").write_text(
            f'[workspace]\nresolver = "2"\nmembers = ["member"]\n'
            f"exclude = {json.dumps(excluded)}\n\n[patch.crates-io]\n{patch}")
        helper = ""
        if helper_features:
            (root / "helper/src").mkdir(parents=True)
            (root / "helper/src/lib.rs").write_text("")
            (root / "helper/Cargo.toml").write_text(
                '[package]\nname = "helper"\nversion = "0.0.0"\nedition = "2021"\n\n'
                '[dependencies]\nserde_json = { path = "../vendor/serde_json", '
                f"features = {json.dumps(list(helper_features))} }}\n")
            helper = 'helper = { path = "../helper", optional = true }\n'
            optional = [*optional, "dep:helper"]
        (root / "member/src").mkdir(parents=True)
        (root / "member/src/lib.rs").write_text("")
        (root / "member/Cargo.toml").write_text(
            '[package]\nname = "member"\nversion = "0.0.0"\nedition = "2021"\n\n'
            f"[dependencies]\n{dependencies}{helper}\n"
            f"[features]\nextra = {json.dumps(list(optional))}\n")
        (root / "vendor/upstream.json").write_text(json.dumps(upstream))
        (root / "vendor/patches.json").write_text(json.dumps(patches))
        (root / "vendor/test-ca-provenance.json").write_text(json.dumps({"files": {}}))
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root,
                       check=True, capture_output=True)
        metadata = resolve(root)
        self.assertIsNotNone(metadata, "the fixture workspace does not resolve")
        return check(root, metadata)

    def test_optional_workspace_feature_with_reviewed_features_passes(self):
        reviewed = [f"{name}/{feature}" for name, (_, feature, _) in self.PACKAGES.items()]
        self.assertEqual(self.resolve_workspace(reviewed), [])
        self.assertEqual(self.resolve_workspace([], helper_features=["raw_value"]), [])

    def test_unreviewed_feature_behind_optional_workspace_feature_is_rejected(self):
        for name, (_, _, feature) in self.PACKAGES.items():
            with self.subTest(name=name, feature=feature):
                errors = self.resolve_workspace([f"{name}/{feature}"])
                self.assertTrue(any(name in error and feature in error for error in errors),
                                errors)

    def test_unreviewed_feature_behind_optional_dependency_is_rejected(self):
        errors = self.resolve_workspace([], helper_features=["unbounded_depth"])
        self.assertTrue(any("serde_json" in error and "unbounded_depth" in error
                            for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
