#!/usr/bin/env python3
"""Verify the pinned source and resolved dependencies of the erasure patches."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib


# Resolved Cargo features of each patched package whose allocation paths the
# erasure patches cover (vendor/README.md). Any other resolved feature fails the
# contract until its paths are reviewed, patched where needed and listed here.
REVIEWED_FEATURES = {
    "bytes": {"default", "std"},
    "hyper": {"client", "default", "http1", "http2", "server"},
    "rustls": {"aws-lc-rs", "aws_lc_rs", "log", "logging", "ring", "std", "tls12"},
    "serde_json": {"arbitrary_precision", "default", "float_roundtrip", "raw_value", "std"},
    "tungstenite": {
        "__rustls-tls", "data-encoding", "handshake", "http", "httparse", "rustls",
        "rustls-pki-types", "sha1",
    },
}


def check(root: Path, metadata: dict) -> list[str]:
    errors = []
    try:
        upstream = json.loads((root / "vendor/upstream.json").read_text())
        patches = json.loads((root / "vendor/patches.json").read_text())
        manifest = tomllib.loads((root / "Cargo.toml").read_text())
        lock = tomllib.loads((root / "Cargo.lock").read_text())
        fixtures = json.loads((root / "vendor/test-ca-provenance.json").read_text())
        if upstream["schema"] != 1 or patches["schema"] != 1:
            return ["unsupported vendor manifest schema"]
        required = set(REVIEWED_FEATURES)
        if set(upstream["packages"]) != required or set(patches["packages"]) != required:
            return ["required plaintext-erasure source inventory is missing"]
        resolve = metadata.get("resolve")
        nodes = {node["id"]: node for node in (resolve or {}).get("nodes") or []}
        if not nodes:
            errors.append("resolved dependency features are missing")
        for name, record in upstream["packages"].items():
            path = root / "vendor" / name
            expected = {**record["upstream_files"], **patches["packages"][name]["files"]}
            # Only a local build directory at the package root is not source.
            actual = {
                str(p.relative_to(path)): p for p in path.rglob("*")
                if p.is_file() and p.relative_to(path).parts[0] != "target"
            }
            if actual.keys() != expected.keys():
                errors.append(f"{name}: source inventory differs from the recorded patch")
            for rel, sha in expected.items():
                source = actual.get(rel)
                if source is None or hashlib.sha256(source.read_bytes()).hexdigest() != sha:
                    errors.append(f"{name}: source hash differs for {rel}")
            if manifest.get("patch", {}).get("crates-io", {}).get(name, {}).get("path") != f"vendor/{name}":
                errors.append(f"{name}: workspace dependency patch is missing")
            resolved = [p for p in metadata["packages"] if p["name"] == name]
            if len(resolved) != 1:
                errors.append(f"{name}: expected exactly one resolved version")
                continue
            package = resolved[0]
            if (package["version"] != record["version"] or package.get("source") is not None
                    or Path(package["manifest_path"]).resolve() != (path / "Cargo.toml").resolve()):
                errors.append(f"{name}: resolved dependency bypasses the pinned patch")
            node = nodes.get(package["id"])
            if node is None:
                errors.append(f"{name}: resolved features are missing")
            else:
                unreviewed = sorted(set(node["features"]) - REVIEWED_FEATURES[name])
                if unreviewed:
                    errors.append(f"{name}: unreviewed resolved features: {', '.join(unreviewed)}")
            locked = [p for p in lock["package"] if p["name"] == name]
            if len(locked) != 1 or locked[0]["version"] != record["version"] or locked[0].get("source"):
                errors.append(f"{name}: lockfile bypasses the pinned patch")
        for rel, record in fixtures["files"].items():
            path = root / "vendor" / rel
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
                errors.append(f"rustls: public test fixture hash differs for {rel}")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, StopIteration) as error:
        errors.append(f"vendor contract is incomplete or malformed: {type(error).__name__}")
    return errors


def resolve(root: Path) -> dict | None:
    """Return the locked dependency metadata of the workspace at root, or None."""
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        return None
    return json.loads(result.stdout)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    metadata = resolve(root)
    if metadata is None:
        print("Cannot resolve the locked dependencies for the vendor contract.", file=sys.stderr)
        return 1
    errors = check(root, metadata)
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print("Pinned erasure sources, dependency paths, reviewed features and public TLS "
              "fixtures verified.")
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
