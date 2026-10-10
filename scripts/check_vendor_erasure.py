#!/usr/bin/env python3
"""Verify the pinned source and resolved dependencies of the erasure patches."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib


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
        required = {"bytes", "hyper", "rustls", "serde_json", "tungstenite"}
        if set(upstream["packages"]) != required or set(patches["packages"]) != required:
            return ["required plaintext-erasure source inventory is missing"]
        for name, record in upstream["packages"].items():
            path = root / "vendor" / name
            expected = {**record["upstream_files"], **patches["packages"][name]["files"]}
            actual = {
                str(p.relative_to(path)): p for p in path.rglob("*")
                if p.is_file() and "target" not in p.relative_to(path).parts
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
            locked = [p for p in lock["package"] if p["name"] == name]
            if len(locked) != 1 or locked[0]["version"] != record["version"] or locked[0].get("source"):
                errors.append(f"{name}: lockfile bypasses the pinned patch")
            if name == "serde_json":
                features = next(n["features"] for n in metadata["resolve"]["nodes"] if n["id"] == package["id"])
                if "float_roundtrip" in features:
                    errors.append("serde_json: an unreviewed allocation feature is enabled")
        for rel, record in fixtures["files"].items():
            path = root / "vendor" / rel
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
                errors.append(f"rustls: public test fixture hash differs for {rel}")
    except (OSError, ValueError, KeyError, StopIteration) as error:
        errors.append(f"vendor contract is incomplete or malformed: {type(error).__name__}")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        print("Cannot resolve the locked dependencies for the vendor contract.", file=sys.stderr)
        return 1
    errors = check(root, json.loads(result.stdout))
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print("Pinned erasure sources, dependency paths, features and public TLS fixtures verified.")
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
