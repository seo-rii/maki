#!/usr/bin/env python3
"""Prepare a local Debian release candidate from committed HEAD; never publish it."""

import argparse
import gzip
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def fail(message):
    raise SystemExit(f"prepare-release: {message}")


def run(command, *, cwd=None, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        fail(f"{command[0]} exited {result.returncode}:\n{result.stderr[-8000:]}")
    return result.stdout.strip()


def git(*args):
    return run(["git", "-C", str(ROOT), *args])


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def prepare(output):
    # Capture only a committed source tree. Untracked files are excluded by
    # git archive, and staged/unstaged tracked changes must not be mistaken
    # for source included in this candidate.
    if output.exists() or output.is_symlink():
        fail(f"output already exists: {output}")
    if git("status", "--porcelain", "--untracked-files=no"):
        fail("tracked changes must be committed before preparing a candidate")
    commit = git("rev-parse", "HEAD")
    tree = git("rev-parse", f"{commit}^{{tree}}")
    epoch = int(git("show", "-s", "--format=%ct", commit))
    workspace_version = tomllib.loads(git("show", f"{commit}:Cargo.toml"))["workspace"]["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", workspace_version):
        fail("candidate preparation requires a numeric major.minor.patch workspace version")
    version = f"{workspace_version}~rc+git{commit[:12]}"
    architecture = run(["dpkg", "--print-architecture"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", architecture):
        fail("dpkg returned an invalid native architecture")
    rustc = run(["rustc", "-vV"])
    host = next((line[6:] for line in rustc.splitlines() if line.startswith("host: ")), None)
    if not host or not re.fullmatch(r"[A-Za-z0-9_-]+", host):
        fail("rustc did not report a native host target")
    distribution = {}
    for line in pathlib.Path("/etc/os-release").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ("ID", "VERSION_ID", "VERSION_CODENAME"):
            values = shlex.split(value)
            distribution[key.lower()] = values[0] if values else ""
    if not distribution.get("id") or not distribution.get("version_id"):
        fail("/etc/os-release must identify the build distribution and version")
    toolchain = {
        "rustc": rustc,
        "cargo": run(["cargo", "--version"]),
        "dpkg_deb": run(["dpkg-deb", "--version"]).splitlines()[0],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    # Keep the bundle staging directory on the output filesystem; publish it
    # with a single rename only after packaging and all hashes succeed.
    with tempfile.TemporaryDirectory(prefix=".maki-candidate-", dir=output.parent) as temporary:
        work = pathlib.Path(temporary)
        bundle = work / "bundle"
        bundle.mkdir()
        source_name = f"maki-{version}-source.tar.gz"
        source_archive = bundle / source_name
        archive_tar = work / "source.tar"
        subprocess.run(
            ["git", "-C", str(ROOT), "archive", "--format=tar", f"--prefix=maki-{workspace_version}/",
             f"--output={archive_tar}", commit],
            check=True,
        )
        with archive_tar.open("rb") as source, source_archive.open("wb") as target:
            with gzip.GzipFile(fileobj=target, filename="", mode="wb", mtime=epoch) as compressed:
                shutil.copyfileobj(source, compressed)
        extracted = work / "source"
        extracted.mkdir()
        with tarfile.open(archive_tar) as archive:
            # Python 3.11 does not yet provide tarfile's data filter. Git
            # tracks no device files, and this project needs no source links;
            # reject links instead of letting extraction escape the build.
            members = archive.getmembers()
            for member in members:
                relative = pathlib.PurePosixPath(member.name)
                if relative.is_absolute() or ".." in relative.parts or not (member.isdir() or member.isfile()):
                    fail(f"unsupported source archive entry: {member.name}")
            archive.extractall(extracted, members=members)
        source = extracted / f"maki-{workspace_version}"
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = str(epoch)
        environment["CARGO_TARGET_DIR"] = str(work / "target")
        # Record inherited compiler customization rather than claiming a
        # reproducible build across machines or silently changing its flags.
        build_environment = {
            key: environment[key]
            for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")
            if key in environment
        }
        command = [
            "cargo", "build", "--release", "--locked", "--target", host,
            "-p", "maki", "-p", "maki-attach", "-p", "maki-check", "-p", "maki-nbdkit",
        ]
        print(f"Building candidate {version} for {architecture} from {commit}", flush=True)
        subprocess.run(command, cwd=source, env=environment, check=True)
        package_name = f"maki_{version}_{architecture}.deb"
        package = bundle / package_name
        run(
            [sys.executable, "-B", str(source / "packaging/debian/build-deb.py"),
             "--release-dir", str(work / "target" / host / "release"),
             "--version", version, "--architecture", architecture, "--output", str(package)],
            cwd=source,
            env=environment,
        )
        manifest = {
            "schema_version": 1,
            "qualification": "candidate-only; production approval remains separate",
            "workspace_version": workspace_version,
            "source": {"commit": commit, "tree": tree, "source_date_epoch": epoch,
                       "filename": source_name, "sha256": digest(source_archive)},
            "build_host": {"distribution": distribution, "architecture": architecture, "rust_target": host},
            "toolchain": toolchain,
            "build": {"command": command, "compiler_environment": build_environment},
            "package": {"filename": package_name, "version": version, "sha256": digest(package),
                        "depends": run(["dpkg-deb", "--field", str(package), "Depends"])},
        }
        (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        checksums = "".join(f"{digest(path)}  {path.name}\n" for path in sorted(bundle.iterdir()))
        (bundle / "SHA256SUMS").write_text(checksums)
        # A second check protects an output created while the build ran.
        if output.exists() or output.is_symlink():
            fail(f"output already exists: {output}")
        bundle.rename(output)
    print(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=pathlib.Path, help="new candidate directory")
    args = parser.parse_args()
    prepare(args.output.absolute())


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, tarfile.TarError, ValueError, KeyError) as error:
        fail(str(error))
