#!/usr/bin/env python3
"""Prepare a local Debian release candidate from committed HEAD; never publish it."""

import argparse
import ctypes
import errno
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


ROOT = pathlib.Path(__file__).resolve().parents[1]


def fail(message):
    raise SystemExit(f"prepare-release: {message}")


def run(command, *, cwd=None, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        fail(f"{command[0]} exited {result.returncode}:\n{result.stderr[-8000:]}")
    return result.stdout.strip()


def git_command(*args, repo=None):
    return ["git", "--no-replace-objects", "-C", str(ROOT if repo is None else repo), *args]


def git(*args):
    # Legacy grafts change rev-list ancestry even with --no-replace-objects.
    return run(git_command(*args), env={**os.environ, "GIT_GRAFT_FILE": os.devnull})


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def archive_source(destination, commit, prefix, epoch, *, repo=None):
    # Read the committed blobs directly. git archive applies checkout-local
    # attributes such as export-ignore and export-subst to the same tree.
    listing = subprocess.check_output(git_command("ls-tree", "-rz", "-t", commit, repo=repo))
    with tarfile.open(destination, "w", encoding="utf-8", pax_headers={"comment": commit}) as archive, \
            subprocess.Popen(git_command("cat-file", "--batch", repo=repo),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE) as blobs:
        directory = tarfile.TarInfo(prefix)
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.mtime = epoch
        archive.addfile(directory)
        for entry in listing.rstrip(b"\0").split(b"\0"):
            metadata, name = entry.split(b"\t", 1)
            mode, _, oid = metadata.split()
            path = name.decode("utf-8", "surrogateescape")
            member = tarfile.TarInfo(f"{prefix}/{path}")
            member.mtime = epoch
            if mode == b"040000":
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                archive.addfile(member)
                continue
            if mode not in (b"100644", b"100755", b"120000"):
                fail(f"unsupported source archive entry: {member.name}")
            blobs.stdin.write(oid + b"\n")
            blobs.stdin.flush()
            header = blobs.stdout.readline().split()
            if len(header) != 3 or header[:2] != [oid, b"blob"]:
                fail(f"cannot read committed blob for {member.name}")
            size = int(header[2])
            if mode == b"120000":
                member.type = tarfile.SYMTYPE
                member.mode = 0o777
                member.linkname = blobs.stdout.read(size).decode("utf-8", "surrogateescape")
                archive.addfile(member)
            else:
                member.size = size
                member.mode = 0o755 if mode == b"100755" else 0o644
                archive.addfile(member, blobs.stdout)
            if blobs.stdout.read(1) != b"\n":
                fail(f"incomplete committed blob for {member.name}")
        blobs.stdin.close()
        if blobs.wait():
            fail("git cat-file failed while preparing the source archive")


def commit_epoch(commit, *, repo=None):
    return int(subprocess.check_output(
        git_command("show", "--no-show-signature", "-s", "--format=%ct", commit, repo=repo)
    ))


def checkout_filemode(repo):
    """Override core.fileMode only where the checkout can represent Git's executable bit."""
    if os.name != "posix":
        return []
    configured = subprocess.check_output(
        git_command("config", "--bool", "--default", "true", "--get", "core.fileMode", repo=repo))
    if configured.strip() == b"true":
        return []
    # Git can legitimately disable fileMode on a mount with fixed permissions.
    # Test a private file on the same filesystem, without chmodding any tracked file.
    device = repo.stat().st_dev
    for directory in (repo, None):  # try the system temp directory if the checkout is read-only
        try:
            with tempfile.TemporaryFile(dir=directory) as probe:
                fd = probe.fileno()
                before = os.fstat(fd)
                if before.st_dev != device:
                    continue
                os.fchmod(fd, before.st_mode ^ 0o100)
                if (os.fstat(fd).st_mode ^ before.st_mode) & 0o100:
                    return ["-c", "core.fileMode=true"]
                return []
        except OSError:
            continue
    return []


def tracked_changes(*, repo=None):
    repo = ROOT if repo is None else repo
    filemode = checkout_filemode(repo)
    command = git_command("--no-optional-locks", *filemode, "status",
                          "--porcelain", "--untracked-files=no", repo=repo)
    if subprocess.check_output(command):
        return True
    # A fresh index compares contents through Git's normal clean filters without
    # inheriting cached stat data or assume-unchanged hints from the checkout.
    # Only absent, explicitly skipped paths are allowed to lack a working copy.
    entries = subprocess.check_output(git_command("ls-files", "-t", "-z", repo=repo)).split(b"\0")
    absent_skipped = [entry[2:] for entry in entries if entry.startswith(b"S ")
                      and not os.path.lexists(repo / os.fsdecode(entry[2:]))]
    with tempfile.TemporaryDirectory() as directory:
        env = {**os.environ, "GIT_INDEX_FILE": str(pathlib.Path(directory) / "index")}
        private_git = git_command("-c", "core.sparseCheckout=false", "-c", "core.splitIndex=false",
                                  *filemode, repo=repo)
        subprocess.run([*private_git, "read-tree", "HEAD"], env=env, check=True)
        if absent_skipped:
            subprocess.run([*private_git, "update-index", "--skip-worktree", "-z", "--stdin"],
                           input=b"\0".join(absent_skipped) + b"\0", env=env, check=True)
        return bool(subprocess.check_output([*private_git, "status", "--porcelain", "--untracked-files=no"],
                                            env=env))


def candidate_source_version():
    import tomllib

    # Capture only a committed source tree. Untracked files are excluded by
    # the selected Git tree, and staged/unstaged tracked changes must not be mistaken
    # for source included in this candidate.
    commit = git("rev-parse", "--verify", "HEAD^{commit}")
    if tracked_changes():
        fail("tracked changes must be committed before preparing a candidate")
    if git("rev-parse", "--verify", "HEAD^{commit}") != commit:
        fail("HEAD changed while checking tracked changes; retry candidate preparation")
    if git("rev-parse", "--is-shallow-repository") != "false":
        fail("candidate versions require complete Git history; fetch --unshallow before retrying")
    workspace_version = tomllib.loads(git("show", f"{commit}:Cargo.toml"))["workspace"]["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", workspace_version):
        fail("candidate preparation requires a numeric major.minor.patch workspace version")
    # A descendant has strictly more reachable commits than its ancestor.
    # Compare that number before the hash; neither hashes nor timestamps are
    # monotonic. The 'rev' prefix also sorts above legacy '~rc+git' versions.
    revision = int(git("rev-list", "--count", commit))
    return commit, workspace_version, f"{workspace_version}~rc+rev{revision}.git{commit[:12]}"


def publish_bundle(bundle, output):
    # The Debian builder runs on Linux. RENAME_NOREPLACE makes the existence
    # check part of the rename, including when the destination is an empty dir.
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError:
        fail("candidate publication requires renameat2 with RENAME_NOREPLACE")
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    at_fdcwd, rename_noreplace = -100, 1
    if renameat2(at_fdcwd, os.fsencode(bundle), at_fdcwd, os.fsencode(output), rename_noreplace) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            fail(f"output already exists: {output}")
        raise OSError(error, os.strerror(error), output)


def prepare(output):
    if output.exists() or output.is_symlink():
        fail(f"output already exists: {output}")
    commit, workspace_version, version = candidate_source_version()
    tree = git("rev-parse", f"{commit}^{{tree}}")
    epoch = commit_epoch(commit)
    architecture = run(["dpkg", "--print-architecture"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", architecture):
        fail("dpkg returned an invalid native architecture")
    # Make the compiler selection explicit instead of probing PATH's rustc
    # while Cargo may select another one from the environment or its config.
    compiler = shutil.which(os.environ.get("RUSTC") or os.environ.get("CARGO_BUILD_RUSTC") or "rustc")
    if compiler is None:
        fail("selected Rust compiler is not executable or was not found")
    # Preserve symlinks: rustup's proxy chooses its tool from the invoked name.
    # Relative selections refer to the caller's directory, before extraction.
    compiler = os.path.abspath(compiler)
    distribution = {}
    for line in pathlib.Path("/etc/os-release").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ("ID", "VERSION_ID", "VERSION_CODENAME"):
            values = shlex.split(value)
            distribution[key.lower()] = values[0] if values else ""
    if not distribution.get("id") or not distribution.get("version_id"):
        fail("/etc/os-release must identify the build distribution and version")
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
        archive_source(archive_tar, commit, f"maki-{workspace_version}", epoch)
        with archive_tar.open("rb") as source, source_archive.open("wb") as target:
            with gzip.GzipFile(fileobj=target, filename="", mode="wb", mtime=epoch) as compressed:
                shutil.copyfileobj(source, compressed)
        extracted = work / "source"
        extracted.mkdir()
        with tarfile.open(archive_tar, encoding="utf-8") as archive:
            # Python 3.11 does not yet provide tarfile's data filter. Git
            # tracks no device files, and this project needs no source links;
            # reject links instead of letting extraction escape the build.
            members = archive.getmembers()
            for member in members:
                relative = pathlib.PurePosixPath(member.name)
                if relative.is_absolute() or ".." in relative.parts or not (member.isdir() or member.isfile()):
                    fail(f"unsupported source archive entry: {member.name}")
                # Hand the original Git path bytes back to the local filesystem.
                member.name = os.fsdecode(member.name.encode("utf-8", "surrogateescape"))
            archive.extractall(extracted, members=members)
        source = extracted / f"maki-{workspace_version}"
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = str(epoch)
        environment["CARGO_TARGET_DIR"] = str(work / "target")
        environment["CARGO_BUILD_BUILD_DIR"] = str(work / "build")
        environment["RUSTC"] = compiler
        # Probe in the same directory and environment as the build. This also
        # keeps rustup's per-directory toolchain selection consistent.
        rustc = run([compiler, "-vV"], cwd=source, env=environment)
        host = next((line[6:] for line in rustc.splitlines() if line.startswith("host: ")), None)
        if not host or not re.fullmatch(r"[A-Za-z0-9_-]+", host):
            fail("rustc did not report a native host target")
        toolchain = {
            "rustc": rustc,
            "rustc_executable": compiler,
            "cargo": run(["cargo", "--version"], cwd=source, env=environment),
            "dpkg_deb": run(["dpkg-deb", "--version"]).splitlines()[0],
        }
        # Record inherited compiler customization rather than claiming a
        # reproducible build across machines or silently changing its flags.
        target_prefix = f"CARGO_TARGET_{host.upper().replace('-', '_')}"
        build_environment = {
            key: environment[key]
            for key in ("RUSTC", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                        f"{target_prefix}_RUSTFLAGS", f"{target_prefix}_LINKER", "CARGO_BUILD_RUSTFLAGS",
                        "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")
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
            "build": {
                "command": command,
                "compiler_environment": build_environment,
                "package_environment": {
                    key: environment[key] for key in (
                        "DPKG_DEB_COMPRESSOR_TYPE", "DPKG_DEB_COMPRESSOR_LEVEL", "DPKG_DEB_THREADS_MAX"
                    ) if key in environment
                },
            },
            "package": {"filename": package_name, "version": version, "sha256": digest(package),
                        "depends": run(["dpkg-deb", "--field", str(package), "Depends"])},
        }
        (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        hashes = {source_name: manifest["source"]["sha256"], package_name: manifest["package"]["sha256"],
                  "manifest.json": digest(bundle / "manifest.json")}
        checksums = "".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes))
        (bundle / "SHA256SUMS").write_text(checksums)
        publish_bundle(bundle, output)
    try:
        print(output, flush=True)
    except BrokenPipeError:
        # Publication succeeded. Avoid retrying the broken buffered stream at shutdown.
        with open(os.devnull, "wb") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=pathlib.Path, help="new candidate directory")
    action.add_argument("--print-version", action="store_true",
                        help="print the committed source's candidate version without building")
    args = parser.parse_args()
    if args.print_version:
        print(candidate_source_version()[2])
    else:
        prepare(args.output.absolute())


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, tarfile.TarError, ValueError, KeyError) as error:
        fail(str(error))
