#!/usr/bin/env python3
"""Checks and assembly for the release workflow (.github/workflows/release.yml).

check-tag      refuse a tag or ref the workflow must not publish
rpm-manifest   write manifest.json and SHA256SUMS beside a built RPM
assemble       verify both bundles, give the assets their release names,
               write the combined SHA256SUMS and render the release notes
state          report whether a release (draft, pre-release, release) and a tag exist
uploaded       compare the draft's uploaded assets with the local ones

Only the standard library; runs on Python 3.9 (RHEL 9) and later.
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import string
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
# GitHub rewrites other characters in asset names (the candidate version's
# '~' and '+' among them), which would break the checksum list.
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
HASH_LINE = re.compile(r"([0-9a-f]{64})  ([^/\n]+)")
COMMIT = re.compile(r"[0-9a-f]{40}")


def fail(message):
    raise SystemExit(f"release-assets: {message}")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def workspace_version(cargo_toml):
    import tomllib

    try:
        version = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read [workspace.package] version from {cargo_toml}: {error}")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        fail(f"the workspace version {version!r} is not major.minor.patch")
    return version


def check_tag(tag, ref, cargo_toml):
    """Return (workspace version, release candidate number) or refuse."""
    if ref != "refs/heads/main":
        fail(f"releases are made from main only; this run is for {ref!r}")
    version = workspace_version(cargo_toml)
    if tag == f"v{version}":
        fail(f"{tag} is a final release; production approval is pending (docs/status.md), so this "
             f"workflow publishes release candidates only: use v{version}-rc.<n>")
    match = re.fullmatch(r"v([0-9]+\.[0-9]+\.[0-9]+)-rc\.([1-9][0-9]{0,3})", tag)
    if match is None:
        fail(f"{tag!r} is not a release candidate tag v{version}-rc.<n> (n = 1, 2, ...)")
    if match.group(1) != version:
        fail(f"{tag} names version {match.group(1)}, but the workspace version in Cargo.toml is {version}")
    return version, int(match.group(2))


def read_checksums(bundle):
    """{name: sha256} from a bundle's SHA256SUMS, checked against its files."""
    listing = bundle / "SHA256SUMS"
    if not listing.is_file():
        fail(f"{bundle} has no SHA256SUMS")
    hashes = {}
    for line in listing.read_text(encoding="utf-8").splitlines():
        match = HASH_LINE.fullmatch(line)
        if match is None or match.group(2) in hashes:
            fail(f"malformed or repeated line in {listing}: {line!r}")
        hashes[match.group(2)] = match.group(1)
    present = sorted(path.name for path in bundle.iterdir() if path.name != "SHA256SUMS")
    if sorted(hashes) != present:
        fail(f"{listing} lists {sorted(hashes)}, but {bundle} holds {present}")
    for name, expected in hashes.items():
        path = bundle / name
        if not path.is_file() or path.is_symlink():
            fail(f"{path} is not a regular file")
        if sha256(path) != expected:
            fail(f"{path} does not match its SHA256SUMS entry")
    return hashes


def single(bundle, hashes, suffix):
    names = [name for name in hashes if name.endswith(suffix)]
    if len(names) != 1:
        fail(f"{bundle} must hold exactly one *{suffix}, found {names}")
    return names[0]


def load_manifest(bundle):
    try:
        return json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"cannot read {bundle / 'manifest.json'}: {error}")


def os_release():
    fields = {}
    for line in pathlib.Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ("ID", "VERSION_ID", "NAME", "PRETTY_NAME"):
            fields[key.lower()] = value.strip().strip('"')
    return fields


def output_of(command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()


def rpm_manifest(package, version, commit):
    """manifest.json and SHA256SUMS for the RPM bundle (the RPM's own directory)."""
    if not COMMIT.fullmatch(commit):
        fail(f"{commit!r} is not a full commit id")
    if not package.is_file():
        fail(f"{package} does not exist")
    bundle = package.parent
    others = sorted(path.name for path in bundle.iterdir() if path != package)
    if others:
        fail(f"{bundle} must hold only the RPM, found {others}")
    header = output_of(["rpm", "-qp", "--queryformat",
                        "%{NAME}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n", str(package)]).splitlines()
    if header[0] != "maki" or header[1] != version:
        fail(f"{package.name} is {header[0]} {header[1]}, not maki {version}")
    rustc = output_of(["rustc", "-vV"])
    manifest = {
        "schema_version": 1,
        "qualification": "candidate-only; production approval remains separate",
        "source": {"commit": commit},
        "build_host": {"distribution": os_release(), "dist": output_of(["rpm", "--eval", "%{?dist}"]),
                       "architecture": header[3]},
        "toolchain": {"rustc": rustc, "cargo": output_of(["cargo", "--version"]),
                      "rpmbuild": output_of(["rpmbuild", "--version"])},
        "package": {"filename": package.name, "version": header[1], "release": header[2],
                    "sha256": sha256(package),
                    "requires": output_of(["rpm", "-qp", "--requires", str(package)]).splitlines(),
                    "conflicts": output_of(["rpm", "-qp", "--conflicts", str(package)]).splitlines()},
    }
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                          encoding="utf-8")
    hashes = {package.name: manifest["package"]["sha256"], "manifest.json": sha256(bundle / "manifest.json")}
    (bundle / "SHA256SUMS").write_text("".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes)),
                                       encoding="utf-8")


def assemble(tag, commit, repository, deb_bundle, rpm_bundle, template, output, notes, cargo_toml):
    if not COMMIT.fullmatch(commit):
        fail(f"{commit!r} is not a full commit id")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        fail(f"{repository!r} is not owner/name")
    version, _ = check_tag(tag, "refs/heads/main", cargo_toml)
    if output.exists() or notes.exists():
        fail(f"{output} or {notes} already exists")
    deb_hashes = read_checksums(deb_bundle)
    rpm_hashes = read_checksums(rpm_bundle)
    deb_manifest, rpm_manifest_ = load_manifest(deb_bundle), load_manifest(rpm_bundle)
    deb = single(deb_bundle, deb_hashes, ".deb")
    source = single(deb_bundle, deb_hashes, "-source.tar.gz")
    rpm = single(rpm_bundle, rpm_hashes, ".rpm")
    if sorted(deb_hashes) != sorted([deb, source, "manifest.json"]) or \
            sorted(rpm_hashes) != sorted([rpm, "manifest.json"]):
        fail("a bundle holds files other than its package, source archive and manifest")
    try:
        package_version = deb_manifest["package"]["version"]
        checks = [
            (deb_manifest["source"]["commit"], commit, "the Debian bundle's commit"),
            (rpm_manifest_["source"]["commit"], commit, "the RPM bundle's commit"),
            (deb_manifest["workspace_version"], version, "the Debian bundle's workspace version"),
            (rpm_manifest_["package"]["version"], package_version, "the RPM's version"),
            (deb_manifest["package"]["filename"], deb, "the Debian package's file name"),
            (deb_manifest["package"]["sha256"], deb_hashes[deb], "the Debian package's hash"),
            (deb_manifest["source"]["filename"], source, "the source archive's file name"),
            (deb_manifest["source"]["sha256"], deb_hashes[source], "the source archive's hash"),
            (rpm_manifest_["package"]["filename"], rpm, "the RPM's file name"),
            (rpm_manifest_["package"]["sha256"], rpm_hashes[rpm], "the RPM's hash"),
        ]
        distribution = deb_manifest["build_host"]["distribution"]
        deb_label = distribution["id"] + distribution["version_id"]
        deb_architecture = deb_manifest["build_host"]["architecture"]
        rpm_label = rpm_manifest_["build_host"]["dist"].lstrip(".")
        rpm_architecture = rpm_manifest_["build_host"]["architecture"]
        rpm_distribution = rpm_manifest_["build_host"]["distribution"]
    except (KeyError, TypeError) as error:
        fail(f"a manifest lacks {error}")
    for actual, expected, what in checks:
        if actual != expected:
            fail(f"{what} is {actual!r}, expected {expected!r}")
    if not rpm_label:
        fail("the RPM bundle does not record its distribution tag (%{dist})")
    label = tag[1:]
    names = {
        "deb": f"maki-{label}-{deb_label}-{deb_architecture}.deb",
        "deb_manifest": f"maki-{label}-{deb_label}-{deb_architecture}-manifest.json",
        "rpm": f"maki-{label}-{rpm_label}-{rpm_architecture}.rpm",
        "rpm_manifest": f"maki-{label}-{rpm_label}-{rpm_architecture}-manifest.json",
        "source": f"maki-{label}-source.tar.gz",
    }
    for name in names.values():
        if not ASSET_NAME.fullmatch(name):
            fail(f"asset name {name!r} has characters GitHub would rewrite")
    sources = {"deb": deb_bundle / deb, "deb_manifest": deb_bundle / "manifest.json",
               "rpm": rpm_bundle / rpm, "rpm_manifest": rpm_bundle / "manifest.json",
               "source": deb_bundle / source}
    output.mkdir(parents=True)
    hashes = {}
    for key, name in names.items():
        shutil.copyfile(sources[key], output / name)
        hashes[name] = sha256(output / name)
    (output / "SHA256SUMS").write_text("".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes)),
                                       encoding="utf-8")
    values = dict(
        names, tag=tag, label=label, commit=commit, repository=repository, version=package_version,
        rpm_release=rpm_manifest_["package"].get("release", ""),
        deb_platform="{} {} ({}), {}".format(
            distribution.get("id", "").capitalize(), distribution["version_id"],
            distribution.get("version_codename", ""), deb_architecture),
        rpm_platform="RHEL 9 and its rebuilds, {} (built on {} {})".format(
            rpm_architecture, rpm_distribution.get("name", rpm_distribution.get("id", "")),
            rpm_distribution.get("version_id", "")),
    )
    try:
        rendered = string.Template(template.read_text(encoding="utf-8")).substitute(values)
    except (KeyError, ValueError) as error:
        fail(f"cannot render {template}: {error}")
    notes.write_text(rendered, encoding="utf-8")
    for name in sorted(names.values()) + ["SHA256SUMS"]:
        print(output / name)


def releases_from(path):
    """Releases from `gh api --paginate` output: one JSON array per page."""
    text, releases, position = path.read_text(encoding="utf-8"), [], 0
    decoder = json.JSONDecoder()
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        page, position = decoder.raw_decode(text, position)
        if not isinstance(page, list):
            fail(f"{path} is not a list of releases")
        releases.extend(page)
    return releases


def state(tag, releases, refs):
    """'release=none|draft|prerelease|release' and 'tag=none|<sha>' for one tag.

    A published release wins over drafts of the same name; 'release' is a
    published release that is not marked as a pre-release."""
    matching = [release for release in releases_from(releases) if release.get("tag_name") == tag]
    published = [release for release in matching if not release.get("draft")]
    if not matching:
        release = "none"
    elif not published:
        release = "draft"
    elif all(release.get("prerelease") for release in published):
        release = "prerelease"
    else:
        release = "release"
    exact = [ref for ref in json.loads(refs.read_text(encoding="utf-8") or "[]")
             if ref.get("ref") == f"refs/tags/{tag}"]
    tag_state = exact[0]["object"]["sha"] if exact else "none"
    print(f"release={release}")
    print(f"tag={tag_state}")


def uploaded(view, assets):
    """The draft must hold exactly the local assets, uploaded, with their sizes."""
    try:
        listed = {asset["name"]: asset for asset in json.loads(view.read_text(encoding="utf-8"))["assets"]}
    except (OSError, ValueError, KeyError, TypeError) as error:
        fail(f"cannot read the release's assets from {view}: {error}")
    local = {path.name: path.stat().st_size for path in assets.iterdir()}
    if sorted(listed) != sorted(local):
        fail(f"the release holds {sorted(listed)}, expected {sorted(local)}")
    for name, size in local.items():
        if listed[name].get("size") != size or listed[name].get("state", "uploaded") != "uploaded":
            fail(f"{name} was not uploaded completely: {listed[name]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check-tag")
    check.add_argument("--tag", required=True)
    check.add_argument("--ref", required=True)
    check.add_argument("--cargo-toml", type=pathlib.Path, default=ROOT / "Cargo.toml")
    manifest = commands.add_parser("rpm-manifest")
    manifest.add_argument("--package", required=True, type=pathlib.Path)
    manifest.add_argument("--version", required=True)
    manifest.add_argument("--commit", required=True)
    build = commands.add_parser("assemble")
    for name in ("--tag", "--commit", "--repository"):
        build.add_argument(name, required=True)
    for name in ("--deb-bundle", "--rpm-bundle", "--template", "--output", "--notes"):
        build.add_argument(name, required=True, type=pathlib.Path)
    build.add_argument("--cargo-toml", type=pathlib.Path, default=ROOT / "Cargo.toml")
    query = commands.add_parser("state")
    query.add_argument("--tag", required=True)
    query.add_argument("--releases", required=True, type=pathlib.Path)
    query.add_argument("--refs", required=True, type=pathlib.Path)
    upload = commands.add_parser("uploaded")
    upload.add_argument("--view", required=True, type=pathlib.Path)
    upload.add_argument("--assets", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "check-tag":
        version, candidate = check_tag(args.tag, args.ref, args.cargo_toml)
        print(f"workspace_version={version}")
        print(f"release_candidate={candidate}")
    elif args.command == "rpm-manifest":
        rpm_manifest(args.package, args.version, args.commit)
    elif args.command == "assemble":
        assemble(args.tag, args.commit, args.repository, args.deb_bundle, args.rpm_bundle,
                 args.template, args.output, args.notes, args.cargo_toml)
    elif args.command == "state":
        state(args.tag, args.releases, args.refs)
    else:
        uploaded(args.view, args.assets)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError) as error:
        fail(str(error))
