# Preparing a release candidate

The first release scope is a Debian package for one native architecture and
build distribution, together with the exact committed source, build metadata,
and SHA-256 checksums. Candidate preparation is available locally; the current
qualification and publication state remains in [status](status.md).

The package contains `maki`, `maki-attach`, `maki-check`, the nbdkit plugin,
systemd units, and configuration examples. `maki-benchmark` is a development
and qualification tool built separately from the included source. Candidate
preparation does not install packages, create Git tags, publish a GitHub
Release, start services, or qualify a production deployment. The release
workflow builds such a candidate, with an RPM beside it, and publishes it as a
GitHub pre-release ([publishing a pre-release](#publishing-a-pre-release)).

## Build prerequisites and source boundary

Use a native Debian build host for the intended deployment distribution, with
Python 3.11 or newer, Git, Rust/Cargo 1.94.0 (the CI baseline), a native C toolchain,
`dpkg-dev`, and the dependencies in the
[Debian installation guide](getting-started/installation-debian.md). Packages
inherit the build host's native library requirements; an ELF architecture
match alone does not make a package compatible with an older distribution.
The package needs no NBD client: the helper connects NBD devices itself.

Prepare candidates after committing the intended changes. The command refuses
staged or unstaged tracked changes and exports only `HEAD`; untracked files,
local credentials and existing `target/` artifacts do not enter the source
archive. With `core.fileMode=false` on POSIX, the check probes a temporary file
on the checkout filesystem. If its executable bit can be toggled, mode-only
edits also require a commit. The source archive uses committed file bytes and executable modes,
including files that local Git archive attributes would omit or transform.
It builds in an isolated temporary directory with `--release
--locked --target <rustc host>` and always enables the package builder's
[ELF and native dependency validation](../packaging/debian/README.md#artifact-validation).
Source links are rejected during extraction. No cross-compilation or
`--no-shlibdeps` escape hatch is provided.

Cargo can download locked dependencies, so arrange registry access/cache before
an offline build. An independent release build needs enough free temporary
space for its own final and intermediate artifacts. Both `CARGO_TARGET_DIR`
and `CARGO_BUILD_BUILD_DIR` are set inside the unique candidate directory,
overriding inherited environment and Cargo configuration paths; the build does
not reuse the checkout's build cache. The temporary build is placed beside the
requested output and removed on ordinary success or failure. A machine crash can leave a
`.maki-candidate-*` temporary directory for manual inspection and cleanup.

The compiler is selected from a nonempty `RUSTC`, then `CARGO_BUILD_RUSTC`, then
`rustc` on `PATH`. Relative compiler paths refer to the directory invoking the
preparation command. The selected executable is passed to Cargo through
`RUSTC`, overriding `build.rustc` in Cargo configuration, and recorded in the
manifest. Its version and host are queried in the extracted source directory
with the build environment, so rustup uses the same toolchain selection.
Compiler wrappers and flags remain supported and recorded as below; this
selection policy does not make an arbitrary wrapper or Cargo configuration
hermetic.

## Candidate version ordering

For workspace version `0.1.0`, the package version is
`0.1.0~rc+rev<count>.git<12-character-commit>`. The count is
`git rev-list --count <commit>`: all commits reachable from the selected source,
including merged ancestry. Local graft files and replacement refs are ignored.
A descendant has a strictly larger count than its
ancestor, so Debian orders it as an upgrade for the same workspace version even
when its hash or commit timestamp sorts earlier. The numeric revision precedes
the hash, so revision 10 also sorts above revision 9.

This ordering applies along ancestry with complete history. It does not define
a chronological order between incomparable branches or across rebased or
rewritten histories. Use an approved source lineage for upgrades. Shallow
repositories are refused before producing a version or starting a build;
fetch their complete history with `git fetch --unshallow` before retrying.

New candidates sort above the previous `0.1.0~rc+git<commit>` candidates and
below the final `0.1.0`. After publishing a final release, bump the workspace
version before preparing its successor's candidates. Both source-build recipes
and the bundle builder use the same command for the version:

```bash
python3 -B scripts/prepare_release.py --print-version
```

This mode checks committed source and complete history, prints one version,
and creates no build or output directory. It needs Python and Git, without
probing Rust or Debian packaging tools.

Both modes of the command refuse a source tree that is not the top level of
its own Git checkout. Git looks for a repository in every parent directory,
so a tree unpacked from a source archive below another checkout would
otherwise get that repository's version and commit. An archive has no
history to count; its version is recorded in its release's manifest
([rebuilding from a published source archive](#rebuilding-from-a-published-source-archive)).

### Migrating legacy source-build packages

Earlier source-build recipes used `0.1.0+git<commit>`. Debian orders those
versions above both the new candidates and the final `0.1.0`. A prerelease
cannot both upgrade those legacy packages and sort below that final version.
Moving an installed legacy package to the new scheme therefore requires an
explicitly reviewed one-time downgrade, even if the source commit is newer.

Compare the installed version (`dpkg-query -W -f='${Version}\n' maki`) with the
intended package (`dpkg-deb --field ./maki.deb Version`), review its source and
checksums, and follow the stopped-workload
[runtime upgrade procedure](operations.md#upgrading-the-runtime-layout).
Only for that approved migration, add `--allow-downgrades` to the one-time
`apt install -y` invocation. Keep normal installs and subsequent upgrades on
the ordinary command without that flag.

## Prepare and inspect

From the repository root, choose a new output directory. The following Bash
commands keep the long build in the background with a private log and preserve
its PID and exit status:

```bash
umask 077
mkdir -p "$HOME/logs"
chmod 700 "$HOME/logs"
candidate_output="$HOME/maki-candidates/$(git rev-parse --short=12 HEAD)-$(dpkg --print-architecture)"
candidate_log="$(mktemp "$HOME/logs/maki-candidate.XXXXXX.log")"
candidate_status="${candidate_log%.log}.status"
(
  candidate_rc=0
  rustup run 1.94.0 python3 -B scripts/prepare_release.py --output "$candidate_output" || candidate_rc=$?
  printf '%s\n' "$candidate_rc" > "$candidate_status"
  exit "$candidate_rc"
) > "$candidate_log" 2>&1 < /dev/null &
candidate_pid=$!
printf 'PID=%s\nlog=%s\nstatus=%s\n' "$candidate_pid" "$candidate_log" "$candidate_status"
candidate_rc=0
wait "$candidate_pid" || candidate_rc=$?
cat "$candidate_status"
tail -n 40 "$candidate_log"       # inspect only after the process exits
(exit "$candidate_rc")
```

A successful directory contains:

| File | Purpose |
|---|---|
| `maki_<candidate-version>_<architecture>.deb` | Runtime package with scanned native dependencies |
| `maki-<candidate-version>-source.tar.gz` | Git archive of the exact committed source, including `Cargo.lock` |
| `manifest.json` | Commit/tree IDs, source epoch, distro/version, architecture, Rust target, tool versions, build command, compiler and Debian compression environment overrides, Cargo configuration files outside the source, package dependencies and artifact hashes |
| `SHA256SUMS` | Hashes of the package, source archive and manifest |

The output appears only after all build and packaging steps succeed. An
existing output is refused; choose another directory for another build. Verify
the bundle before transferring it to a qualification host:

```bash
(cd "$candidate_output" && sha256sum --check SHA256SUMS)
python3 -m json.tool "$candidate_output/manifest.json"
dpkg-deb --info "$candidate_output"/*.deb
dpkg-deb --contents "$candidate_output"/*.deb
```

The fixed source epoch and deterministic package builder make repeated
packaging of identical artifacts stable. The command does not claim bitwise
reproducibility across compiler versions, system libraries, paths, or Cargo
configuration. It handles inherited build inputs as follows; Cargo applies its
usual precedence when several are set:

| Input | Handling |
|---|---|
| `CARGO_PROFILE_RELEASE_*`, `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*` and Cargo-internal `__CARGO_*` variables; a `[profile.release]` or `[unstable]` table, or an `include` of further files, in Cargo configuration outside the committed source | Refused before building. The committed `Cargo.toml` defines the release profile, including the `unwind` panic strategy that the nbdkit plugin's panic boundary needs, and candidates use stable toolchain features only. Commit a needed profile change instead |
| `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS` and the `CARGO_TARGET_<TRIPLE>_RUSTFLAGS` for the selected build target; the target-specific linker from `CARGO_TARGET_<TRIPLE>_LINKER`; compiler wrappers from `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_BUILD_RUSTC_WRAPPER` and `CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER`; `CARGO_INCREMENTAL` and `CARGO_BUILD_INCREMENTAL` | Recorded in `compiler_environment` |
| C toolchain inputs of the aws-lc-sys and ring build scripts: `CC`, `CFLAGS`, `CXX`, `CXXFLAGS`, `AR`, `ARFLAGS`, `RANLIB`, `RANLIBFLAGS`, `ASM`, `ASMFLAGS`, `LDFLAGS`, `CXXSTDLIB`, `CROSS_COMPILE`, `CRATE_CC_NO_DEFAULTS`, `CC_FORCE_DISABLE`, `CC_SHELL_ESCAPED_FLAGS` and `CC_KNOWN_WRAPPER_CUSTOM`, also with a `HOST_` or `TARGET_` prefix or a suffix naming the selected target (`CC_x86_64-unknown-linux-gnu`, `CFLAGS_x86_64_unknown_linux_gnu`); every `CMAKE*`, `PKG_CONFIG*`, `AWS_LC_*` and `RING_*` variable; `OPENSSL_DIR`, `OPENSSL_INCLUDE_DIR` and `OPENSSL_LIB_DIR`, where aws-lc-sys looks for a system library | Recorded in `compiler_environment` |
| Cargo configuration outside the committed source: `.cargo/config` (or else `.cargo/config.toml`) in each directory above the extracted source, then in `CARGO_HOME` | Path and SHA-256 recorded in `cargo_configuration`, in Cargo's search order |

Independently of this command, `maki-nbdkit` does not compile with
`panic = "abort"`, however that strategy is selected.
The recorded environment overrides are diagnostic metadata;
they are not a hermetic-build attestation. Review the recorded values and
configuration paths before sharing the manifest. Checksums establish bundle consistency, not publisher
authenticity; a public release additionally needs the chosen signing or
attestation policy.

## Retain the complete deployment inputs

For the first deployment profile, retain one manifest of all installed package
versions and the kernel, filesystem and Maki configuration. Qualify fresh-host
installation, stopped-workload upgrade, and backup restore using those exact
Maki artifacts on Debian 12 with local AES-GCM-SIV and a single
NBD/PV/VG/XFS LV. Attach results to the final integrated commit and package
hashes. Changes to packages or configuration require the affected checks to be
run again; creating a PR or passing unit tests does not supply those results.

## Qualification and publication handoff

Keep the candidate's source commit and SHA-256 values attached to each
qualification report. Verify install, stopped-workload upgrade, backup/restore,
and removal on the intended distribution using the
[runtime upgrade procedure](operations.md#upgrading-the-runtime-layout) and
[external qualification checklist](testing.md). Maintainer scripts do not
manage live volume lifecycles. Creating a candidate does not satisfy the
remaining durability, resource-bound, transport-memory, or deployment-specific
qualification gates.

Before a public release, the maintainer must select the final release version
and immutable commit, reconcile [support](deployment/support-matrix.md),
[status](status.md) and [changelog](../CHANGELOG.md) with the attached evidence,
review redistribution/license notices for the packaged dependencies, and
approve the target distribution/architecture and signing/attestation policy.
Build final artifacts from that reviewed commit with the
[Debian builder](../packaging/debian/README.md), retaining native dependency
scanning and the same provenance/checksum evidence. Tagging, public upload and
production approval are separate maintainer actions; this command intentionally
produces candidate versions only.

## Publishing a pre-release

[`.github/workflows/release.yml`](../.github/workflows/release.yml) publishes
a release candidate as a GitHub pre-release. It runs only when a maintainer
dispatches it (`workflow_dispatch`) on `main`, with the tag to create:

```bash
gh workflow run release.yml --ref main -f tag=v0.1.0-rc.1
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

The Actions tab's "Run workflow" button does the same. The tag must be
`v<workspace version>-rc.<n>` (`n` = 1, 2, ...), with the workspace version
read from `Cargo.toml` at the dispatched commit. Before anything is built, the
`check` job refuses a run from another ref, any other tag, and a tag or
published release of that name that already exists; drafts are visible only
to the `publish` job's token, which refuses an existing draft before it
creates anything. Both jobs also refuse when a query of the releases or of
the tag fails or is cut off: an answer that is missing, empty or incomplete
is never read as "no release and no tag". A final tag
(`v0.1.0`) is refused while production approval is pending
([status](status.md)); allowing one is a reviewed change to
`scripts/release_assets.py` and the workflow, which then also decides whether
the release becomes "latest". Runs are serialised.

Every job checks out the dispatched commit (`github.sha`); the build jobs
fetch its whole history, which the candidate version needs. Nothing is
restored from a cache.

- `deb`, in a `debian:12` container: `python3 -B scripts/prepare_release.py
  --output dist/deb` builds the [candidate bundle](#prepare-and-inspect)
  (package, source archive, `manifest.json`, `SHA256SUMS`) with Rust 1.94.0,
  and the job checks it with `sha256sum --check`.
- `rpm`, in a `quay.io/centos/centos:stream9` container: the release binaries,
  then [`packaging/rpm/build-rpm.py`](../packaging/rpm/README.md) with the same
  candidate version as the Debian package (rpm 4.16 accepts its `~` and `+`
  and orders candidates as dpkg does), the commit time as `SOURCE_DATE_EPOCH`,
  and a `manifest.json` and `SHA256SUMS` from `scripts/release_assets.py
  rpm-manifest`.
- `publish`, the only job with `contents: write`: checks both bundles against
  their sums and manifests (one commit, one version), copies the assets under
  release names, writes one `SHA256SUMS` over them and renders the notes from
  [`.github/release-notes.md`](../.github/release-notes.md). It then creates a
  draft pre-release with the runner's `gh` (`gh release create <tag> --draft
  --prerelease --latest=false --target <commit>`), checks that every asset
  arrived under its name and size, and publishes the draft. GitHub creates the
  tag, at the dispatched commit, only when the draft is published.

For `v0.1.0-rc.1` the release holds:

| Asset | Content |
|---|---|
| `maki-0.1.0-rc.1-debian12-amd64.deb` | Debian 12 package, built on Debian 12 |
| `maki-0.1.0-rc.1-debian12-amd64-manifest.json` | The Debian bundle's `manifest.json` |
| `maki-0.1.0-rc.1-el9-x86_64.rpm` | RHEL 9 package, built on CentOS Stream 9 |
| `maki-0.1.0-rc.1-el9-x86_64-manifest.json` | The RPM's manifest |
| `maki-0.1.0-rc.1-source.tar.gz` | The exact committed source the packages were built from |
| `SHA256SUMS` | SHA-256 of every other asset |

The packages carry the candidate version (`0.1.0~rc+rev<count>.git<commit>`);
the asset names use the tag because GitHub rewrites `~` and `+` in asset
names, which would break the sums. The manifests keep the build's own file
names.

What the workflow does not do: the assets are not signed or attested, so
the `SHA256SUMS` published beside them show that a download is complete, not
who published it; the notes say so. It installs nothing and qualifies
nothing: a published candidate has passed the build jobs only, and the
[qualification handoff](#qualification-and-publication-handoff) still
applies. It does not edit the changelog, the status page or the support
matrix, and it never marks a release as "latest".

If a run fails before the draft is published, its last step deletes the
incomplete draft and no tag exists. If it fails after publication (the tag
did not land on the dispatched commit), nothing is deleted automatically and
the run's summary names what is left. To remove a bad release and its tag,
or what a failed run left:

```bash
gh release delete v0.1.0-rc.1 --cleanup-tag --yes   # a published release and its tag
gh release delete v0.1.0-rc.1 --yes                 # a draft (it has no tag)
git push --delete origin v0.1.0-rc.1                # a tag without a release
```

A deleted tag stays in clones that fetched it. Do not publish different
content under a deleted tag's name; publish the next release candidate
number instead.

## Rebuilding from a published source archive

The source archive of a release (`maki-<tag>-source.tar.gz`) holds the
committed tree without its history, in a directory named
`maki-<workspace version>`. `prepare_release.py` therefore cannot be used in
it: `--print-version` and `--output` stop with "is not a Git checkout" and
name the manifest. A candidate bundle is prepared from a clone of the
repository at the commit that `source.commit` names.

To build a package from the archive itself, take the version and the source
epoch from the Debian manifest published beside it (`package.version` and
`source.source_date_epoch`), build the binaries as the
[installation guide](getting-started/installation-debian.md#build-the-maki-package)
does, and give both values to the package builder. With the release's assets
in the current directory, on the build distribution the manifest names:

```bash
set -euo pipefail
sha256sum --check --ignore-missing SHA256SUMS
manifest="$PWD/maki-0.1.0-rc.1-debian12-amd64-manifest.json"
tar -xzf maki-0.1.0-rc.1-source.tar.gz
cd maki-0.1.0
maki_version="$(python3 -c 'import json, sys
print(json.load(open(sys.argv[1]))["package"]["version"])' "$manifest")"
SOURCE_DATE_EPOCH="$(python3 -c 'import json, sys
print(json.load(open(sys.argv[1]))["source"]["source_date_epoch"])' "$manifest")"
export SOURCE_DATE_EPOCH CARGO_TARGET_DIR="$PWD/target"
maki_host="$(rustc +1.94.0 -vV | sed -n 's/^host: //p')"
cargo +1.94.0 build --release --locked --target "$maki_host" \
  -p maki -p maki-attach -p maki-check -p maki-nbdkit
python3 packaging/debian/build-deb.py \
  --release-dir "$CARGO_TARGET_DIR/$maki_host/release" \
  --version "$maki_version" \
  --architecture "$(dpkg --print-architecture)" \
  --output ../maki.deb
```

[`packaging/rpm/build-rpm.py`](../packaging/rpm/README.md) takes the same
`--version` and `SOURCE_DATE_EPOCH` on a RHEL 9 family build host. Cargo
downloads the locked dependencies that `vendor/` does not hold.

The package carries the release's version, and the package builder is
deterministic: from the same binaries, version and epoch it writes the same
file. The compiled binaries are not expected to be identical to the
release's, for the reasons given under
[prepare and inspect](#prepare-and-inspect) (compiler, system libraries,
build paths, Cargo configuration), so neither is the package, and nothing
here signs or qualifies it.

## Maintainer checks

```bash
python3 -B -m unittest scripts.test_release_preparation scripts.test_debian_package -v
python3 -B -m unittest scripts.test_release_workflow_validation -v
python3 -B scripts/check_docs_links.py
```

The preparation contract uses a temporary Git repository, small native C ELF
fixtures, a simulated Cargo build and the real Debian package/dependency tools.
It checks committed-source provenance, checksums, deterministic packaging,
version ordering with real Git history and `dpkg`, shallow- and dirty-source
refusal, the refusal of a source tree that is not the top level of its own
checkout (unpacked alone or below another repository), the rebuild block of
this page from a source archive and its manifest, output preservation,
source-link refusal, intermediate build isolation,
compiler selection, refused and recorded build inputs and failure cleanup
without rebuilding the Rust workspace.
The Linux PR job runs it;
successful contract tests are not a full candidate-build or installation result.
`scripts/test_release_workflow_validation.py` checks the release workflow's
structure, the tag and bundle checks of `scripts/release_assets.py`, the notes,
and the publish and cleanup steps against a stand-in `gh`, also when its
queries of the releases or of the tag fail, are cut off between pages or
answer with an error; it needs `rpm` and `rpmbuild` for a fixture RPM.
