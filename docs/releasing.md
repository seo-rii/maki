# Preparing a release candidate

The first release scope is a Debian package for one native architecture and
build distribution, together with the exact committed source, build metadata,
and SHA-256 checksums. Candidate preparation is available locally; the current
qualification and publication state remains in [status](status.md).

The package contains `maki`, `maki-attach`, `maki-check`, the nbdkit plugin,
systemd units, and configuration examples. `maki-benchmark` is a development
and qualification tool built separately from the included source. Candidate
preparation does not install packages, create Git tags, publish a GitHub
Release, start services, or qualify a production deployment.

## Build prerequisites and source boundary

Use a native Debian build host for the intended deployment distribution, with
Python 3.11 or newer, Git, a working Rust/Cargo toolchain, a native C toolchain,
`dpkg-dev`, and the dependencies in the
[Debian installation guide](getting-started/installation-debian.md). Packages
inherit the build host's native library requirements; an ELF architecture
match alone does not make a package compatible with an older distribution.
The target must also provide the versioned `nbd-client >= 3.27.0` dependency.

Prepare candidates after committing the intended changes. The command refuses
staged or unstaged tracked changes and exports only `HEAD`; untracked files,
local credentials and existing `target/` artifacts do not enter the source
archive. It builds in an isolated temporary directory with `--release
--locked --target <rustc host>` and always enables the package builder's
[ELF and native dependency validation](../packaging/debian/README.md#artifact-validation).
Source links are rejected during extraction. No cross-compilation or
`--no-shlibdeps` escape hatch is provided.

Cargo can download locked dependencies, so arrange registry access/cache before
an offline build. An independent release build needs enough free temporary
space for its own target directory; it does not reuse the checkout's target
cache. The temporary build is placed beside the requested output and removed
on ordinary success or failure. A machine crash can leave a
`.maki-candidate-*` temporary directory for manual inspection and cleanup.

## Prepare and inspect

From the repository root, choose a new output directory. The candidate package
version is `0.1.0~rc+git<12-character-commit>` while the workspace version is
`0.1.0`; Debian orders that candidate below the final `0.1.0` release.
The following Bash commands keep the long build in the background with a
private log and preserve its PID and exit status:

```bash
umask 077
mkdir -p "$HOME/logs"
chmod 700 "$HOME/logs"
candidate_output="$HOME/maki-candidates/$(git rev-parse --short=12 HEAD)-$(dpkg --print-architecture)"
candidate_log="$(mktemp "$HOME/logs/maki-candidate.XXXXXX.log")"
candidate_status="${candidate_log%.log}.status"
(
  python3 -B scripts/prepare_release.py --output "$candidate_output"
  candidate_rc=$?
  printf '%s\n' "$candidate_rc" > "$candidate_status"
  exit "$candidate_rc"
) > "$candidate_log" 2>&1 < /dev/null &
candidate_pid=$!
printf 'PID=%s\nlog=%s\nstatus=%s\n' "$candidate_pid" "$candidate_log" "$candidate_status"
wait "$candidate_pid"
cat "$candidate_status"
tail -n 40 "$candidate_log"       # inspect only after the process exits
```

A successful directory contains:

| File | Purpose |
|---|---|
| `maki_<candidate-version>_<architecture>.deb` | Runtime package with scanned native dependencies |
| `maki-<candidate-version>-source.tar.gz` | Git archive of the exact committed source, including `Cargo.lock` |
| `manifest.json` | Commit/tree IDs, source epoch, distro/version, architecture, Rust target, tool versions, build command, compiler environment overrides, package dependencies and artifact hashes |
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
configuration. The recorded environment overrides are diagnostic metadata;
they are not a hermetic-build attestation. Review those overrides before
sharing the manifest. Checksums establish bundle consistency, not publisher
authenticity; a public release additionally needs the chosen signing or
attestation policy.

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

## Maintainer checks

```bash
python3 -B -m unittest scripts.test_release_preparation scripts.test_debian_package -v
python3 -B scripts/check_docs_links.py
```

The preparation contract uses a temporary Git repository, small native C ELF
fixtures, a simulated Cargo build and the real Debian package/dependency tools.
It checks committed-source provenance, checksums, deterministic packaging,
dirty-source refusal, output preservation, source-link refusal and failure
cleanup without rebuilding the Rust workspace. The Linux PR job runs it;
successful contract tests are not a full candidate-build or installation result.
