# Debian package build

For a reviewable candidate with source provenance, host metadata and checksums,
use [the release preparation command](../../docs/releasing.md). It builds from
committed source and always retains the native dependency scan described below.

From a clean tracked checkout with complete Git history, obtain the candidate
version, build the release binaries, then package that immutable artifact
directory:

```bash
set -euo pipefail
maki_version="$(python3 -B scripts/prepare_release.py --print-version)"
cargo build --release --locked -p maki -p maki-attach -p maki-check -p maki-nbdkit
SOURCE_DATE_EPOCH="$(git show --no-show-signature -s --format=%ct HEAD)" \
python3 packaging/debian/build-deb.py \
  --release-dir target/release \
  --version "$maki_version" \
  --architecture "$(dpkg --print-architecture)" \
  --output ../maki.deb
```

The version command needs Python 3.11 or newer and Git. It shares the bundle
builder's [version policy](../../docs/releasing.md#candidate-version-ordering):
`<workspace>~rc+rev<ancestor-count>.git<commit>` increases along source ancestry
and sorts below the final workspace version. Shallow checkouts must fetch their
complete history before building. Existing packages made with the old
`<workspace>+git<commit>` recipe require an
[explicitly reviewed one-time downgrade migration](../../docs/releasing.md#migrating-legacy-source-build-packages).

The package installs the daemon, helper, checker, plugin, service templates,
sysusers/tmpfiles rules, examples and a plain UTF-8 copyright notice at
`/usr/share/doc/maki/copyright`. When changing dependencies, release crate
features or supported targets, run `python3 packaging/debian/update-copyright.py`
and review the updated notices alongside the dependency changes. This
maintenance step uses Cargo; assembling the package uses the checked-in notice.
Review additional notices from toolchain components or custom linked inputs
for the actual release as described in [the release handoff](../../docs/releasing.md#qualification-and-publication-handoff).
The package installs section 8 manual pages for all three commands.
The package version and upstream release notes are available under
`/usr/share/doc/maki` in `changelog.Debian.gz` and `NEWS.gz`.

The package deliberately owns no file below
`/etc/maki`, does not enable a volume, and does not start or restart a service
during install or upgrade. Stop and detach the workload with the old package,
install the new package, update root-controlled configuration if required, and
start the lifecycle target explicitly as described in
[the runtime-layout upgrade procedure](../../docs/operations.md#upgrading-the-runtime-layout).

The package requires `nbd-client` 3.27.0 or later ([how to obtain it on
Debian 12](../../docs/getting-started/installation-debian.md#nbd-client-327-or-later))
because trusted attachment
identity uses its netlink identifier. A target distribution must supply that
version as a package or a separately reviewed backport. Replacing the binary
outside the package database does not satisfy this dependency.

Run the package contract tests with:

```bash
python3 -B -m unittest scripts.test_debian_package -v
```

## Artifact validation

The builder reads the ELF header of every release file and refuses to
package it unless its machine, class and byte order match the requested
`--architecture` (`amd64`, `arm64`, `i386`, `armhf`, `armel`, `ppc64el`,
`s390x`, `riscv64`, `mips64el`, `loong64`), the plugin is a shared object
and the binaries are executables. A wrong artifact used to produce a
"valid" package for the wrong CPU (R4-007).

Every file must carry the generic System V or GNU/Linux ELF OS ABI. A FreeBSD
executable can otherwise have the same CPU, word size, and byte order as Linux.

For `armel` and `armhf`, the builder also requires EABI version 5 and checks
the ARM floating-point procedure-call flags in every artifact. `armhf`
requires the hard-float flag; `armel` accepts the soft-float flag or the
implicit base standard when neither flag is set. Conflicting flags are
rejected. These meanings follow the
[AAELF32 header contract](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#elf-header).

For Debian `riscv64` and `loong64`, all artifacts must declare the LP64D (double-float)
calling convention in their ELF flags.

For Debian `ppc64el`, a PowerPC64 ABI marker must be ELFv2 or unspecified
(ABI-neutral). The builder rejects ELFv1 and the reserved ABI value.

For `mips64el`, the builder reads the version-zero MIPS ABI flags program
header. It accepts the double-precision hardware calling convention and
ABI-independent code. Missing flags or incompatible conventions fail validation.

Both shared libraries and PIE executables use ELF type `ET_DYN`. For the
plugin, the builder also rejects a `PT_INTERP` program header or the
`DF_1_PIE` dynamic flag, including static PIE without an interpreter. These
checks use program headers and work without section headers; they do not
load or execute the artifact. PIE remains allowed for the CLI binaries.
This checks artifact kind, not the plugin API or runtime compatibility.

For dynamically linked programs, the default native dependency scan also
checks the actual `PT_INTERP` path against the target architecture's installed
Debian glibc or musl package and adds its owner to `Depends`. A private loader
path can work on a build host and still prevent the packaged executable from
starting elsewhere. Standard merged-`/usr` aliases are recognized. Static
executables, including static PIE, have no interpreter dependency.

The builder then computes the native library dependencies of the binaries
with `dpkg-shlibdeps` (package `dpkg-dev`) and appends them to `Depends`, for
example `libc6 (>= 2.39), libgcc-s1 (>= 4.2)`. The scan is on by default and
fails closed: the build is refused rather than guessing when `dpkg-shlibdeps`
is missing or cannot analyse an artifact. `--no-shlibdeps` skips it with a
warning and keeps only the static `Depends`; it exists for the contract tests'
header-only ELF stubs and must not be used for a package that will be
installed.

## Removal and upgrade behaviour

`prerm` refuses `remove` while any volume is attached: a trusted attachment
record under `/run/maki-attach/`, or an active `maki@`, `maki-attach@`,
`maki-recover@` or `maki-workload@` unit (R4-003, R5-015). A failed `systemctl` query also refuses the removal: it proves nothing about the units. The helper this package installs is what the
lifecycle needs to detach cleanly, so removing it under a live attachment
would strand the operator. Stop workloads, then deactivate each volume's
`maki-workload@<volume>.target` lifecycle target. The dependency ordering
unmounts/detaches while the daemon still accepts I/O, then daemon shutdown
performs the final drain/checkpoint. Wait for all units to become inactive,
then remove the package. Do not explicitly drain before unmount: XFS may
still need writeback or metadata I/O after workload processes have stopped.

Upgrades are not blocked and no maintainer script starts, stops or restarts
a service. Detaching before an upgrade remains the operator's step in the
[runtime-layout upgrade procedure](../../docs/operations.md#upgrading-the-runtime-layout).
