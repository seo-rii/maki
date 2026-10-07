# Debian package build

For a reviewable candidate with source provenance, host metadata and checksums,
use [the release preparation command](../../docs/releasing.md). It builds from
committed source and always retains the native dependency scan described below.

Build the release binaries first, then create the package from that immutable
artifact directory:

```bash
cargo build --release --locked -p maki -p maki-attach -p maki-check -p maki-nbdkit
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
python3 packaging/debian/build-deb.py \
  --release-dir target/release \
  --version 0.1.0+git$(git rev-parse --short=12 HEAD) \
  --architecture "$(dpkg --print-architecture)" \
  --output ../maki.deb
```

The package installs the daemon, helper, checker, plugin, service templates,
sysusers/tmpfiles rules, and examples. It deliberately owns no file below
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
would strand the operator. Drain each volume, deactivate its lifecycle
target, wait for the units to become inactive, then remove the package.

Upgrades are not blocked and no maintainer script starts, stops or restarts
a service. Detaching before an upgrade remains the operator's step in the
[runtime-layout upgrade procedure](../../docs/operations.md#upgrading-the-runtime-layout).
