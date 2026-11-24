# RPM package build (RHEL 9)

`build-rpm.py` packages prebuilt release artifacts for RHEL 9 and its
rebuilds (CentOS Stream 9, Rocky Linux 9, AlmaLinux 9) with `maki.spec`.
Nothing is compiled by `rpmbuild`. The
[RHEL 9 installation guide](../../docs/getting-started/installation-rhel.md)
gives the whole procedure; on a RHEL 9 build host, with the release binaries
built and the version selected as there:

```bash
set -euo pipefail
SOURCE_DATE_EPOCH="$(git --no-replace-objects show --no-show-signature -s --format=%ct HEAD)" \
python3 packaging/rpm/build-rpm.py \
  --release-dir "$maki_target_dir/$maki_host/release" \
  --version "$maki_version" \
  --architecture "$(rpm --eval '%{_arch}')" \
  --output ../maki.rpm
```

`--version` takes the same candidate version as the Debian package
(`<workspace>~rc+rev<count>.git<commit>`), which rpm orders the way dpkg
does: descendants sort higher and candidates sort below the final workspace
version. `--release` (default `1`) is the RPM release.

## What the package installs

The same files, owners and modes as the [Debian package](../debian/README.md),
at the same paths: the three binaries in `/usr/bin`, the plugin at
`/usr/lib/maki/maki-nbdkit.so`, the systemd units, sysusers and tmpfiles
rules, the examples, `NEWS.gz`, the manual pages and the notice at
`/usr/share/doc/maki/copyright`, everything owned by root. The test suite
builds both packages from the same artifacts and compares them file by file.
The differences are deliberate:

- `maki@.service` runs `/usr/sbin/nbdkit`, where RHEL 9's `nbdkit-server`
  installs it; Debian installs `/usr/bin/nbdkit`. The checked-in unit names
  the Debian path and the builder rewrites exactly that line, refusing a unit
  without exactly one such `ExecStart=`. A bare `ExecStart=nbdkit` would work
  on both, but systemd resolves a bare name through `/usr/local/sbin` and
  `/usr/local/bin` first, and whatever it finds there would receive the
  volume's crypto credential instead of the nbdkit the package requires.
- The RPM adds the Apache-2.0 text at `/usr/share/licenses/maki/LICENSE`:
  the notice points to Debian's `/usr/share/common-licenses`, which RHEL
  does not have. Both license files are `%license` files, so an installation
  without documentation (`--nodocs`, as in container images) keeps them;
  the manual pages, examples and `NEWS.gz` are documentation.
- There is no `changelog.Debian.gz`; the package's own entry is in the RPM
  header (`rpm -q --changelog maki`).

The package owns only its own directories. It owns no file below
`/etc/maki`, does not enable a volume, and does not start, stop or restart a
service during install, upgrade or removal.

## Dependencies

```text
Requires: nbdkit-server, lvm2, xfsprogs, util-linux, systemd >= 249, kmod
```

`nbdkit-server` provides `/usr/sbin/nbdkit`; the `nbdkit` metapackage would
add plugins and filters Maki does not use and, on a host with the targeted
SELinux policy, the `nbdkit-selinux` module, under which the policy lets
systemd neither execute nbdkit nor transition to its domain
([SELinux](../../docs/getting-started/installation-rhel.md#selinux)).
nbd-client is not required.

rpm adds the binaries' shared-library requirements itself (`libc.so.6`,
`libgcc_s.so.1`, `libm.so.6` with their symbol versions). Its generator reads
`DT_NEEDED` but not the ELF interpreter, so by default the builder also asks
the build host's RPM database which package owns each binary's `PT_INTERP`
loader and requires it (`glibc`), and refuses to build when no package owns
it: a private loader path would otherwise produce a package that installs and
cannot start. Build on the target distribution for that reason; on a host
without an RPM database the default build fails. `--no-autoreq` turns both
off with a warning and keeps only the static `Requires`; it exists for the
contract tests' header-only ELF stubs and must not be used for a package that
will be installed. The plugin is excluded from rpm's provides: it is loaded by
nbdkit, not linked by other packages.

## Artifact validation

The builder applies the Debian builder's ELF checks (machine, class, byte
order, OS ABI, executable versus shared object, PIE markers on the plugin) for
the RPM architectures RHEL 9 is built for: `x86_64`, `aarch64`, `ppc64le`
(ELFv2 or ABI-neutral) and `s390x`. Any other architecture is refused.

The release binaries are packaged byte for byte: the spec turns off
stripping, the debuginfo split, build-id links and the other post-install
processing that would change them.

## Scriptlets

`%post` runs `systemd-sysusers` and `systemd-tmpfiles --create` for Maki's
files and `systemctl daemon-reload` when systemd is running, like the Debian
`postinst`. `%postun` reloads systemd after an erase. `%preun` refuses an
erase while any volume is attached (an attachment record under
`/run/maki-attach/`, or an active `maki@`, `maki-attach@`, `maki-recover@` or
`maki-workload@` unit, or a failed `systemctl` query), with the same check and
message as the Debian `prerm`; rpm then keeps the package installed. An
upgrade is never blocked: detach with the old helper first, as the
[runtime-layout upgrade procedure](../../docs/operations.md#upgrading-the-runtime-layout)
describes.

## Builds and tests

The build is reproducible for a given `SOURCE_DATE_EPOCH` and rpm version:
the build time and every file time come from it and the build host name is
fixed. Run the contract tests with:

```bash
python3 -B -m unittest scripts.test_rpm_package -v
```

They need `rpm`, `rpmbuild`, `rpm2cpio` and `cpio`; on Debian and Ubuntu
`apt install rpm cpio` provides them, and Python 3.9 or newer. The comparison
with the Debian package also needs `dpkg-deb` and is skipped without it (on
RHEL), unless `MAKI_TEST_REQUIRE_DPKG_DEB=1`.
