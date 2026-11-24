# Installing Maki on RHEL 9

This guide takes a RHEL 9 host, or one of its rebuilds (CentOS Stream 9,
Rocky Linux 9, AlmaLinux 9), to an installed Maki RPM, using packages from
the BaseOS and AppStream repositories only. It ends where the
[quick start](quickstart.md) begins.

Everything here runs as root unless stated otherwise. Use a disposable host.

## Status: not qualified

RHEL 9 is **not qualified** ([support matrix](../deployment/support-matrix.md)).
No kernel attachment and no external campaign has run on RHEL 9 or a rebuild.
What is checked, on every change, is the userspace: the CI `rhel9` job builds
the packaged binaries in a CentOS Stream 9 container, checks the nbdkit plugin
ABI against EL9's header, runs the helper, attach and plugin test suites
(whose native tests load Maki's plugin into EL9's nbdkit 1.38), and builds,
installs and removes the RPM ([testing](../testing.md#automated-ci)). That
container runs on the CI runner's Ubuntu kernel, so the following have never
run: RHEL's kernel and its `nbd` driver, SELinux in enforcing mode,
`maki-attach` attach, detach or grow, and any workload. Rocky Linux and
AlmaLinux were not tested; they rebuild RHEL, of which CentOS Stream 9 is the
upstream.

RHEL 8 is outside the design: its systemd 239 lacks the `OnSuccess=` that the
recovery unit needs.

## What Maki needs on the host

Versions are those of CentOS Stream 9 on 2026-11-24.

| Component | Requirement | RHEL 9 package (repository) | Version seen |
|---|---|---|---|
| nbdkit | API v2, as `/usr/sbin/nbdkit` | `nbdkit-server` (AppStream) | 1.38.5 |
| Kernel NBD module | `nbd` with the sysfs backend identifier | `kernel-modules-core` (BaseOS), installed with the kernel | 5.14.0-765 |
| kmod | `modprobe` to load the module | `kmod` (BaseOS) | 31 |
| LVM2 | `fullreport`, `--devices` and UUID-scoped activation | `lvm2` (BaseOS) | 2.03.33 |
| XFS tools | `mkfs.xfs`, `xfs_growfs` | `xfsprogs` (BaseOS) | 6.4.0 |
| systemd | 249 or later for `OnSuccess=` in the recovery unit | `systemd` (BaseOS) | 252 |
| util-linux | `blkid`, `blockdev`, `findmnt` | `util-linux` (BaseOS) | 2.37.4 |
| glibc | 2.34, the version the binaries are built against | `glibc` (BaseOS) | 2.34 |

The EL9 kernel's `nbd` driver sets the sysfs `backend` attribute from the
identifier given when a device is connected (checked in the CentOS Stream 9
kernel source). Maki does not use `nbd-client`, which RHEL 9 does not ship.

The RPM declares these dependencies; rpm adds the binaries' shared-library
requirements and the builder the owner of their ELF loader (`glibc`):

```text
Requires: nbdkit-server, lvm2, xfsprogs, util-linux, systemd >= 249, kmod
Conflicts: nbdkit-selinux
```

so `dnf install ./maki.rpm` installs whatever of them is missing from
BaseOS and AppStream. It requires `nbdkit-server`, not the `nbdkit`
metapackage, and conflicts with the SELinux module the metapackage installs,
which by the policy's rules stops systemd from starting nbdkit
([SELinux](#selinux)).

## Repositories

BaseOS and AppStream are enabled by default on RHEL 9 with a subscription,
and on CentOS Stream 9, Rocky Linux 9 and AlmaLinux 9. Nothing here needs EPEL.
Check with:

```bash
dnf repolist
```

The CodeReady Linux Builder repository (`crb` on the rebuilds,
`codeready-builder-for-rhel-9-$(arch)-rpms` on RHEL) holds `nbdkit-devel`,
which only the ABI test (`cargo test -p maki-nbdkit --test review_abi`) needs.
Neither building nor installing Maki needs it.

## Build the Maki package

No prebuilt packages are published. Build the release binaries and the RPM on
a RHEL 9 family build host, then copy the `.rpm` to the target. The binaries
link against the build host's glibc, and the RPM builder requires that a
package of the build host's RPM database owns their ELF loader, so do not
build the RPM on another distribution. For a candidate bundle that also
records the exact committed source, tool versions and checksums, follow
[release preparation](../releasing.md).

The pinned toolchain is Rust **1.94.0**, the CI baseline. AppStream's
`rust-toolset` (1.99.1 on CentOS Stream 9 on 2026-11-24) meets the minimum
versions the lockfile declares (the highest is 1.88), but no CI job builds
with it; use rustup, which BaseOS and AppStream do not package. Install it
from [rustup.rs](https://rustup.rs/), as the user who builds:

```bash
set -euo pipefail
dnf install -y gcc git-core python3 python3.11 rpm-build
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup-init.sh
sh rustup-init.sh -y --profile minimal --default-toolchain none
. "$HOME/.cargo/env"
rustup toolchain install 1.94.0 --profile minimal
```

Then build, as in the [Debian guide](installation-debian.md#build-the-maki-package):

```bash
set -euo pipefail
git clone https://github.com/seo-rii/maki.git
cd maki
# Select and record the immutable revision being qualified before building.
git rev-parse HEAD
maki_version="$(python3.11 -B scripts/prepare_release.py --print-version)"
maki_target_dir="$(cargo +1.94.0 metadata --format-version 1 --no-deps |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
maki_host="$(rustc +1.94.0 -vV | sed -n 's/^host: //p')"
cargo +1.94.0 build --release --locked --target "$maki_host" \
  -p maki -p maki-attach -p maki-check -p maki-nbdkit
SOURCE_DATE_EPOCH="$(git --no-replace-objects show --no-show-signature -s --format=%ct HEAD)" \
python3 packaging/rpm/build-rpm.py \
  --release-dir "$maki_target_dir/$maki_host/release" \
  --version "$maki_version" \
  --architecture "$(rpm --eval '%{_arch}')" \
  --output ../maki.rpm
```

The version command needs Python 3.11 or newer (RHEL 9's `python3` is 3.9;
`python3.11` is in AppStream), a clean tracked checkout and complete Git
history (`git fetch --unshallow` for a shallow clone). The RPM uses the same
[candidate version](../releasing.md#candidate-version-ordering) as the Debian
package, and rpm orders it the same way. The builder checks that every
artifact is an ELF image for the requested architecture (`x86_64`,
`aarch64`, `ppc64le` or `s390x`).
[`packaging/rpm/README.md`](../../packaging/rpm/README.md) describes what the
package contains and how it differs from the Debian package: the daemon unit
runs `/usr/sbin/nbdkit`, and the Apache-2.0 text is added under
`/usr/share/licenses/maki/`. It owns nothing below `/etc/maki`, does not
enable a volume, and never starts, stops or restarts a service.

## Install the Maki package

```bash
dnf install -y ./maki.rpm
rpm -q nbdkit-selinux   # expected: package nbdkit-selinux is not installed
```

The package's `%post` runs `systemd-sysusers` and `systemd-tmpfiles --create`
for Maki's rules, so the `maki` user, the `maki-admin` group and the runtime
directories exist once the command returns:

| Path | Owner and mode | Purpose |
|---|---|---|
| `/etc/maki/volumes/` | `root:maki 0750` | Data-plane volume configurations (`<volume>.toml`, each `root:maki 0640`) |
| `/etc/maki/attach/` | `root:root 0700` | Privileged attach configurations, never readable by the daemon |
| `/etc/maki/secrets/` | `root:root 0700` | Credentials loaded by systemd `LoadCredential=` |
| `/var/lib/maki/` | `root:maki 0750` | Backing directories, one `0700` subdirectory per volume owned by `maki` |
| `/run/maki/` | `root:maki 0750` | NBD sockets |
| `/run/maki-control/` | `root:maki-admin 0750` | Administrative control sockets |
| `/run/maki-attach/` | `root:root 0700` | Trusted attachment records |

Make sure the kernel module is available now and after reboot:

```bash
modprobe nbd
echo nbd > /etc/modules-load.d/maki.conf
```

Check the installed units once:

```bash
systemd-analyze verify maki@demo.service maki-attach@demo.service \
  maki-recover@demo.service maki-workload@demo.target
```

As on Debian, `verify` does not evaluate `Assert*=` settings, so it says
nothing about the `/etc/maki/attach/demo.toml` that `maki-attach@demo.service`
asserts; [provisioning](first-volume.md) writes that file.
`systemd-analyze condition --unit=maki-attach@demo.service` evaluates the
assertion without starting anything.

Grant administrators access to control sockets through the `maki-admin`
group, never the `maki` group, exactly as the
[Debian guide](installation-debian.md#install-the-maki-package) describes.

## The LVM devices file

RHEL 9's LVM2 enables its devices file by default (`use_devicesfile=1`).
Where `/etc/lvm/devices/system.devices` exists (the RHEL installer writes it),
LVM uses only the devices listed there, and `pvcreate` and `vgcreate` add the
PVs they create. Do not add `/dev/nbd*` to it (`lvmdevices --adddev`). Every
LVM command the helper runs passes `--devices` with the NBD device and
partitions it verified or recorded, which replaces the devices file for that
command, and the [provisioning](first-volume.md) commands do the same. Listed
in the file, a Maki device would also be seen by the host's own LVM commands
and autoactivation, outside the helper's identity checks. To inspect a volume
by hand, pass `--devices /dev/nbdN` as well, for example
`vgs --readonly --devices /dev/nbd0`.

With LVM 2.03.33 on a loop device (no activation) and a devices file present,
`pvcreate --devices` and `vgcreate --devices` left the file unchanged, `vgs`
without `--devices` did not find the new VG, and `vgs --devices` did.

## SELinux

Maki ships no SELinux policy module, and the targeted policy has none for it.
What follows is read from the CentOS Stream 9 targeted policy
(`selinux-policy-targeted` 38.1.87) with `sesearch` and `selabel_lookup`;
**nothing was run with SELinux enforcing.**

- The installed files take the policy's default labels: the binaries
  `bin_t`, the plugin `lib_t`, `/etc/maki` `etc_t`, `/var/lib/maki`
  `var_lib_t`, `/run/maki*` `var_run_t`, the units `systemd_unit_file_t`, and
  `/dev/nbd*` `fixed_disk_device_t`. rpm labels the files when it installs
  them; after copying a file by hand, run `restorecon -v` on it.
- systemd starts a `bin_t` program in `unconfined_service_t`
  (`type_transition init_t bin_t:process unconfined_service_t`), so the
  daemon (`maki@`, nbdkit with the plugin) and the helper (`maki-attach@`)
  both run unconfined. SELinux adds no confinement; the boundaries are the
  daemon unit's sandbox and unprivileged user and the helper's checks
  ([security boundaries](../architecture.md#security-boundaries)).
- The `nbdkit` metapackage requires `nbdkit-selinux` on any host with the
  targeted policy. That module labels `/usr/sbin/nbdkit` `nbdkit_exec_t` for
  libvirt (only `virtd_t` transitions to `nbdkit_t`), and the policy gives
  systemd's `init_t` neither a transition for that type nor permission to
  execute it, so in enforcing mode systemd would be refused when it starts
  `maki@` (this follows from the policy; it was not observed). The Maki RPM
  requires `nbdkit-server`, which does not install the module, and declares
  `Conflicts: nbdkit-selinux`: dnf refuses to install Maki where the module
  is installed, and refuses a later transaction that would add it (such as
  `dnf install nbdkit`, or a package that requires the metapackage), naming
  the conflict, rather than leaving `maki@` to fail at its next start, which
  may be the next boot. The cost: Maki cannot be installed beside the module,
  so neither a host that needs it for libvirt or virt-v2v nor one where
  SELinux is permissive or disabled and the module would be harmless can run
  Maki; both are outside what this guide covers. `dnf --allowerasing` would
  resolve the conflict by removing Maki, which its `%preun` refuses while a
  volume is attached. `ls -Z /usr/sbin/nbdkit` should show `bin_t`.

Check the mode and look for denials after starting a volume:

```bash
getenforce
ausearch -m AVC,USER_AVC -ts recent
ausearch -m AVC -c nbdkit
ausearch -m AVC -c maki-attach
```

`ausearch` is in the `audit` package. Report any denial that involves Maki's
files, processes or `/dev/nbd*` with the policy version
(`rpm -q selinux-policy-targeted`).

## Next steps

- [Quick start](quickstart.md): create a key, a volume and a first
  filesystem, attach it, and survive a restart. It is written for Debian 12;
  its commands are the same here once the package is installed.
- [Provisioning the first volume](first-volume.md): the LVM and XFS bootstrap
  in detail.
- [Operations](../operations.md): the full lifecycle reference.

## Upgrading and removal

Stop workloads and detach every volume with the *old* helper before
installing a newer package (`dnf install ./maki.rpm` with the newer file),
then follow
[upgrading the runtime layout](../operations.md#upgrading-the-runtime-layout).
No package script stops or restarts a service, and an upgrade is never
refused. `dnf remove maki` is refused while any volume is attached (an
attachment record under `/run/maki-attach/` or an active Maki unit): the
package's `%preun` fails with the stop procedure, and rpm keeps the package
installed.
