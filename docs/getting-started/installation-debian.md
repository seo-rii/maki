# Installing Maki on Debian 12

This guide takes a clean Debian 12 (bookworm) host to an installed Maki
package with every dependency satisfied. It ends where the
[quick start](quickstart.md) begins. Debian 12 is the primary platform (see
the [support matrix](../deployment/support-matrix.md)); other distributions
need the same components but are not qualified. On every change CI runs the
[install steps](#install-the-maki-package), the quick start and its
first-volume bootstrap as written in a booted Debian 12 cloud image, a KVM
guest on a GitHub runner VM, after refreshing its package lists
([testing](../testing.md#automated-ci)).

Everything here runs as root unless stated otherwise. Use a disposable host
for a first installation.

## What Maki needs on the host

| Component | Requirement | Debian 12 status |
|---|---|---|
| `nbdkit` | Any recent release with API v2 and `NBD_OPT_GO` (1.32.5 tested) | `apt install nbdkit` |
| kmod | `modprobe` to load the NBD module | `apt install kmod` |
| Kernel NBD module | `nbd` with its netlink interface and the sysfs backend identifier (Linux 6.1 tested) | Included |
| LVM2 | `fullreport`, `--devices` and UUID-scoped activation (2.03.16 tested) | `apt install lvm2` |
| XFS tools | `mkfs.xfs`, `xfs_growfs` (6.1.0 tested) | `apt install xfsprogs` |
| systemd | 249 or later for `OnSuccess=` in the recovery unit | 252 |
| util-linux | `blkid`, `blockdev`, `findmnt` | Included |

The Debian package declares these dependencies, followed by the native
library packages that `dpkg-shlibdeps` finds in the binaries at build time
(such as `libc6`):

```text
Depends: nbdkit, lvm2, xfsprogs, util-linux, systemd (>= 249), kmod
```

No NBD client package is needed: `maki-attach` negotiates with the volume
daemon's socket and connects and disconnects the kernel device over netlink
itself, setting the attachment's identity as the device's backend
identifier.

<a id="nbd-client-327-or-later"></a>
A source-built `nbd-client` that a host installed for an earlier Maki release
is no longer used and may be removed, and attachments it connected stay
detachable, because the helper checks the same kernel backend identifier
(`/sys/block/nbdN/backend`) that `nbd-client -identifier` set and disconnects
through the same netlink interface.

## Build the Maki package

Release candidates are published only as unsigned GitHub pre-releases
([release workflow](../releasing.md#publishing-a-pre-release)); to install one,
check it against its `SHA256SUMS` and continue with
[Install the Maki package](#install-the-maki-package). Otherwise build the release binaries and the
package on a native Debian 12 build host with Rust **1.94.0**, the pinned CI
baseline (a separate job also checks latest stable), then copy the `.deb` to
the target. For a candidate bundle that also records the exact committed
source, tool versions and checksums, follow [release preparation](../releasing.md).

```bash
set -euo pipefail
git clone https://github.com/seo-rii/maki.git
cd maki
# Select and record the immutable revision being qualified before building.
git rev-parse HEAD
rustup toolchain install 1.94.0 --profile minimal
apt install -y python3 dpkg-dev build-essential
maki_version="$(python3 -B scripts/prepare_release.py --print-version)"
maki_target_dir="$(cargo +1.94.0 metadata --format-version 1 --no-deps |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
maki_host="$(rustc +1.94.0 -vV | sed -n 's/^host: //p')"
cargo +1.94.0 build --release --locked --target "$maki_host" \
  -p maki -p maki-attach -p maki-check -p maki-nbdkit
SOURCE_DATE_EPOCH="$(git --no-replace-objects show --no-show-signature -s --format=%ct HEAD)" \
python3 packaging/debian/build-deb.py \
  --release-dir "$maki_target_dir/$maki_host/release" \
  --version "$maki_version" \
  --architecture "$(dpkg --print-architecture)" \
  --output ../maki.deb
```

The builder verifies that every artifact is an ELF image for the requested
architecture and records the binaries' native library dependencies in
`Depends` with `dpkg-shlibdeps` (which is why `dpkg-dev` is required).
The version command requires a clean tracked checkout and complete Git history.
It uses the same [candidate version policy](../releasing.md#candidate-version-ordering)
as release bundles: descendant commits increase in version, and candidates sort
below their final workspace version. Fetch missing history with
`git fetch --unshallow` if the checkout is shallow.

[`packaging/debian/README.md`](../../packaging/debian/README.md) describes what
the package contains. It deliberately owns nothing below `/etc/maki`, does not
enable a volume, and never starts or restarts a service during install or
upgrade.

## Install the Maki package

If Maki was installed from an older `0.1.0+git<commit>` source-build recipe,
first follow the [one-time migration guidance](../releasing.md#migrating-legacy-source-build-packages).
Those legacy versions sort above the new candidates and final `0.1.0`;
the normal command below intentionally refuses an unattended downgrade.

```bash
apt install -y ./maki.deb
systemd-sysusers
systemd-tmpfiles --create
```

This installs `maki`, `maki-attach`, `maki-check`, the nbdkit plugin at
`/usr/lib/maki/maki-nbdkit.so`, the systemd templates, the `maki` user with the
`maki-admin` group, and the runtime directories:

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

`verify` checks the unit files and the programs they run; it does not evaluate
`Assert*=` settings, so it reports nothing about the
`/etc/maki/attach/demo.toml` that `maki-attach@demo.service` asserts. That
file exists only once [provisioning](first-volume.md) writes it, and until then
the unit cannot start; that is expected.
`systemd-analyze condition --unit=maki-attach@demo.service` evaluates the
assertion without starting anything: it prints `Asserts failed.` and exits 1
while the file is missing.

Grant an administrator account access to control sockets by adding it to the
`maki-admin` group. Root does not need it. The volume configuration is
readable only by root and group `maki`, so a `maki-admin` member names the
socket directly: `maki status --socket /run/maki-control/<volume>/control.sock`.
Keep it that way: Maki refuses a volume configuration its group or others can
write, one owned by a user other than root or the loading process's user, a
symlink and a file with a second hard link
([configuration file](../configuration.md#configuration-file)).
Do not add administrators to group `maki` instead: it also opens the NBD
sockets under `/run/maki`.

## Next steps

- [Quick start](quickstart.md): create a key, a volume and a first
  filesystem, attach it, and survive a restart.
- [Provisioning the first volume](first-volume.md): the LVM and XFS bootstrap
  in detail.
- [Operations](../operations.md): the full lifecycle reference.

## Upgrading

Stop workloads and detach every volume with the *old* helper before replacing
the package, then follow
[upgrading the runtime layout](../operations.md#upgrading-the-runtime-layout).
A package upgrade on a stopped host was qualified once on Debian 12
([report](../qualification/package-topology-migration-validation-2026-09-19.md)).
