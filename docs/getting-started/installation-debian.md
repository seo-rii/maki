# Installing Maki on Debian 12

This guide takes a clean Debian 12 (bookworm) host to an installed Maki
package with every dependency satisfied. It ends where the
[quick start](quickstart.md) begins. Debian 12 is the primary platform (see
the [support matrix](../deployment/support-matrix.md)); other distributions
need the same components but are not qualified.

Everything here runs as root unless stated otherwise. Use a disposable host
for a first installation.

## What Maki needs on the host

| Component | Requirement | Debian 12 status |
|---|---|---|
| `nbdkit` | Any recent release with API v2 (1.32.5 tested) | `apt install nbdkit` |
| `nbd-client` | **3.27.0 or later**, built with netlink support | Stock package is 3.24: **too old**, see below |
| Kernel NBD module | `nbd` with the sysfs backend identifier (Linux 6.1 tested) | Included |
| LVM2 | `fullreport`, `--devices` and UUID-scoped activation (2.03.16 tested) | `apt install lvm2` |
| XFS tools | `mkfs.xfs`, `xfs_growfs` (6.1.0 tested) | `apt install xfsprogs` |
| systemd | 249 or later for `OnSuccess=` in the recovery unit | 252 |
| util-linux | `blkid`, `blockdev`, `findmnt` | Included |

The Debian package declares these dependencies:

```text
Depends: nbd-client (>= 1:3.27.0), nbdkit, lvm2, xfsprogs, util-linux, systemd
```

so `apt install ./maki_*.deb` refuses to install until a suitable
`nbd-client` is present. Replacing the binary under `/usr/sbin` by hand does
not satisfy the dependency and is not a supported configuration.

## nbd-client 3.27 or later

Trusted attachment identity relies on the kernel backend identifier that
`nbd-client` passes over netlink starting with
[NBD 3.27.0](https://github.com/NetworkBlockDevice/nbd/releases/tag/nbd-3.27.0).
Check what your host offers:

```bash
apt-cache policy nbd-client | head -n 5
nbd-client -h 2>&1 | grep -o 'version [0-9.]*'
```

If the candidate version is `1:3.27.0` or later, install it with `apt` and
skip to [Install the Maki package](#install-the-maki-package).

On Debian 12 the candidate is `1:3.24-*`. The qualification campaigns used
`nbd-client` 3.27.1 built from upstream commit
`f96f7fca3b37f4254c26c95f5c6c9dae70e030a1` and installed as the versioned
Debian package `1:3.27.1-1`. The repository does not ship that package, and
the exact recipe used during qualification is not preserved here; the
standard Debian backport workflow below produces an equivalent versioned
package. Review it before use and keep the resulting `.deb` with your
deployment artifacts so every host installs the same build.

```bash
# 1. Build dependencies of the existing Debian source package, plus the
#    autoconf archive the upstream build needs. Enable `deb-src` first:
#    uncomment the deb-src lines in /etc/apt/sources.list, or add
#    "Types: deb deb-src" to the .sources file if the host uses deb822.
apt update
apt install -y build-essential devscripts autoconf-archive
apt build-dep -y nbd-client

# 2. Fetch the Debian packaging and the upstream release tarball.
mkdir -p /usr/local/src/nbd && cd /usr/local/src/nbd
apt source nbd-client
curl -fsSLO https://github.com/NetworkBlockDevice/nbd/releases/download/nbd-3.27.1/nbd-3.27.1.tar.xz
sha256sum nbd-3.27.1.tar.xz      # compare with the upstream release page

# 3. Rebase the Debian packaging onto the new upstream version.
cd nbd-3.24*/
uupdate --upstream-version 3.27.1 ../nbd-3.27.1.tar.xz
cd ../nbd-3.27.1

# 4. Build unsigned binary packages and install the client.
dpkg-buildpackage -us -uc -b
apt install -y ../nbd-client_3.27.1-*_amd64.deb   # the epoch is not part of the file name
```

Verify the result before continuing:

```bash
dpkg -s nbd-client | grep '^Version'         # 1:3.27.1-… or later
nbd-client -h 2>&1 | grep -o 'version [0-9.]*'
```

`uupdate` may report packaging patches that no longer apply; drop patches
that upstream 3.27 already contains and re-run the build. If the
`libnl-genl-3` development package is missing, netlink support is compiled
out and `maki-attach` will fail closed at attach time, so keep
`apt build-dep` in step 1.

Pin the package so an ordinary `apt upgrade` does not replace it with the
older stock version:

```bash
apt-mark hold nbd-client
```

## Build the Maki package

No prebuilt packages are published yet. Build the release binaries and the
package on a build host with the current stable Rust toolchain (CI uses
stable), then copy the `.deb` to the target:

```bash
git clone https://github.com/seo-rii/maki.git && cd maki
apt install -y python3 dpkg-dev
cargo build --release --locked -p maki -p maki-attach -p maki-check -p maki-nbdkit
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
python3 packaging/debian/build-deb.py \
  --release-dir target/release \
  --version 0.1.0+git$(git rev-parse --short=12 HEAD) \
  --architecture "$(dpkg --print-architecture)" \
  --output ../maki.deb
```

[`packaging/debian/README.md`](../../packaging/debian/README.md) describes what
the package contains. It deliberately owns nothing below `/etc/maki`, does not
enable a volume, and never starts or restarts a service during install or
upgrade.

## Install the Maki package

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
| `/etc/maki/volumes/` | `root:maki 0750` | Data-plane volume configurations (`<volume>.toml`) |
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

(`maki-attach@demo.service` reports a missing `/etc/maki/attach/demo.toml`
assertion until a volume exists; that is expected.)

Grant an administrator account access to control sockets by adding it to the
`maki-admin` group. Root does not need it.

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
