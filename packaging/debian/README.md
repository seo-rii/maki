# Debian package build

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

The package requires `nbd-client` 3.27.0 or later because trusted attachment
identity uses its netlink identifier. A target distribution must supply that
version as a package or a separately reviewed backport. Replacing the binary
outside the package database does not satisfy this dependency.

Run the package contract tests with:

```bash
python3 -B -m unittest scripts.test_debian_package -v
```
