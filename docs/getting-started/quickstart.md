# Quick start

One volume, local AES-256-GCM-SIV, the packaged systemd lifecycle, a file
written and read back across a full stop and start. Every command is meant
to be pasted in order on a disposable Debian 12 host as root.

Remote crypto providers, pinned NBD devices, database workloads and
production hardening are deliberately left out; the
[PostgreSQL deployment guide](../deployment/postgres.md) is the next step
after this page.

Before you start:

- Maki is [installed](installation-debian.md), including `nbd-client` 3.27+.
- `/srv/demo` and `/dev/nbd0` are unused. The host has at least 10 GiB free
  under `/var/lib/maki`.
- You have read the [status page](../status.md): nothing here is
  production-qualified.

## 1. Create the key

The packaged data-plane unit loads one credential named `crypto-token` from
`/etc/maki/secrets/<volume>.token`. For the local provider that file *is*
the 32-byte AES key (raw bytes or 64 hex characters).

```bash
bash <<'BASH'
set -euo pipefail
umask 077
install -d -m 0700 -o root -g root /etc/maki/secrets
python3 - <<'PY'
import os
import tempfile

target = "/etc/maki/secrets/demo.token"
directory = os.path.dirname(target)
directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    with tempfile.NamedTemporaryFile(dir=directory, prefix=".maki-key-") as key:
        os.fchmod(key.fileno(), 0o400)
        key.write(os.urandom(32))
        key.flush()
        os.fsync(key.fileno())
        # Atomic publication refuses every existing path, including symlinks.
        os.link(key.name, target, follow_symlinks=False)
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
BASH
```

Run the whole block and continue only if it succeeds. It publishes a complete
key with mode `0400` and refuses to replace an existing file or symlink, even
as root. If the name already exists, preserve it and inspect the existing
volume instead of deleting it to retry. A failure before publication removes
the temporary file; a failure after publication leaves the complete key in
place for inspection. Never regenerate that key to bypass an error.

Back this file up separately from the backing directory. Without it the
volume is unreadable; with it and the backing directory the volume is
recoverable on any host.

## 2. Write the volume configuration

`/etc/maki/volumes/demo.toml`, owner `root:maki`, mode `0640`:

```toml
config_schema_version = 1

[volume]
name = "demo"
max_virtual_size = "8GiB"       # size of the exported block device; fixed after create
device_block_size = 4096
crypto_unit_size = 4096
shard_logical_size = "1GiB"

[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
# The key arrives as the systemd credential `crypto-token`; never a literal.
key = { source = "credential", name = "crypto-token" }

[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384

[backing]
root = "/var/lib/maki/demo"
journal_segment_size = "64MiB"
journal_max_bytes = "512MiB"
checkpoint_reserve_bytes = "512MiB"
journal_emergency_reserve_bytes = "256MiB"

[nbd]
socket = "/run/maki/demo/nbd.sock"
device_block_size = 4096

[control]
socket = "/run/maki-control/demo/control.sock"
group = "maki-admin"
```

```bash
install -m 0640 -o root -g maki demo.toml /etc/maki/volumes/demo.toml
```

The [configuration reference](../configuration.md) explains every section.
The `[security]` defaults (locked secret buffers, no core dumps) apply
without being written; the production profile additionally sets
`require_secure_swap_policy = true`.

## 3. Create the volume

The backing tree must be owned by the daemon user, so create it as `maki`:

```bash
install -d -o maki -g maki -m 0700 /var/lib/maki/demo
sudo -u maki maki volume create /etc/maki/volumes/demo.toml
maki volume inspect /etc/maki/volumes/demo.toml
maki check /etc/maki/volumes/demo.toml
```

`inspect` prints the volume UUID the bootstrap will pin and the format-file
sizes at full allocation.

## 4. Provision LVM and XFS on the export

Follow [provisioning the first volume](first-volume.md#1-provision-and-record-the-layout)
with the `demo` defaults. Run its entire Bash block, then return here only if
it succeeds. It checks that the NBD device, VG/LV names and mountpoint are
unused, stops on every failed command or size mismatch, and checks the live
NBD and device-mapper identities immediately before creating XFS. It writes
`/etc/maki/attach/demo.toml` with the observed UUIDs and releases the bootstrap
layout.

If it fails, preserve and inspect the partial layout using that guide's
[recovery notes](first-volume.md#recovering-from-a-failed-bootstrap). Do not
continue at the formatting command or overwrite an existing filesystem.

## 5. Review the attach configuration

```bash
cat /etc/maki/attach/demo.toml
maki-attach attach --volume demo --plan
```

The plan lists every command the helper would run. Nothing has executed yet.

## 6. Start the lifecycle and write data

```bash
(
set -euo pipefail
systemctl start maki-workload@demo.target
systemctl is-active --quiet maki@demo.service
systemctl is-active --quiet maki-attach@demo.service
maki-attach verify --volume demo
findmnt /srv/demo
cat /srv/demo/.maki-sentinel                 # equals volume_uuid in the attach configuration
sed -i 's/^init_sentinel = true/init_sentinel = false/' /etc/maki/attach/demo.toml

echo "hello from maki $(date -u +%FT%TZ)" > /srv/demo/hello.txt
sync
maki status /etc/maki/volumes/demo.toml
)
```

`verify` is the read-only gate a real workload runs in `ExecStartPre=`
before every start. The subshell stops at the first failure, and the identity
gate runs before creating any workload data. `status` should report `state: ready`.

## 7. Planned stop with a durability acknowledgement

`maki drain` closes I/O admission, flushes and checkpoints, and returns the
checkpoint sequence as an explicit acknowledgement that everything written so
far is durable. First close every file on the demo mount, verify its identity,
and unmount while admission is still open: unmount may write filesystem data
or metadata even after `sync`. Only after unmount succeeds, drain, stop the
target, and wait for every unit to become inactive before an offline check.
For a normal stop without a separate acknowledgement, stop the target directly;
successful cleanup unmounts before requesting daemon shutdown and final drain.
If cleanup fails, the daemon stays running for the remaining mount; follow the
[failed-stop procedure](../operations.md#retry-a-failed-planned-stop).

```bash
# Succeeds once every named unit is inactive; fails at once if one failed
# (inspect it before continuing) or after WAIT_SECONDS (default 600).
wait_stopped() {
    local unit state deadline=$((SECONDS + ${WAIT_SECONDS:-600}))
    for unit in "$@"; do
        while state=$(systemctl show -P ActiveState "$unit"); [ "$state" != inactive ]; do
            if [ "$state" = failed ] || [ "$SECONDS" -ge "$deadline" ]; then
                echo "$unit is $state: preserve the host state and inspect it" >&2
                return 1
            fi
            sleep 1
        done
    done
}
maki-attach verify --volume demo &&
    umount -- /srv/demo &&
    maki drain /etc/maki/volumes/demo.toml &&
    systemctl stop maki-workload@demo.target &&
wait_stopped maki-attach@demo.service maki@demo.service &&
    { findmnt /srv/demo || echo "unmounted"; } &&
    maki check /etc/maki/volumes/demo.toml --deep
```

`systemctl is-active` is not a stop test: it also fails while a unit is still
`deactivating` or has `failed`, so `wait_stopped` polls for `inactive`.

## 8. Start again and read the data back

```bash
systemctl start maki-workload@demo.target
maki-attach verify --volume demo
cat /srv/demo/hello.txt
```

The same commands work after a reboot once the target is enabled:

```bash
systemctl enable maki-workload@demo.target
```

Do not enable `maki@demo.service` or `maki-attach@demo.service` directly;
the target owns their ordering and the recovery unit
([why](../operations.md#privileged-helper)).

## 9. Clean up

```bash
systemctl disable --now maki-workload@demo.target &&
wait_stopped maki-attach@demo.service maki@demo.service &&
    rm -rf /var/lib/maki/demo /etc/maki/attach/demo.toml /etc/maki/volumes/demo.toml &&
    shred -u /etc/maki/secrets/demo.token
```

## What you have and have not seen

You ran the real data plane, kernel NBD, LVM, XFS, the trusted attach
record, the identity gate and a checkpoint acknowledgement. You have not
exercised recovery after a crash, provider failure, or a database. Continue
with:

- [Operations](../operations.md): drain, recovery, control socket, growth.
- [PostgreSQL deployment guide](../deployment/postgres.md): the production
  profile with a registered workload.
- [Support matrix](../deployment/support-matrix.md): before changing any layer
  of the stack.
