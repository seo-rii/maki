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
install -d -m 0700 -o root -g root /etc/maki/secrets
head -c 32 /dev/urandom > /etc/maki/secrets/demo.token
chmod 0400 /etc/maki/secrets/demo.token
```

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

`inspect` prints the volume UUID you will pin in step 5 and the format-file
sizes at full allocation.

## 4. Provision LVM and XFS on the export

This is the one-time bootstrap from [provisioning the first volume](first-volume.md),
condensed:

```bash
systemctl start maki@demo.service           # data plane only; the key is bound on this first start
dev=/dev/nbd0
nbd-client -unix /run/maki/demo/nbd.sock $dev -b 4096
[ "$(blockdev --getsize64 $dev)" = 8589934592 ] || echo "unexpected device size"

vg=vg_maki_demo; lv=data
pvcreate --yes $dev
vgcreate $vg $dev
lvcreate --yes -L 6G -n $lv $vg
mkfs.xfs -f /dev/$vg/$lv

pv_uuid=$(pvs --readonly --noheadings -o pv_uuid $dev | tr -d ' ')
vg_uuid=$(vgs --readonly --noheadings -o vg_uuid $vg | tr -d ' ')
lv_uuid=$(lvs --readonly --noheadings -o lv_uuid $vg/$lv | tr -d ' ')
fs_uuid=$(blkid --probe --cache-file /dev/null --match-tag UUID --output value /dev/$vg/$lv)
volume_uuid=$(maki volume inspect /etc/maki/volumes/demo.toml | awk '/^uuid:/ {print $2}')

vgchange -an $vg
nbd-client -d $dev
systemctl stop maki@demo.service
```

## 5. Write the attach configuration

```bash
install -d -m 0700 -o root -g root /etc/maki/attach /srv/demo
cat > /etc/maki/attach/demo.toml <<EOF
volume_uuid = "$volume_uuid"
device_block_size = 4096
vg_name = "$vg"
lv_name = "$lv"
mountpoint = "/srv/demo"
fs_uuid = "$fs_uuid"
init_sentinel = true

[lvm_identity]
pv_uuids = ["$pv_uuid"]
vg_uuid = "$vg_uuid"
lv_uuid = "$lv_uuid"
EOF
chmod 0600 /etc/maki/attach/demo.toml
maki-attach attach --volume demo --plan
```

The plan lists every command the helper would run. Nothing has executed yet.

## 6. Start the lifecycle and write data

```bash
systemctl start maki-workload@demo.target
systemctl is-active maki@demo.service maki-attach@demo.service
findmnt /srv/demo
cat /srv/demo/.maki-sentinel                 # equals $volume_uuid
sed -i 's/^init_sentinel = true/init_sentinel = false/' /etc/maki/attach/demo.toml

echo "hello from maki $(date -u +%FT%TZ)" > /srv/demo/hello.txt
sync
maki-attach verify --volume demo && echo "identity gate ok"
maki status /etc/maki/volumes/demo.toml
```

`verify` is the read-only gate a real workload runs in `ExecStartPre=`
before every start. `status` should report `state: ready`.

## 7. Planned stop with a durability acknowledgement

`maki drain` closes I/O admission, flushes and checkpoints, and returns the
checkpoint sequence as an explicit acknowledgement that everything written so
far is durable. Run it after the workload has quiesced (here: after `sync`),
then stop the target and wait for every unit to become inactive before an
offline check:

```bash
maki drain /etc/maki/volumes/demo.toml
systemctl stop maki-workload@demo.target
while systemctl is-active --quiet maki-attach@demo.service || \
      systemctl is-active --quiet maki@demo.service; do sleep 1; done
findmnt /srv/demo || echo "unmounted"
maki check /etc/maki/volumes/demo.toml --deep
```

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
maki drain /etc/maki/volumes/demo.toml
systemctl disable --now maki-workload@demo.target
while systemctl is-active --quiet maki@demo.service; do sleep 1; done
rm -rf /var/lib/maki/demo /etc/maki/attach/demo.toml /etc/maki/volumes/demo.toml
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
