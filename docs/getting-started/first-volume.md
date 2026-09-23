# Provisioning the first volume

`maki-attach attach` mounts an *existing* XFS filesystem on an *existing*
LVM logical volume. A freshly created Maki volume exports an empty block
device, so the first attachment needs a one-time bootstrap that creates the
physical volume, volume group, logical volume and filesystem, then records
their identities in the root-owned attach configuration.

This page is that bootstrap. It is the manual procedure the qualification
runbook (`scripts/privileged-linux-validation.sh`) performs; a dedicated
`maki-attach provision` command does not exist yet. The
[quick start](quickstart.md) embeds these steps in a complete first run.

Prerequisites: the package is [installed](installation-debian.md), the
volume configuration exists at `/etc/maki/volumes/<volume>.toml`, its
credential is in place, and `maki volume create` has already run. Nothing
below touches an existing attachment; pick a volume name that is not in use.

Replace `demo` with your volume name throughout. Run as root.

## 1. Start the data plane alone

The bootstrap needs the export online without the attach helper, so start the
daemon unit directly (start, do not enable):

```bash
systemctl start maki@demo.service
systemctl is-active maki@demo.service      # active: recovery, key check and control socket are done
maki status /etc/maki/volumes/demo.toml    # state: ready
```

The first start also binds the configured key to the volume through the key
canary. Make sure this is the intended production key: a wrong key on an
empty volume means deleting and recreating the volume, not re-binding it
([key binding](../operations.md#key-binding-at-first-attach)).

## 2. Connect a disposable NBD device

Choose a free device. The helper later allocates the lowest free one itself,
so any free device works here.

```bash
dev=/dev/nbd0
[ "$(blockdev --getsize64 $dev)" = 0 ] || echo "$dev is in use; pick another"
nbd-client -unix /run/maki/demo/nbd.sock $dev -b 4096
blockdev --getsize64 $dev        # equals volume.max_virtual_size
```

`-b 4096` must match `device_block_size` in both the volume and the attach
configuration.

## 3. Create PV, VG, LV and XFS

Use the VG and LV names the attach configuration will use. The packaged
defaults are `vg_maki_<volume>` and `data`.

```bash
vg=vg_maki_demo
lv=data
pvcreate --yes $dev
vgcreate $vg $dev
lvcreate --yes -L 6G -n $lv $vg          # leave VG free space if you plan to `maki-attach grow`
mkfs.xfs -f /dev/$vg/$lv
```

Size the LV below the exported device size. `maki-attach grow` later extends
the LV within the VG and grows XFS; the exported size itself is fixed at
`maki volume create`.

Do not mount the filesystem here. The helper mounts it and writes the
`.maki-sentinel` file on the first attach.

## 4. Record the identities

The production profile pins the filesystem UUID and the complete LVM
identity. Collect them while the layout is still active:

```bash
pv_uuid=$(pvs --readonly --noheadings -o pv_uuid $dev | tr -d ' ')
vg_uuid=$(vgs --readonly --noheadings -o vg_uuid $vg | tr -d ' ')
lv_uuid=$(lvs --readonly --noheadings -o lv_uuid $vg/$lv | tr -d ' ')
fs_uuid=$(blkid --probe --cache-file /dev/null --match-tag UUID --output value /dev/$vg/$lv)
volume_uuid=$(maki volume inspect /etc/maki/volumes/demo.toml | awk '/^uuid:/ {print $2}')
printf 'volume %s\nfs %s\npv %s\nvg %s\nlv %s\n' "$volume_uuid" "$fs_uuid" "$pv_uuid" "$vg_uuid" "$lv_uuid"
```

LVM UUIDs have the form `xxxxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxxxx`; the
filesystem and volume UUIDs are RFC 4122 UUIDs. If any value looks different,
stop and investigate before writing the configuration.

## 5. Release the bootstrap layout

The helper must find the device unused:

```bash
vgchange -an $vg
nbd-client -d $dev
systemctl stop maki@demo.service
```

Stopping the daemon here is optional but keeps the next step identical to a
normal boot: the lifecycle target starts it again.

## 6. Write the attach configuration

`/etc/maki/attach/demo.toml`, owner root, mode `0600`
(template: [`packaging/examples/attach.toml`](../../packaging/examples/attach.toml)):

```toml
volume_uuid = "<volume_uuid>"
device_block_size = 4096

# Defaults shown; change them only if step 3 used other names.
vg_name = "vg_maki_demo"
lv_name = "data"
mountpoint = "/srv/demo"

fs_uuid = "<fs_uuid>"

# First attach only: create <mountpoint>/.maki-sentinel on the empty filesystem.
init_sentinel = true

[lvm_identity]
pv_uuids = ["<pv_uuid>"]
vg_uuid = "<vg_uuid>"
lv_uuid = "<lv_uuid>"
```

```bash
install -d -m 0700 -o root -g root /etc/maki/attach
install -m 0600 -o root -g root demo-attach.toml /etc/maki/attach/demo.toml
install -d /srv/demo
maki-attach attach --volume demo --plan     # review the plan; nothing is executed
```

Omitting `fs_uuid` or `[lvm_identity]` is accepted for compatibility but is
outside the production profile: without them the helper cannot authenticate
the discovered layout against what you created.

## 7. First attach and sentinel

```bash
systemctl start maki-workload@demo.target
findmnt /srv/demo
cat /srv/demo/.maki-sentinel          # the volume UUID
maki-attach verify --volume demo      # read-only identity gate, exit 0
```

Now turn the one-shot sentinel creation off so a later attach on a wrong or
empty filesystem cannot plant a new sentinel:

```bash
sed -i 's/^init_sentinel = true/init_sentinel = false/' /etc/maki/attach/demo.toml
```

The volume is provisioned. Register a workload against the target as
described in [operations](../operations.md#privileged-helper), or continue
with the [quick start](quickstart.md) for a restart round trip.

## Recovering from a failed bootstrap

- `pvcreate` refuses a device with existing signatures: the device is not
  empty. Check that `$dev` is the NBD device you connected and that the
  volume is new, then use `wipefs -a $dev` only on a device you own.
- The attach plan fails validation: a UUID was copied with whitespace or from
  the wrong device. Re-run step 4.
- Attach reports an LVM identity mismatch: the pins do not match what LVM
  reports on the connected device. Never "fix" this by removing the pins;
  re-derive them with the layout activated and confirm the device.
- The helper refuses because the device already has a holder or partitions:
  release the bootstrap layout (step 5) and retry.
