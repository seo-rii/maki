# Provisioning the first volume

`maki-attach attach` mounts an *existing* XFS filesystem on an *existing*
LVM logical volume. A freshly created Maki volume exports an empty block
device, so the first attachment needs a one-time bootstrap that creates the
physical volume, volume group, logical volume and filesystem, then records
their identities in the root-owned attach configuration.

This page is that bootstrap. A dedicated `maki-attach provision` command does
not exist yet. The [quick start](quickstart.md) uses this same procedure.

Prerequisites: the package is [installed](installation-debian.md), the volume
configuration exists at `/etc/maki/volumes/demo.toml`, its credential is in
place, and `maki volume create` has already run. This example exports 8 GiB
with 4096-byte blocks and creates a 6 GiB LV. Edit the variables together if
your configuration differs. The socket must be the one in that volume's
configuration.

Use a disposable host as root. The NBD device, VG name, attach configuration
and mountpoint must be unused. Do not run other provisioning, LVM or NBD
commands concurrently. The script takes the helper's attach lock, but that
lock cannot coordinate unrelated administrator commands.

## 1. Provision and record the layout

Run this entire block as one Bash invocation. A failed command, unexpected
size or identity stops it before the next mutation. It does not automatically
clean up after an error: preserve the partially created layout and inspect
it before doing anything else. Do not continue at an arbitrary later line.

The first daemon start binds the configured key through the key canary. Make
sure it is the intended key: an empty volume bound to the wrong key must be
recreated ([key binding](../operations.md#key-binding-at-first-attach)).

```bash
bash <<'BASH'
set -euo pipefail
umask 077
volume=demo
dev=/dev/nbd0
expected_bytes=8589934592
block_size=4096
vg=vg_maki_demo
lv=data
lv_size=6G
mountpoint=/srv/demo
config=/etc/maki/volumes/demo.toml
socket=/run/maki/demo/nbd.sock
attach_config=/etc/maki/attach/demo.toml
nbd=${dev#/dev/}
lv_path=/dev/$vg/$lv

die() { echo "$*" >&2; exit 1; }
trap 'echo "Bootstrap stopped at line $LINENO; preserve the layout and inspect it before retrying." >&2' ERR

[[ $nbd =~ ^nbd[0-9]+$ ]] || die "Expected a kernel NBD device name"
[[ -b "$dev" ]] || die "NBD device is missing"
[[ ! -e "$attach_config" && ! -L "$attach_config" ]] || die "Attach configuration already exists"
[[ ! -e "$lv_path" && ! -L "$lv_path" ]] || die "LV path already exists"
[[ ! -e "$mountpoint" ]] || die "Use a new mountpoint"
# Coordinate with maki-attach; the packaged runtime directory is root-only.
[[ ! -L /run/maki-attach/attach.lock ]] || die "Unexpected lock symlink"
exec 9>>/run/maki-attach/attach.lock
flock -n 9

existing_vgs=$(vgs --readonly --noheadings -o vg_name | awk '{$1=$1};1')
while IFS= read -r name; do
    [[ $name != "$vg" ]] || die "VG already exists: $vg"
done <<< "$existing_vgs"
# Query failure must also stop: absence is not inferred from a failed command.
existing_lvs=$(lvs --readonly --noheadings -o vg_name,lv_name | awk '{print $1 "/" $2}')
while IFS= read -r name; do
    [[ $name != "$vg/$lv" ]] || die "LV already exists: $vg/$lv"
done <<< "$existing_lvs"
size=$(blockdev --getsize64 "$dev")
[[ $size == 0 && ! -e /sys/block/$nbd/pid ]] || die "$dev is in use"
if [[ -e /sys/block/$nbd/backend ]]; then
    previous_backend=$(cat "/sys/block/$nbd/backend")
    [[ -z $previous_backend ]] || die "$dev already has a backend"
fi
layout=$(lsblk -anr -o TYPE "$dev")
[[ $layout == disk ]] || die "$dev has partitions or holders"
mounts=$(lsblk -anr -o MOUNTPOINTS "$dev")
[[ -z $mounts ]] || die "$dev is mounted"

volume_uuid=$(maki volume inspect "$config" | awk '/^uuid:/ {print $2}')
[[ $volume_uuid =~ ^[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}$ ]] || die "Invalid volume UUID"
maki check "$config"
connection_id="maki-bootstrap-$(cat /proc/sys/kernel/random/uuid)"
systemctl start "maki@$volume.service"
systemctl is-active "maki@$volume.service"
# A background nbd-client must not inherit the helper's lock descriptor.
nbd-client -unix "$socket" "$nbd" -b "$block_size" -identifier "$connection_id" 9>&-

verify_backend() {
    local backend bytes
    backend=$(cat "/sys/block/$nbd/backend")
    [[ $backend == "$connection_id" ]] || die "NBD backend identity changed"
    bytes=$(blockdev --getsize64 "$dev")
    [[ $bytes == "$expected_bytes" ]] || die "Unexpected device size"
}
verify_backend
# Refuse existing signatures; neither PV nor filesystem creation uses force.
signatures=$(wipefs --no-act --noheadings --output TYPE "$dev")
[[ -z $signatures ]] || die "Export already has signatures"
pvcreate --devices "$dev" "$dev"
verify_backend
vgcreate --devices "$dev" "$vg" "$dev"
verify_backend
lvcreate --devices "$dev" --type linear -L "$lv_size" -n "$lv" "$vg"

pv_uuid=$(pvs --readonly --devices "$dev" --noheadings -o pv_uuid "$dev" | tr -d '[:space:]')
vg_uuid=$(vgs --readonly --devices "$dev" --noheadings -o vg_uuid "$vg" | tr -d '[:space:]')
lv_uuid=$(lvs --readonly --devices "$dev" --noheadings -o lv_uuid "$vg/$lv" | tr -d '[:space:]')
for identity in "$pv_uuid" "$vg_uuid" "$lv_uuid"; do
    [[ $identity =~ ^[[:alnum:]]{6}(-[[:alnum:]]{4}){5}-[[:alnum:]]{6}$ ]] || die "Invalid LVM UUID"
done
lv_device=$(readlink -e "$lv_path")
[[ -b "$lv_device" && ${lv_device##*/} == dm-* ]] || die "LV is not a device-mapper device"
dm=${lv_device##*/}
# Recheck the backend and the live mapping immediately before formatting.
verify_backend
dm_uuid=$(cat "/sys/class/block/$dm/dm/uuid")
[[ $dm_uuid == "LVM-${vg_uuid//-/}${lv_uuid//-/}" ]] || die "LV device identity mismatch"
slaves=$(ls -A "/sys/class/block/$dm/slaves")
[[ $slaves == "$nbd" ]] || die "LV does not map solely to the selected NBD device"
current_lv_device=$(readlink -e "$lv_path")
[[ $current_lv_device == "$lv_device" ]] || die "LV path changed"
mkfs.xfs "$lv_device"
fs_uuid=$(blkid --probe --cache-file /dev/null --match-tag UUID --output value "$lv_device")
[[ $fs_uuid =~ ^[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}$ ]] || die "Invalid filesystem UUID"

verify_backend
vgchange --devices "$dev" -an "$vg"
verify_backend
nbd-client -d "$nbd"
systemctl stop "maki@$volume.service"
install -d -m 0700 -o root -g root /etc/maki/attach "$mountpoint"
# noclobber prevents replacing a configuration created during this procedure.
set -C
cat > "$attach_config" <<EOF
volume_uuid = "$volume_uuid"
device_block_size = $block_size
vg_name = "$vg"
lv_name = "$lv"
mountpoint = "$mountpoint"
fs_uuid = "$fs_uuid"
init_sentinel = true

[lvm_identity]
pv_uuids = ["$pv_uuid"]
vg_uuid = "$vg_uuid"
lv_uuid = "$lv_uuid"
EOF
chmod 0600 "$attach_config"
printf 'Created %s; review it before starting the lifecycle.\n' "$attach_config"
BASH
```

`nbd-client` 3.27+ takes the kernel name (`nbd0`) with netlink, while block
and LVM tools take `/dev/nbd0`. Its unique `-identifier` must appear unchanged
in the kernel's `backend` attribute. A missing or unreadable attribute is a
failure. LVM queries and mutations after connection are restricted to that
one device. Before formatting, the device-mapper UUID must contain the newly
observed VG and LV UUIDs and its only backing device must be that NBD device.
These checks assume a trusted root administrator; they cannot prevent another
root process from replacing a mapping between a check and a command.

The LV is deliberately smaller than the exported device. `maki-attach grow`
later expands the LV within its VG and grows XFS; the export size is fixed at
`maki volume create`. Do not mount the new filesystem during bootstrap. The
helper mounts it and creates `.maki-sentinel` on the first attach.

## 2. Review the attach configuration

The script writes `/etc/maki/attach/demo.toml` as root with mode `0600`,
including the filesystem UUID and complete LVM identity. Compare it with the
[attach template](../../packaging/examples/attach.toml), then inspect the plan:

```bash
cat /etc/maki/attach/demo.toml
maki-attach attach --volume demo --plan
```

The plan is read-only. A failed bootstrap does not authorize continuing here.
Omitting identity pins is outside the production profile: the helper needs
them to authenticate the layout it discovers.

## 3. First attach and sentinel

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

- Do not re-run just `mkfs.xfs`, add `-f`, or erase signatures to get past a
  failed check. Inspect the NBD backend, LVM identities and any partial layout
  first. The script intentionally leaves resources in place on failure.
- A VG/LV name or attach configuration already exists: choose unused names
  for a new volume, or use the existing volume's verified attach procedure.
- The export contains signatures: it may already contain data. Confirm the
  configuration, socket and volume UUID before considering a separate,
  explicitly destructive reset.
- The attach plan fails validation: inspect the root-owned configuration and
  compare its UUIDs with the intended layout. Never remove pins to bypass a
  mismatch.
- The helper reports a holder or partitions after an interrupted bootstrap:
  identify the layout first, then deactivate only the VG you created and
  disconnect only an NBD backend that still has this run's connection identity.
  The error path does not automatically stop a service or disconnect a device
  whose ownership may have changed.
