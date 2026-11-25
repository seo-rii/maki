# Provisioning the first volume

`maki-attach attach` mounts an *existing* XFS filesystem on an *existing*
LVM logical volume. A freshly created Maki volume exports an empty block
device, so the first attachment needs a one-time bootstrap that creates the
physical volume, volume group, logical volume and filesystem, then records
their identities in the root-owned attach configuration.

This page is that bootstrap. A dedicated `maki-attach provision` command does
not exist yet. The [quick start](quickstart.md) uses this same procedure.

Prerequisites: the package is [installed](installation-debian.md), the volume
configuration exists at `/etc/maki/volumes/demo.toml` (`root:maki 0640`, as
the [quick start](quickstart.md#2-write-the-volume-configuration) installs
it), its credential is in place, and `maki volume create` has already run.
This example exports 8 GiB with 4096-byte blocks and creates a 6 GiB LV. Edit
the variables together if your configuration differs. The socket must be the
one in that volume's configuration.

Use a disposable host as root. The NBD device, VG name, attach configuration
and mountpoint must be unused. Do not run other provisioning, LVM or NBD
commands concurrently. The script takes the helper's attach lock, but that
lock cannot coordinate unrelated administrator commands.

## 1. Provision and record the layout

Run this entire block as one Bash invocation. A failed command, unexpected
size or identity stops it before the next mutation, and it does not clean up
after an error. Before its first change to the host (starting the daemon) it
creates a record of the run, `/etc/maki/attach/demo.bootstrap` (root, mode
`0600`), with the variables a later run must share, the volume UUID and the
connection identifier, and it adds the PV, VG and LV UUIDs and then the filesystem UUID as soon as it
has read them. A run that stops prints the record. Then run the same block
again: it continues from the record instead of creating anything, as
[recovering from a failed bootstrap](#recovering-from-a-failed-bootstrap)
describes. Do not continue at an arbitrary later line.

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
record=/etc/maki/attach/demo.bootstrap
nbd=${dev#/dev/}
lv_path=/dev/$vg/$lv
# A run that continues from the record must have the values that made it.
parameters=(volume dev expected_bytes block_size vg lv mountpoint attach_config)
uuid='[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}'
lvm_uuid='[[:alnum:]]{6}(-[[:alnum:]]{4}){5}-[[:alnum:]]{6}'

die() { echo "$*" >&2; exit 1; }
trap 'echo "Bootstrap stopped at line $LINENO." >&2' ERR
# Once the record exists, the host has been changed: say how to go on.
trap 'if (( $? )) && [[ -e $record ]]; then
    echo "The bootstrap has changed the host; $record records what it did:" >&2
    cat "$record" >&2
    echo "Change nothing else, fix the cause and run this block again: it continues from the record." >&2
fi' EXIT
note() {
    local name
    for name; do
        printf '%s=%s\n' "$name" "${!name}" >> "$record"
    done
}
verify_backend() {
    local backend bytes
    backend=$(cat "/sys/block/$nbd/backend")
    [[ $backend == "$connection_id" ]] || die "NBD backend identity changed"
    bytes=$(blockdev --getsize64 "$dev")
    [[ $bytes == "$expected_bytes" ]] || die "Unexpected device size"
}

for name in "${parameters[@]}"; do
    # One line per value in the record.
    [[ ${!name} != *[[:cntrl:]]* ]] || die "$name contains a control character"
done
[[ $nbd =~ ^nbd[0-9]+$ ]] || die "Expected a kernel NBD device name"
[[ -b "$dev" ]] || die "NBD device is missing"
# Coordinate with maki-attach; the packaged runtime directory is root-only.
[[ ! -L /run/maki-attach/attach.lock ]] || die "Unexpected lock symlink"
exec 9>>/run/maki-attach/attach.lock
flock -n 9

if [[ -e $record || -L $record ]]; then
    # An earlier run stopped after it changed the host. Its record, not what
    # the host shows now, says what it created: continue from there.
    [[ -f $record && ! -L $record && -O $record ]] || die "$record is not a regular file of this user"
    declare -A recorded=()
    while IFS= read -r line; do
        [[ $line =~ ^([a-z_]+)=(.*)$ && -z ${recorded[${BASH_REMATCH[1]}]+set} ]] ||
            die "Unreadable line in $record: $line"
        recorded[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
    done < "$record"
    for name in "${parameters[@]}"; do
        [[ ${recorded[$name]-} == "${!name}" ]] ||
            die "$record was made with $name=${recorded[$name]-}; run the block that made it"
    done
    volume_uuid=${recorded[volume_uuid]-} connection_id=${recorded[connection_id]-}
    pv_uuid=${recorded[pv_uuid]-} vg_uuid=${recorded[vg_uuid]-} lv_uuid=${recorded[lv_uuid]-}
    fs_uuid=${recorded[fs_uuid]-}
    [[ $volume_uuid =~ ^$uuid$ && $connection_id =~ ^maki-bootstrap-$uuid$ ]] || die "Invalid record"
    for identity in "$pv_uuid" "$vg_uuid" "$lv_uuid"; do
        [[ -z $identity || $identity =~ ^$lvm_uuid$ ]] || die "Invalid LVM UUID in the record"
    done
    [[ -z $fs_uuid || ($fs_uuid =~ ^$uuid$ && -n $pv_uuid && -n $vg_uuid && -n $lv_uuid) ]] ||
        die "Invalid filesystem UUID in the record"
else
    [[ ! -e "$attach_config" && ! -L "$attach_config" ]] || die "Attach configuration already exists"
    [[ ! -e "$lv_path" && ! -L "$lv_path" ]] || die "LV path already exists"
    [[ ! -e "$mountpoint" ]] || die "Use a new mountpoint"
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
    [[ $volume_uuid =~ ^$uuid$ ]] || die "Invalid volume UUID"
    maki check "$config"
    connection_id="maki-bootstrap-$(cat /proc/sys/kernel/random/uuid)"
    install -d -m 0700 -o root -g root /etc/maki/attach
    (set -C; : > "$record")
    note "${parameters[@]}" volume_uuid connection_id
    systemctl start "maki@$volume.service"
    systemctl is-active "maki@$volume.service"
    # The helper's own NBD connect, outside any attachment; it takes no lock,
    # since this shell holds it, and inherits no lock descriptor.
    maki-attach nbd-connect --nbd-device "$dev" --socket "$socket" \
        --block-size "$block_size" --identifier "$connection_id" 9>&-

    verify_backend
    # Refuse existing signatures; neither PV nor filesystem creation uses force.
    signatures=$(wipefs --no-act --noheadings --output TYPE "$dev")
    [[ -z $signatures ]] || die "Export already has signatures"
    pvcreate --devices "$dev" "$dev"
    verify_backend
    # Only maki-attach activates this VG: LVM's own autoactivation skips it.
    vgcreate --devices "$dev" --setautoactivation n "$vg" "$dev"
    verify_backend
    lvcreate --devices "$dev" --type linear -L "$lv_size" -n "$lv" "$vg"

    pv_uuid=$(pvs --readonly --devices "$dev" --noheadings -o pv_uuid "$dev" | tr -d '[:space:]')
    vg_uuid=$(vgs --readonly --devices "$dev" --noheadings -o vg_uuid "$vg" | tr -d '[:space:]')
    lv_uuid=$(lvs --readonly --devices "$dev" --noheadings -o lv_uuid "$vg/$lv" | tr -d '[:space:]')
    for identity in "$pv_uuid" "$vg_uuid" "$lv_uuid"; do
        [[ $identity =~ ^$lvm_uuid$ ]] || die "Invalid LVM UUID"
    done
    note pv_uuid vg_uuid lv_uuid
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
    [[ $fs_uuid =~ ^$uuid$ ]] || die "Invalid filesystem UUID"
    note fs_uuid
fi

# Release the export. A mapping of the device is deactivated only once the
# connection is shown unchanged and each holder to be a mapping of this VG.
holders=$(ls -A "/sys/block/$nbd/holders")
if [[ -n $holders ]]; then
    verify_backend
    live_vg_uuid=$(vgs --readonly --devices "$dev" --noheadings -o vg_uuid "$vg" | tr -d '[:space:]')
    [[ $live_vg_uuid =~ ^$lvm_uuid$ && (-z $vg_uuid || $live_vg_uuid == "$vg_uuid") ]] ||
        die "VG identity changed"
    for holder in $holders; do
        holder_uuid=$(cat "/sys/block/$nbd/holders/$holder/dm/uuid")
        [[ $holder_uuid == "LVM-${live_vg_uuid//-/}"* ]] || die "$holder holds $dev and is not a mapping of $vg"
    done
    vgchange --devices "$dev" -an "$vg"
fi
# Only this run's connection; nothing when the device shows no connection.
maki-attach nbd-disconnect --nbd-device "$dev" --identifier "$connection_id" 9>&-
systemctl stop "maki@$volume.service"
if [[ -z $fs_uuid ]]; then
    cat "$record" >&2
    rm "$record"
    die "Released the export, stopped maki@$volume.service and removed $record: the run stopped before it created the filesystem, so there is nothing to attach. See 'Recovering from a failed bootstrap' before running this block again."
fi

install -d -m 0700 -o root -g root /etc/maki/attach "$mountpoint"
attach=$(cat <<EOF
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
)
if [[ -e $attach_config || -L $attach_config ]]; then
    # Only the configuration an earlier run wrote from this record is kept.
    [[ -f $attach_config && ! -L $attach_config && $(< "$attach_config") == "$attach" ]] ||
        die "Attach configuration already exists"
else
    # noclobber prevents replacing a configuration created during this procedure.
    (set -C; printf '%s\n' "$attach" > "$attach_config")
fi
chmod 0600 "$attach_config"
rm "$record"
printf 'Created %s; review it before starting the lifecycle.\n' "$attach_config"
BASH
```

`maki-attach nbd-connect` negotiates with the daemon's socket and connects the
device over netlink with the helper's own code, the same as an attach; no
`nbd-client` is needed. Its unique `--identifier` must appear unchanged in the
kernel's `backend` attribute, and an identifier of the form attach records use
(`maki-<uuid>`) is refused. It refuses a device that shows a connection or that
an attach record names, and `nbd-disconnect` disconnects only a device
connected under its identifier. It then waits up to 15 seconds until the
device no longer shows that connection, which the kernel keeps showing while
anything has the device open (udev probes a device that was just written to),
and fails if it still does. The block then stops, and running it again asks
for the disconnect again under the recorded identifier. A missing or
unreadable attribute is a failure. LVM queries and mutations after connection
are restricted to that one device. Before formatting, the device-mapper UUID
must contain the newly observed VG and LV UUIDs and its only backing device
must be that NBD device. Before the VG is deactivated, the device must still
show the run's connection and size, and each of its holders must be a mapping
of the VG: a device-mapper UUID that begins with `LVM-` and the VG's UUID.
These checks assume a trusted root administrator; they cannot prevent another
root process from replacing a mapping between a check and a command.

The VG is created with LVM's autoactivation property off
(`--setautoactivation n`, an option as old as `--devices`: LVM 2.03.12), as
a precaution. `maki-attach` activates the VG itself, by its UUID and on the
device it verified, and refuses an attach that finds a mapping of the VG
already active, so nothing else should activate it. LVM's event activation,
on by default in Debian 12 and RHEL 9 (`event_activation = 1`), runs
`vgchange -aay` from a udev rule when a PV appears. For a device that is not
a device-mapper, MD or loop device, that rule acts only on the device's
`add` event, and a kernel NBD device that already exists gets `change`
events when it is connected and disconnected, so the rule does not normally
act on a Maki volume. It can when an `add` event of the device is handled
while the export is connected: when the `nbd` module was loaded only just
before the connect, which `maki-attach attach` does if the module is missing
(the installation guides load it at boot), or when events are replayed with
`udevadm trigger --action=add`. With the property off, `vgchange -aay` skips
the VG. Plain activation ignores the property, so `lvcreate` above and the
helper's own activation are unaffected. On RHEL 9, a devices file that does
not list the NBD device already keeps LVM commands that pass no `--devices`,
the rule's `pvscan` included, from using it
([LVM devices file](installation-rhel.md#the-lvm-devices-file)). This is read
from the udev rules and manual pages that Debian 12 (LVM 2.03.16) and RHEL 9
(LVM 2.03.33) ship, from the LVM 2.03.16 sources and from the kernel's NBD
driver; none of it has been exercised on a host.

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

The plan is read-only. Continue here only after a run of the block printed
`Created`: one that stopped does not authorize it.
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

A run that stops before it has created its record has not started the daemon
or connected the export. Fix the cause and run the block again.

A run that stops later prints its record, `/etc/maki/attach/demo.bootstrap`.
The daemon may be running, the export connected under the recorded
`connection_id`, and the PV, VG, LV or filesystem partly created. Until a run
of the block has finished or released it:

- Keep the record as it is: it holds the only copy of the connection
  identifier and of the identities the run had read.
- Leave `maki@demo.service` as it is. The block stops it once the export is
  released.
- Release the connection only by running the block, which runs `maki-attach
  nbd-disconnect` with the recorded identifier. Never use `nbd-client -d`.
- Do not activate the VG, mount or format the LV, start
  `maki-workload@demo.target`, or run another bootstrap on the device or VG.

Fix what the run printed and run the same block again, with the same
variables: it refuses a record whose volume, device, sizes, VG, LV,
mountpoint or attach configuration path differ. The block takes the attach
lock and reads the record instead of checking for unused resources, creates
nothing, and ends the way a run that does not stop ends:

1. While the device has holders, it checks the connection, the size and the
   holders as above, then deactivates the VG.
2. It runs `maki-attach nbd-disconnect` with the recorded identifier, which
   does nothing for a device that shows no connection and refuses another
   identifier's, then stops `maki@demo.service`.
3. If the record names the filesystem, the layout is complete. The block
   writes the attach configuration from the record, removes the record and
   prints `Created /etc/maki/attach/demo.toml`; continue with
   [step 2](#2-review-the-attach-configuration). It keeps an attach
   configuration that already exists only if it is the one the record gives.
4. If it does not, the run stopped before the filesystem was created and
   there is nothing to attach. The block prints the record, removes it and
   fails, saying that it released the export. The next run starts over.

A run that stops again keeps the record; fix the new cause and run the block
once more. When `nbd-disconnect` stops it because something still has the
device open, find what does before running it again: `udevadm settle` waits
for udev's probes, and `fuser -v /dev/nbd0` (psmisc) lists the processes that
have the device open.

- Do not re-run just `mkfs.xfs`, add `-f`, or erase signatures to get past a
  failed check. Inspect the NBD backend, LVM identities and any partial layout
  first. The block intentionally leaves resources in place when it stops, and
  only a later run of the block releases them.
- A VG/LV name or attach configuration already exists: choose unused names
  for a new volume, or use the existing volume's verified attach procedure.
- The export contains signatures: it may already contain data. Confirm the
  configuration, socket and volume UUID before considering a separate,
  explicitly destructive reset. A run released after its `pvcreate` leaves
  its own signatures, so the run after it stops here. A volume that never
  held data is reset by deleting and recreating it, as for a volume bound to
  the wrong key ([key binding](../operations.md#key-binding-at-first-attach)):
  with the quick start's configuration, remove `/var/lib/maki/demo` while
  `maki@demo.service` is stopped and run its
  [creation block](quickstart.md#3-create-the-volume) again.
- The attach plan fails validation: inspect the root-owned configuration and
  compare its UUIDs with the intended layout. Never remove pins to bypass a
  mismatch.
- A run of the block refuses to release the export (a holder that is not a
  mapping of this VG, another backend identifier, a changed size), or the
  record is gone: identify the layout first, then deactivate only the VG you
  created and disconnect only an NBD backend that still has this run's
  connection identity. The block never deactivates, disconnects or stops
  anything for a device whose ownership it cannot show.
