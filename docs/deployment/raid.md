# RAID and Maki

"Does Maki support RAID?" has three different answers depending on where the
array sits. Existing documents mostly talk about case C, which is the one the
privileged helper inspects; readers often mean case A. Status words follow the
[support matrix](support-matrix.md).

## Case A: RAID below the backing store

```text
SSD ─┐
SSD ─┼─ md RAID1 / hardware RAID ─ ext4 ─ /var/lib/maki/<volume>
SSD ─┘                                        │
                                          Maki daemon
                                              │
                                          /dev/nbdN
```

Maki writes ordinary files into `backing.root` and issues `fdatasync`,
directory `fsync` and `posix_fallocate`. It neither knows nor cares what block
device is underneath, so nothing in Maki refuses this layout.

Status: **not qualified**. The durability model assumes that a completed
`fdatasync` means the bytes survive power loss. With RAID that assumption
holds only if the array forwards FLUSH/FUA to every member and the members
honour it:

- `mdadm` RAID1/10 on drives with volatile write caches: correct if the
  kernel passes flushes through (it does for md) and the drives honour them.
- Hardware RAID with a battery- or flash-backed write cache: correct when the
  cache is protected; a controller in write-back mode without protection can
  acknowledge a flush that is later lost.
- Any array in a degraded or rebuilding state adds failure modes Maki cannot
  see.

The GCE Persistent Disk campaigns are the only external evidence for the
backing tier. Qualify a RAID backing with a real power-cut campaign and an
independent acknowledgement ledger before trusting it
([external checklist](../testing.md#external-qualification-checklist)).

## Case B: RAID across several Maki devices

```text
Maki A ─ /dev/nbd0 ─┐
Maki B ─ /dev/nbd1 ─┼─ md RAID ─ filesystem
Maki C ─ /dev/nbd2 ─┘
```

Status: **unsupported**. Each `maki-attach` instance owns exactly one NBD
device, one VG and one LV, records that identity, and refuses a filesystem
that is stored on any other device. There is no helper mode that manages a
multi-device array, no identity record that spans devices, and no recovery
path for a partially attached array. Redundancy belongs below the backing
store (case A), not above the export.

## Case C: LVM RAID (or thin, cache) on one Maki device

```text
Maki ─ /dev/nbdN ─ PV ─ VG ─ LVM RAID / thin / cache LV ─ XFS
```

Status: **refused or fail closed**. This is what
"multi-LV/internal thin/cache/RAID mappings … fail closed" in
[operations](../operations.md#privileged-helper) refers to. `cachevol`
layouts are refused at activation. Thin pools, LVM RAID and other internal
device-mapper layers may activate, but every recovery path (dead-`nbdkit`
cleanup, pre-activation intent, partial mapping cleanup) accepts only the
single-target mapping of the qualified topology and otherwise keeps the
trusted record for operator diagnosis. LVM RAID on a single underlying device
also adds no redundancy.

Use one plain linear data LV. Additional LVs in the same VG attach and detach
normally but exclude the VG from the automatic cleanup fallback
([support matrix](support-matrix.md#exported-stack-above-maki)).

## Summary

| Case | Layout | Status |
|---|---|---|
| A | RAID below the backing filesystem | Not qualified; depends on FLUSH/FUA behaviour of the array |
| B | RAID across several Maki exports | Unsupported |
| C | LVM RAID/thin/cache on one export | Refused or fail closed; use a linear LV |
