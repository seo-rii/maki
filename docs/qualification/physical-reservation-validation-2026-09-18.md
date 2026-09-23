# Physical checkpoint-space reservation validation — 2026-09-18

## Result

Revision `3cac300` passed a destructive Linux filesystem-space campaign on a
disposable GCE VM and a separate 10 GiB standard Persistent Disk. The actual
release Maki nbdkit plugin returned its first FUA acknowledgement only after
the 4,608-byte checkpoint slot range had physical ext4 blocks. Both A/B
allocation-map files also existed with allocated blocks before that
acknowledgement.

After another file consumed all unprivileged filesystem space, a second FUA
failed with `No space left on device`. The failed reservation did not consume
a journal sequence, change the journal bytes, or allocate the next slot. Once
the unrelated file was removed, the same write succeeded and remained exact
after a clean nbdkit restart. The offline deep check and an unmounted read-only
`e2fsck` both passed.

## Environment and immutable input

- GCE `e2-standard-2`, Debian 12, Linux `6.1.0-53-cloud-amd64`.
- A separate 10 GiB `pd-standard` device with a 4,096-byte physical block
  size, formatted as ext4 and mounted directly at `/mnt/maki-space`.
- nbdkit 1.32.5 and libnbd synchronous I/O with native FUA.
- Local AES-GCM-SIV, 64 MiB virtual volume, 4 KiB crypto units, 4,608-byte
  slots, and 8 MiB logical shards.
- Source archive SHA-256
  `41b6c91b39ba4ab2ac0723a984eee4e1a67c18492873535de1a2a20a49ee6d17`,
  built from `3cac300c9d06a36aba6ba7613c9036032b2b8f3a`.
- `checkpoint_reserve_bytes` and `journal_emergency_reserve_bytes` were zero.
  This deliberately isolated the write path's physical reservation from the
  separate free-space admission threshold.

The complete private evidence is under
`/home/seorii/logs/maki-physical-reservation-20260918`. Harness and source
hashes, GCE resource descriptions, qualification JSON, nbdkit logs, the deep
check, and filesystem check are retained there.

## Procedure and observations

1. The harness created the ext4 filesystem and a fresh Maki volume, then
   started the release plugin as an ordinary user.
2. A 4 KiB FUA write to unit 0 succeeded. Maki reported
   `appended_sequence = durable_sequence = 1` and checkpoint sequence 0.
3. Before accepting that record, the 9,437,184-byte sparse shard data file
   owned 8,192 bytes of physical filesystem blocks. Its slot size was 4,608
   bytes. Each 288-byte allocation-map copy owned 4,096 bytes.
4. The harness measured 9,910,247,424 free bytes, then used a separate filler
   file to reduce the ordinary user's available ext4 space to zero.
5. A FUA write to unit 1 returned
   `nbd_pwrite: write: command failed: No space left on device`. Before and
   after this refusal, `appended_sequence` and `durable_sequence` stayed at 1,
   journal length and SHA-256 records were identical, and the shard's allocated
   block count was unchanged.
6. Removing and syncing the filler restored 9,910,247,424 free bytes. Retrying
   the same unit succeeded as sequence 2. Live reads matched independent
   SHA-256 values for both 4 KiB payloads.
7. After stopping and restarting nbdkit, recovery reported checkpoint sequence
   2 and returned the same payload hashes. The deep check found two allocated
   slots, no invalid slots, no journal record newer than the checkpoint, and
   `check passed`.
8. After unmounting, `e2fsck -fn` completed all five passes without an error.

The VM, its auto-delete boot disk, and the separate data disk were deleted.
Exact instance and disk lookups failed afterward, and the final
`maki-physical-*` instance and disk queries both returned empty arrays.

## Boundary of the result

This qualifies the Linux `posix_fallocate` path for two slots on ext4 over one
GCE standard Persistent Disk. It is not full-volume preallocation and does not
reserve untouched slots, database temporary space, filesystem metadata growth,
or configured free-space headroom. Other filesystems, COW/reflink behavior,
quotas, thin provisioning, and production storage classes need their own
campaigns. The VM and Persistent Disk service stayed powered throughout, so
this is not physical power-loss evidence.
