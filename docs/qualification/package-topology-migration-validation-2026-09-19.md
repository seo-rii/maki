# Debian package, topology, and migration validation — 2026-09-19

## Result

Revision `3cac300` passed 10 qualification checks on one disposable Debian 12
GCE VM. The campaign installed a generated older Maki Debian package on a clean
host, ran two simultaneous kernel NBD/LVM/XFS/SQLite volumes, upgraded to the
current package, and reattached both volumes without changing configuration,
credential, or logical database hashes.

The same run exercised three separate boundaries. A corrupt SQLite DB-native
restore was rejected before a clean retry succeeded. An actual legacy v1 Maki
volume was read with the matching old binary, backed up, refused by the current
writable path without changing either superblock, and restored exactly into a
fresh v2 volume. Finally, recovery refused a dead backend with two top-level
LVM mappings, and cleanup refused a foreign backend attached to the recorded
NBD number. Both refusal paths preserved their mappings or backend and trusted
record until explicit, independently observed cleanup.

This is scoped qualification evidence, not production approval.

## Environment and immutable inputs

- One disposable Debian 12 GCE `n2-standard-4` VM, Linux
  `6.1.0-53-cloud-amd64`, with an 80 GB balanced Persistent Disk boot volume.
- nbdkit 1.32.5, LVM 2.03.16, XFS tools 6.1.0, and SQLite 3.40.1.
- nbd-client 3.27.1 built from upstream commit
  `f96f7fca3b37f4254c26c95f5c6c9dae70e030a1` and installed as Debian package
  `1:3.27.1-1`.
- Current source `3cac300c9d06a36aba6ba7613c9036032b2b8f3a`, archive SHA-256
  `41b6c91b39ba4ab2ac0723a984eee4e1a67c18492873535de1a2a20a49ee6d17`.
- Pre-upgrade source `3ba71e9fe8466d317a865c52a22276b2a2c9aff2`, archive SHA-256
  `73fe073ee353a15116c85be50d88ec1d1c35c81ac30f69fc1fedcdc2bdf2e19a`.
- Legacy-v1 source `f643005386089b2c043cd05f1a2c0854468fc350`, archive SHA-256
  `721b1565fe36a043ceced5200bce11c34e4a3eea330a38daaea41a6c229a7b58`.
- Generated package SHA-256 values were
  `bfd05ba69f6c0149dae028d63ccbdb6405536d80d3aaa5154ddfc10ffa973386`
  for the pre-upgrade package and
  `beb2f09b27c7fb536ea14a99e21e38644b64621670e2dc3ab4459ca694befcac`
  for the current package.

Private evidence is retained under
`/home/seorii/logs/maki-package-topology-20260918`. It includes source,
binary, package and harness hashes; package metadata; systemd verification;
attach records; database and configuration hashes; refusal journals; offline
checks; GCE resource descriptions; and the retained failed harness attempts.

## Procedure and observations

1. The VM installed nbd-client 3.27.1 as a versioned Debian package, then built
   the legacy, pre-upgrade and current Maki revisions in isolated Cargo target
   directories. The current package builder produced old and current Maki
   packages from their respective release artifacts.
2. Installing `0.1.0+git3ba71e9-1` on the clean host created the packaged users,
   groups and directories. It did not start a volume. The installed systemd
   templates passed `systemd-analyze verify`.
3. The old package created `topoa` on `/dev/nbd14` and `topob` on
   `/dev/nbd15`, each with a pinned single-PV VG and XFS data LV. `topoa` also
   had a second 64 MiB sidecar LV. Both volumes were attached and verified at
   the same time, and SQLite WAL databases were written with
   `synchronous=FULL`.
4. After orderly cleanup and drain, installing `0.1.0+git3cac300-1` preserved
   every volume and attach configuration hash, all three token-file hashes and
   the key bytes. No volume auto-started during upgrade. Both volumes then
   reattached, and their logical database hashes matched the pre-upgrade values.
5. SQLite `.backup` created a native backup of the source DB. Zeroing its first
   512 bytes made `.restore` fail. Removing the failed destination and restoring
   the unchanged backup passed `PRAGMA integrity_check` and matched source hash
   `00910b0838391fb3d34424a5cc243ccf9db050dfa06ae081aa59bef76742a0d1`.
6. The legacy binary created and served an envelope-v1 volume through actual
   nbdkit, kernel NBD, LVM and XFS. A 24-row SQLite database was backed up after
   clean unmount and drain. The current plugin then refused writable open with
   `legacy v1 volume requires an explicit migration`; SHA-256 records for
   `superblock.a` and `superblock.b` were unchanged. Restoring the old-reader
   backup into the v2 destination passed integrity checking and matched legacy
   hash `3b5c9f1e9bdc13878ecbc9c90caa9cb78c367a32b39a6f36ab5a99a8baeecbb0`.
7. Killing `maki@topoa` triggered packaged recovery while both the data and
   sidecar mappings remained. Normal LVM deactivation failed, and the
   proof-scoped fallback refused because it did not observe one exact top-level
   target mapping. Both mappings and both trusted records remained. After
   explicit manual removal, convergent cleanup retired `topoa` and its deep
   offline check passed with 16,512 allocated slots and zero invalid slots.
8. After cleanly stopping `topob`, a memory nbdkit backend was attached to the
   same `/dev/nbd15` with identifier `foreign-qualification`. `maki-attach
   cleanup` refused the foreign backend, left that identifier unchanged and
   retained the trusted record. Disconnecting the foreign backend allowed
   cleanup to converge; the final deep check passed with 16,510 allocated slots
   and zero invalid slots.
9. No qualification mount, device-mapper mapping, NBD connection or trusted
   record remained. The VM and its auto-delete disk were deleted. Exact
   instance and disk lookups failed, and `maki-pkg-topo-*` prefix queries for
   instances and disks returned empty arrays.

## Boundary of the result

The Maki packages were generated directly by the current repository builder;
the run did not qualify a signed package repository, package-manager download,
downgrade, maintainer-script rollback or distribution other than Debian 12.
The legacy source was cleanly drained before backup, so the result does not
resolve an ambiguous or damaged v1 acknowledgement tail. The DB-native test
used SQLite and a stopped source; it is not evidence for live snapshotting,
PostgreSQL backup/restore or application cutover.

The multi-mapping case used two top-level LVs in one VG, and the foreign-device
case used a same-number in-memory NBD backend with a different identifier.
Other partitions, nested device-mapper stacks, open holders, hot replacement
during I/O, udev races, filesystems and deployment storage classes remain
target-specific qualification work. Production database profiles, an actual
vendor provider, long-duration load and physical power loss also remain open.
