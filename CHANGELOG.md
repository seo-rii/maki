# Changelog

All notable changes to Maki, in particular anything that affects on-disk
compatibility, the runtime layout, credentials or operator procedures. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
Maki has no final release yet (release candidates are tagged
`v0.1.0-rc.<n>` as GitHub pre-releases), so everything is under *Unreleased*
with the commit that introduced it. Procedures for each change live in the linked
documents.

## Unreleased

### Breaking changes

- **A cleared slot whose header reads back as zeros over written bytes reads
  EIO, not zeros** (AUD-211, 2026-11-27;
  [#422](https://github.com/seo-rii/maki/pull/422)). A slot whose allocation
  bit, and on a v3 volume its discard bit, is clear was read as a hole when
  its 64 header bytes were all zero, whatever the rest of the slot held, so a
  checkpointed unit whose newest allocation-map copy no longer decoded and
  whose header sector read back as zeros (a remapped or zero-filled bad
  sector) was served as zeros, and `maki check --deep` called the volume
  `clean`. Such a slot is now a hole only if its header and its ciphertext
  area (the `64 + max_ciphertext_size` bytes a slot write reaches) are all
  zero below the end of the file. Otherwise the unit reads EIO (`unit N:
  unlisted slot holds written bytes under an all-zero header …`) and the deep
  check reports it as `unrecoverable`; that includes a stray byte in a
  never-written slot's ciphertext area, which nothing tells apart from a
  written slot whose header was zeroed. A trim of such a unit journals a
  tombstone and retires it. A zeroed header under a journal record that the
  checkpoint covers no longer refuses attach with "covered journal write at
  sequence N has no visible slot": that unit reads EIO. On a volume without a
  key canary, attach's search for a ciphertext to probe the key fails on such
  a slot, where it took it for a hole. An uncataloged shard with an empty
  allocation map and a short data file counts as truncated when a slot below
  the end holds a ciphertext byte under a zeroed header, so its units past the
  end read EIO. The deep check calls a slot write that a crash tore (its
  header lost over surviving ciphertext, its journal record newer than the
  checkpoint) `recoverable` where it said `clean`, and its warning for a
  recoverable slot ends "recovery rewrites the slot, or discards the unit when
  that record is a trim". A read of a hole in an existing shard reads the
  slot's ciphertext area too (about 1.5 µs instead of 0.7 µs with a warm page
  cache, in the pull request's measurement on ext4), and the deep check reads
  nearly all of every shard file (about 20–21 s instead of 8–10 s for a full
  64 GiB shard, scaled from a 2 GiB one). No format changes ([volume
  lifecycle](docs/operations.md#volume-lifecycle), SPEC §22).
- **`maki check` fails for a configuration that does not match the volume, and
  attach compares the configuration before it loads a provider credential**
  (AUD-194, 2026-11-25; [#399](https://github.com/seo-rii/maki/pull/399)).
  `maki check` and `maki check --deep` exited 0 for a configuration whose
  geometry, provider, key name, compatibility id or random prefix length
  differed from what the volume stores, and attach then refused it. Both now
  compare the settings fixed at creation with the volume, as attach does,
  print one `ERROR: configuration mismatch: <setting> is <value> in the
  configuration, the volume has <value>; attach refuses this configuration`
  line per difference and exit 1; a matching configuration prints one more
  `info:` line. They load no credential and contact no provider, so a
  different key under the same name and the provider's own checks are still
  found only at attach; `maki-check <root>` reads no configuration and
  compares nothing, and `maki volume inspect` does not compare the geometry or
  crypto identity. Attach of an existing volume refuses a changed provider,
  key name, compatibility id or prefix length before it loads any provider
  credential or builds a provider transport. For a local provider a
  compatibility id or prefix mismatch is now `crypto identity mismatch: volume
  was created with compatibility id "…", configuration says "…"`, where it was
  `provider fatal: crypto compatibility mismatch: …` once the key had been
  loaded. For a remote provider, at attach and in
  `build_provider_with_endpoints`, a changed provider type or compatibility id
  is `crypto identity mismatch: …` where it was `unsupported: remote
  configuration does not match the locked volume identity/geometry`, and a
  volume that records a key identity is refused before any endpoint is
  contacted. The geometry and NBD messages are unchanged (maki(8), [volume
  lifecycle](docs/operations.md#volume-lifecycle), SPEC §20). *Changed on
  2026-11-26 (AUD-202, [#407](https://github.com/seo-rii/maki/pull/407)): `maki
  check` now also reads a remote-protected backing, and to ask its authority
  loads the witness client's TLS identity, still no provider credential.*
- **`maki-witness init` and `init-etcd` refuse a nil volume identity with
  status 2** (AUD-196, 2026-11-25;
  [#397](https://github.com/seo-rii/maki/pull/397)). The nil UUID parsed as a
  UUID: `init` handed it to the state store, which refused it, and `init-etcd`
  read its configuration first, and both exited 1. Both now refuse it with
  `maki-witness: volume identity must be nonzero` and status 2 before anything
  is read or created, as `maki volume resume-enrollment` refuses a nil
  identity.
- **Attach refuses a shard whose allocation map lists slots but whose data
  file is missing, and every attach stores the loaded shard catalog again**
  (AUD-181, AUD-182, 2026-11-25;
  [#394](https://github.com/seo-rii/maki/pull/394)). A shard-catalog copy
  whose `fdatasync` failed when it first named a shard was read back from
  the page cache after a restart and never stored again, so writes were
  acknowledged for that shard while no durable catalog copy named it, and
  the next power loss removed it from the catalog. A crash alone lost no
  data, but one lost data file then made the shard read as zeros with a
  clean `maki check --deep`. Every attach of a volume whose catalog names a
  shard now stores the catalog once more (one more A/B store with its
  syncs) at the first write into a loaded shard, the first idle checkpoint
  or recovery's replay into one, whichever comes first; if that store
  fails, the write or checkpoint fails and the next one retries it. A
  volume with a shard that the loaded catalog copy does not name, that has
  no data file and whose allocation map lists a slot no longer attaches
  ("shard N: data file missing: ..."), and `maki check` and `maki check
  --deep` report it as an error; it used to attach and read those units as
  zeros. A short data file of an uncataloged shard that holds a written
  slot header is truncation, so units beyond its end read as EIO where they
  read zeros. Open now reads the allocation copies of a shard that the
  catalog copy does not name and that has no data file and, for each shard
  it adopts with an empty map, up to one 64-byte slot header per slot until
  it finds a written one, at every open until the shard is cataloged; an
  I/O error on either read fails the attach. A cataloged
  shard's truncated data file gets its damage marks stored and its file
  grown back at the same first write or idle checkpoint, so the deep check
  then reports those units as allocated slots with an invalid header. A new
  shard's creation also proves the size of every shard whose size no sync
  has proven, where an adopted shard whose size proof had failed could be
  cataloged as it was and read as EIO after a power loss (AUD-182)
  ([architecture](docs/architecture.md), SPEC §14, §22). *Changed on
  2026-11-27 (AUD-211, [#422](https://github.com/seo-rii/maki/pull/422)): for
  a short data file open reads each slot's header and ciphertext area, where
  it read 64 bytes, and a written byte of the ciphertext area under a zeroed
  header also makes the file a truncated one.*
- **An option given where `maki` or `maki-witness` expects a path exits 2**
  (AUD-190, 2026-11-25; [#393](https://github.com/seo-rii/maki/pull/393)).
  With the configuration forgotten, `maki check --deep`, `maki status
  --help`, `maki volume inspect --help` and the like opened a file named
  after the option and exited 1, and `maki-witness init --state <uuid>`
  created a state directory named `--state` and exited 0. A word that
  starts with `-` where `maki` expects a volume or administrator
  configuration, a backup directory or a reload section, or where
  `maki-witness init`, `init-etcd`, `serve`, `inspect` or `fingerprint`
  expects its path, is now refused with the usage and status 2 before
  anything is opened or created; `--help` after a command is refused the
  same way. A file whose name starts with `-` is named `./-name` (maki(8)).
- **`maki-benchmark` exits 1 for a backing root that is a symbolic link to a
  volume** (AUD-184, 2026-11-25;
  [#391](https://github.com/seo-rii/maki/pull/391)). Without
  `--destroy-data` it exited 2 and asked for that option. It now refuses the
  root, which no backing follows through a symbolic link, with "the backing
  root <root> (`backing.root`) is a symbolic link, which is not followed:
  configure the directory itself", and exits 1.
- **On RHEL 9 Maki is removed with `rpm -e maki`; `dnf remove maki` is always
  refused** (AUD-161, AUD-173, 2026-11-24;
  [#384](https://github.com/seo-rii/maki/pull/384)). rpm cannot stop a
  transaction from a scriptlet: under an attached volume `dnf remove maki`
  kept Maki, whose `%preun` refused, and erased `nbdkit-server`, `lvm2`,
  `xfsprogs` and `kmod` as unused dependencies, and
  `dnf install --allowerasing nbdkit` installed `nbdkit-selinux` beside it.
  The RPM now installs `/etc/dnf/protected.d/maki.conf`, so dnf refuses,
  before it changes anything, to remove Maki or a package it requires,
  whether or not a volume is attached. Remove Maki with `rpm -e maki`, which
  `%preun` still refuses under an attachment, then `dnf autoremove`;
  reinstalling and upgrading are not refused. The RPM also declares
  `Conflicts: nbdkit` (the metapackage) beside `Conflicts: nbdkit-selinux`,
  so it cannot be installed on a host that has the metapackage, and it
  provides `user(maki)`, `group(maki)` and `group(maki-admin)` wherever it is
  built. The `v0.1.0-rc.1` RPM has neither the protection nor the provides:
  remove it with `rpm -e` as well. When this entry was written no later
  release candidate had been tagged
  ([RHEL 9 removal](docs/getting-started/installation-rhel.md#upgrading-and-removal)).
- **The export advertises fast zero and refuses every fast zero request**
  (AUD-160, 2026-11-24; [#381](https://github.com/seo-rii/maki/pull/381)).
  nbdkit asserts, rather than checks, that a WRITE_ZEROES request with
  `NBD_CMD_FLAG_FAST_ZERO` was advertised, so one such request from any
  client of the volume's NBD socket aborted an nbdkit built with assertions
  (Ubuntu 24.04's 1.36.3), although the plugin would have refused it. The
  plugin now advertises `NBD_FLAG_SEND_FAST_ZERO` and refuses every fast zero
  request with `ENOTSUP`, without changing the export, as the NBD protocol
  allows. The
  transmission flags are 0x084d on a default volume and 0x086d on a discard
  volume (0x004d and 0x006d before); `maki-attach` forwards them to the
  kernel unchanged, and the Linux NBD driver neither reads that flag nor
  sends such a request ([space reclamation](docs/space-reclamation.md), SPEC
  §48).
- **`maki-attach nbd-disconnect` waits until the connection is gone, and
  `--plan` fails for a default configuration it cannot examine** (AUD-165,
  AUD-167, 2026-11-24; [#383](https://github.com/seo-rii/maki/pull/383),
  [#385](https://github.com/seo-rii/maki/pull/385)). The kernel acknowledges a
  disconnect while the device still shows the connection, and refuses a new
  connect, until the last opener has closed it. `nbd-disconnect` now waits up
  to 15 s for the device to stop showing the connection it disconnected and
  exits 1, saying that something still has the device open, where it returned
  0 at once; run it again once the opener has let go. Detach and cleanup are
  unchanged. `maki-attach <verb> --plan` without `--config` used to print the
  plan of the built-in defaults, with status 0, whenever the default
  configuration could not be examined (a caller who may not search
  `/etc/maki/attach`); only a path that does not exist selects the defaults
  now, and any other answer, a dangling symbolic link included, fails with
  the path and status 1, for `--plan` and for the executing verbs
  (`maki-attach(8)`, [helper](docs/operations.md#privileged-helper)).
  *Changed on 2026-11-25 (AUD-197,
  [#398](https://github.com/seo-rii/maki/pull/398)): detach, cleanup and the
  failed-start hook's rollback now wait the same way.*

- **The privileged helper connects and disconnects NBD devices itself; no NBD
  client is used** (AUD-147, AUD-151, AUD-153, 2026-11-24;
  [#375](https://github.com/seo-rii/maki/pull/375)). `maki-attach` starts no
  program for its NBD steps: it negotiates with the volume daemon's socket
  (fixed-newstyle `NBD_OPT_GO` for the default export) and sends
  `NBD_CMD_CONNECT` and `NBD_CMD_DISCONNECT` to the kernel's `nbd`
  generic-netlink family, setting the attachment's connection identifier as
  the device's backend identifier, as `nbd-client -identifier` did. The Debian
  package's `Depends` no longer lists `nbd-client (>= 1:3.27.0)`; its static
  list is `nbdkit, lvm2, xfsprogs, util-linux, systemd (>= 249), kmod`,
  followed by the library packages `dpkg-shlibdeps` finds. A source-built
  `nbd-client` is no longer used and may be removed, and attachments it
  connected stay detachable. A kernel whose `nbd` family takes no backend
  identifier is refused before anything is connected. The plan prints `connect
  nbdN to <socket> over netlink (block size B, backend identifier
  '<generated-connection-uuid>'; the export must advertise FLUSH and FUA)` and
  `disconnect nbdN over netlink` instead of the `nbd-client` command lines. A
  disconnect that the kernel cannot complete (a daemon that stopped reading
  with a full send buffer) now holds the helper and the attach lock until the
  daemon reads again or its socket closes, where the helper used to abandon a
  stuck `nbd-client` at the 120 s step limit; the unmount and the VG
  deactivation before it fail first in that case, and the unit's timeout is
  the outer bound. This replaces the `nbd-client` 3.27.0 requirement listed
  further down ([prerequisites](docs/operations.md#prerequisites),
  [Debian](docs/getting-started/installation-debian.md#nbd-client-327-or-later)).
- **An NBD export without FLUSH and FUA is refused** (AUD-149, 2026-11-24;
  [#375](https://github.com/seo-rii/maki/pull/375)). Before the kernel sees
  the socket, the helper refuses an export that does not advertise
  `NBD_FLAG_HAS_FLAGS`, `NBD_FLAG_SEND_FLUSH` and `NBD_FLAG_SEND_FUA`, an
  export of size 0 or above 2^63 − 1 bytes, and a server that offers no
  fixed-newstyle negotiation or does not answer `NBD_OPT_GO`, with no fallback
  to `NBD_OPT_EXPORT_NAME`. `SEND_FLUSH` is required for durability: without
  it the kernel gives the device no write cache, so FLUSH requests complete
  without reaching the server and FUA writes go out as plain writes.
  `SEND_FUA` is required by policy (without it the block layer emulates each
  FUA write with a full flush) and `HAS_FLAGS` by the NBD protocol.
  `nbd-client` accepted such exports. Maki's own plugin always advertises
  FLUSH and FUA, and nbdkit answers `NBD_OPT_GO` in every release the project
  documents (SPEC §6).
- **Provisioning connects a new volume's export with `maki-attach nbd-connect`
  and `nbd-disconnect`** (AUD-152, 2026-11-24;
  [#375](https://github.com/seo-rii/maki/pull/375)). `maki-attach nbd-connect
  --nbd-device /dev/nbdN --socket <path> --identifier <id> [--block-size <n>]`
  and `maki-attach nbd-disconnect --nbd-device /dev/nbdN --identifier <id>`
  replace the `nbd-client` commands of the provisioning procedure and the
  privileged validation runner. They refuse an identifier of the attach-record
  form (`maki-` and a UUID); `nbd-connect` refuses a device that shows a
  connection, whose backend cannot be read or that a trusted attach record
  names, and `nbd-disconnect` touches only a device connected under its own
  identifier. Neither takes the attach lock, which the procedure holds for its
  whole run ([provisioning](docs/getting-started/first-volume.md),
  `maki-attach(8)`). *Changed by AUD-165
  ([#383](https://github.com/seo-rii/maki/pull/383)): `nbd-disconnect` waits
  until the device no longer shows the connection.*

- **The command-line binaries exit 2 for misuse, and `maki-attach` actions
  exit 3 off Linux** (AUD-137, AUD-144, 2026-11-23;
  [#363](https://github.com/seo-rii/maki/pull/363)). `maki-witness` exits 2
  instead of 1 for an unknown command, a missing or extra argument and a
  volume identity that is not a UUID, and for an argument that is not UTF-8,
  where it panicked with 101. `maki` exits 2 instead of 1 for `--timeout`
  without a positive number of seconds, `--socket` without a path, beside a
  configuration or on a command without a control round trip, a malformed
  `reload cache` option, and a malformed fence, root or storage identity
  given to `volume takeover`, `restore` or `resume-enrollment`, which is now
  refused before the configuration is read. `maki-attach` exits 2 for a
  malformed `--volume` before it reads any file (it exited 1 for
  `recover-failed-start`, and for the other verbs with an unreadable
  `--config`), and off Linux `recover-failed-start` without `--plan` exits 3
  like every other action, where it exited 0 or 1. The messages are those
  printed before, but `maki-attach` now follows a malformed `--volume` with
  the usage for every verb, `recover-failed-start` included, and `maki`
  reports a malformed approval before a missing or unreadable configuration.
  A command that fails still exits 1: a script that detects misuse by
  status 1 must test for 2. `maki(8)` and `maki-attach(8)` have an
  EXIT STATUS section.
- **The three remote crypto transports trust one set of TLS roots: the
  host's trust store, the public roots compiled into the binary and
  `ca_file`** (AUD-133, [#369](https://github.com/seo-rii/maki/pull/369)).
  `remote-http` now also trusts the host's trust store (the system bundle, or
  `SSL_CERT_FILE` and `SSL_CERT_DIR` when set), so a private CA installed
  there authenticates an HTTP endpoint without a TLS section, where it was
  refused with `EndpointFatal`. `remote-grpc` now also trusts the compiled-in
  public roots (webpki-roots) and no longer fails to build its provider on a
  host whose trust store is empty: a public endpoint is reachable from such
  an image, and a private endpoint that none of the roots vouches for is
  refused at the TLS handshake instead of when the provider is built (with
  a single endpoint attach still fails, now at the self-test's handshake). A
  gRPC deployment with
  `ca_file` on a host whose trust store is empty (a distroless image,
  `SSL_CERT_FILE` naming an empty bundle) trusted that CA alone; it now also
  accepts a server whose certificate chains to a public root and matches the
  endpoint's name, and no setting restores CA-only trust. `remote-websocket`
  is unchanged. `ca_file` still adds to the roots and is parsed strictly; the
  CA bundle errors read the same in all three transports, and an HTTP client
  identity that rustls rejects is reported as `bad client identity: …`. The
  remote witness still trusts only its own CA
  ([providers](docs/configuration.md#providers)).
  *Corrected on 2026-11-25 (AUD-188,
  [#392](https://github.com/seo-rii/maki/pull/392)): with a single endpoint
  that held only under `bounded-error`; under the default `stall` the
  attach waited without end and logged nothing. A lone endpoint is now
  probed at attach, and a failed TLS handshake refuses it under either
  policy.*
- **Attach reserves the NBD devices that other volumes' attach records name**
  (AUD-120, [#354](https://github.com/seo-rii/maki/pull/354)). Under the
  attach lock, attach reads every `/run/maki-attach/<volume>.nbd` record
  before it chooses a device: automatic allocation skips a device another
  volume's record names, and a pinned `nbd_device` that such a record names
  is refused even when the device is free in sysfs. A record that outlived
  its connection (a helper killed before the connect or after the
  disconnect) keeps its device until that volume's next attach, cleanup,
  detach or recover, or until `/run` is cleared; when every device is
  connected, in use or recorded, attach fails with "no free /dev/nbdN
  device", which now mentions records. An attach is refused, naming the
  file, while any `<volume>.nbd` entry cannot be read as a trusted record.
  Before, another volume could be handed the device, and every verb of the
  first volume then refused it as a foreign backend
  ([privileged helper](docs/operations.md#privileged-helper)).
- **Detach, cleanup, recovery and grow run LVM only on the recorded devices**
  (AUD-135, [#368](https://github.com/seo-rii/maki/pull/368)). The
  deactivation of a record with a mapping proof, or of one from before
  proofs and intents, runs `vgchange --devices <recorded PVs> --activate n
  --select vg_uuid=<recorded> --config "devices {
  allow_changes_with_duplicate_pvs=0 }" <vg>` (the selection where the
  record names a VG UUID), and growth runs `lvextend --devices <recorded
  PVs> --config "…" -L <n>b <vg>/<lv>`, instead of `vgchange -an <vg>` and
  `lvextend -L <n>b <vg>/<lv>` resolved over LVM's own device scan. The
  deactivation of an activation intent, like activation and its rollback,
  was already scoped. A VG of the same name on another disk is never
  extended or deactivated: grow used to report success after extending the
  other disk's LV when the volume's PV was outside LVM's scan, and cleanup
  after a daemon death deactivated the other VG instead of reaching its
  `dmsetup` fallback. A devices file or filter that leaves `/dev/nbd*` out no
  longer stops grow and detach. A record from before mapping proofs and
  activation intents is scoped to its NBD device alone, so such an
  attachment whose PV is a partition now fails detach with "not found" and
  keeps the record; a mapping proof whose uuids do not name one VG UUID is
  refused before any command. The plan and step texts name the scope
  ([privileged helper](docs/operations.md#privileged-helper)).
- **The failed-start hook rolls back an interrupted LVM activation itself**
  (AUD-118, AUD-119, AUD-142, AUD-143;
  [#356](https://github.com/seo-rii/maki/pull/356),
  [#370](https://github.com/seo-rii/maki/pull/370)). When an attach dies
  between LVM activation and its mapping proof, `maki-attach
  recover-failed-start` now deactivates the VG within the recorded scope,
  disconnects the NBD device and retires the record under the attach lock,
  while the daemon still serves and never with an unmount; before, it only
  queued `maki-recover@`, which stops the daemon first, so the mapping had to
  be removed by hand. The hook reads the trusted record first and stops there
  when it holds no activation intent, writing no journal line; with one it
  reads `/etc/maki/attach/<volume>.toml` like `cleanup` (`--config` is still
  refused), waits up to 15 s for the attach unit's control group to settle,
  waits up to 40 s in turn for the attach lock and gives its commands 30 s
  once it holds it, so it can take up to about 87 s within the unit's
  `TimeoutStopSec=120`. Its journal lines name what they are about ("cannot
  tell whether volume pg has an interrupted LVM activation to roll back",
  "did not roll back the interrupted LVM activation of volume pg: …", "could
  not roll back the interrupted LVM activation …"), and `--plan` prints one
  more line. Cleanup's `dmsetup` fallback no longer runs after a `vgchange
  -an` killed by a signal, only after one that exited nonzero, and the
  refusal for an intent whose deactivation fails says what is left. A daemon
  that stops inside that window still needs the documented manual step
  ([systemd deployment](docs/operations.md#systemd-deployment),
  [interrupted activation](docs/operations.md#interrupted-activation-after-the-daemon-stopped)).

- **A volume configuration must be a regular file that no other user can
  change** (AUD-106, 2026-11-23;
  [#339](https://github.com/seo-rii/maki/pull/339)). The daemon, every `maki`
  command that takes a configuration and `maki-benchmark` refuse, before
  parsing it, a file that is a symlink, has a second hard link, is owned by a
  user other than root and the user the process runs as, or is writable by
  its group or others (a file written under `umask 002`, or one with a POSIX
  ACL that grants write access); the daemon fails attach on such a file.
  Group and other read stay allowed. Before upgrading, list the affected
  files and reinstall each with `install -m 0640 -o root -g maki`. A file
  owned by the daemon user is still accepted by the daemon, but refused by
  commands run as root
  ([configuration file](docs/configuration.md#configuration-file),
  [upgrade](docs/operations.md#upgrading-the-runtime-layout)).
- **A root process creates backing and witness entries for the owner of
  their directory, and fails when it cannot** (AUD-111,
  [#344](https://github.com/seo-rii/maki/pull/344)). On Linux, a command run
  as root (`maki check --deep`, `maki-check --deep`, `maki volume inspect`,
  `create`, `takeover`, `restore` or `resume-enrollment`) creates each file
  and directory below a backing root or a local witness directory for the
  owner of the directory it is created in. A root run on a volume the daemon
  user owns therefore no longer leaves root-owned files that stop the next
  attach, and the procedures drop their `chown -R maki:maki` step. A root
  process that cannot change the owner (CAP_CHOWN dropped) now fails instead
  of creating a root-owned entry.
  Opening a local rollback witness as root gives a root-owned anchor in the
  daemon's directory back to the daemon user, refuses an anchor a third user
  owns, and removes a leftover `anchor.next` instead of publishing it; a
  file a third user puts back under that name is refused. A hand-back is
  still needed for a restored copy whose files lost their owners, for a
  volume or witness directory root had to create itself (the `volume create`
  warning, now printed only then, names it) and after a root run that a
  crash interrupted ([volume lifecycle](docs/operations.md#volume-lifecycle),
  [rollback
  protection](docs/rollback-protection.md#local-configuration-and-creation)).
- **Candidate builds refuse release-profile and unstable-toolchain overrides,
  and `maki-nbdkit` requires unwinding panics** (AUD-103,
  [#336](https://github.com/seo-rii/maki/pull/336)).
  `scripts/prepare_release.py` stops before building when its environment
  holds a `CARGO_PROFILE_RELEASE_*`, `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*` or
  `__CARGO_*` variable, or when Cargo configuration outside the committed
  source (above the build directory or in `CARGO_HOME`) has a
  `[profile.release]` or `[unstable]` table or an `include`: unset the
  variable, or commit the profile change. The manifest also records
  `CARGO_INCREMENTAL`, the C toolchain inputs of the native dependencies and
  each external Cargo configuration file with its digest. `maki-nbdkit` no
  longer compiles with `panic = "abort"`, however that strategy is selected,
  because the plugin would lose its panic boundary
  ([releasing](docs/releasing.md#prepare-and-inspect)).
- **A crypto call that ends at its `bounded-error` deadline returns the last
  endpoint error, and `maki_crypto_deadline_exceeded_total` counts every
  expired call once** (AUD-109,
  [#342](https://github.com/seo-rii/maki/pull/342)). Wherever the deadline
  expires, the call returns the last error an endpoint returned before it for
  the RPC batch in progress, with that error's class (`throttled: HTTP 429`,
  for example), or `operation deadline exceeded` when no endpoint failed that
  batch. Before, an RPC cut off by the deadline got the bare deadline error
  whatever the endpoints had answered, and so did a caller whose budget ran
  out in the batch scheduler before the dispatcher's, the usual case on a
  remote volume. The counter no longer follows the error text: it counts each
  call whose own deadline expired exactly once, including one that returns an
  endpoint error and the exit right after a failed RPC. Alert on the counter
  rather than on the error text
  ([metrics](docs/operations.md#metrics-and-health)).
- **A quarantined endpoint is validated again after an inconclusive failure
  instead of staying excluded until the daemon restarts** (AUD-110,
  [#343](https://github.com/seo-rii/maki/pull/343)). A malformed or truncated
  reply during background validation (a proxy error page, an endpoint
  restarting mid-response) used to mark the endpoint `rejected` for the life
  of the process. Only proof that it serves another contract does so now:
  another key, compatibility id or canary, a claimed capability it does not
  honour, or an explicit refusal of the volume's context. An endpoint that
  refuses the volume's key canary with an integrity failure is rejected; it
  used to be deferred and validated again forever. Inconclusive attempts are
  repeated after `circuit_breaker.open_initial`, the spacing doubling up to
  `circuit_breaker.open_max`, instead of at a fixed interval, so an endpoint
  that was unreachable for long can take up to `open_max` to return after it
  recovers ([endpoint
  validation](docs/configuration.md#websocket-and-grpc-contracts)).
- **With `crypto.random_prefix_bytes`, the attach self-test's
  compatibility-id probe reaches the provider** (AUD-107,
  [#340](https://github.com/seo-rii/maki/pull/340)). The random-prefix
  wrapper used to answer that probe itself, so a remote provider that
  declares context binding but ignores the compatibility id, or a transport
  mapping that drops the field, attached with a prefix and was refused
  without one. It is now refused at attach in both cases ("compatibility id
  decrypts to the original plaintext"); fix the provider or the mapping. A
  prefixed volume's self-test sends one more decrypt request ([random
  plaintext
  prefixes](docs/random-plaintext-prefix.md#existing-volumes-and-endpoint-compatibility)).
- **A lock ends when its holder releases it, even while a forked child still
  holds its descriptor** (AUD-108,
  [#341](https://github.com/seo-rii/maki/pull/341)). The volume, rollback,
  witness, attach and control-socket directory locks were released only by
  closing their descriptor, so a child forked by another thread kept them
  held until its `exec`: an attach right after a detach or a create could
  fail with `VOLUME_ALREADY_ATTACHED`, and a closed rollback backing or
  witness store could refuse to reopen. Every lock is now unlocked before its
  descriptor closes. As a consequence, remote GC no longer treats a namespace
  as live because a forked child inherited the descriptor of a lifetime lock
  its holder has dropped; a held lifetime lock still keeps its namespace
  ([backing namespace](docs/architecture.md#backing-namespace)).

- **The `maki-witness` configuration, state directory and state files must be
  owned by root or by the user that runs the command** (AUD-075, AUD-076,
  2026-11-17; [#170](https://github.com/seo-rii/maki/pull/170)). `serve`,
  `init-etcd` and `inspect` refuse a configuration owned by another user, and
  `init` and `serve` refuse a state directory or `remote.state`, `remote.next`
  or `remote.lock` owned by another user or writable by group or others, before
  writing anything or binding the listener. A command run as root therefore
  refuses a configuration or state directory the service account owns:
  `chown -R` the state directory to the account that runs `serve` and
  `chmod go-w` it and its files, or use a root-owned configuration ([witness
  service](docs/remote-witness-service.md#credential-and-configuration-files)).
- **A witness frontend whose allow-list does not name a trusted client
  certificate answers with a final denial** (AUD-077,
  [#179](https://github.com/seo-rii/maki/pull/179)). Failover no longer tries
  another frontend, a mutation is not retried, and a remote rollback session
  stops until it is reopened; before, the dropped connection looked like an
  unavailable witness and another frontend could answer. List every client on
  every frontend ([frontend
  failover](docs/remote-witness-service.md#configure-frontend-failover)).
- **`MAKI_LOG` directives need a level, and `maki` refuses `--timeout` on
  commands without a control round trip** (AUD-094, AUD-095,
  [#188](https://github.com/seo-rii/maki/pull/188)). A directive that is
  neither a level nor `<target>=<level>`, such as a misspelt `warning` (which
  silenced every Maki event, ERROR included) or a bare `maki_core` (which meant
  that target at trace and every other target off), now falls back to `info`
  and logs one `MAKI_LOG is not a valid filter` warning; write
  `maki_core=trace` for one target. Only `status`, `metrics`, `checkpoint`,
  `drain` and `reload` take `--timeout`; `maki volume` and `maki check` refuse
  it with the usage and exit status 2 instead of ignoring it
  ([logging](docs/operations.md#logging)).
- **gRPC method paths, HTTP item fields and `env` credential names are
  validated as the providers send them** (AUD-072 to AUD-074,
  [#172](https://github.com/seo-rii/maki/pull/172)). `encrypt_path` and
  `decrypt_path` must be an absolute path with an optional query and no
  fragment, with characters outside RFC 3986's path and query sets
  percent-encoded. A batch body's top-level `fields` may not use the `payload`,
  `unit_index` or `batch_index` source (map it in `item_fields`), and a
  per-item body may not have `item_fields`. An `env` name may not contain `=`
  or NUL. These configurations used to fail every attach or send empty values
  ([HTTP mapping](docs/configuration.md#remote-http-mapping)).
- **Recovery and `maki check --deep` refuse inconsistent metadata they used to
  disagree on** (AUD-055 to AUD-059,
  [#185](https://github.com/seo-rii/maki/pull/185)). Both refuse a checkpoint
  above the durable proof's horizon, whose acknowledged writes then read zeros;
  a v2/v3 durable sequence or segment index that leaves no room for one more
  record or segment, or a metadata generation in the top quarter of its range,
  after which every write or a later checkpoint failed; and a covered proof
  that names a location past the newer records. Only damage or a foreign writer
  produces these states ([durable
  recovery](docs/durable-recovery.md#cost-and-verification-limits)). The deep
  check reports a lost key canary as an `ERROR` only when the volume has
  history but no ciphertext left, which every attach refuses, and as a warning
  otherwise ([operations](docs/operations.md#volume-lifecycle)).

- **Credential and witness key files must be owned by root or by the user that
  loads them** (AUD-029, AUD-031, 2026-11-16;
  [#158](https://github.com/seo-rii/maki/pull/158),
  [#162](https://github.com/seo-rii/maki/pull/162)). This applies to `file`
  credentials, files in the systemd credentials directory, an HTTP combined
  certificate and private-key PEM, and witness TLS private keys, whatever their
  mode. A process run as root therefore refuses a key owned by the daemon user:
  run `maki-benchmark`, a daemon started by hand or `maki volume witness` with
  the daemon's writer configuration as that user (`sudo -u maki`). See
  [credentials](docs/configuration.md#credentials-and-secrets) and the [witness
  service](docs/remote-witness-service.md#credential-and-configuration-files).
- **An empty or whitespace-only credential is refused like a missing one**
  (AUD-030, [#158](https://github.com/seo-rii/maki/pull/158)), so a token file
  truncated by a failed rotation stops attach instead of sending
  `Authorization: Bearer ` without its token.
- **Credential references must be loadable as written** (AUD-032, AUD-036,
  [#159](https://github.com/seo-rii/maki/pull/159)). A header or metadata
  `format` needs exactly one `{}` placeholder, and `format` on `crypto.key` or
  a `tls.client_key` is refused. A `credential` name, and the file name of a
  `file` path, may contain only ASCII letters, digits, `.`, `_` and `-` and
  must not start with `.`, as the loaders require; `volume create` used to
  store another key name as the volume's immutable key identity, after which
  every attach failed.
- **`nbd.preferred_io` above 32 MiB and geometries that reach the key-canary
  unit index are refused** (AUD-034, AUD-035,
  [#159](https://github.com/seo-rii/maki/pull/159)). nbdkit failed every client
  handshake for the first, and attach refused the second; a stored superblock
  with such a geometry now loads as an invalid copy. See [validation
  rules](docs/configuration.md#validation-rules).
- **`remote-http` request mappings are validated as the provider builds them**
  (AUD-026, [#161](https://github.com/seo-rii/maki/pull/161)). Unknown field
  sources or payload encodings, an encoding on a source other than `payload`, a
  request pointer or `items_path` without a leading slash, pointers of one
  object that overlap (including a field at, under or above `items_path`), and
  a declared context binding without a per-item `unit_index` fail validation
  instead of failing attach or every request. SPEC §18 no longer lists the
  `utf8`, `integer` and `uuid` encodings, which the provider never implemented
  ([HTTP mapping](docs/configuration.md#remote-http-mapping)).

- **Remote transport limits must hold a full ciphertext batch** (BUG-092,
  2026-10-14). gRPC `max_message_bytes`, WebSocket `max_frame_bytes` and, for
  a batched HTTP mapping, `max_response_bytes` are checked against the larger
  of the plaintext and the ciphertext batch (base64 where encoded), and a zero
  WebSocket or gRPC `timeout` is refused. A configuration that validated
  before but could not carry a full batch now fails validation instead of
  failing every full batch at runtime; raise the limit or lower
  `crypto.batch.max_items`/`max_bytes`. HTTP context binding now counts only
  mappings the provider sends (BUG-093). See
  [validation rules](docs/configuration.md#validation-rules).
- **An AES-XTS key with identical halves is refused** (BUG-095, 2026-10-14):
  IEEE 1619 requires distinct data and tweak keys.
- **File credentials and TLS files need absolute paths** (BUG-122,
  2026-10-15). A relative `file` credential name or TLS `ca_file` /
  `client_cert_file` resolved against each process's working directory and
  now fails validation; write the absolute path. See
  [configuration](docs/configuration.md).

- **Remote witness authority and wire v2 require private session ownership**
  (2026-10-12). `MAKIRW02` authority state stores a digest of a random 256-bit
  session capability. Writers must prove the current capability for activation,
  advancement and release; public inspection cannot authorize another writer or
  an older session under the same credential. Authority/wire v1 is refused;
  preserve the old source, create a fresh independent identity and verify a
  logical copy. The outer remote COW marker, enrollment and inner volume bytes
  remain unchanged. See [migration](docs/durable-recovery.md#protected-outer-backing-formats)
  and [service upgrade](docs/remote-witness-service.md#authority-protocol-compatibility).

- **Executing `maki-attach` verbs require a root-controlled attach config**
  (R5-030): a root-owned regular file with one link, not group/other
  writable, below root-owned directories. `--plan` reads any file.
- **A CA bundle or a WebSocket/gRPC `client_cert_file` containing a private
  key is refused** (R5-028); supply the key through `client_key`.
- **The mountpoint directory must be root-owned and not group/other
  writable** (R5-024), like its ancestors: a workload-owned mountpoint let
  the workload stack a FUSE mount over it before attach mounted the volume.
  Recreate it with `install -d -m 0755 /srv/<volume>` (root) before attach;
  the volume's own root directory keeps the workload's ownership.
- **`maki-benchmark` refuses an existing volume without `--destroy-data`**
  (R5-017): it overwrites the start of the device (partition table,
  filesystem superblock) and used to do so to whatever volume its
  configuration named.
- **Credential-like header names refuse literal values** (R5-007). An HTTP
  header or gRPC metadata name containing `auth`, `token`, `secret`,
  `passw`, `cookie`, `session`, `signature`, `credential`, `apikey`,
  `api_key`, `-key` or `_key` must use a credential reference
  ([configuration](docs/configuration.md#credentials-and-secrets)); a
  configuration that put such a value inline no longer validates.
- **Superblock envelope v2 with mirrored durable proofs is required for
  writable volumes** (`1bc0ab5`, 2026-09-12). Older binaries reject v2
  volumes; this build refuses writable recovery of legacy v1 volumes and
  supports them read-only with a warning. There is no in-place upgrade:
  follow [durable recovery and migration](docs/durable-recovery.md). The
  crypto AAD `format_version` is unchanged.
- **Privileged helper runtime layout** (2026-09-05 review fixes). Attachment
  records moved to `/run/maki-attach/<volume>.nbd` with a versioned trusted
  format; legacy `/run/maki/attach/*.nbd` records are refused. The default
  control socket is `/run/maki-control/<volume>/control.sock`. Detach with
  the old helper before upgrading:
  [upgrade procedure](docs/operations.md#upgrading-the-runtime-layout).
- **`nbd-client` 3.27.0 or later is required** for privileged attachment; the
  helper verifies the kernel NBD backend identifier over netlink and fails
  closed otherwise. Debian 12's 3.24 is too old
  ([installation](docs/getting-started/installation-debian.md)).
  *Superseded by AUD-147
  ([#375](https://github.com/seo-rii/maki/pull/375)): the helper connects
  NBD devices itself and needs no NBD client.*
- **Credential sources no longer fall back**: `credential`, `file` and `env`
  are each read only from the source they declare; the same name may not be
  declared with different sources in one configuration.
- **`crypto.capabilities.mode` accepts only `declared`**; `hybrid` and
  `probed` are configuration errors.
- **Plaintext transports to non-loopback hosts are refused**; `http://`,
  `ws://` and gRPC `http://` endpoints are accepted only for loopback.
- **Production remote-provider contracts must declare `integrity` and
  `context_binding`**, and a provider that declares context binding must
  receive the whole context (volume UUID, compatibility id, format version)
  or attach fails (`be23a11`).
- **`maki-attach grow` takes an absolute `--size-bytes`**; the relative
  `--add-bytes` is rejected because a retry could not identify itself.

### Added

- **CI boots Debian 12 and Rocky Linux 9 guests and runs the guides and the
  privileged runner in them** (AUD-209, 2026-11-27;
  [#412](https://github.com/seo-rii/maki/pull/412)). For developers: four jobs
  run on every pull request, push to `main`, dispatch and scheduled run.
  `debian12-package` builds the Debian package from the commit in `debian:12`,
  and `el9-package` the RPM in the release workflow's CentOS Stream 9
  container. `debian12-guest` and `el9-guest` boot Debian 12's generic cloud
  image and Rocky Linux 9.9's GenericCloud image, pinned by digest and cached,
  as KVM guests under QEMU on GitHub's runner VMs, a fresh guest per suite
  (`scripts/booted-host-validation.py`, `scripts/booted-host-guest.py`). In
  one, as root, the installation guide's host steps (the RHEL guide's on
  Rocky, `documented_quickstart.py --installation rhel`), the quick start and
  the first-volume bootstrap run with the package; in the other the privileged
  runner's lifecycle runs as the guest's user `ci` with the package's binaries
  (`privileged-linux-validation.sh --prebuilt DIR`). On Rocky Linux the job
  requires SELinux enforcing, auditd active, no AVC that names Maki or an NBD
  device and, after the guides, `maki@`'s nbdkit in `unconfined_service_t`
  and the labels the RHEL guide lists. The privileged runner waits for its
  opener by reading `/proc`, no longer with `kill -0`, which fails for a
  process that sudo started while sudo checks its policy. The guests are
  virtual machines on GitHub's hardware, not bare-metal hosts, Rocky Linux is
  a rebuild of RHEL, not RHEL, and the jobs qualify nothing ([automated
  CI](docs/testing.md#automated-ci)).
- **CI's `kernel-lifecycle` job reaches cleanup's disconnected recovery, stops
  the first-volume block and continues it, and stops three volumes together**
  (AUD-208, 2026-11-27; [#413](https://github.com/seo-rii/maki/pull/413)). For
  developers: `privileged-linux-validation.sh --kill-daemon` kills nbdkit a
  second time and releases its device by hand
  (`privileged_validation_nbd.py kernel-disconnect --volume`, an unmount and a
  `dmsetup remove`), so that cleanup starts on a device that shows no
  connection, and now needs `dmsetup`; every run captures what the helper's
  readers parse into `helper-outputs.json`.
  `documented_quickstart.py --stop-once mkfs.xfs|vgchange` writes the program
  with the bootstrap's first run made to fail at that command and the block
  run again as its recovery notes say, and
  `scripts/stop-together-validation.py` stops three volumes whose devices are
  held open with one `systemctl stop` and reads each stop's times from PID 1's
  journal. The program writer now refuses `&&` or `||` lists at every depth of
  a block unless `DEEPER_LISTS` names them. The job's limit is 150 minutes
  ([automated CI](docs/testing.md#automated-ci), [privileged validation
  runbook](docs/qualification/privileged-linux-validation.md)).
- **A dispatched 24 CPU-hour fuzz qualification, a big-endian seed replay and
  each fuzz target's input length** (AUD-210, 2026-11-27;
  [#415](https://github.com/seo-rii/maki/pull/415)). For developers:
  `.github/workflows/fuzz-qualification.yml`, run only when dispatched
  (`targets`, `cpu_hours` 24 by default, `shard_hours` at most 5,
  `max_parallel` at most 20), builds every target once, fuzzes each in shards
  of 4 libFuzzer processes on hosted runners until the kernel has charged
  every process its share of CPU time, merges each target's corpora and
  writes a summary that fails unless every target qualified
  (`scripts/fuzz_campaign.py`). Each target's `-max_len` is in that script,
  which the scheduled `fuzz` job reads too: the job had given `nbd_netlink`
  4,096 bytes and so cut its 16,392-byte seed. A `big-endian-seeds` job
  replays the committed seeds on `s390x-unknown-linux-gnu` under `qemu-user`
  on every change. `helper_sysfs` builds its trees under a directory of its
  process's own and removes the trees of a crashing input and of ended
  processes, and `witness_etcd` gains five seeds at etcd's 256 KiB answer and
  the 64 KiB state. No 24 CPU-hour campaign had finished when this was
  written. The first, dispatched on 2026-11-27, had already failed both
  `nbd_handshake` shards: every process ended at libFuzzer's 2048 MB memory
  limit after about 10 million executions. The coordinator measured the
  cause: that target's entry function spawns a thread for every input, under
  which an AddressSanitizer build grows; a fix is pending, so
  `nbd_handshake` is not qualified ([fuzz
  qualification](docs/testing.md#fuzz-qualification)). *Changed on 2026-11-27
  (AUD-223, AUD-224, [#421](https://github.com/seo-rii/maki/pull/421),
  [#424](https://github.com/seo-rii/maki/pull/424)): the campaign finished and
  qualified eleven targets. `nbd_handshake` no longer starts a thread per
  input, and the summary's "qualified" for `witness_etcd`, `http_response`,
  `grpc_response` and `helper_reports` was wrong, since their shard corpora
  never reached their merges; those five were dispatched again, and that run
  had not finished when the tenth round was recorded.*
- **CI requires the IPv6 loopback address for the connect tests and runs a
  packet-drop test as root** (AUD-206, 2026-11-27;
  [#414](https://github.com/seo-rii/maki/pull/414)). For developers:
  `MAKI_TEST_REQUIRE_IPV6=1`, set for the whole workflow, makes the HTTP and
  gRPC tests of a connect to the other address family fail without the IPv6
  loopback address instead of skipping, and `scripts/run_root_tests.py`
  passes it on and runs `maki-crypto-http`'s unit tests as root, one of which
  drops SYNs with a packet filter in a private network namespace ([automated
  CI](docs/testing.md#automated-ci)).

- **A CI job drives whole attachments and the documented quick start through a
  runner's kernel** (AUD-203, 2026-11-26;
  [#406](https://github.com/seo-rii/maki/pull/406)). For developers:
  `kernel-lifecycle` runs on every pull request, push to `main`, dispatch and
  scheduled run, on GitHub's `ubuntu-latest` VM with its kernel, udev and
  systemd. It runs `scripts/privileged-linux-validation.sh --install-missing
  --kill-daemon` on `/dev/nbd15`. After its workload the runner now writes and
  fsyncs data, detaches while `scripts/privileged_validation_opener.py` holds
  the device open and requires that the detach returned only after the
  opener began to close it (AUD-197), attaches again and compares the data;
  with the new `--kill-daemon` it kills nbdkit under the mount, cleans up
  without it, starts a new nbdkit, attaches a third time and detaches, and it
  writes more evidence files, which the runbook lists. The job then builds
  the Debian package from the commit and runs the Debian guide's install
  blocks, the quick start and its first-volume bootstrap, which
  `scripts/documented_quickstart.py` writes into one program, under systemd
  with the installed units. It builds in release mode twice and keeps its logs
  as `kernel-lifecycle-logs`. The runner is Ubuntu, not the Debian 12 primary
  platform, and the job qualifies nothing ([automated
  CI](docs/testing.md#automated-ci), [privileged validation
  runbook](docs/qualification/privileged-linux-validation.md)).
- **Fuzz targets for the witness's RPC and etcd readers, the remote providers'
  response readers and the root helper's readers of command output and
  sysfs** (AUD-204, 2026-11-26;
  [#408](https://github.com/seo-rii/maki/pull/408)). For developers: `fuzz/`
  gains `witness_rpc`, `witness_etcd`, `http_response`, `websocket_response`,
  `grpc_response`, `helper_reports` and `helper_sysfs` (the last two Linux
  only), with 270 more seeds in `fuzz/seeds/<target>/`, which the default
  suite replays (`helper_sysfs`'s create and remove temporary directories). A
  change to one of these readers may need its seeds written again
  (`MAKI_FUZZ_WRITE_SEEDS=1 cargo test -p maki-fuzz-harness --test
  review_fuzz_corpus`). `maki-witness`, `maki-crypto-http`,
  `maki-crypto-websocket` and `maki-crypto-grpc` gain a `fuzzing` feature,
  and `maki-privileged`'s now also exposes the executor's readers. Only the
  harness enables them: `cargo build --workspace` turns them on through
  feature unification, a release build does not, and no packaged binary
  changes. `fuzz/Cargo.toml` also patches the vendored `hyper`, `rustls` and
  `tungstenite`, the scheduled `fuzz` job runs the seven targets too, and a
  big-endian host replays netlink seeds made in its own byte order
  ([fuzzing](docs/testing.md#fuzzing)).

- **Fuzz targets for the root helper's NBD handshake and netlink answer and
  for `maki-backing`'s records, committed seeds, and a scheduled fuzz job**
  (AUD-200, 2026-11-25; [#401](https://github.com/seo-rii/maki/pull/401)). For
  developers: `fuzz/` gains `nbd_handshake`, `nbd_netlink` and
  `backing_records`, each of the nine targets is one line that calls its
  function in `fuzz/harness` (`maki-fuzz-harness`, a workspace member), and
  each has seeds in `fuzz/seeds/<target>/`, which the default suite replays on
  stable (`review_fuzz_corpus.rs`). A change to an encoding needs the seeds
  written again (`MAKI_FUZZ_WRITE_SEEDS=1 cargo test -p maki-fuzz-harness
  --test review_fuzz_corpus`). A `fuzz` job in the scheduled tier, also run on
  dispatch, runs every target for 30 seconds from its seeds with the pinned
  `nightly-2026-11-24` and `cargo-fuzz` 0.13.2, and `fuzz/Cargo.toml` now
  patches the vendored `serde_json` and `bytes`, which the fuzz workspace had
  taken from crates.io. `maki-privileged` and `maki-backing` gain a `fuzzing`
  feature that only the harness enables: `cargo build --workspace` turns it on
  through feature unification, a release build does not, and no packaged
  binary changes ([fuzzing](docs/testing.md#fuzzing)).

- **Release workflow**: `.github/workflows/release.yml`, dispatched by hand on `main` with a
  tag `v<workspace version>-rc.<n>`, builds the Debian 12 candidate bundle with
  `scripts/prepare_release.py` and the RHEL 9 RPM with `packaging/rpm/build-rpm.py`
  from the same commit, and publishes them with the source, both manifests and one
  `SHA256SUMS` as an unsigned GitHub pre-release. Final tags are refused while
  production approval is pending; a run that fails before publication leaves no
  tag ([publishing a pre-release](docs/releasing.md#publishing-a-pre-release)).

- **An RPM package for RHEL 9 and its rebuilds** (AUD-148, AUD-154,
  2026-11-24; [#374](https://github.com/seo-rii/maki/pull/374)).
  `packaging/rpm/build-rpm.py` packages the prebuilt release artifacts like
  the Debian builder, with the same files, owners and modes, units, sysusers
  and tmpfiles rules and scriptlet behaviour (`%preun` refuses an erase under
  a live attachment and never blocks an upgrade). It declares `Requires:
  nbdkit-server, lvm2, xfsprogs, util-linux, systemd >= 249, kmod` and
  `Conflicts: nbdkit-selinux`: by the targeted policy, that module's label on
  `/usr/sbin/nbdkit` keeps systemd from starting `maki@` under enforcing
  SELinux, and the `nbdkit` metapackage installs it, so dnf refuses to install
  Maki beside it and refuses a later transaction that would add it. Maki
  therefore cannot be installed on a host that needs the module for libvirt or
  virt-v2v. The package's `maki@.service` runs `/usr/sbin/nbdkit`: the builder
  rewrites the one `ExecStart=/usr/bin/nbdkit` line, and SPEC §10 requires the
  unit to name nbdkit by its absolute path, never by a bare name that systemd
  would look up in `/usr/local` first. `SOURCE_DATE_EPOCH` must be given, 1990
  or later ([packaging/rpm/README.md](packaging/rpm/README.md)).
  *Superseded in part by AUD-161
  ([#384](https://github.com/seo-rii/maki/pull/384)): `%preun` cannot stop a dnf
  transaction, so the package is dnf-protected and also conflicts with the
  `nbdkit` metapackage.*

- **A RHEL 9 installation guide** (AUD-158, 2026-11-24;
  [#374](https://github.com/seo-rii/maki/pull/374)): BaseOS and AppStream
  only, the toolchain, the build and installation, `modprobe nbd`, the LVM
  devices file and SELinux. RHEL 9 is not qualified: nothing has run on a RHEL
  kernel or with SELinux enforcing, and nothing has attached a device there
  ([RHEL 9 installation](docs/getting-started/installation-rhel.md)).
  *Changed on 2026-11-27 (AUD-209,
  [#412](https://github.com/seo-rii/maki/pull/412)): on every change CI boots
  Rocky Linux 9.9 with SELinux enforcing as a KVM guest and attaches through
  its kernel; Rocky Linux is a rebuild of RHEL, not RHEL, and nothing has run
  on RHEL itself.*

- **CI checks a RHEL 9 userspace and connects a kernel NBD device** (AUD-155,
  AUD-156, 2026-11-24; [#375](https://github.com/seo-rii/maki/pull/375),
  [#374](https://github.com/seo-rii/maki/pull/374)). A `rhel9` job in a CentOS
  Stream 9 container builds the packaged binaries, checks the plugin ABI
  against EL9's nbdkit header, runs the `maki-privileged`, `maki-attach` and
  `maki-nbdkit` suites with EL9's nbdkit 1.38, and builds, installs, verifies
  and removes the RPM, on the runner's Ubuntu kernel. The Ubuntu job loads the
  `nbd` module and connects and disconnects a real `/dev/nbdN` through the
  helper as root; `MAKI_TEST_REQUIRE_NBD=1`, `MAKI_TEST_REQUIRE_NBDKIT=1` and
  `MAKI_TEST_REQUIRE_NBD_HEADERS=1` make the NBD tests fail there instead of
  skipping ([automated CI](docs/testing.md#automated-ci)).

- **Concurrent and mixed benchmark workloads**: configurable concurrency,
  sequential/random access, read ratio, working set, FUA and periodic drained
  FLUSH; setup is separate from measurement. Reports preserve existing schema-1
  fields and add per-class/barrier latency, pending/resource peaks and optional
  Linux RSS. A deterministic endpoint outage/recovery harness compares 1/2/8/32
  callers ([benchmark guide](docs/benchmark.md)).

- **Complete Engine request metrics**: actual active requests are separate from
  retained admission slots. Full read/write/trim/FLUSH/FUA latency includes
  admission, provider and storage waits plus errors and cancellation; exactly
  one outcome is recorded per public Engine call. Explicit journal-sync timing
  includes failed and background barriers; legacy successful storage series
  retain their meaning ([metric boundaries](docs/observability.md#request-counts-and-latency-boundaries)).

- **Same-identity initial remote enrollment recovery**: an administrator can
  resume a never-activated authority using an approved storage identity and
  exact current fence. A durable supplementary v1 identity/capacity binding
  and a fresh writer namespace preserve interrupted artifacts; successful
  activation permanently prevents enrollment reset. Existing remote COW and
  witness-state bytes are unchanged
  ([procedure](docs/rollback-protection.md#resume-interrupted-initial-enrollment),
  [compatibility](docs/durable-recovery.md#protected-outer-backing-formats)).

- **Safe automatic remote-writer namespace reclamation**: authenticate the
  current physical root, retain authority sources and live file handles, then
  durably retire quiescent lower-fence namespaces before confined deletion.
  `maki volume gc` retries cleanup without claiming a writer
  ([rollback protection](docs/rollback-protection.md#remote-namespace-reclamation)).

- **Optional etcd-quorum witness HA**: stateless TLS frontends share a pinned
  cluster/key through linearizable reads and exact canonical-state transactions;
  identity-pinned endpoint sets retry identical operations within one deadline.
  Explicit `maki-witness init-etcd` initializes new authorities; there is no
  automatic local fallback or restore of rolled-back witness state
  ([service guide](docs/remote-witness-service.md)).

- **Remote rollback witness (experimental)**: a TLS 1.3 mTLS service persists
  exact compare-and-swap state, monotonic writer fences and restore epochs.
  A new remote outer backing V2 gives every session a separate reserved
  namespace. Offline snapshot, exact-current takeover and approved-root restore
  commands never lower the witness. Existing local format bytes are unchanged;
  no in-place conversion is supported ([operations](docs/remote-witness-service.md),
  [migration](docs/durable-recovery.md#protected-outer-backing-formats)).
- **Measured whole-process memory admission**: optional
  `security.memory_budget` verifies the applied cgroup-v2 ceiling, visible
  ancestor headroom and memlock before recovery and READY. The opt-in systemd
  template sets operator-measured limits; defaults remain unchanged
  ([configuration](docs/configuration.md#measured-memory-budget)).

- **Benchmark reports**: `maki-benchmark --json` records throughput, IOPS,
  bounded-memory p50/p95/p99 latency estimates, final FLUSH time and verified
  readback; `--fua` selects durable individual writes. Invalid workload
  arguments are refused before creating a volume; recovered geometry is
  rechecked before I/O. See
  [performance profiles](docs/performance.md).
- **Release candidate preparation**: `scripts/prepare_release.py` builds
  committed source in isolation and bundles the Debian package, source
  archive, host/toolchain provenance and SHA-256 checksums without publishing.
  See [release preparation](docs/releasing.md).
- [Deployment qualification profiles](docs/deployment/qualification-profile.md)
  define acceptance criteria for performance, memory, provider maintenance,
  backup/restore and cutover; protected volumes have a separate
  [witness backup/recovery procedure](docs/rollback-protection.md#backup-and-recovery-procedure).

- **Overlay memory bound**: `limits.max_overlay_bytes` (default 256 MiB)
  and `limits.max_overlay_entries` (default 262144) bound the in-memory
  ciphertext overlay independently of the on-disk journal; a write over the
  bound checkpoints inline and fails with ENOSPC if that cannot make room,
  and the worker checkpoints at half the bound (R4-005;
  [configuration](docs/configuration.md#journal-bounds)). Existing
  configurations gain the defaults; set either to `0` to keep the old
  unbounded behaviour.
- **Deep-check verdict**: `maki check --deep` and `maki-check --deep` end
  with `deep check verdict: clean | recoverable | unrecoverable`; slot damage
  that a validated journal record repairs is a warning, not an error
  (R4-004; [operations](docs/operations.md#volume-lifecycle)).
  *Changed on 2026-11-25 (AUD-195,
  [#403](https://github.com/seo-rii/maki/pull/403)): on Linux a check of a
  backing root it may not write states `unproven` in place of `clean` and
  `recoverable`.* *Corrected on 2026-11-27 (AUD-217,
  [#422](https://github.com/seo-rii/maki/pull/422)): a deep check that stops
  before its verdict (the volume lock held, no valid checkpoint state copy, a
  superblock that no longer loads) prints no verdict line and exits 1.*
- **Debian package safety**: `prerm` refuses removal while a volume is
  attached (upgrades are exempt), the builder verifies every artifact's ELF
  architecture against `--architecture`, and native library dependencies are
  added to `Depends` with `dpkg-shlibdeps` by default (the build now needs
  `dpkg-dev`; `--no-shlibdeps` opts out for test fixtures only) (R4-003, R4-007;
  [packaging README](packaging/debian/README.md)).
- **Runtime logging**: the nbdkit plugin, `maki` and `maki-check` install a
  stderr `tracing` subscriber (`MAKI_LOG` filter, default `info`), so
  checkpoint, journal-sync, control-server and store-repair warnings reach
  the service journal (R4-001; [operations](docs/operations.md#logging)).
- Opt-in **envelope v3** with durable TRIM and Linux backing-space
  reclamation: `maki volume create <config> --discard` (`8f7606f`,
  `e911471`; [space reclamation](docs/space-reclamation.md)).
- Experimental **rollback-protected backing** with an independent local
  witness for new Linux volumes (`d2c4fb7`, `64ff710`;
  [rollback protection](docs/rollback-protection.md)). Not qualified.
- **Debian package** builder and package contract tests (`8b69efc`,
  `07fed8b`); the package owns nothing under `/etc/maki` and never starts a
  volume.
- **`[lvm_identity]` pins** (complete PV set, VG and target LV UUIDs) in the
  attach configuration. Grow and detach refuse a configuration that changes
  them, and recovery checks the identity attach recorded against them.
- **Native readiness**: the data-plane unit is `Type=notify` and reports
  `READY=1` only after recovery, provider checks and control binding
  (`2a3f023`).
- **Physical write reservation**: `posix_fallocate` of the journal range and
  the checkpoint slot before a record is published (`ced2bda`).
- **Bounded recovery replay** through a fixed 1 MiB payload batch (`733833c`).
- **Volume capacity plan** in `maki volume inspect` (`5803be8`).
- Verified **WSS and gRPC TLS/mTLS** for the WebSocket and gRPC providers
  (`a1aac42`).
- **RustSec dependency audit** in CI (`47058d2`).
- Optional **random plaintext prefix** (`crypto.random_prefix_bytes`, 16 to
  256 bytes in multiples of 16) prepended to every crypto unit before
  provider encryption; new volumes only (`562b397`, `1115e1d`;
  [random plaintext prefixes](docs/random-plaintext-prefix.md)).
- Getting-started, deployment and status documentation; `LICENSE`,
  `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and a documentation link
  checker in CI (2026-09-23).

### Changed

- **A remote read-only command holds what it logs until the authority answers,
  and the refusal of a root without a remote lock file no longer sends the
  operator to open a copy to write** (AUD-212, AUD-213, 2026-11-27;
  [#418](https://github.com/seo-rii/maki/pull/418)). With a remote witness,
  `maki check`, `maki check --deep` and `maki volume inspect` wrote what they
  logged while they read (the store's warnings, such as `shard data file not
  listed by the loaded catalog copy; adopting it`, and the view's own
  `read-only rollback session stopped: …`) to stderr at once, also when the
  authority then answered that it no longer selected what was read. Those
  lines are now held back from the moment the view is open and written, in
  order, once the authority has answered that it still selects what was read,
  before the report or the error. When it has not (it changed, answered so
  that the view stopped, or could not be asked), they are dropped, any warning
  about the connections to the authority among them, and `warning: dropped N
  log lines held back since the volume was opened: the remote authority did
  not confirm that it still selects what was read` comes before the error. At
  most 16 MiB of log text is kept (`log lines held back beyond 16 MiB of log
  text were not kept`), and lines that a panic leaves unreleased are dropped
  with `log lines held back were dropped unwritten: nothing released them`. A
  command with a local witness or none holds nothing, and exit statuses,
  reports and the number of inspections are unchanged. The read-only refusal
  of a missing lock file said that opening the backing where it can be written
  recreates the file, which no open does for the `rollback.lock` of a remote
  root's current namespace: on a `maki volume snapshot` destination, which
  holds that namespace without its lock, following it with attach or `volume
  snapshot` claimed a writer and moved the volume onto the copy, after which
  its own root was refused as one that does not hold the authority's current
  generation. That refusal now says that the root is probably a copy, such as
  a snapshot destination, and not to attach it or open it to write; the
  refusal of a remote root without `remote.operation.lock` says that it is
  either the live root with the file removed or a copy made without its lock
  files, and not to attach a copy or open it to write. A local root's refusals
  are unchanged. The operations and remote witness guides say how to put a
  volume that was moved onto a copy back on its own root. For developers,
  `maki_nbdkit::daemon::read_failure` and `still_current` return `Reported`
  instead of `String`, and `maki_core::logging` gains `hold` ([checking a
  backing that cannot be
  written](docs/operations.md#checking-a-backing-that-cannot-be-written),
  [snapshot, takeover and
  restore](docs/remote-witness-service.md#snapshot-takeover-and-restore),
  maki(8), SPEC §27).
- **Attach probes a set's endpoints at the same time, and the probes extend
  the service's start deadline** (AUD-216, 2026-11-27;
  [#419](https://github.com/seo-rii/maki/pull/419)). Attach probed the
  endpoints of a remote provider one after another, so each endpoint that
  never answered delayed the next by about three times `timeout` (six over
  WebSocket) and two `retry.initial_delay`s: at the default 10 s, three such
  WebSocket endpoints listed before a healthy one, six over HTTP or gRPC, or
  two at a 30 s `timeout`, held its probe past `maki@`'s
  `TimeoutStartSec=180`, and systemd would stop the start. The endpoints are
  now probed at once: endpoints that do not answer cost the attach about one
  probe however many are listed (60 s for three WebSocket endpoints at 10 s in
  the pull request's test), and the attach still waits until every probe has
  ended. Their key canary checks still run one at a time in configuration
  order, so the same endpoint establishes, rewrites or verifies the canary as
  before, and endpoints that pass their self-test and then fail their canary
  check with transport failures still delay the ones after them, each by up to
  its own probe. Every endpoint is now sent its self-test requests at the
  start, also one listed after an endpoint whose probe refuses the attach,
  which was never contacted before. The refusals, their texts and their order
  (configuration order) are unchanged, and a lone endpoint is probed as
  before. With `NOTIFY_SOCKET` set, each probe request that ends, answered or
  failed, and each request of the cross-endpoint check after the probes sends
  `EXTEND_TIMEOUT_USEC=180000000` with `STATUS=Probing crypto endpoints`, at
  most once every 30 s, a limit it shares with recovery's extension. The
  deadline still expires when no request ends for about 150 s, and the
  engine's self-test after the probes extends nothing. A failed notification
  fails the start as during recovery, with "startup progress notification
  failed" for both, where recovery's said "recovery progress notification
  failed" ([WebSocket and gRPC
  contracts](docs/configuration.md#websocket-and-grpc-contracts), [data-plane
  readiness](docs/operations.md#data-plane-readiness), SPEC §10, §34).
- **A TLS failure inside a remote call is handled where its error is
  recognised** (AUD-214, AUD-215, 2026-11-27;
  [#417](https://github.com/seo-rii/maki/pull/417)). Over WebSocket, a TLS
  protocol failure on an established connection while a request waits for its
  reply (a record that does not decrypt, a fatal alert from the server)
  returns `endpoint fatal: websocket TLS authentication or protocol failure`,
  where it returned `retryable: connection lost: closed`: the endpoint's
  circuit opens at once, and a retry-safe provider no longer sends the request
  again on a new connection within the call. The request still counts as sent,
  so the dispatcher fails it over only for a retry-safe provider. A connection
  lost otherwise, also one closed without `close_notify`, stays retryable.
  Over gRPC, a TLS failure of tonic's reconnect inside a cached channel now
  retires the channel also when no call had completed on it and its first 4 ×
  `timeout` had not passed, so the next call opens a new connection through
  Maki's own connection attempt, whose failure is marked unsent and fails over
  also for a provider that is not retry-safe; before, such a channel was kept,
  and the next call's TLS failure counted as sent. A TLS failure on an
  established gRPC connection, a TLS 1.3 server's refusal of the client
  certificate among them, is still a retryable status counted as sent, which
  the documents now say ([provider error
  signals](docs/configuration.md#provider-error-signals), [known
  limitations](docs/status.md#known-limitations), SPEC §18).
- **With a remote witness, attach compares the configuration before it claims
  a writer, and a read-only command asks the authority three or four times
  instead of before every backing operation** (AUD-207, 2026-11-27;
  [#411](https://github.com/seo-rii/maki/pull/411)). With remote rollback
  protection attach compared the configuration with the volume only after
  opening the backing to write, which claims a writer at the authority,
  copies the current generation into a namespace of its own and recovers the
  volume there, so a configuration it refused had already raised the
  authority's fence and replaced its session and current namespace; a remote
  provider built on its own did the same. Attach, and such a provider, now
  compare the settings fixed at creation and
  `backing.rollback_protection.capacity` with the authority's current
  generation before the claim, reading the two superblock copies through a
  view that authenticates every page and asks the authority nothing: a
  mismatch is refused with the error attach gave after recovery, after one
  inspection, and the authority and the root are unchanged. A superblock page
  that does not authenticate is refused there with `rollback arena page
  authentication failed`, where the claim was granted and the copy failed with
  `source page authentication failed`. A normal attach reads at most two
  4 KiB pages more and opens the arena once more. `maki volume inspect`,
  `maki check` and `maki check --deep` of a remote-protected volume send three
  inspections (four for `--deep`) however large the volume, where they sent
  one per backing operation: the view asks while it opens, and the commands
  ask again once they have read everything, before they print their report,
  and before they report a failure. An authority that changed while one of
  them read fails it at the end, with `the remote authority changed after the
  backing was opened read-only`, where it failed at the next operation, and a
  command that fails after the open reports the authority's change instead of
  its own error, or names an authority it could not ask beside it. An
  authority that cannot be reached now matters only while the view opens and
  at those last inspections. A local witness is still read before every
  operation, a writer's view still asks before every operation, and exit
  statuses are unchanged ([checking a backing that cannot be
  written](docs/operations.md#checking-a-backing-that-cannot-be-written),
  [diagnostic
  commands](docs/remote-witness-service.md#diagnostic-commands-and-writer-ownership),
  maki(8), SPEC §20, §27).
- **The gRPC transport starts the other address family halfway through a
  `timeout` under 600 ms, and an HTTP `timeout` under 600 ms gets a warning**
  (AUD-206, 2026-11-27; [#414](https://github.com/seo-rii/maki/pull/414)). The
  gRPC transport waited 300 ms before it dialed the endpoint host's other
  address family, so with a `timeout` of 300 ms or less a call whose first
  family did not answer failed, retryable and unsent, and only a later call
  could be served. It now waits `min(300 ms, timeout / 2)`, counted from the
  dial; nothing changes at 600 ms or more. The HTTP transport keeps its
  300 ms, which no option of reqwest 0.12.28 or 0.13.5 changes, so with an
  HTTP `timeout` of 300 ms or less the other family is still never tried while
  the first does not answer. A `remote-http` configuration whose
  `[crypto.http] timeout` is under 600 ms is still accepted, and gets a
  warning: `[crypto.http] timeout is 300ms: while the first address family of
  an endpoint's host does not answer, the other family gets less than half of
  a timeout under 600 ms and is never tried at 300 ms or less, so such a host
  can fail every connect`. `maki volume create` prints it to stderr after it
  has created the volume, `maki check` and `maki check --deep` print it as a
  `warning:` line with their verdict and exit status unchanged, and attach
  logs it at the warning level once the configuration matches the volume.
  Nothing changes on the wire over HTTP or WebSocket ([remote HTTP
  mapping](docs/configuration.md#remote-http-mapping), [WebSocket and gRPC
  contracts](docs/configuration.md#websocket-and-grpc-contracts), [known
  limitations](docs/status.md#known-limitations)).
- **Detach and cleanup wait for a held-open device without the attach lock**
  (AUD-205, 2026-11-27; [#410](https://github.com/seo-rii/maki/pull/410)).
  After its disconnect a detach or cleanup waits up to 15 s for the device to
  let go of the connection, and it held the global attach lock meanwhile, so
  when the devices of many volumes were held open and the volumes stopped
  together, their cleanups queued 15 s each on it and from about the eighth
  on reached `TimeoutStopSec=120` before they had changed anything. When the
  first look after the disconnect still shows the connection, they now let go
  of the lock for the wait and take it again, in turn, before they act: the
  waits run side by side, and each cleanup holds the lock only for its own
  steps and the checks before the record is retired. In CI three such stops
  with a 10 s hold ended together after about 10 s, where they had ended about
  10, 20 and 30 s after they began. A device held open for the whole 15 s
  still fails its own cleanup with "disconnect has not completed", its volume
  torn down and its record kept. A record that another helper of the volume
  retired during the wait ends the command as a success, logged as such, and
  one that an attach of the volume replaced meanwhile fails it with "the
  volume's attach record was replaced while this helper waited for … to let
  go of the disconnected connection: another helper attached volume … again.
  That record and its attachment are left as they are". During the wait an
  `attach` of the same volume is refused while the device shows the
  connection; since the record still names the device, another volume's
  attach pinned to it is refused at once ("… is named by the attach record of
  volume …") and an automatic one for which it was the last free device fails
  with no free NBD device, where all three waited for the lock: run them again
  once the detach has finished. The first-volume block's `flock -n` now gets
  the lock during such a wait, and `nbd-connect` still refuses the device. A
  cleanup that waited queues for its second turn behind every helper that
  took the lock meanwhile, an attach of another volume included (up to its
  180 s start timeout), so systemd can end it there, after its volume is torn
  down, and the next cleanup retires the record. The failed-start hook keeps
  the lock through its wait. For developers,
  `maki_privileged::exec::AttachLock` and `lock_attach` are gone ([privileged
  helper](docs/operations.md#privileged-helper), maki-attach(8), SPEC §6).
- **`maki-attach cleanup` logs the path it takes** (AUD-208, 2026-11-27;
  [#413](https://github.com/seo-rii/maki/pull/413)). Before its first step it
  writes one more `INFO` line to standard error, `<device> shows the
  attachment's connection; cleanup follows the detach path` or `<device> shows
  no connection; cleanup follows disconnected recovery`; a device that shows
  another connection logs its outcome as before. Nothing else changes
  ([privileged helper](docs/operations.md#privileged-helper), maki-attach(8)).

- **`maki check` and `maki volume inspect` read a rollback-protected backing
  they cannot write, and every remote-protected one, read-only** (AUD-202,
  2026-11-26; [#407](https://github.com/seo-rii/maki/pull/407)). On Linux a
  local protected backing whose backing root or witness directory the user
  may not write was refused with "… cannot be written by this process, and a
  rollback-protected backing cannot be checked or inspected read-only: …",
  and `maki` refused a remote-protected one on every root with "read-only
  remote backing inspection is not supported; …". The commands now read such
  a backing through a view that authenticates it against its witness as
  attach does (the manifest the witness selects, every committed page),
  creates, writes, syncs and removes nothing below the backing root or in the
  witness directory, and asks a remote authority only to inspect, never
  claiming a writer there. The report has a `warning: read-only check:` line
  and the deep verdict is `unproven`; exit statuses are unchanged. To ask a
  remote authority the commands now load the witness client's TLS identity
  (`client_key_file` and its certificates), but no volume key or provider
  credential. Unlike on a plain backing, `volume inspect` and the fast check
  take a lock here too: all three take the writer's locks shared
  (`rollback.lock` and `witness.lock`, or `remote.operation.lock` and the
  current namespace's `rollback.lock`), and refuse a backing that a daemon or
  another writer holds ("… is held by another process") and one whose lock
  file is missing ("… is missing, and a read-only open cannot create it"); a
  daemon that starts meanwhile fails to take its lock, with a remote witness
  at attach's operation lock. With a remote witness a record that changes
  while the locks are taken refuses the command ("the remote authority
  changed while the backing was opened read-only: run the command again"),
  and each backing operation inspects the authority again, over a connection
  of its own, so a deep check of a large volume sends many requests. By the
  code, a configuration pointed at a snapshot destination is refused, since a
  snapshot has no `rollback.lock` in its namespace; that was not tested.
  Damage, a manifest the witness does not select, a capacity mismatch and an
  unfinished creation are refused as attach refuses them. A local pair whose
  two directories can both be written is opened to write, as before, and
  `maki-check <root>` still refuses protected roots ([checking a backing that
  cannot be written](docs/operations.md#checking-a-backing-that-cannot-be-written),
  [diagnostic
  commands](docs/remote-witness-service.md#diagnostic-commands-and-writer-ownership),
  maki(8), maki-check(8), SPEC §27). *Changed on 2026-11-27 (AUD-207,
  [#411](https://github.com/seo-rii/maki/pull/411)): a remote view's command
  sends three inspections, four for `check --deep`, whatever the volume
  holds, and the refusal of a snapshot destination is tested.*
- **An HTTP connect gives each of the endpoint host's addresses a share of the
  timeout, and the WebSocket transport reaches the other address family with
  a short timeout** (AUD-201, 2026-11-26;
  [#405](https://github.com/seo-rii/maki/pull/405)). An HTTP endpoint host's
  address that did not answer held the request until its `timeout`, and a
  live address after it in the same family was never tried. Each of a
  family's `n` addresses may now take `timeout / n` to connect, so a dead
  address before a live one costs half the `timeout` for two. When every
  address fails within its share, the request fails then, before its
  `timeout`, retryable and marked unsent, so the dispatcher may send it to
  another endpoint even for a provider that is not `retry_safe`; it reads
  `connect timeout: …` when the first address's share ran out and `transport
  error: …` when the first refused the connection, where it used to fail at
  its `timeout` with `request timeout: …`. The shares are fixed: a live
  address slower than its share to accept the connection is given up, so keep
  `timeout` well above `n` times the expected connect time (one lost SYN
  delays a Linux connect by 1 s). A host with one address per family behaves
  as before. The other family still starts after 300 ms, which reqwest does
  not let Maki change, so with an HTTP `timeout` of 300 ms or less it is never
  tried when the first does not answer. With less than 600 ms of a connect
  left when it dials, the WebSocket transport starts the other family halfway
  to the deadline instead of after 300 ms, so a `timeout` of 300 ms or less
  still reaches it ([remote HTTP
  mapping](docs/configuration.md#remote-http-mapping), [WebSocket and gRPC
  contracts](docs/configuration.md#websocket-and-grpc-contracts), [known
  limitations](docs/status.md#known-limitations)).

- **Detach and cleanup wait for the device to let go of a disconnected
  connection** (AUD-197, 2026-11-25;
  [#398](https://github.com/seo-rii/maki/pull/398)). When something held
  `/dev/nbdN` open at the disconnect, `maki-attach detach`, `cleanup` (the
  attach unit's `ExecStop`) and the failed-start hook's rollback failed at
  once with "disconnect has not completed; keeping the attach record for
  cleanup retry" and had to be run again. Like `nbd-disconnect`, they now wait
  up to 15 s, looking every 100 ms and within the hook's 30 s for its
  commands, until the device no longer shows the connection, and then remove
  the record. A device that still shows it keeps the record and fails with the
  same message and status, up to 15 s later; run the command again once
  nothing holds the device open. The wait holds the attach lock, so another
  volume's helper can wait up to 15 s longer for it, and when the devices of
  many volumes are all held open and they stop together, the cleanups from
  about the eighth on reach `TimeoutStopSec=120` and fail by timeout with
  their records kept ([privileged
  helper](docs/operations.md#privileged-helper), maki-attach(8), SPEC §6).
  *Changed on 2026-11-27 (AUD-205,
  [#410](https://github.com/seo-rii/maki/pull/410)): the wait no longer holds
  the attach lock, so the held-open devices of volumes that stop together wait
  side by side.*
- **The WebSocket transport goes on to the endpoint host's other addresses
  within its connect deadline** (AUD-198, 2026-11-25;
  [#400](https://github.com/seo-rii/maki/pull/400)). An address that did not
  answer held every connect until the deadline, and the next address was never
  tried. The transport now resolves the host itself, starts the other address
  family 300 ms after the first, and gives each address of a family but the
  last an equal share of what is left of the request's `timeout`: a dead IPv6
  route before a live IPv4 address costs about 300 ms per connect, and a dead
  address before a live one of the same family at most its share. With a
  `timeout` of 300 ms or less the other family is never tried when the first
  does not answer. The certificate is still verified for the URL's host, and a
  TLS or upgrade failure is not retried at another address. A connect opened
  after the request waited for the connection now ends with the request's
  attempt, and then reports "websocket connect timeout" where it reported
  "websocket request timeout"; both are retryable. The HTTP transport sets no
  connect timeout, so there a dead address before a live one of the same
  family can still take the whole request `timeout` ([WebSocket and gRPC
  contracts](docs/configuration.md#websocket-and-grpc-contracts), [known
  limitations](docs/status.md#known-limitations)). *Changed on 2026-11-26
  (AUD-201, [#405](https://github.com/seo-rii/maki/pull/405)): with less than
  600 ms of a connect left the WebSocket transport starts the other family
  halfway to the deadline, and the HTTP transport gives each address of a
  family a share of its `timeout`.*
- **On Linux, `maki check`, `maki-check` and `maki volume inspect` read a
  backing root they may not write, read-only** (AUD-195, 2026-11-25;
  [#403](https://github.com/seo-rii/maki/pull/403)). On a read-only mount, on
  a root without write permission for the user and on an immutable root they
  failed with "Read-only file system", "Permission denied" or "Operation not
  permitted". They now open such a root read-only and create, write and sync
  nothing; a root they may write is opened as before. Each such report has a
  `warning: read-only check:` line, records to replay and journal repairs are
  warnings, and the deep verdict is `unproven`, or `unrecoverable` with an
  error, never `clean` or `recoverable`. Exit statuses are unchanged, so an
  `unproven` check exits 0; a script that needs `clean` reads the verdict
  line. The deep check takes the volume lock shared and fails without
  `volume.lock`, which it cannot create there. The root alone decides: a
  `0500` root with writable files, which a writable check used to read, is now
  checked read-only, so its deep verdict is `unproven` where it was `clean` (a
  script that needs `clean` sees `unproven` there, with status 0), and a
  writable root whose files cannot be written still fails. A local
  rollback-protected backing whose root or witness directory cannot be written
  is refused with the directory, its setting and the reason, since opening one
  rewrites its authenticated state ([checking a backing that cannot be
  written](docs/operations.md#checking-a-backing-that-cannot-be-written),
  maki(8), maki-check(8), SPEC §27). *Changed on 2026-11-26 (AUD-202,
  [#407](https://github.com/seo-rii/maki/pull/407)): such a backing, and every
  one with a remote witness, is now read read-only.*
- **Attach probes a lone remote endpoint and refuses one that cannot serve
  as configured** (AUD-188, AUD-189, 2026-11-25;
  [#392](https://github.com/seo-rii/maki/pull/392)). Under the default
  `stall` policy an attach whose only endpoint failed TLS authentication
  (another host's certificate, an untrusted CA) waited without end: it
  logged nothing, bound no control socket and never became ready. A lone
  endpoint is now probed like the endpoints of a set, which adds one
  self-test and canary round at attach. An endpoint failure in any attempt
  (TLS authentication, a 401, 403 or 404, an invalid WebSocket upgrade)
  refuses the attach under either policy, and so does a failure after
  which a request of a provider that is not `retry_safe` may have reached
  the endpoint. A lone endpoint that failed only transiently, when the
  request may be sent again, is still retried under the policy, after a
  `WARN` that names it, its failure and the policy. "no remote endpoint is
  reachable; attach refused" now names each endpoint's failure, and a lone
  endpoint that fails its self-test otherwise is refused with "endpoint
  "<name>" failed its self-test: ...". The gRPC transport classifies a TLS
  failure that reaches a call (tonic reconnecting a cached channel to a
  server whose certificate is not trusted) as an endpoint failure, which
  opens the endpoint's circuit at once. A TLS 1.3 server's refusal of the
  client certificate over gRPC is still reported as retryable
  ([provider error signals](docs/configuration.md#provider-error-signals),
  SPEC §34, §35).
- **`maki status` reports a stopped rollback session as degraded, and the
  daemon logs a failed requested checkpoint or drain** (AUD-187, AUD-191,
  2026-11-25; [#395](https://github.com/seo-rii/maki/pull/395)). A
  rollback-protected session that stopped for good (after `maki volume
  takeover` or a restore beside a live daemon, an older anchor put back, an
  uncertain commit or a damaged page) failed every request with EIO while
  `maki status` reported `state: ready` and `maki_volume_state` 1, until a
  checkpoint worker pass failed, or for good. From the first request that
  finds the stop, status now reports `state: degraded` with a reason that
  starts `rollback session stopped:` and names the cause, and
  `maki_volume_state` is 2; nothing clears it, and the daemon logs one
  `WARN` with the cause. With a remote witness a restart alone does not
  reopen such a volume: the next daemon's claim is refused until `maki
  volume takeover` ([failure handling](docs/operations.md#failure-handling)).
  A checkpoint that `maki checkpoint` requested, and a drain (the `drain`
  verb or the one shutdown runs), that fails now logs one `WARN` per
  request, `requested checkpoint failed: <error>` and `drain failed:
  <error>; I/O admission stays closed until a drain succeeds`, without a
  rate limit; only the checkpoint worker's failures were logged before
  ([logs](docs/observability.md#logs)).
- **`maki volume create` continues a local creation that stopped after its
  witness anchor** (AUD-159, AUD-169, AUD-170, 2026-11-24;
  [#382](https://github.com/seo-rii/maki/pull/382)). A local rollback creation
  that stopped between its anchor and its superblock left a pair that
  `create` refused and that held no volume, and both directories had to be
  emptied by hand. Running `create` again now opens the pair against its
  witness and continues it if, and only if, it holds nothing but an
  unfinished creation, with the capacity that creation reserved; every other
  pair is refused as before and left unchanged. Until then the daemon,
  `maki check` and `maki volume inspect` fail when the backing is opened and
  name `maki volume create` as what continues it, where they said "No such
  file or directory" or a bare "no valid superblock"; `maki check` therefore
  prints an error and exits 1 for such a pair, where it printed a failed
  report. The first superblock copy of a new volume is written as
  `superblock.next` and renamed, so a creation can leave that transient file
  and no longer a `superblock.a` without a superblock; a root that holds such
  a file from an earlier release is refused with its causes and never
  initialized again
  ([local creation](docs/rollback-protection.md#local-configuration-and-creation),
  [operations](docs/operations.md)).
- **A remote `maki volume create` continues a root in which a binding was
  left without its format marker** (AUD-172, 2026-11-24;
  [#387](https://github.com/seo-rii/maki/pull/387)). An interrupted
  `volume resume-enrollment` could keep the binding, staged or published,
  and lose the marker after a power loss; `create` then answered
  `remote enrollment requires an empty backing` and `resume-enrollment`
  `No such file or directory`. Recovery now makes the marker's name durable before it
  stages a binding, and `create` continues such a root: a staged binding is
  written again, and a published one is accepted only if it is the binding
  this creation would write, under an authority that is released and was
  never activated. A binding for another authority or capacity and a staged
  entry that is not a regular file the command can write again are refused
  with a message that names the way out. A binding that cannot be read keeps
  `remote enrollment requires an empty backing` from `create`, and
  `resume-enrollment` under a released authority says what to do with it
  ([resume enrollment](docs/rollback-protection.md#resume-interrupted-initial-enrollment)).
- **A connect keeps its negotiated connection across busy answers, waits for
  the daemon's export and can move to the next free NBD device** (AUD-162 to
  AUD-164, 2026-11-24; [#383](https://github.com/seo-rii/maki/pull/383)). The
  helper retries two answers every 100 ms for up to 5 s, counted from the
  first of them: the kernel's `EBUSY`, now on the connection it has already
  negotiated while that is still usable, and the daemon's "export not
  available" (`NBD_REP_ERR_UNKNOWN` to `NBD_OPT_GO`), which nbdkit also
  answers for a moment after a previous connection closed. A server that
  really has no default export is therefore refused after 5 s, not at once.
  The daemon logs a warning for each second connection it refuses. An attach
  that allocated its device itself and finds it busy to the end moves to the
  next free device instead of failing, replacing its record first; it then
  prints a second `# bound NBD device:` line. A pinned `nbd_device` is never
  given up ([prerequisites](docs/operations.md#prerequisites), SPEC §6).
- **An A/B metadata store empties an undecodable copy before it writes it**
  (AUD-171, 2026-11-24; [#386](https://github.com/seo-rii/maki/pull/386)). A
  copy that a power loss left torn could, after a second interrupted store,
  hold a complete earlier record that no store had acknowledged. A store now
  truncates such a copy to zero length and syncs that before it writes the
  record; a copy that decodes is never emptied. After a power loss a copy
  can be found empty where it held torn bytes, which every release reads as
  an invalid copy. The store needs free blocks again and can fail with
  `ENOSPC` on a filesystem that has none, where it fails closed
  ([architecture](docs/architecture.md), SPEC §43).

- **A connect retries while the kernel reports the NBD device busy** (AUD-150,
  2026-11-24; [#375](https://github.com/seo-rii/maki/pull/375)). The kernel
  refuses `NBD_CMD_CONNECT` with `EBUSY` while anything has the unconnected
  device open, as udev's probe does right after a disconnect, so an attach
  right after a detach of the same device could fail, with `nbd-client` too.
  The helper retries every 100 ms for up to 5 s within the step's deadline, on
  a fresh connection to the daemon and only while the device still shows no
  connection; a device held open longer still fails as busy
  ([prerequisites](docs/operations.md#prerequisites)).
  *Superseded in part by AUD-162 to AUD-164
  ([#383](https://github.com/seo-rii/maki/pull/383)): the negotiated connection
  is kept while it is usable, the 5 s count from the first busy answer, and
  an attach that allocated the device itself moves to the next free one.*

- **A displaced attach record is retired automatically once nothing of its
  attachment remains** (AUD-134, 2026-11-23;
  [#367](https://github.com/seo-rii/maki/pull/367)). A trusted record whose
  NBD device is connected under another identity (an NBD client started
  outside the helper, or two volumes left sharing a device by an older
  helper) was refused by every verb until root removed it by hand. Attach,
  cleanup, recover and detach now retire it under the attach lock, without
  running a command or touching the device, when the record names its VG
  UUID, no device-mapper device of that VG exists on the host, every holder
  of the device and its partitions is an LVM mapping of another VG, nothing
  is mounted at the recorded mountpoint or from a mapping of that VG, no
  other record names the device with the same VG UUID or with none, the
  backend stays the same across two observations, and every observation can
  be read. Otherwise the refusal adds `The record is not retired
  automatically: <reason>`. A record that names no VG UUID (an attach without
  `[lvm_identity]` pins that stopped before the connect) keeps the manual
  step. Cleanup with a configuration that does not match the record is
  refused with "cleanup configuration does not match the trusted attach
  record" ([privileged helper](docs/operations.md#privileged-helper)).
- **`maki volume gc` goes on past a namespace it cannot examine or finish
  retiring** (AUD-113, AUD-138;
  [#357](https://github.com/seo-rii/maki/pull/357),
  [#365](https://github.com/seo-rii/maki/pull/365)). A stale namespace that
  GC cannot open or examine (a root-owned leftover of an interrupted root
  `takeover`, an entry it may not read) is kept and listed in a new
  `skipped_unreadable` array of `{"name", "error"}` objects. One whose
  retirement stopped at a step that changes it alone (an unlink, its
  directory sync or removal, or its rename when its own directory is
  immutable or append-only and the root is neither) is kept as the step left
  it and listed in a new `unfinished` array; a later pass resumes it.
  `counts` gains `skipped_unreadable` and `unfinished`. Both cases used to
  end the pass with an error, leaving every higher-fence namespace on disk
  with a full arena; `maki volume gc` now exits 0 with the entries listed.
  A pass still ends with an error for an authority failure or a changed
  record, a root whose marker, current generation, binding, listing or mount
  identity cannot be read, a rename the root or its filesystem refuses, a
  failed sync of the root directory and an entry that changed identity while
  it was being retired. The automatic pass after an activation, which was
  silent, logs a `WARN` when it did not complete and names the first entry
  it could not examine or finish
  ([retire old writer namespaces](docs/remote-witness-service.md#retire-old-writer-namespaces)).
- **An interrupted creation can be run again** (AUD-114, AUD-115, AUD-136,
  AUD-139; [#358](https://github.com/seo-rii/maki/pull/358),
  [#366](https://github.com/seo-rii/maki/pull/366)). A remote `maki volume
  create` writes its format marker and its binding under a temporary name
  (`rollback.format.next`, `remote.enrollment.next`) and renames them into
  place. `create` completes a root that holds only an unwritten or staged
  marker, and `resume-enrollment` continues a creation cut while it wrote
  the binding, which needed the file moved out by hand; an invalid binding
  that an older binary left keeps that step. `maki-witness init` no longer
  creates an empty `remote.state` first, so an interrupted `init` can be run
  again; an empty `remote.state` is still refused, now with its causes and
  the way out. A local-witness `maki volume create` completes a backing and
  witness directory that hold only what an interrupted creation leaves (the
  marker, the arena, a first manifest slot that holds only zeros or the
  initial empty manifest and a second that holds only zeros, `anchor.next`),
  where it refused every pair that was not empty, for example after the arena
  reservation ran out of space. It still never creates over an existing
  `anchor` or over a backing that committed data, short of both manifest
  slots lost or zeroed entirely, and a creation that stopped after
  publishing the anchor is still refused (*superseded by AUD-159,
  [#382](https://github.com/seo-rii/maki/pull/382): `create` continues
  it*). The local witness
  no longer installs an empty anchor first; an empty `anchor` that an
  earlier release left is refused with an explanation
  ([local creation](docs/rollback-protection.md#local-configuration-and-creation),
  [remote enrollment](docs/rollback-protection.md#resume-interrupted-initial-enrollment),
  [witness initialization](docs/remote-witness-service.md#initialize-a-local-authority)).
- **Background validation of a quarantined endpoint treats a generic refusal
  or a provider failure as inconclusive** (AUD-116, AUD-140;
  [#350](https://github.com/seo-rii/maki/pull/350),
  [#364](https://github.com/seo-rii/maki/pull/364)). A request refused
  without an integrity verdict (over HTTP every 4xx the transport classifies
  as a request error, such as 400, 421 or a 422 without the
  `maki-crypto-error` header; a WebSocket `bad-request`; a gRPC
  `InvalidArgument`, `NotFound`, `OutOfRange` or bare `FailedPrecondition`),
  a validation RPC that the endpoint set's own byte budget refuses, and a
  `ProviderFatal` error of the candidate's own provider no longer mark the
  endpoint `rejected` for the life of the daemon. It stays quarantined and is
  validated again every `circuit_breaker.open_initial`, doubling up to
  `open_max`, with a warning per attempt. Only proof of another contract
  excludes it: an integrity refusal of the other endpoint's ciphertext or of
  the key canary, a wrong plaintext, a foreign compatibility id, a claimed
  capability it does not honour or an explicit refusal of the volume's
  context. An endpoint that always answers so is still never admitted and is
  now probed for as long as the daemon runs. Attach is unchanged
  ([endpoint validation](docs/configuration.md#websocket-and-grpc-contracts)).
- **An `EndpointSet` bound to one plaintext size reports only that size**
  (AUD-117, [#351](https://github.com/seo-rii/maki/pull/351)). With
  `with_plaintext_size`, as the daemon builds its set, the reported
  capabilities list the bound size alone (`[512]` instead of `[512, 4096]`,
  or `[512 + prefix]` with a random prefix), so the batch scheduler refuses a
  unit of another size alone at admission instead of letting it fail a
  coalesced call. Limits and security claims are still the intersection over
  every endpoint.

### Fixed

- **2026-11-27 tenth round: the fuzz qualification's verdicts** (AUD-220,
  AUD-223, AUD-224; [#416](https://github.com/seo-rii/maki/pull/416),
  [#421](https://github.com/seo-rii/maki/pull/421),
  [#424](https://github.com/seo-rii/maki/pull/424)). For developers.
  `fuzz_campaign.py merge` records the inputs libFuzzer's merge wrote and the
  attempts its log shows, and the merge fails on a crash, timeout,
  out-of-memory or leak input, on a second attempt and on a log that shows
  none: libFuzzer's `-merge=1` exits 0 after an input fails its inner process
  and leaves the input out, so such a merge had qualified its target. The fuzz
  job uploads each shard's output as one archive (`shard.tar` in
  `fuzz-shard-<target>-<n>`), and the merge job the merged corpus as
  `merged.tar` in `fuzz-corpus-<target>`; the merge requires
  `--planned-shards`, reads each planned shard's archive and fails without a
  corpus of every one, and the summary checks the merge's sources against the
  plan and each merged corpus against its shard record's count.
  `actions/upload-artifact@v4` had failed with `Maximum call stack size
  exceeded` on the shard corpora of four targets (143,835 to 405,750 files),
  whose merges then held their seeds alone and which the summary of the first
  24 CPU-hour campaign (run 45983119347) called qualified. `nbd_handshake`'s
  entry function runs the server side of its socket pair on the calling
  thread, where it started a thread for every input, under which every process
  of that campaign's AddressSanitizer build ran out of memory after about 10
  million executions ([fuzz
  qualification](docs/testing.md#fuzz-qualification)).
- **2026-11-27 tenth round: tests** (AUD-221, AUD-222, AUD-225;
  [#416](https://github.com/seo-rii/maki/pull/416),
  [#423](https://github.com/seo-rii/maki/pull/423)). For developers.
  `documented_quickstart.py --stop-once` requires the mark its shim leaves, so
  a bootstrap whose first run failed before the shimmed command no longer
  passes as stopped there. Rules of the validation scripts that no test held
  now have tests: a plan without targets, the coverage run's status, a round
  after one that failed, the stopped bootstrap's record, connection and reset,
  a leftover backend or mount after the stop together, and the guest runner
  phase's and the `run` command's exit statuses. Refused test endpoints are
  sockets that are bound and never listen, held for the whole test, where a
  listener was dropped and its port could be handed to a parallel test's
  `127.0.0.1:0` bind, which failed two tests of maki-crypto-websocket's
  `review_unsent_failover.rs` in CI ([automated
  CI](docs/testing.md#automated-ci)).
- **2026-11-25 ninth round: refusals of the rollback-protected backing**
  (AUD-183 to AUD-186; [#391](https://github.com/seo-rii/maki/pull/391)).
  `maki volume gc` refuses a remote backing root that does not hold the
  authority's current generation in attach's words ("this backing root
  does not hold the remote authority's current generation (...); check the
  witness address and backing root before retrying"), where it printed "No
  such file or directory (os error 2)" or "no exact remote witnessed
  manifest". The daemon, `maki check`, `maki volume inspect` and
  `maki-benchmark` refuse a backing root or witness directory that does not
  exist, is not a directory or that the user may not open with its path,
  the setting that names it (`backing.root`,
  `backing.rollback_protection.witness_root`) and what to check, where they
  printed the bare system error; `check` and `inspect` word a backing root
  this way for plain volumes too. A local backing without its format
  marker is offered `volume create` only where `create` continues it;
  otherwise the refusal names the entries that stop a creation, such as a
  `lost+found`. `volume create` refuses a root whose arena, manifest slot or
  staged marker is not a regular file with one name before it publishes
  anything and names the entry. It used to publish its marker and then fail
  at every run for such an arena, fail every run before the marker for a
  link or a directory under the staged marker's name, and fail with the
  bare error of the open that checks it for a slot; a FIFO or a second name under the staged
  marker's name, which the failed first run removed, is now refused until
  it is removed. It removes a staged marker that its user may not open, as
  a creation run as root and killed before it gave the file away leaves
  one, and continues in one run; and it refuses an arena or slot its user
  may not open with the way out (`chown`, `chmod`)
  ([local creation](docs/rollback-protection.md#local-configuration-and-creation)).
- **2026-11-24 eighth round: `maki-attach` messages** (AUD-166, AUD-168;
  [#385](https://github.com/seo-rii/maki/pull/385)). An executed connect step
  logs and reports the backend identifier it sent, where it printed the
  plan's placeholder `'<generated-connection-uuid>'`. An error about the
  attach state directory, `attach.lock` or the configuration that `verify`
  reads names the path, a permission refusal for a caller who is not root
  ends with `; run this command as root`, and a program that cannot be
  started is named (`cannot run modprobe: ...`), where each printed only the
  operating system's error. A failed step prints `failed with status 1`, or
  `failed without an exit status (a signal ended it)`, where it printed
  `status Some(1)` and `status None`. Exit statuses are unchanged.
- **2026-11-24 eighth round: release tooling** (AUD-174, AUD-175;
  [#380](https://github.com/seo-rii/maki/pull/380)). The publish step of the
  release workflow read a failed query of the releases or of the tag as "the
  tag is free" and went on to create the draft; it now fails there, having
  created nothing, and `scripts/release_assets.py state` refuses an answer
  that is empty, not JSON, an error object or incomplete.
  `scripts/prepare_release.py` refuses a source tree that is not the top
  level of its own Git checkout, where a published source archive unpacked
  below another checkout got that repository's version
  ([rebuilding from a published source archive](docs/releasing.md#rebuilding-from-a-published-source-archive)).

- **2026-11-23 fifth audit: command-line output** (AUD-122, AUD-123;
  [#353](https://github.com/seo-rii/maki/pull/353)). The five binaries no
  longer exit 101 with a panic when stdout or stderr cannot be written. A
  closed stdout is not an error, and the command keeps its own status: a
  clean `maki check … | grep -q …` under `pipefail` passes again and a failed
  check still exits 1. Another failure to write a command's result exits 1
  and names the verdict, a command that has already changed something
  (`volume takeover`, `gc`, `restore`, `maki-attach verify`) only warns, and a
  diagnostic stderr cannot take is dropped. An executing `maki-attach` verb no
  longer panics at a log line or a device announcement nobody reads, and an
  unwritable copy of its plan never decides the outcome. `maki-attach --help`,
  `-h`, `help`, `--version` and `-V`, `maki-witness --version` and `-V`, and
  `maki-benchmark --version` and `-V` exit 0, each only as the sole argument.
  `maki --help` says that the helper verbs only print the `maki-attach`
  command, `maki-attach grow --add-bytes` is refused with the reason, and two
  validation messages lost a stray line break.
- **2026-11-23 fifth audit: privileged helper** (AUD-121). A volume group of
  64 logical volumes, which preflight admits, no longer fails proof capture
  and rolls back on every attach: the inventory behind the mapping proof
  holds 64 devices and 64 mappings, and the preflight refusal of a 65th LV
  names the limit ([#355](https://github.com/seo-rii/maki/pull/355);
  [checking LVM](docs/storage-recovery.md#checking-lvm-before-activation)).
- **2026-11-23 follow-ups: command line and plugin** (AUD-144). The nbdkit
  plugin's five stderr lines (configuration refusals, a failed startup or
  shutdown) no longer turn a log pipe whose reader has gone into a caught
  panic and EIO, and `cargo doc` no longer documents the `maki-witness`
  binary over the `maki_witness` library
  ([#363](https://github.com/seo-rii/maki/pull/363)).
- **2026-11-23 follow-ups: CI on Windows** (AUD-146). The CI formatting step
  runs on Linux only: on Windows `cargo fmt --all --check` passes every
  target's root file to one rustfmt command line, which the workspace has
  outgrown ("The filename or extension is too long", os error 206), so from
  #369's merge `main`'s Windows jobs stopped before their clippy and test
  steps; each pull request's own run passed them. Formatting does not
  depend on the platform; check it on Windows one package at a time with
  `cargo fmt -p <package> --check`
  ([#372](https://github.com/seo-rii/maki/pull/372);
  [running checks](docs/testing.md#run-checks-locally)).
- **2026-11-23 fifth audit and follow-ups: tests and CI** (AUD-128 to
  AUD-132, AUD-145). Eight golden vectors freeze the allocation map, the
  shard catalog, the checkpoint state, the durable proof, the journal
  segment and record headers and the v2 and v3 superblock envelopes, and an
  inventory test requires a vector for every record magic
  ([#352](https://github.com/seo-rii/maki/pull/352)). The Linux CI job runs
  the test targets that need root as root (`scripts/run_root_tests.py`),
  fails when a Python suite leaves bytecode in the checkout and runs every
  script test module ([#360](https://github.com/seo-rii/maki/pull/360));
  since [#366](https://github.com/seo-rii/maki/pull/366) the root step also
  runs maki-backing's unit tests. Tests that passed without asserting (the
  mount-target rule, the release of locked pages, the memory-budget path
  bytes), a test that used failpoints without their lock and native tests
  that skipped without a notice are fixed
  ([#361](https://github.com/seo-rii/maki/pull/361)). Fixtures no longer
  depend on the umask, a `TMPDIR` private to root or a host trust store
  ([#362](https://github.com/seo-rii/maki/pull/362)), nor on `/dev/shm` or a
  short `TMPDIR`, and the Python campaign tests no longer leave a `0077`
  umask behind; `MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1`, which CI sets, makes
  a missing second filesystem fail the rollback tests instead of skipping
  them ([#371](https://github.com/seo-rii/maki/pull/371); [running
  checks](docs/testing.md#automated-ci)). See the remediation log's
  [fifth](docs/review-remediation.md#internal-audit-fifth-round-2026-11-23-aud-113aud-132)
  and
  [sixth](docs/review-remediation.md#sixth-round-follow-ups-2026-11-23-aud-133aud-146)
  rounds.

- **2026-11-23 audit: privileged helper and daemon admission** (AUD-101,
  AUD-102). A mount with an empty source (`mount -t tmpfs '' /dir`) anywhere
  in the namespace no longer fails NBD allocation, attach, detach, cleanup,
  recovery, grow and the workload verify gate for every volume, or the start
  of a memory-budgeted daemon: both mount-table parsers split a record by
  field position. Memory-budget admission reads the table as a stream, so a
  host with thousands of mounts is no longer refused with "oversized kernel
  field /proc/self/mountinfo"; one record longer than 1 MiB still is
  ([#337](https://github.com/seo-rii/maki/pull/337); [memory
  budget](docs/configuration.md#measured-memory-budget)). See the
  [remediation
  log](docs/review-remediation.md#internal-audit-fourth-round-2026-11-23-aud-098aud-112).
- **2026-11-23 audit: storage, remote providers and secrets** (AUD-098 to
  AUD-100). A file whose name is not UTF-8 in a volume's `data/` or
  `journal/` directory no longer fails every attach or leaves `maki check`
  inconclusive: the scans skip it like any other unknown name, while volume
  creation and rollback enrollment still refuse it
  ([#338](https://github.com/seo-rii/maki/pull/338)). A request with a unit
  that is refused before anything is sent (an empty ciphertext recorded by a
  damaged slot, a ciphertext above the provider's maximum, plaintext of a
  size the provider does not accept) now fails alone at scheduler admission;
  with a provider that is not retry-safe it used to fail every request
  coalesced with it, so one such slot gave healthy reads EIO
  ([#334](https://github.com/seo-rii/maki/pull/334);
  [batching](docs/configuration.md#batching-and-pending-bounds)). The search
  of each encrypt result for its own plaintext no longer builds a table
  derived from that plaintext in ordinary heap memory, where it was not
  page-locked and was freed without erasure
  ([#335](https://github.com/seo-rii/maki/pull/335); [transport
  memory](docs/transport-memory.md#local-providers-and-key-material)).
- **2026-11-23 audit: tests** (AUD-112). The preserve-first rule of the A/B
  metadata stores is pinned for every record type by the copy a torn retry
  keeps, and for the checkpoint state at the volume level
  ([#345](https://github.com/seo-rii/maki/pull/345)). The memory-budget
  admission recheck, which no test covered, has one
  ([#337](https://github.com/seo-rii/maki/pull/337)).

- **2026-11-17 audit: durability and recovery** (AUD-052 to AUD-062, AUD-091).
  A worker pass started by the interval, the overlay bound or a write refused
  for space now checkpoints the records already durable when its journal sync
  fails, as watermark and low-space passes did, and a watermark at or below the
  segment size no longer costs a sync and a checkpoint per write
  ([#176](https://github.com/seo-rii/maki/pull/176)). A final journal segment
  exactly one header long whose header fails its checksum, left by an older
  binary's torn header write, no longer blocks attach when the durable proof
  and mark name earlier segments
  ([#177](https://github.com/seo-rii/maki/pull/177)). Allocation map padding
  bits, and positions past the device's end in a partial last shard, no longer
  make a never-written short shard read EIO
  ([#184](https://github.com/seo-rii/maki/pull/184),
  [#186](https://github.com/seo-rii/maki/pull/186)). See the remediation log's
  [second](docs/review-remediation.md#internal-audit-second-round-2026-11-17-aud-052aud-090)
  and
  [third](docs/review-remediation.md#internal-audit-third-round-2026-11-17-aud-091aud-097)
  rounds.
- **2026-11-17 audit: remote providers** (AUD-066 to AUD-071). WebSocket and
  gRPC responses no longer take about 43 and 49 times their size in memory
  while they are parsed ([#173](https://github.com/seo-rii/maki/pull/173)). A
  request of a provider that is not retry-safe now fails over when its attempt
  failed before any request byte was sent (a refused connection, a failed TLS
  handshake, a refused WebSocket upgrade); under `stall` it stays pending while
  its only endpoint refuses connections, instead of failing at once. An
  operation whose deadline expires while it waits for endpoint admission
  reports the last endpoint error, as the other deadline exits do
  ([#174](https://github.com/seo-rii/maki/pull/174)). The patched serde_json
  builds error messages in linear time and erases the owned raw text a
  `&RawValue` rejects ([#183](https://github.com/seo-rii/maki/pull/183)).
- **2026-11-17 audit: witness, rollback protection and admission** (AUD-078 to
  AUD-080, AUD-082, AUD-092, AUD-093). One name that is not UTF-8 in a remote
  rollback backing root no longer makes every GC pass fail (which left
  predecessor namespaces on disk until the filesystem filled), and a damaged
  manifest length no longer allocates about 72 MiB per open
  ([#181](https://github.com/seo-rii/maki/pull/181)). A root
  `maki check --deep`, `maki volume inspect` or other open of a local rollback
  witness keeps the anchor's owner, so the daemon can still attach, and a root
  `maki volume create` names the witness directory in its `chown` warning
  ([#182](https://github.com/seo-rii/maki/pull/182)). Memory-budget admission
  reads the mount table as bytes, so one non-UTF-8, newline or very deep mount
  path elsewhere no longer stops every memory-budgeted volume from starting
  ([#180](https://github.com/seo-rii/maki/pull/180)). A failure before a local
  witness authority renames its new state now fails only that request, instead
  of making `serve` answer every later request as unavailable until a restart,
  and `maki volume restore` reads a snapshot it may not write, such as one on a
  read-only mount or with immutable files
  ([#189](https://github.com/seo-rii/maki/pull/189); [witness
  service](docs/remote-witness-service.md#initialize-a-local-authority)).
- **2026-11-17 audit: tooling and tests** (AUD-063 to AUD-065, AUD-083). The
  vendor erasure contract resolves every workspace feature
  ([#183](https://github.com/seo-rii/maki/pull/183)). `CrashableBacking` and
  `MemBacking` refuse directory names as locks and in `remove` as `FileBacking`
  does, three recovery and journal regressions that could not fail now fail
  without the rewrite they are named after, and MAKI-011 has a dedicated test
  ([#175](https://github.com/seo-rii/maki/pull/175)).

- **2026-11-16 audit: durability and recovery** (AUD-001 to AUD-007). Recovery
  rewrites both superblock copies from their exact bytes and completes a
  missing one before any other repair, so a failed or killed `volume create`
  can no longer leave a volume whose only superblock copy is in the page cache;
  every attach now does a few extra 4 KiB superblock writes and syncs
  ([#164](https://github.com/seo-rii/maki/pull/164)). `maki volume create` also
  refuses a root that still holds an earlier volume's `superblock.*`,
  `shard-catalog.*` or `canary.*`
  ([#164](https://github.com/seo-rii/maki/pull/164)). A torn journal segment
  header left by a failed segment roll no longer blocks attach
  ([#166](https://github.com/seo-rii/maki/pull/166)). Concurrent writers can no
  longer take the space an inline reclaim frees for the write that ran it,
  which turned a reclaimable journal or overlay bound into ENOSPC; this
  replaces the four-round retry of the R4-005 follow-up. Watermark and
  low-space checkpoints sync the journal first instead of applying nothing, and
  still checkpoint durable records when that sync fails
  ([#168](https://github.com/seo-rii/maki/pull/168)). Recovery's rewrite of the
  journal it adopts is covered by a power-loss sweep
  ([#167](https://github.com/seo-rii/maki/pull/167)). See the [remediation
  log](docs/review-remediation.md#internal-audit-2026-11-16-aud-001aud-051).
- **2026-11-16 audit: remote providers** (AUD-019 to AUD-025). A gRPC peer can
  no longer panic a call with malformed `grpc-status-details-bin` or change its
  error class with undecodable `grpc-message` text, and IPv6-literal gRPC TLS
  endpoints can be built ([#150](https://github.com/seo-rii/maki/pull/150)).
  Under `stall`, a contract violation ends an operation only once every
  validated endpoint has broken the contract for it; until then the request
  waits for the remaining peers, including one whose circuit is cooling
  ([#154](https://github.com/seo-rii/maki/pull/154)). A WebSocket upgrade
  refused with any 3xx or 4xx other than 408 and 429 opens that endpoint's
  circuit, a retry-safe request fails over, and attach quarantines the endpoint
  instead of refusing ([#155](https://github.com/seo-rii/maki/pull/155)). HTTP
  refuses a close-delimited success response and a raw encrypt response shorter
  than its plaintext as contract errors, which previously stored a truncated
  body as the unit's ciphertext, and a JSON response no longer takes about 43
  times its size in memory ([#157](https://github.com/seo-rii/maki/pull/157)).
  WebSocket reads no longer rewrite the whole retained read buffer
  ([#160](https://github.com/seo-rii/maki/pull/160)).
- **2026-11-16 audit: logging, witness and privileged helper** (AUD-027,
  AUD-028, AUD-033, AUD-037 to AUD-041). `tungstenite`, `tokio_tungstenite` and
  `reqwest` are capped at `debug`, and `tungstenite::protocol` at `info`,
  whatever `MAKI_LOG` says, so `MAKI_LOG=trace` no longer writes WebSocket
  payloads, upgrade query credentials or close reasons to the journal; their
  trace output is no longer available
  ([#155](https://github.com/seo-rii/maki/pull/155);
  [logging](docs/operations.md#logging)). Validation errors no longer quote an
  HTTP operation path ([#159](https://github.com/seo-rii/maki/pull/159)).
  Enrollment recovery refuses a root that holds another volume's data,
  `maki volume resume-enrollment` refuses a provider the build cannot
  construct, and a local socket denial (netfilter EPERM) is a transport
  failure, so witness failover continues and the rollback backing refuses only
  that operation ([#156](https://github.com/seo-rii/maki/pull/156)). The
  privileged helper reads the mount table as bytes, so one non-UTF-8 mount path
  anywhere no longer fails attach, detach, recovery and NBD allocation for
  every volume, and the workload verify gate runs in a unit without
  `CAP_FOWNER` ([#153](https://github.com/seo-rii/maki/pull/153)).
- **2026-11-16 audit: tooling and tests** (AUD-008 to AUD-018, AUD-042 to
  AUD-046). The privileged validation runner requires the expected permission
  denial instead of any failure, the nightly plugin and fake-provider gates
  require the exact symbol and refusal, and `scripts/run_cargo_tests.py` runs
  `--doc` selections ([#151](https://github.com/seo-rii/maki/pull/151)). The
  vendor erasure check compares resolved features with a reviewed list
  ([#160](https://github.com/seo-rii/maki/pull/160)); the standalone vendor
  test loggers no longer depend on unmaintained `humantime` (RUSTSEC-2026-0542,
  [#155](https://github.com/seo-rii/maki/pull/155)). `CrashableBacking` keeps a
  failed sync's writes uncertain instead of lost, writes back whole 4 KiB
  pages, and ends every handle and lock at a simulated power loss
  ([#165](https://github.com/seo-rii/maki/pull/165)). `MemBacking` applies
  POSIX path rules, a zero-length `allocate_range` is a no-op on every backing
  including `FileBacking`, and the fake provider, `ManualClock` and
  `DeterministicScheduler` follow the contracts they stand in for; two tests
  that failed only as root now inject their faults for root too
  ([#163](https://github.com/seo-rii/maki/pull/163)).

- **Mixed benchmark write verification** (BUG-134, 2026-10-20): check the
  latest expected value at every initialized slot after measurement, including
  writes that no measured read visits. Reports separate written/read-after-write
  slot coverage and final sweep count/time from measured read verdicts, IOPS and
  latency. Fault controls reject discarded measured writes and a lost final
  write; the sweep uses the current engine/cache rather than crash recovery
  ([benchmark guide](docs/benchmark.md)).

- **2026-10-14 project review**: inline reclaim keeps reclaiming while a
  checkpoint has not covered every append, so a concurrent FUA no longer turns
  a write into ENOSPC (BUG-089). `maki-check --deep` fails instead of passing
  when its own superblock read fails (BUG-090). Journal segment and shard file
  names parse only in canonical form, and the fast checker reports the orphan
  shards recovery adopts (BUG-091). An endpoint-fatal answer opens that
  endpoint's circuit at once (BUG-094). The root helper never passes a mount
  source to `blkid` as an option (BUG-096). A configured gRPC CA works on hosts
  with an empty trust store (BUG-097). nbdkit callbacks fail with EIO instead
  of aborting on a panic, and failed requests are logged, rate-limited
  (BUG-098). The nightly release gates run to completion, with the etcd quorum
  gate behind `etcd-qualification` (TEST-003), and tokio's `test-util` is no
  longer part of production builds. See the
  [remediation log](docs/review-remediation.md#project-review-2026-10-14).
- **2026-10-14 second review pass**: binding the control socket refuses any
  file at the address other than a dead socket (BUG-099). Volume creation
  writes the superblock last, so a creation interrupted before it writes a
  superblock copy is not a volume (BUG-100). The checkpoint worker waits one interval after a failed pass
  (BUG-101), and a write refused for free space wakes it (BUG-106). A
  coalesced provider call never carries one unit twice (BUG-102). A remote
  witness that cannot be reached refuses each operation without stopping the
  session; a mismatch still stops it (BUG-103). Witness workers are given only
  to authenticated connections (BUG-104). An encrypt result that carries its
  own plaintext is refused on every call (BUG-105). Remote attach and takeover
  authenticate the current generation in the local root before changing the
  authority, so a damaged or foreign root leaves it unchanged rather than
  Claimed (BUG-107). The crash simulator models inodes and atomic rename, and
  the durability sweeps retire superseded failed writes (TEST-004, TEST-005).
  Control commands take `--socket <path>` in place of the volume
  configuration, so `maki-admin` members can use them, and only parse a
  configuration they are given (BUG-108).
- **2026-10-14 third review pass**: configuration errors never print a value
  (BUG-113). Only encrypting cryptsetup mappings count as encrypted swap
  (BUG-114). A gRPC TLS handshake is bounded by the connect timeout
  (BUG-115), and WebSocket frames outside the response contract fail the
  connection as a contract error (BUG-117). Attach refuses a mountpoint with
  mounts below it (BUG-118) and `grow --size-bytes` takes plain digits only
  (BUG-116). Superblocks with unknown flags or format version are refused
  (BUG-109); `maki-check --deep` no longer writes into a directory that is not
  a volume (BUG-110); the witness keeps accepting after EMFILE (BUG-111);
  `maki` and `maki-check` gain `--help` and `--version` (BUG-112); key-file
  open errors say why (BUG-119); a non-UTF-8 nbdkit `config=` path is refused
  (BUG-120). A power-loss sweep with TRIM joins the release gates (TEST-006),
  a page-lock unit test no longer races on Windows (TEST-007), and witness
  transport tests no longer time out on loaded runners (TEST-008).
- **2026-10-15 fourth review pass**: a gRPC response cut inside a message, or
  OK without one, is a contract error (BUG-121). File credentials and TLS
  files must be absolute paths (BUG-122). A failed hole punch no longer fails
  an idle checkpoint, so drain and shutdown work while punching fails
  (BUG-123). The daemon and CLIs raise the soft descriptor limit for shard
  files, and a failed shard open other than a missing file is reported as
  I/O, not corruption (BUG-124). A panic while the volume write lock is held
  stops the engine until the volume is attached again (BUG-125). An encrypt
  result carrying its plaintext anywhere is refused, and `grow --size-bytes`
  must be a multiple of 512 (BUG-105, BUG-116 follow-ups). The operator guides
  correct the overlay metrics, full-backing behaviour, start-limit reset,
  instance naming and witness takeover procedures.

- **2026-10-12 correctness and recovery review**: journal sync/recovery retries
  reassert accepted file lengths and verified bytes; volume creation holds its
  exclusive lock through final directory sync. Completed batch errors cancel
  earlier pending batches while successful outputs keep unit order. HTTP
  oversized responses and gRPC `Unimplemented` are endpoint failures for
  breaker/failover, with unsafe no-resend preserved. Resolved gRPC metadata and
  daemon intermediates are erased on all ownership paths. Sentinel publication
  is atomic without replacement, and identical retries rewrite then synchronize
  bytes and length. Attach compares stored geometry before provider setup;
  malformed attach CLI options are usage errors; unrepresentable retry probe
  intervals are rejected without library panics. Admission waits without holding
  global capacity and reselects available peers. Rust 1.99 warnings are fixed;
  reproducible Rust 1.94 and latest-stable Linux/Windows jobs run independently.
  See [regressions](docs/review-remediation.md#correctness-and-recovery-review--2026-10-12).
- **Bounded recovery slot-write amplification**: every historical record stays
  validated, while only each unit's latest sequence within the existing batch
  writes slot data; a last discard skips superseded writes. Allocation evidence,
  metadata publication order and batch boundaries are preserved.

- **HTTP response JSON ownership**: completed strings and object keys are
  guarded before the full response is parsed, so malformed partial JSON and
  duplicate replacement erase their owned plaintext too. Single-item and
  batch responses share the guarded parser; serde scratch and transport-private
  allocations remain outside that ownership guarantee
  ([memory scope](docs/transport-memory.md)).
- Current support documentation includes the scoped PostgreSQL 17/Debian 13
  and cross-host provider-reset evidence; it no longer presents completed
  reference-provider campaigns as unexecuted work. Production approval remains
  pending.

- A request's provider batches run concurrently within the
  `max_active_callbacks` limit, and a per-item HTTP mapping (no
  `items_path`) is batched one unit per call. Sequential I/O through such a
  mapping with 10 ms of provider latency went from about 330 KiB/s to
  2.8 MiB/s (R5-039).
- **Writes longer than `nbd.maximum_io` were refused and, under buffered
  writeback, silently lost** (R5-038). Linux 6.12 (Debian 13) sends up to
  1280 KiB per request regardless of the advertised 1 MiB maximum; XFS made
  on such a volume could not be mounted. Longer reads and writes are now
  served in `maximum_io` chunks.
- `maki@.service` starts under systemd 257 (Debian 13), which writes
  `LoadCredential=` files with mode `0440`; the credentials directory now
  accepts group read for the service's own group (R5-037).
- NBD WRITE_ZEROES longer than `nbd.maximum_io` (sent by userspace clients
  such as nbdcopy for the holes of a sparse image) failed with EINVAL: the plugin left it to nbdkit's
  single-`pwrite` emulation. Zeroing is now native and chunked, and may
  discard whole units on a `--discard` volume when the client allows it
  (R5-036).
- A bearer token (HTTP header or gRPC metadata credential) or PEM private
  key that happens to be an even-length hex string is used verbatim; the
  daemon used to hex-decode it like a local key and refused to start
  (R5-035). Tokens generated with `openssl rand -hex` were affected.
- `maki@.service` sets `SystemCallFilter=@system-service` with
  `SystemCallErrorNumber=EPERM`, after three packaged PostgreSQL lifecycles
  ran under it without a denial, and `MemoryDenyWriteExecute=yes`, after the
  local and all three remote providers round-tripped data under it.
- Rollback-protected backing (experimental): a write's cost no longer grows
  with committed data (R5-034); a 64 KiB write at 128 MiB committed went
  from about 150 ms to under 1 ms.
- Lowering `backing.journal_segment_size` no longer makes a cleanly stopped
  volume fail recovery as corrupt (R5-033); the setting is now limited to
  1 GiB.
- `maki@.service` adds kernel-log, clock, hostname, realtime, namespace,
  syscall-ABI and address-family restrictions (R5-031).
- `maki-check` no longer creates a missing root directory (R5-026), and the
  deep check no longer reports nonexistent units of a truncated partial last
  shard (R5-027).
- Detach, cleanup and attach rollback no longer require
  `<mountpoint>/.maki-sentinel` (R5-006): a workload that deleted or
  rewrote it blocked `maki-attach cleanup`. The mount is identified from
  kernel metadata, as recovery already did; attach and `verify` still check
  the sentinel.
- `maki-attach` refuses `mountpoint = "/"` (R5-019).
- `maki volume create` refuses a backing root that still holds an earlier
  volume's `data/`, `journal/` or `checkpoint/` files (R5-018); they used to
  be adopted and served by the new volume.
- Package removal is also refused while a `maki-recover@` unit is active
  (R5-015).
- A huge configured circuit-breaker duration no longer panics the
  dispatcher on the first trip (R5-013); `reload cache` refuses a size of 0
  or larger than the device (R5-014).
- v3 discard works under space pressure and on damaged units (R5-011,
  R5-012): tombstones are admitted against the emergency reserve alone, not
  the checkpoint headroom, and a unit whose slot is damaged can be discarded
  (previously EIO). "Already zero" is decided from the slot header, so a
  discard no longer reads every payload twice under the volume lock.
- v3 discard: **trims longer than `nbd.maximum_io` are accepted** (R5-010).
  The maximum block size bounds payloads; kernel discards (`fstrim`,
  `-o discard`) are far larger and all failed with EINVAL.
- v3 discard: a checkpoint **punches retired slots only after its state is
  durable** (R5-008), so a crash or failed state store can no longer leave
  recovery replaying an older write into a released hole (ENOSPC on a full
  backing). A failed punch now defers reclamation instead of failing the
  checkpoint. A failed shard-catalog commit no longer makes later
  reclamation checkpoints panic (R5-009).
- Remote providers: a **broken endpoint now fails over** (R5-005). A
  contract-violating response (malformed JSON, wrong item count, bad
  encoding) or HTTP 404/405/410 counts as an endpoint failure, opens that
  endpoint's circuit and lets a retry-safe request move to a healthy peer;
  previously every request failed while the circuit stayed closed.
- `remote-http` **ignores environment proxies** (R5-003): an inherited
  `HTTP_PROXY`/`ALL_PROXY` no longer receives plaintext encrypt requests.
  Deployments that relied on a proxy to reach the provider must connect to
  it directly.
- **The volume is mounted `nosuid,nodev`** (R5-002). A setuid binary or a
  device node inside the volume no longer takes effect on the host; attach
  verification refuses a mount without both flags, and `maki@.service` sets
  `DevicePolicy=closed`. Workloads that need setuid programs or device nodes
  on the volume are not supported. The `maki-attach verify` workload gate
  refuses a mount without both flags as well: reattach volumes mounted by an
  earlier build before restarting their workload.
- `remote-http`: a combined certificate/private-key PEM (`client_cert_file`
  without `client_key`) now passes the `file` credential checks (no symlink,
  not group/other-readable); every TLS file must be a regular file, so a
  FIFO cannot hang attach ([configuration](docs/configuration.md)).
- `remote-http`: a header credential that resolves to an invalid header
  value (a control character inside it) is refused at attach as
  `ProviderFatal` instead of failing every request as a retryable error.

- `maki-attach` refuses to mount onto a path a non-root user could redirect:
  every ancestor of the mountpoint must be a root-owned, non-group/other-
  writable real directory and the mountpoint a real directory. A workload
  that replaced the mountpoint with a symlink previously got its filesystem
  mounted by root at the symlink target (e.g. `/etc`), beyond rollback and
  detach ([operations](docs/operations.md#privileged-helper)).
- Pinned NBD devices must be spelled canonically (`/dev/nbd1`, not
  `/dev/nbd01` or `/dev/nbd+1`).

- Remote providers: an integrity (or other non-retryable, request-specific)
  rejection of a coalesced batch no longer fails every request merged into
  it; the batch scheduler re-sends each request alone, so a tampered unit
  read by one client cannot turn another client's healthy read into EIO.
  The re-send happens only for a retry-safe provider (a provider that is
  not retry-safe gets the error fanned out, as before), and each re-send is
  counted in flight and abandoned when its caller leaves (R5-004).

- Configuration validation refuses a `control.socket` that names the same
  file as `nbd.socket` (defaults included); binding the control socket
  replaces whatever is at its path.
- The control server's "unknown command" error echoes at most 64 characters
  of the name, so the response always fits the client's 64 KiB line limit.

- `control.group` resolution retries `getgrnam_r` with a larger buffer on
  `ERANGE`; a directory group whose record exceeded 16 KiB made attach fail.

- `file` and `credential` key sources open the credential once
  (`O_NOFOLLOW | O_NONBLOCK` on Unix) and run the regular-file and mode
  checks on the opened descriptor; checking the path and opening it again
  let a swap in between be loaded as the key, and a FIFO could block the
  open.

- `maki check --deep` now probes the slots the allocation map does not list:
  a damaged header there reads as EIO, but the check walked only allocated
  units and reported such a volume `clean` (R4-004 follow-up;
  [operations](docs/operations.md#volume-lifecycle)).

- A write that still exceeded the overlay bound or the journal hard limit
  after its inline reclaim failed with ENOSPC even when the space was held
  by another writer's volatile records, which that reclaim could not retire;
  it now syncs and reclaims again (up to four rounds) before refusing
  (R4-005 follow-up; [configuration](docs/configuration.md#journal-bounds)).

- `maki-attach` now installs a stderr `tracing` sink (`MAKI_LOG`, default
  `info`); its executed steps and halted-rollback errors were silently
  dropped before ([operations](docs/operations.md#logging)).
- The package `prerm` refuses removal when `systemctl list-units` fails,
  instead of reading the empty output as "no active maki units"
  ([packaging README](packaging/debian/README.md#removal-and-upgrade-behaviour)).

- A plaintext-cache hit now skips the ciphertext payload read (it reads the
  64-byte slot header to establish the version) instead of only skipping
  decryption; a hit no longer re-verifies an already validated payload's
  CRC until the entry is evicted; `cache.verify_on_hit = true` restores
  payload verification on every hit and skips only the decryption (R4-006;
  [configuration](docs/configuration.md#read-cache)).
- Local providers now encrypt and decrypt in place inside pre-allocated
  `SecretBuffer`s and key files are read straight into guarded memory, so
  plaintext and keys never first exist in an unlocked allocation; the
  expanded AES key schedules live in a page-locked `SecretBox` under
  `secure-buffers` and are zeroized on drop (R4-002;
  [transport memory](docs/transport-memory.md#local-providers-and-key-material)).

Every fix has a regression test named in the
[review remediation log](docs/review-remediation.md). Highlights that change
observable behaviour:

- Recovery no longer accepts never-synced page-cache bytes after a process
  restart (K-01) and makes the checkpoint state it selects durable before the
  writer resumes (BUG-022).
- A failed `fdatasync` is never retried bare: the journal rewrites and
  verifies the unsynced records before syncing again (F01 / BUG-021).
- Media damage to a shard data file (truncation, damaged slot headers on
  cleared allocation bits) reads as EIO, never as zeros (S-01 residuals,
  `db39faa`). *Corrected on 2026-11-27 (AUD-211,
  [#422](https://github.com/seo-rii/maki/pull/422)): a header that read back
  as zeros over the slot's surviving ciphertext still read as zeros, and reads
  EIO since; the cases that still read as zeros are in the [remediation
  log](docs/review-remediation.md#not-closed-in-the-tenth-round).*
- The attach helper rolls back observed steps on failure, refuses foreign
  mounts, verifies the backend identity before every disconnect, and drains
  control sessions on shutdown (BUG-015, BUG-018, O-07, F06).
- HTTP redirects are refused instead of re-sending plaintext (C-01);
  remote error bodies are redacted.
- Circuit-breaker half-open slots are always returned (N-10 / BUG-004);
  per-RPC deadlines cover gRPC readiness plus the call (BUG-017).

### Documentation

- **2026-11-27 tenth round** (AUD-217 to AUD-219;
  [#422](https://github.com/seo-rii/maki/pull/422),
  [#416](https://github.com/seo-rii/maki/pull/416),
  [#420](https://github.com/seo-rii/maki/pull/420)). The operations guide,
  maki(8) and maki-check(8) say that a deep check that stops before its
  verdict (the volume lock held, a read-only check without `volume.lock`, a
  superblock that no longer loads, no valid checkpoint state copy, a root with
  no superblock file) prints no verdict line and exits 1, where the guide said
  that every deep report states one. The testing guide says that a qualifying
  process's rounds may end early, where it said that every round ran to its
  time limit. The third follow-up round's records change added notes to this
  file's entry for #398 and to the remediation log's AUD-197 row saying that
  the wait no longer holds the attach lock. The records change of the tenth
  round updates the testing guide's and the background storage page's
  statements about the 24 CPU-hour campaign and adds a development guide trap
  about ports that a dropped listener frees. `v0.1.0-rc.2` was tagged at
  `92d4dd4` on 2026-11-26, before the second follow-up round, and no later
  release candidate had been tagged when this was written.
- **2026-11-27 third follow-up round** (AUD-209;
  [#412](https://github.com/seo-rii/maki/pull/412)). The RHEL guide's install
  block checks for the SELinux module with `! rpm -q nbdkit-selinux`: the line
  succeeds while the module is absent and fails if it is installed. With
  `rpm -q`, which exits 1 for an absent package, the block failed exactly when
  the module was absent, as the guide expects ([Install the Maki
  package](docs/getting-started/installation-rhel.md#install-the-maki-package)).
  The README, both installation guides, the support matrix and the status
  page say what the booted-guest jobs run. The records change corrects the
  kernel that the status page, the testing guide and the privileged validation
  runbook gave for #413's run at `8b9ef4d` (`7.0.0-1016-aws`, not
  `7.0.0-1020-azure`) and the testing guide's statements that fuzzing had run
  only on one core and that no campaign had run, and adds three traps to the
  development guide. `v0.1.0-rc.2` was tagged at `92d4dd4` on 2026-11-26,
  before the second follow-up round, and no later release candidate had been
  tagged when this was written.

- **2026-11-26 second follow-up round** (AUD-203;
  [#406](https://github.com/seo-rii/maki/pull/406)). The first-volume block
  exports `LVM_SUPPRESS_FD_WARNINGS=1` before it opens the attach lock on
  descriptor 9, which the LVM commands it runs inherit, so they no longer
  print `File descriptor 9 (/run/maki-attach/attach.lock) leaked on …
  invocation` each; what the block runs and records is unchanged ([first
  volume](docs/getting-started/first-volume.md#1-provision-and-record-the-layout)).
  The records change corrects the operations guide on where a writable open
  of a pair whose witness directory cannot be written, beside a backing root
  that can, fails (it creates a missing `rollback.lock` before it fails at the
  witness) and the comment of `maki-witness`'s `volume_identity`. `v0.1.0-rc.2` was tagged at `92d4dd4`
  on 2026-11-26, before this round.

- **2026-11-25 follow-up round** (AUD-199;
  [#402](https://github.com/seo-rii/maki/pull/402)). The first-volume block
  writes a record of its run, `/etc/maki/attach/<volume>.bootstrap` (root,
  mode `0600`), before it starts the daemon, adds the LVM and filesystem UUIDs
  as it reads them, and prints the record when it stops. Running the same
  block again takes the attach lock and continues from the record: it releases
  the connection with the recorded identifier and finishes, or, when no
  filesystem was recorded, releases the export, removes the record and fails.
  While a record exists, keep it, leave the daemon as it is and run nothing
  else on the device or the VG ([recovering from a failed
  bootstrap](docs/getting-started/first-volume.md#recovering-from-a-failed-bootstrap)).
  The records change says on the status page that only Linux checks a backing
  root it may not write read-only. When this entry was written, no release
  candidate had been tagged since `v0.1.0-rc.1`, which predates this round,
  the ninth and the eighth. *`v0.1.0-rc.2` was tagged at `92d4dd4` on
  2026-11-26, after this round.*
- **2026-11-25 ninth round** (AUD-192;
  [#390](https://github.com/seo-rii/maki/pull/390)). maki-attach(8) says
  which errors tell a caller without the permission to run the command as
  root (those about the state directory, its lock and the gate
  configuration `verify` reads, not the attachment file of the other
  commands) and that `--block-size` goes up to the kernel's page size (4096
  on x86_64). The witness service guide says that a `remote.state` that
  changes or stops decoding under a running `serve` makes it refuse the next
  request as invalid, which stops the session that sent it, before it
  answers unavailable until a restart, and that `serve` logs nothing about
  it. The records change adds to the status page's known limitations that
  the WebSocket transport does not divide its connect deadline across the
  endpoint host's addresses. When this entry was written, no release
  candidate had been tagged since `v0.1.0-rc.1`, which predates this round
  and the eighth. *`v0.1.0-rc.2`, tagged at `92d4dd4` on 2026-11-26, includes
  them.* *Changed on
  2026-11-25 (AUD-198, [#400](https://github.com/seo-rii/maki/pull/400)): the
  transport now races the address families and shares its connect deadline
  among the addresses; the status page states what remains.*
- **2026-11-24 eighth round** (AUD-176 to AUD-178;
  [#379](https://github.com/seo-rii/maki/pull/379)). Seven statements that the
  code, the CI workflow or the tree contradicted are corrected: what the
  `MAKI_LOG` fallback warning carries, two refusals the rollback guide
  quoted, the claim of `SECURITY.md` and this file's header that nothing had
  been tagged, where formatting runs in CI, the status page's date, and the
  layouts of SPEC §11 and the README. The guides run commands as the daemon
  user or the witness
  account with `runuser -u <user> -- <command>` instead of `sudo -u`, which
  neither package depends on, and the warning `maki volume create` prints
  when run as root names the same form. SPEC §6 says what a stuck
  `NBD_CMD_DISCONNECT` holds besides the attach lock: the global
  generic-netlink mutex and the callback lock, so that other generic-netlink
  families and family lookups on the host wait too. The provisioning guide
  creates the volume group with `--setautoactivation n`, as a precaution
  against LVM's event activation that was not exercised on a host. The
  records change ([#389](https://github.com/seo-rii/maki/pull/389)) adds that an
  A/B store which empties a torn copy can fail
  with `ENOSPC` (configuration, operations) and the backing filesystem
  assumption behind it (SPEC §43, support matrix).

- **2026-11-24 seventh round** (AUD-147, AUD-148, AUD-151, AUD-157, AUD-158).
  SPEC §6 gains an "NBD connection" section: the handshake, the netlink
  requests, the refusals, the busy retry, the provisioning connection's rules,
  and exactly what the time bound covers (the helper's own waits, not the
  kernel's work on a request); §8 says that the live backend is the device's
  kernel backend identifier, and §10 that the daemon unit names nbdkit by its
  absolute path ([#375](https://github.com/seo-rii/maki/pull/375),
  [#374](https://github.com/seo-rii/maki/pull/374)). The status page, the
  support matrix and operations say that every external campaign that attached
  a kernel NBD device did so through `nbd-client` (3.27.1 where the report
  names the version, 3.24 in the 2026-09-02 privileged run) and predates the
  helper's own connect; the Debian guide's `nbd-client` section is one
  sentence, kept under its old anchor. The support matrix has RHEL 9, Fedora
  and RHEL 8 rows, and the testing guide describes the new tests, the CI
  switches and the `rhel9` job. SPEC §6, the helper's documentation and its
  refusal message say why each export flag is required (`SEND_FLUSH` for
  durability, `SEND_FUA` by policy, `HAS_FLAGS` by the protocol), where they
  said that without any of them the kernel completes FLUSH and FUA without
  sending them ([#376](https://github.com/seo-rii/maki/pull/376)). The
  remediation log records the seventh round and marks the statements it
  supersedes.

- **2026-11-23 fifth audit and follow-ups** (AUD-124 to AUD-127, AUD-141).
  SPEC §43 classifies journal damage by the durable proof and mark instead of
  refusing corruption before a valid successor record, and SPEC, the
  architecture, testing and status pages match the code on envelope v3, the
  discard maps, the conditional swap check, the module layout, recovery's
  replay and discard admission
  ([#347](https://github.com/seo-rii/maki/pull/347)). The configuration guide
  names the nine byte keys that take only plain integers and says what the
  batch byte limit and the cache keys do, and the reclamation, latency and
  key-rotation pages match the code; a test loads every documented volume
  configuration ([#349](https://github.com/seo-rii/maki/pull/349)). The
  guides say that the stop after `maki drain` depends on cleanup's
  single-mapping fallback (detach an attachment with an additional LV before
  the drain), give the key-rotation runbook's stop order for backups and the
  PostgreSQL default-cluster precondition, and the manual pages document
  every option ([#348](https://github.com/seo-rii/maki/pull/348)). SPEC §18
  and a new [provider error
  signals](docs/configuration.md#provider-error-signals) section give the
  integrity tokens a provider must send and each transport's complete error
  classification, and SPEC gives the byte layout of every on-disk record
  ([#359](https://github.com/seo-rii/maki/pull/359)). What an inexact
  WebSocket probe error envelope, an upgrade reply that is not a valid
  upgrade and an HTTP/2 reset or GOAWAY under a gRPC call are classified as
  is documented and pinned, and SPEC §7 lists the remote-volume commands
  ([#364](https://github.com/seo-rii/maki/pull/364),
  [#363](https://github.com/seo-rii/maki/pull/363)). The remediation log
  records the fifth and sixth rounds and marks the statements they
  supersede.

- **2026-11-23 audit** (AUD-104, AUD-105): the nbd-client 3.27 backport
  recipe in the Debian guide stops at the first failed step, builds in a new
  directory, refuses a tarball that does not match the digest the operator
  verified against the upstream signature (`NBD_TARBALL_SHA256`) and installs
  exactly the package it built for the host's architecture; the quoted
  `Depends` line includes `systemd (>= 249)`
  ([installation](docs/getting-started/installation-debian.md#nbd-client-327-or-later),
  [#336](https://github.com/seo-rii/maki/pull/336)). The link checker counts
  a tab after a block quote or list margin to the line's next tab stop, so
  links on such lines are no longer skipped as indented code
  ([#333](https://github.com/seo-rii/maki/pull/333)). The remediation log
  records the fourth audit and marks the statements it supersedes; SPEC §8
  says that non-Unix hosts also hold a volume configuration to 1 MiB, SPEC
  §34 that a quarantined endpoint serves no volume request before its
  validation succeeds, and the architecture page that the echo check finds
  the plaintext anywhere in an encrypt result.

- **2026-11-17 audit** (AUD-081, AUD-084 to AUD-090, AUD-096, AUD-097): the
  link checker verifies reference-style link definitions and references
  ([#171](https://github.com/seo-rii/maki/pull/171)). A copy-on-write backing
  filesystem (btrfs with copy-on-write data, ZFS) is unsupported and btrfs
  NOCOW backing files are not qualified, because there an overwrite needs new
  space despite the reservation ([status](docs/status.md#known-limitations),
  [#171](https://github.com/seo-rii/maki/pull/171)). The workload verify gate
  needs CAP_DAC_READ_SEARCH or CAP_DAC_OVERRIDE in the unit's bounding set, or
  a volume root others can read and search
  ([#171](https://github.com/seo-rii/maki/pull/171),
  [#187](https://github.com/seo-rii/maki/pull/187)). Inside the checkpoint
  headroom raw discards are admitted, but a filesystem's deletes and XFS
  `fstrim` are refused; the key-rotation procedure masks `maki-recover@` while
  it starts units by hand; SPEC §9 lists only the implemented key sources
  ([#178](https://github.com/seo-rii/maki/pull/178)). `maki volume witness`,
  `snapshot` and `gc` run as the daemon user with the writer configuration, and
  enrollment recovery hands the paths back to it
  ([#182](https://github.com/seo-rii/maki/pull/182)). A remote restore's
  automatic GC deletes the newer state it replaces from the backing root;
  snapshot that state first if it may be needed ([witness
  service](docs/remote-witness-service.md#snapshot-takeover-and-restore),
  [#187](https://github.com/seo-rii/maki/pull/187)). The
  `systemd-analyze verify`, `BindsTo=` and quick-start cleanup statements were
  corrected ([#187](https://github.com/seo-rii/maki/pull/187)).

- **2026-11-16 audit** (AUD-047 to AUD-051): the link checker verifies in-page
  and cross-file anchors against GitHub heading slugs
  ([CONTRIBUTING](CONTRIBUTING.md#documentation)), and the deep check no longer
  names a torn-tail heuristic recovery stopped using
  ([#152](https://github.com/seo-rii/maki/pull/152)). Backing files must not
  share extents with reflink copies: a `cp --reflink` copy (coreutils 9's
  default on XFS and btrfs) can make an in-place write fail with ENOSPC despite
  the space reservation; copy with `cp --reflink=never`
  ([status](docs/status.md#known-limitations),
  [#152](https://github.com/seo-rii/maki/pull/152)). Stale statements in
  CLAUDE.md, SPEC, the operations, performance and testing guides and the
  remediation log's citations were corrected
  ([#152](https://github.com/seo-rii/maki/pull/152)). The guides now say that
  recovery checks the identity attach recorded against the `[lvm_identity]`
  pins rather than reading LVM metadata again
  ([#153](https://github.com/seo-rii/maki/pull/153)), and the privileged
  validation runbook names the results its earlier lenient denial checks cover
  ([#151](https://github.com/seo-rii/maki/pull/151)).

- **2026-10-14 project review**: docs that contradicted `status.md` or the code
  were corrected (remote witness status, power-loss tearing, nightly gate
  scope, deep-check report order, `drain` timeout, duration syntax, overlay
  zero limits, etcd restore and compaction). The operator guides wait for stopped units through
  `ActiveState` instead of `systemctl is-active`. The crate
  maps list `maki-witness`, and stale crate and module comments were fixed.

- [Remote transports under the syscall filter](docs/qualification/remote-transport-syscall-filter-validation-2026-10-04.md):
  the first external campaign for WebSocket and gRPC.
- [PostgreSQL over gRPC, NBD zeroing, MemoryDenyWriteExecute](docs/qualification/remote-database-zero-mdwe-validation-2026-10-04.md).
- [Debian 13: remote transports, sandbox, latency, zeroing](docs/qualification/debian13-remote-transport-validation-2026-10-04.md);
  the support matrix lists Debian 13 as campaign-passed (scoped).
- [Debian 13: PostgreSQL 17 over per-item HTTP, R5-039 throughput](docs/qualification/debian13-postgresql-http-validation-2026-10-05.md).
- [Cross-host remote transports under the sandbox](docs/qualification/cross-host-sandbox-validation-2026-10-05.md).
- [Provider host reset under a writing client](docs/qualification/provider-host-reset-validation-2026-10-05.md).
- The quick start and first-volume bootstrap passed `/dev/nbd0` to
  `nbd-client`; version 3.27, which Maki then required, connects over netlink
  and refuses it ("Invalid nbd device target"). They now pass the kernel name
  (`nbd0`); found by the 2026-10-03 packaged-lifecycle campaign.
- Validation reports moved to `docs/qualification/`; the README now links to
  [status](docs/status.md) instead of carrying the campaign history.
- `docs/architecture.md` now describes the experimental rollback-protected
  backing as implemented and the default formats' rollback limitation
  separately.
