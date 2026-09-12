# Recovering a disconnected attachment

`maki-attach recover` cleans up the recorded XFS mount and LVM mappings after
the NBD backend has disappeared. It never disconnects an active NBD backend,
starts a database, repairs a filesystem, or declares database recovery complete.
Use normal `detach` while the recorded backend is still connected.

The packaged services call the convergent selector instead of choosing those
paths themselves:

```sh
maki-attach cleanup --volume pg --config /etc/maki/attach/pg.toml --plan
sudo maki-attach cleanup --volume pg --config /etc/maki/attach/pg.toml
```

Under one attach lock, `cleanup` treats a missing trusted record as success,
routes a matching connected backend through detach, and routes a known absent
backend through recovery. A foreign or unreadable backend fails without
mutation and preserves the record. Use explicit `detach` for planned connected
maintenance and explicit `recover` when diagnosing a known disconnected
attachment.

When nbdkit dies but its kernel NBD client remains connected, `cleanup` may use
the completed post-activation proof after normal `vgchange -an` exits nonzero.
This fallback accepts only a single target mapping: the original proof and the
current kernel inventory must each contain the same one top-level DM target,
with exact name, UUID, major/minor and slave edge, no mount or foreign holder,
open count zero, and the same backend nonce immediately before mutation. It
issues one plain `dmsetup remove`, rechecks mapping and holder absence, and then
disconnects NBD. It does not run after a command timeout or other I/O error and
never uses force, deferred removal, or retry options.

This path belongs only to convergent `cleanup`. Explicit `detach` and `recover`,
pre-activation intent, multi-LV/internal thin/cache/RAID mappings, open targets,
or changed identity remain fail closed with the trusted record intact.

Before recovery, stop database writers and their supervisors, prevent automatic
restarts, and stop containers that use the volume. Run recovery from the host
mount namespace used by attach. Remove workload bind mounts in their own
namespaces before proceeding. In particular, this helper reads its own
`/proc/self/mountinfo`; it cannot certify that another namespace has no mount
of the volume.

Use the same root-controlled attachment configuration as the original attach:

```sh
maki-attach recover --volume pg --config /etc/maki/attach/pg.toml --plan
sudo maki-attach recover --volume pg --config /etc/maki/attach/pg.toml
```

The plan lists conditional cleanup steps. Execution requires a trusted attach
record and an absent kernel NBD backend before and after every topology
observation. A connected, replaced, or unreadable backend stops cleanup. The
helper unmounts only the expected complete XFS mount, then deactivates only the
recorded VG, re-observing between steps. Another mount of any recorded device,
an unexpected holder, or changed block-device identity stops cleanup.

Before activation, the root-controlled attach record stores a recovery intent
containing the verified NBD device numbers and geometry, partition set, PV
labels, VG/LV UUIDs and admitted layouts. Attach publishes the complete mapping
proof atomically after activation, while its backend identifier still matches,
and removes the intent in the same record update. The proof adds mapper device
numbers, names, UUIDs and slave edges and is checked again before mounting.

If the helper exits between activation and proof publication, ordinary detach
may consume the intent while the recorded backend nonce remains connected;
`recover` may consume it only while that backend remains absent. Both paths
require the exact NBD geometry and partition set, only preflight-verified mapper
names, UUIDs and dependency edges, no unexpected holder, and no mount of the
candidate devices. A partial activation is accepted only when every observed
LV and internal mapping is a verified subset; an unknown mapping name or LVM
UUID suffix is refused. The LVM command is restricted to the recorded device
list and VG UUID. The intent never authorizes an unmount, mount, filesystem
access, or workload start. A record with neither the proof nor the new intent
retains the legacy fail-closed behavior. Topologies over the bounded record or
inventory limits are rejected.

## Checking LVM before activation

After connecting the recorded NBD backend, attach checks its kernel device
number and its actual child partitions, including their parent and geometry.
It refuses existing holders. For each candidate it holds a verified block
descriptor while running bounded, uncached `blkid --probe`, and inventories
the independently observed LVM PV identifiers. Duplicate PV identifiers are
refused even when LVM has selected one copy and omitted the other from its
report.

LVM's `pv_duplicate` field describes unused duplicate devices; a selected copy
can have a zero flag, and `fullreport` does not enumerate every discarded copy.
See the [LVM2 report implementation](https://github.com/lvmteam/lvm2/blob/v2_03_16/lib/report/report.c#L3272)
and [VG report traversal](https://github.com/lvmteam/lvm2/blob/v2_03_16/tools/reporter.c#L1043).

A bounded read-only LVM `fullreport` must agree with that inventory and show
the complete configured VG, including every PV and the configured LV. Foreign,
missing, partial, duplicate, or ambiguous membership refuses activation.
Overlapping PV regions are also refused, including a whole-device PV mixed
with child PV partitions. The helper repeats the observations before invoking
`vgchange` with an explicit candidate device list, the discovered VG UUID, and
complete activation mode.
After activation it compares kernel mapping UUIDs with the discovered VG/LV
identifiers, then captures the existing topology proof. Plan mode prints these
conditional checks; it does not discover or certify live identities.

This path requires LVM2 support for `fullreport`, `--devices`, UUID selection,
and complete activation mode. Unsupported options or report fields fail
closed. The candidate inventory is limited to 64 devices and subprocess
reports to 64 KiB. Every candidate needs a recognized, unambiguous label:
blank spare partitions and unreadable or unclassified candidates are refused.
In particular, `blkid` exit 2 cannot establish that a device is safely empty.
The [blkid CLI implementation](https://github.com/util-linux/util-linux/blob/v2.38.1/misc-utils/blkid.c#L479)
uses that status for both missing signatures and some probe failures.
Shared VGs and VGs with a nonempty system ID require external ownership
coordination and are not admitted by this helper.
LVM cachevol layouts are also refused before activation: they can generate
internal cache device UUIDs that the report's LV UUID inventory does not
describe. The helper does not weaken mapping identity checks to admit them.
UUID parsing supports the alphanumeric IDs generated by modern LVM2;
legacy identifiers containing `!` or `#` are refused.

The optional `[lvm_identity]` attachment table authenticates the independently
observed metadata against administrator-provided pins. It requires the complete
`pv_uuids` set plus `vg_uuid` and the configured target `lv_uuid`; a partial,
duplicate, malformed, missing, additional or changed identity refuses attach
before activation. Configuration order does not affect the PV set. The pins are
part of the trusted attachment identity, so grow and detach reject a changed or
newly omitted table before mutation, and recovery rechecks persisted pins
against its fresh read-only report. Production configurations must provide this
table. Omission remains a compatibility mode and does not independently
authenticate the discovered LVM metadata.

Read-only LVM reporting is lockless and is not a promise that LVM leaves host
hint files untouched. The attach lock does not coordinate other privileged
tools or udev activation triggered by NBD connection. Device identity and
metadata can change after an observation; neither external root races nor
automatic udev activation are made safe by the UUID pins. Qualify the host's
activation policy separately.

Failed-attach rollback uses the same preflight identities before any mount or
VG teardown, and limits VG deactivation to the validated UUID and devices.
An unexpected mapping UUID, or upper layers appearing before the helper
attempted verified activation, stops cleanup and retains the record.
A helper failure does not grant ownership of an unverified mapping.

After activation and before mounting, attach runs a bounded, uncached
`blkid --probe` on the selected LV. It requires XFS and, when configured,
the exact `fs_uuid`. A missing pinned UUID, unexpected filesystem type,
failed probe or ambiguous response refuses mount before filesystem recovery,
sentinel creation or the read/write probe can run. Backend and recorded
mapping identities are checked before and after the block probe and again
before mount. The existing post-mount identity checks remain in place.
Omitting `fs_uuid` checks the filesystem type without independently pinning
its identity. This check occurs after LVM activation. A failure before the
complete mapping proof is published leaves only the narrower recovery intent,
which permits deactivation but never permits mounting the selected LV.

A cleanup command can fail after its effect took place. On any failure, keep
the original attach record and investigate the reported condition. Re-running
the same recovery command observes the remaining layers and resumes cleanup;
it does not repeat an already completed unmount or VG deactivation. Successful
cleanup removes the record only after the backend is absent and the mount,
VG mappings, and NBD users are all gone. A further invocation reports that no
trusted attachment remains. Do not remove a retained record to bypass refusal.

## Checking storage before each workload start

Run the repeatable gate as root, using the same host mount namespace and
root-controlled configuration as attach:

```sh
maki-attach verify --volume pg --config /etc/maki/attach/pg.toml --plan
sudo maki-attach verify --volume pg --config /etc/maki/attach/pg.toml
```

`--plan` prints the required checks only. It does not read the configuration
or inspect a live attachment, and its successful exit is not verification
evidence. Use the second command, without `--plan`, for a workload start gate.
The helper must run with root privileges; an ordinary `User=postgres` service
cannot access the trusted attach lock and record merely by adding an
`ExecStartPre` command. Arrange the privileged gate explicitly in the workload's
service configuration, and refuse workload startup when it fails.

Execution requires both `volume_uuid` and `fs_uuid` in the configuration.
Pin `fs_uuid` from independently verified filesystem identity; the gate never
learns or updates that pin. It accepts only `--volume`, `--config` and `--plan`;
identity overrides such as `--uuid`, `--fs-uuid`, `--mountpoint`, and
`--nbd-device` are rejected. Existing attach, detach, grow and recover command
interfaces retain their prior configuration and override behavior.

The gate opens the existing root-controlled state directory and attach lock
without creating them. Under that lock it opens the configuration through
verified directory descriptors and refuses symlinks, untrusted ownership,
group/other write access, shared config files, or oversized content. The
configuration's attachment identity and optional fixed NBD device must match
the existing record. A missing record or persisted mapping proof fails closed.

Success requires the recorded backend identifier to remain connected, every
persisted mapping identity and dependency to match, and the expected complete
XFS filesystem to be mounted read/write in the caller's namespace. Missing,
stacked, subtree, or additional mounts of recorded devices refuse the gate.
Any nested mount below the configured root is also rejected, including a
foreign filesystem hiding a database data directory. A similarly named sibling
path is unrelated; when the configured root is `/`, every other mount is nested.
The filesystem probe reads an already opened and device-verified LV descriptor
with uncached `blkid --probe`, then checks the configured XFS UUID. The bounded
sentinel read uses held descriptors, refuses links and non-regular files, checks
the mounted device, and suppresses access-time updates. Backend and mapping
identity are checked again after both potentially blocking reads.

Verification does not initialize a sentinel, run a write probe, repair storage,
change the attach record, or start a database. A configured first-attach
`init_sentinel` option does not change that behavior. Existing records lacking
the post-activation proof remain insufficient, including records that contain
only a pre-activation recovery intent. A successful result is a current storage
check, not proof of database recovery, successful future writes, other
namespaces, or continued availability after the command exits. Separate WAL,
temporary-file, or log locations outside the configured root are not covered.
The subprocess probe has an internal bound, but waiting for the attach lock has
no internal deadline and a kernel filesystem read can still hang after backend
failure; the gate does not promise an overall completion deadline.
Because the gate is based on kernel identity and topology, it can still pass
immediately after nbdkit dies while the kernel NBD connection remains present.
Treat daemon supervision and an application I/O/health check as separate gates.

## Packaged workload lifecycle

Install the workload drop-in from
`packaging/examples/maki-workload.service.d/10-maki.conf`, adapt its volume and
service names, enable the workload, and enable
`maki-workload@<volume>.target`. Enable the target instead of the daemon or
attach units directly. The target requires attachment, and each registered
workload binds to that attachment, belongs to the target, conflicts with
recovery, and runs the privileged read-only verify gate before every start.

A daemon failure triggers `maki-recover@<volume>.service`. Its conflict and
ordering first stop registered workloads, the attach unit, and the daemon. It
then runs convergent cleanup. `OnSuccess=` starts a fresh lifecycle only after
cleanup succeeds; a cleanup failure leaves the workload stopped. Retry loops
are bounded by the daemon start limit and the recovery job timeout. The target
stop path runs attach cleanup before the daemon stops.

The graph controls only workloads registered in the target. Disable other
supervisors and Docker restart policies that could start the application
outside it. A host remount is not assumed to update an existing Docker bind
mount; stop and recreate the container, then report workload start success only
after database recovery and health checks complete.

On a disposable Debian 12 GCE host, actual systemd transactions stopped a
fixture workload, ran attach stop and recovery cleanup, and started new daemon
and workload processes (`43687` to `43714`, and `43692` to `43719`). Cleanup
failure did not restart the workload, and a per-start verify failure produced
zero workload `ExecStart` calls. A separate Docker/XFS/SQLite run observed
default `rprivate` propagation, different container IDs and creation times,
SQLite rows advancing from one to two with `integrity_check=ok`, and zero
container starts on a plain directory.

Those packaged lifecycle runs used fixture daemon/attach/verify steps and
loop-backed XFS. A later `8bf0e94` campaign combined actual Maki nbdkit, kernel
NBD, pinned single-PV LVM/XFS, trusted attach/verify/cleanup, and two distinct
default-`rprivate` Docker containers around nbdkit `SIGKILL`. The connected
kernel mapping was removed through the proof-scoped fallback, reattach passed,
and the new container recovered all 32 rows in the independently fsynced ACK
ledger with `integrity_check=ok`. The installed packaged systemd graph was not
part of that combined run.

## Remaining recovery limits

- A pre-activation intent permits only exact, mount-free mapping cleanup. Any
  foreign UUID, changed device number or geometry, changed partition set,
  unexpected holder, mounted upper layer, unreadable observation, or replaced
  backend stops cleanup and preserves the record. Older records without either
  a proof or intent still require independently verified manual recovery when
  an upper layer remains active.
- The attach lock serializes Maki helper operations. It does not coordinate
  manual LVM, mount, or NBD changes made by other privileged processes. Stop
  those operations before cleanup; namespace and concurrent root intervention
  are outside the helper's ownership guarantee.
- Foreign, partial-mapping, and most command-failure cleanup cases use
  production metadata observers with synthetic kernel metadata and injected
  outcomes. The actual single-target nbdkit-death path passed the combined
  kernel NBD/LVM/XFS and Docker ACK campaign above. Multi-mapping fallback,
  packaged systemd integration, whole-VM or physical power loss, repeated
  crashes, and a production topology remain separate qualification gates.
