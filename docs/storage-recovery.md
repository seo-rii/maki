# Recovering a disconnected attachment

`maki-attach recover` cleans up the recorded XFS mount and LVM mappings after
the NBD backend has disappeared. It never disconnects an active NBD backend,
starts a database, repairs a filesystem, or declares database recovery complete.
Use normal `detach` while the recorded backend is still connected.

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

The root-controlled attach record contains the NBD device number and the
activated mappings' device numbers, mapper names, LVM UUIDs, and slave edges.
Attach publishes this proof atomically after activation, while its backend
identifier still matches, and checks it again before mounting. Recovery checks
the kernel metadata against that proof; it does not open the sentinel or any
other file on the disconnected filesystem. Topologies over the bounded record
or inventory limits are rejected during attach.

A cleanup command can fail after its effect took place. On any failure, keep
the original attach record and investigate the reported condition. Re-running
the same recovery command observes the remaining layers and resumes cleanup;
it does not repeat an already completed unmount or VG deactivation. Successful
cleanup removes the record only after the backend is absent and the mount,
VG mappings, and NBD users are all gone. A further invocation reports that no
trusted attachment remains. Do not remove a retained record to bypass refusal.

## Remaining recovery limits

- A process or host failure between VG activation and publication of its
  identity proof leaves an active mapping without sufficient durable evidence.
  Recovery deliberately refuses that cleanup. The same restriction applies to
  older attach records without a proof when any upper layer remains active.
  This path needs independently verified manual recovery; automatic recovery
  from every attach crash stage is not yet supported.
- The attach lock serializes Maki helper operations. It does not coordinate
  manual LVM, mount, or NBD changes made by other privileged processes. Stop
  those operations before cleanup; namespace and concurrent root intervention
  are outside the helper's ownership guarantee.
- The storage cleanup tests use production metadata observers with synthetic
  kernel metadata and injected command outcomes. They do not qualify a real
  kernel NBD/XFS/LVM crash, container restart ordering, database recovery, power
  loss, or a production topology. Keep workload restart gated on separately
  verified storage attachment and database recovery procedures.
