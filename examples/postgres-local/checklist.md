# PostgreSQL on Maki: deployment checklist

Tick every box before handing the host to a workload. Each item links to the
rule it enforces. Guide: [PostgreSQL deployment](../../docs/deployment/postgres.md).

## Host

- [ ] Debian 12 with `nbd-client` ≥ 3.27.0 (`dpkg -s nbd-client`), kernel `nbd`
      module loaded at boot ([installation](../../docs/getting-started/installation-debian.md))
- [ ] Host, backing and topology are listed as at least "Expected" in the
      [support matrix](../../docs/deployment/support-matrix.md)
- [ ] `systemd-analyze verify` passes for `maki@postgres.service`,
      `maki-attach@postgres.service`, `maki-recover@postgres.service`,
      `maki-workload@postgres.target`, `postgresql@15-main.service`
- [ ] `systemd-analyze security maki@postgres.service` reviewed
- [ ] No swap that depends on NBD; `/proc/swaps` readable
      ([swap checks](../../docs/operations.md#swap-dependency-checks))
- [ ] Backing filesystem sized from `maki volume inspect` plus journal,
      checkpoint, filesystem and PostgreSQL temporary headroom

## Data plane

- [ ] `/etc/maki/volumes/postgres.toml` is `root:maki 0640` and uses
      `local-aes-gcm-siv` or a remote provider with `integrity` and
      `context_binding` declared `contractual`
- [ ] `security.require_secure_swap_policy = true`, `disable_core_dump = true`
- [ ] `journal_emergency_reserve_bytes` and `checkpoint_reserve_bytes` are non-zero
- [ ] `/etc/maki/secrets/postgres.token` is `root:root 0400`, 32 bytes, and a
      copy exists in the secret store, outside the storage backup
- [ ] `/var/lib/maki/postgres` is `maki:maki 0700` and `maki volume create`
      ran as `maki`
- [ ] `maki check /etc/maki/volumes/postgres.toml --deep` passes while detached

## Attachment

- [ ] Layout is whole NBD device → one PV → one VG → one linear XFS data LV
- [ ] `/etc/maki/attach/postgres.toml` is `root:root 0600`
- [ ] `volume_uuid`, `fs_uuid` and the complete `[lvm_identity]` are pinned from
      an independent inventory ([identity rules](../../docs/configuration.md#privileged-attachment-identity))
- [ ] `init_sentinel` is `false` after the first attach and
      `<mountpoint>/.maki-sentinel` holds the volume UUID
- [ ] `maki-attach attach --volume postgres --plan` was reviewed
- [ ] `maki-attach verify --volume postgres` exits 0

## Workload

- [ ] Data directory and `pg_wal` are on the Maki mountpoint
- [ ] `fsync = on`, `synchronous_commit = on`, `full_page_writes = on`,
      data checksums enabled
- [ ] Drop-in with `BindsTo`/`After`/`PartOf`/`Conflicts` and
      `ExecStartPre=!/usr/bin/maki-attach verify --volume postgres` installed
- [ ] `postgresql@15-main.service` is enabled (its `RequiredBy` link exists)
      and `maki-workload@postgres.target` is enabled; `maki@` and
      `maki-attach@` are **not** enabled directly
- [ ] Any container or supervisor restart path that bypasses the target is disabled

## Operations

- [ ] Planned-stop runbook: stop PostgreSQL → `maki drain` → stop target →
      wait for all units → offline check
- [ ] Recovery runbook read: [storage recovery](../../docs/storage-recovery.md)
- [ ] Backup shape chosen and rehearsed (unchanged-backing restore or
      database-native), including the credential path
- [ ] Monitoring reads `maki status`/`maki metrics` and alerts on
      `state: degraded`, `journal_writeback_uncertain`, and checkpoint lag
      ([observability](../../docs/observability.md))
- [ ] Upgrade procedure understood: detach with the old helper before
      replacing the package ([upgrade](../../docs/operations.md#upgrading-the-runtime-layout))
