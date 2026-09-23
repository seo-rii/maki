# PostgreSQL deployment guide

This guide assembles the **production profile** for one PostgreSQL cluster on
one Maki volume: the data-plane configuration, the pinned attach
configuration, the credential, the registered workload unit and the checks
around them. The profile is spread across several reference documents; this
page puts it in one order and links to each rule.

The complete file set is in [`examples/postgres-local/`](../../examples/postgres-local/README.md).
Read the [status page](../status.md) first: one scoped PostgreSQL 15 crash
campaign passed, and production approval is still pending. Treat this guide as
the qualified *shape*, not as an approval.

## What "production profile" means

| Rule | Where it is defined |
|---|---|
| Authenticated, context-bound encryption: `local-aes-gcm-siv`, or a remote provider declaring `integrity` and `context_binding` | [configuration](../configuration.md#providers) |
| Secrets only as credential references, delivered with systemd `LoadCredential=` | [configuration](../configuration.md#credentials-and-secrets), SPEC §9 |
| `security.require_secure_swap_policy = true`, core dumps off, locked secret buffers | [configuration](../configuration.md#security-settings) |
| Emergency and checkpoint reserves enabled on the backing | [configuration](../configuration.md#journal-bounds) |
| Attach pins `fs_uuid` **and** the complete `[lvm_identity]` | [configuration](../configuration.md#privileged-attachment-identity) |
| The qualified topology: whole NBD device → one PV → one VG → one linear XFS data LV | [support matrix](support-matrix.md#exported-stack-above-maki) |
| The workload is registered against `maki-workload@<volume>.target` and gated by `maki-attach verify` on every start | [operations](../operations.md#privileged-helper) |
| Planned stops go through `maki drain` before `systemctl stop` of the target | [operations](../operations.md#privileged-helper) |
| Backups capture the backing, both configurations and the credential separately, or use a database-native dump | [operations](../operations.md#fresh-host-restore-of-an-unchanged-v2-backing) |

## 1. Choose the provider

Start with the local provider. It is what every kernel-path campaign used,
needs no network, and gives authenticated, context-bound ciphertext.

Move to `remote-http` only when key custody must leave the host. Then start
from [`packaging/examples/postgres-prod.toml`](../../packaging/examples/postgres-prod.toml),
keep `integrity = "contractual"` and `context_binding = "contractual"`, and
qualify the vendor endpoint with the
[credential rotation](../key-rotation.md) procedures before production. No
commercial endpoint has been qualified.

## 2. Volume configuration

`/etc/maki/volumes/postgres.toml`, `root:maki 0640`. The example
[`volume.toml`](../../examples/postgres-local/volume.toml) is a complete file;
the values that need a decision:

| Setting | Guidance |
|---|---|
| `volume.max_virtual_size` | The exported device size. It cannot grow. Size for the cluster's lifetime; the backing filesystem only needs space for what is written plus reserves |
| `backing.journal_max_bytes`, `checkpoint_reserve_bytes`, `journal_emergency_reserve_bytes` | The shipped 4 GiB / 4 GiB / 1 GiB suit a multi-GiB backing filesystem; keep the emergency reserve non-zero so ENOSPC is refused before acknowledgement |
| `cache.mode` | `off` for a database that has its own buffer cache; `read` with `lock_memory = true` only when measured to help |
| `nbd.maximum_io` | 1 MiB matches PostgreSQL's large sequential I/O; `limits.max_plaintext_bytes` must exceed it by at least one crypto unit |
| `security.require_secure_swap_policy` | `true`. Attach then refuses swap that depends on NBD, and requires readable `/proc/swaps` |

Create the volume as the daemon user, then check it:

```bash
install -d -o maki -g maki -m 0700 /var/lib/maki/postgres
sudo -u maki maki volume create /etc/maki/volumes/postgres.toml
maki volume inspect /etc/maki/volumes/postgres.toml
```

`inspect` reports the format-file sizes at full allocation. Size the backing
filesystem for those, plus journal and checkpoint headroom, filesystem
metadata and PostgreSQL's own temporary space
([capacity](../configuration.md#capacity-and-limits)).

## 3. Credential

```bash
head -c 32 /dev/urandom > /etc/maki/secrets/postgres.token
chmod 0400 /etc/maki/secrets/postgres.token
```

The packaged unit loads it as `crypto-token`. Store a copy in the
deployment's secret store, never in the same backup as the backing directory.
Key rotation is a [migration to a new volume](../key-rotation.md#migrate-to-a-different-encryption-key),
not a file replacement.

## 4. Storage layout and attach configuration

Provision the first layout as described in
[provisioning the first volume](../getting-started/first-volume.md), then fill
[`attach.toml`](../../examples/postgres-local/attach.toml) with the observed
identities and install it as `/etc/maki/attach/postgres.toml`
(`root:root 0600`). Keep `init_sentinel = true` only for the very first
attach.

Mountpoint: `/srv/postgres`. The PostgreSQL data directory and `pg_wal` both
live on this filesystem; do not split WAL onto unencrypted storage.

## 5. Register the PostgreSQL unit

Debian runs clusters as `postgresql@<version>-<cluster>.service`. Create the
cluster on the mounted volume once the first attach has succeeded:

```bash
systemctl start maki-workload@postgres.target
install -d -o postgres -g postgres -m 0700 /srv/postgres/15
pg_createcluster -d /srv/postgres/15/main 15 main -- --data-checksums
```

Then install the drop-in
[`postgresql.service.d/10-maki.conf`](../../examples/postgres-local/postgresql.service.d/10-maki.conf)
as `/etc/systemd/system/postgresql@15-main.service.d/10-maki.conf`:

```ini
[Unit]
BindsTo=maki-attach@postgres.service
After=maki-attach@postgres.service
PartOf=maki-workload@postgres.target
Conflicts=maki-recover@postgres.service

[Service]
ExecStartPre=!/usr/bin/maki-attach verify --volume postgres

[Install]
RequiredBy=maki-workload@postgres.target
```

```bash
systemctl daemon-reload
systemctl enable postgresql@15-main.service      # installs the RequiredBy link
systemctl enable --now maki-workload@postgres.target
systemctl status postgresql@15-main.service
```

`ExecStartPre=!` runs the read-only identity gate as root even though the
service runs as `postgres`. A failed gate prevents the start. The gate does
not test data I/O or daemon liveness; the lifecycle target and
`maki-recover@` handle daemon failure
([what the gate proves](../storage-recovery.md#checking-storage-before-each-workload-start)).

Keep the durability settings the campaign used: `fsync = on`,
`synchronous_commit = on`, `full_page_writes = on`, data checksums enabled.

## 6. Planned stop and start

```bash
systemctl stop postgresql@15-main.service        # or pg_ctlcluster 15 main stop
maki drain /etc/maki/volumes/postgres.toml       # returns the durable checkpoint sequence
systemctl stop maki-workload@postgres.target
while systemctl is-active --quiet postgresql@15-main.service || \
      systemctl is-active --quiet maki-attach@postgres.service || \
      systemctl is-active --quiet maki@postgres.service; do sleep 1; done
maki check /etc/maki/volumes/postgres.toml --deep
```

Start with `systemctl start maki-workload@postgres.target`; the target starts
the daemon, waits for its readiness notification, attaches, runs the gate,
and starts PostgreSQL. Do not start `maki@` or `maki-attach@` by hand in
production.

## 7. Failure behaviour to expect

- Daemon crash: `maki-recover@postgres.service` stops PostgreSQL, cleans up
  the attachment and restarts the lifecycle. PostgreSQL then performs its own
  WAL recovery. The campaign observed this shape with `SIGKILL` of the
  postmaster and of `nbdkit`.
- Cleanup blocked by an open file on the LV: the lifecycle stays down and
  reports the failure; close the descriptor and retry
  ([storage recovery](../storage-recovery.md)).
- Backing filesystem full: writes fail with ENOSPC before acknowledgement;
  PostgreSQL sees write errors and stops. Existing data stays readable.
- Provider unavailable (remote provider): with `availability_policy = "stall"`
  I/O stalls until an endpoint returns; nothing is acknowledged meanwhile.

## 8. Backup and restore

Two supported shapes, both qualified once on Debian 12:

1. **Unchanged backing restore**: drain, stop, capture `/var/lib/maki/postgres`,
   both configuration files and the credential (separately), restore on a
   host with the same package, and verify against an independent ledger
   ([procedure](../operations.md#fresh-host-restore-of-an-unchanged-v2-backing)).
2. **Database-native**: `pg_dump`/`pg_basebackup` from the stopped or quiesced
   cluster into a new volume, which is also the only way to change the
   encryption key or move between formats ([durable recovery](../durable-recovery.md)).

## Checklist

The [deployment checklist](../../examples/postgres-local/checklist.md) lists
every item above as a box to tick, plus the host checks from
[operations](../operations.md#systemd-deployment).
