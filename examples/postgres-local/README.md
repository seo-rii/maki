# Example: PostgreSQL 15 on one Maki volume, local provider

A complete production-profile file set for one Debian PostgreSQL cluster
(`postgresql@15-main.service`) whose data directory and WAL live on one Maki
volume named `postgres`, encrypted with the local AES-256-GCM-SIV provider.

| File | Installs as | Owner and mode |
|---|---|---|
| [`volume.toml`](volume.toml) | `/etc/maki/volumes/postgres.toml` | `root:maki 0640` |
| [`attach.toml`](attach.toml) | `/etc/maki/attach/postgres.toml` | `root:root 0600` |
| [`postgresql.service.d/10-maki.conf`](postgresql.service.d/10-maki.conf) | `/etc/systemd/system/postgresql@15-main.service.d/10-maki.conf` | `root:root 0644` |
| [`checklist.md`](checklist.md) | — | Tick before go-live |

The credential is not a file in this bundle: generate it on the host
(`head -c 32 /dev/urandom > /etc/maki/secrets/postgres.token`, mode `0400`)
and keep a copy in the deployment's secret store.

The order in which to use these files, the decisions each `decide` marker
asks for, and the planned-stop and recovery runbooks are in the
[PostgreSQL deployment guide](../../docs/deployment/postgres.md). The
one-time LVM/XFS bootstrap that yields the UUIDs for `attach.toml` is in
[provisioning the first volume](../../docs/getting-started/first-volume.md).

For a remote HTTP provider, replace the `[crypto]` sections with
[`packaging/examples/postgres-prod.toml`](../../packaging/examples/postgres-prod.toml)
and read [key rotation](../../docs/key-rotation.md) before choosing a vendor.
