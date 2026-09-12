# Credential rotation and key migration

An authentication credential can be replaced on an existing volume only when
the provider still uses the same encryption key and cryptographic profile.
Changing the actual encryption key requires a new volume and a data migration.
Maki has no in-place re-encryption command or mixed-key epoch support.

This procedure describes the current implementation, not a completed production
qualification. Use a maintenance window and the deployment's tested database
backup, shutdown, mount, and restart procedures. The commands below use the
packaged `example` service instance; substitute the existing instance and its
configuration paths. Do not run storage commands against an unreviewed target.

## What can change

| Change | Required procedure |
| --- | --- |
| Bearer token, client authentication credential, or credential source reference that retains access to exactly the same key/profile | Stop and detach the workload, acknowledge drain, stop the daemon, update credentials, and reattach with verification. |
| Endpoint address that serves the same key/profile | The same stopped procedure, with verification of every configured peer against the existing volume. Preserve the required transport security and capability contract. |
| Actual key bytes or provider-side key version, algorithm, incompatible ciphertext encoding/context binding, or provider identity | Create a separate volume and restore a database-native backup into it. |
| Immutable volume geometry or on-disk format | A separately planned volume migration. |

`maki reload <config> credentials` and `maki reload <config> endpoints` return
errors: this build does not apply those changes at runtime. Transport
credentials and local keys are loaded when providers are constructed. Replacing
a credential file alone does not update an attached daemon or perform new key
verification. Do not change a provider's key routing or mutable key alias behind
a running endpoint; an already validated endpoint is not continually rechecked
for a new credential/key epoch.

The superblock binds the provider type, compatibility identity, configured key
name where present, format, and geometry. Retain those values during credential
rotation. The actual key must also remain unchanged: preserving a name or
`crypto_compatibility_id` does not make a different key compatible. Never edit
the superblock or delete `canary.a`/`canary.b` to bypass a mismatch.

## Rotate a credential while retaining the encryption key

1. Prepare a replacement credential through the existing secret-management
   process. Confirm that every peer maps it to the same existing encryption key
   and profile. Keep the previous credential valid through the rollback window
   when that is permitted; do not keep using a revoked or compromised
   credential. Retain the old configuration and a tested database-native
   backup. Record the volume UUID, provider/profile, peer names, and non-secret
   credential version references in the change record.

2. Stop database writers and their supervisors, and prevent automatic restarts.
   Stop containers and release their bind mounts in each relevant mount
   namespace. For an attachment managed by the packaged active attach unit,
   stopping that unit performs unmount, VG deactivation, and NBD disconnect
   while the crypto daemon is still available:

   ```sh
   sudo systemctl stop maki-attach@example.service
   ```

   Verify that the intended storage attachment is gone before continuing.
   An inactive unit does not prove that a manually created attachment was
   removed. For manually managed attachments, use the established helper
   detach procedure instead. If cleanup fails, resolve it before rotating;
   [disconnected storage recovery](storage-recovery.md) has additional limits.

3. With the filesystem unmounted and the daemon still running, request and
   record the explicit durability acknowledgement:

   ```sh
   maki drain /etc/maki/volumes/example.toml
   maki status /etc/maki/volumes/example.toml
   ```

   Require a successful CLI exit and `ok: true` with `data.checkpoint_sequence`
   in the drain response. Status must report `data.io_state: "drained"`.
   A timeout, failed drain, removed socket, or eventual process exit is not an
   acknowledgement. Keep the process alive, correct the failure, and retry
   drain. Successful drain closes I/O admission for that attachment; only a
   new attachment can resume I/O.

4. After the acknowledgement, stop the daemon and confirm it has exited and
   released the volume lock:

   ```sh
   sudo systemctl stop maki@example.service
   maki volume inspect /etc/maki/volumes/example.toml
   ```

   Inspect records the on-disk UUID/profile/geometry; it is not a lock or key
   verification command. Preserve the backing tree. Apply the prepared change
   to the existing root-controlled secret source and configuration. The
   packaged service loads `crypto-token` from `/etc/maki/secrets/example.token`
   through `LoadCredential`; an existing service drop-in may select another
   source. Use the deployment's atomic secret-installation procedure with
   restricted permissions. Do not edit the service's transient
   `$CREDENTIALS_DIRECTORY`, put tokens in TOML or command arguments, or give
   crypto credentials to `maki-attach`. See
   [credential source rules](configuration.md#credentials-and-secrets).

5. Start only the data-plane daemon and keep application writers stopped:

   ```sh
   sudo systemctl start maki@example.service
   maki status /etc/maki/volumes/example.toml
   ```

   `Type=simple` service startup is not readiness evidence. Require an attached
   engine with `data.observability.volume_snapshot: "current"`,
   `data.state: "ready"`, and `data.io_state: "running"`.
   For a remote provider, require every intended peer in
   `data.crypto.endpoints` to have `validated: true`, `rejected: false`, and a
   healthy closed circuit. Keep writers stopped on any identity, canary,
   conformance, or credential error. Do not weaken capability declarations or
   remove a failing peer merely to make this rotation pass.

   These observations are prerequisites, not proof that a workload can start;
   the mount and database checks in step 6 remain required.

   Attach checks the real, locked volume UUID, format, compatibility identity,
   and geometry. Reachable peers undergo individual self-tests, actual-volume
   canary verification, and cross-peer checks. A single peer is checked through
   the engine attach path. An unreachable peer may remain quarantined while
   the daemon attaches with others; that is not verification of that peer.
   Restore its availability and perform another stopped, acknowledged restart
   before accepting the rotation if it was not validated. There is no separate
   administrative command that proves an arbitrary peer against a volume.

6. Reattach the kernel storage through the normal guarded helper, still with
   dependent workloads held stopped:

   ```sh
   sudo systemctl start maki-attach@example.service
   ```

   Verify the trusted attachment and mount identity. Recreate container bind
   mounts when necessary; a host remount does not establish that an existing
   container sees the new mount. Complete the deployment's database recovery
   and read verification before enabling application writes. Retire the old
   authentication credential only after this evidence is accepted. Preserve
   access to the encryption key for retained backups and the existing volume.

## Roll back a credential change

Keep writers stopped if the new credential or any peer fails validation. If a
new daemon attached, repeat the unmount/detach, acknowledged drain, and stop
sequence before changing its inputs again. If attach itself failed, confirm
that the process exited and the volume lock is released; no successful drain
can be inferred from that failure.

Restore the previous root-controlled credential/configuration only when the
old credential is valid and still resolves to the original encryption key.
Repeat all attach, peer, canary, mount, and database checks before resuming.
If the old key is unavailable or the old credential was revoked, restoring a
file or an endpoint name cannot recover access. Preserve the original volume
and escalate through the key custodian and tested restore procedure. Do not
initialize that backing path, erase recovery evidence, or rebind its canary.

## Migrate to a different encryption key

1. Prepare a database-consistent native backup and the required recovery logs,
   and prove a restore with the relevant database version. Retain the original
   volume and old key. Keep backup data protected according to its own storage
   and encryption policy; it may contain plaintext independent of Maki.
2. Define a new volume with a separate empty backing root, sockets, service
   instance, attachment configuration, and new key/profile. Provision its
   capacity and LVM/XFS layout through the deployment's reviewed procedure.
   `maki volume create <new-config.toml>` creates the Maki backing format only;
   it does not create a filesystem or migrate a database. Run creation with
   the ownership described in [volume lifecycle](operations.md#volume-lifecycle).
3. Attach the new volume with the intended new key, verify all peers and its
   newly established canary, then restore the native backup. Do not copy raw
   encrypted shards or rewrite the old volume's identity: those ciphertexts
   remain bound to the old UUID/key/profile.
4. At cutover, stop old-volume writers and complete the database-specific
   final backup/log synchronization. Detach, acknowledge drain, and stop the
   old daemon as above. Validate database recovery and application data on
   the new volume before redirecting the workload and permitting writes.
5. Retain the old volume, configuration, and key through the agreed retention
   window. Once the new database accepts writes, switching back to the old
   volume can lose those writes; rollback then needs a database-level data
   reconciliation or restore plan. Key retirement requires verified access
   to every retained backup that still depends on that key.

## Evidence and limits

Record the before/after volume identity, non-secret configuration versions,
drain acknowledgement, service exit, per-peer validation results, trusted
mount identity, database recovery/read checks, and a rollback rehearsal. An
offline `maki check <config.toml> --deep` checks stored structure and checksums; it does not
decrypt or authenticate the database and cannot replace those checks.

The repository tests cover rejection and canary behavior, not a completed
rotation of a production provider or a database cutover. Provider credential
overlap, key retention, actual mount/container restart ordering, backup restore,
and failure at each transition still require deployment-specific execution
evidence. This runbook does not close those qualification requirements.
