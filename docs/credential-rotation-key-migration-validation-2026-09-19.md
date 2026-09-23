# Credential rotation and key migration validation — 2026-09-19

This report records one scoped three-host qualification of stopped bearer and
mTLS client credential rotation on an existing volume, followed by a
database-native migration to a new volume backed by a different provider key.
The tested source revision was
`bdb911336e83cf7e0c128cebb0d0493a9d33ac00` with `rustls 0.23.45`.

The run passed. It is evidence for the exact reference-provider and SQLite
profile below. It is not server-certificate rotation.
It is not a commercial vendor qualification or approval to rotate encryption
key bytes in place.

## Topology and fixed inputs

The campaign used three disposable Debian 12 GCE VMs in one private VPC:

- two `e2-standard-2` hosts ran nginx 1.22.1 as the TLS and mTLS boundary in
  front of the same frozen reference-provider binary;
- one `n2-standard-4` client ran Linux 6.1.0-53, Maki nbdkit, kernel NBD via
  nbd-client 3.27.1, a pinned single-PV LVM/XFS attachment, and SQLite 3.40.1
  in WAL mode with `synchronous=FULL`;
- provider A and B each exposed K1 on port 8443, K2 on port 9443, and an
  intentional wrong-key control using K1 with the K2 profile on port 10443;
- the server CA and server certificates stayed fixed. The client
  certificate/private key, bearer token, and provider-side CA that authorizes
  client identities changed while storage was stopped.

The final frozen harness is in
`/home/seorii/logs/maki-rotation-migration-final3-20260919`. Its manifest
verified the three scripts, two source archives, and four harness validators
before launch and after collection. The source archive recorded the full
revision above. Secrets remain only in the private evidence directory; this
report includes non-secret identities and hashes.

## Stopped credential rotation

The client first created and attached volume `tlsqual` with K1, bearer version
1, and mTLS identity `maki-storage-client-v1`. Both remote peers were
individually validated, non-rejected, and in a closed circuit. SQLite committed
eight rows, each mirrored to an external fsynced ledger.

The campaign then held writers stopped, cleaned up the trusted attachment,
received an explicit drain acknowledgement, and stopped the daemon. It replaced
the root-controlled bearer credential and mTLS client certificate/private key;
both nginx peers replaced their trusted client CA and bearer token. This was a
stopped bearer credential rotation. Maki does not hot-reload these inputs.

Before reattachment, the following gates passed:

- the old bearer received HTTP 403 and the new bearer received HTTP 200;
- the old `maki-storage-client-v1` identity was refused after the client-CA
  change;
- `maki-storage-client-v2`, issued by the new client CA, received HTTP 204 from
  both peers;
- both peers again reported `validated: true`, `rejected: false`, and
  `circuit: closed` through the actual-volume attach path;
- SHA-256 manifests of both superblocks and both key-canary copies were
  byte-identical before and after the credential change.

The existing volume then reattached through the trusted helper, passed mount
verification, matched the original eight rows, and advanced to 16 externally
acknowledged rows.

## Migration to a new provider key

The provider produced distinct provider key fingerprints for K1 and K2:

```text
K1 b793f9b89effa727c8aa6be156020bb878684617c372c26bef1ad5632324de34
K2 58be0e7270437f8fc171248e7fc7d509c3bc53ed85ad5931495672aa397b01e3
```

Maki cannot independently identify the intended key version on the first attach
of an empty volume: that attach establishes the canary for the key actually
served. The deployment must therefore record a provider-side non-secret key
version or fingerprint before creation. The campaign compared those external
fingerprints and also required different volume identities:

```text
old_volume_uuid=e824480f-7626-4b30-9f65-31ac50b17af4
new_volume_uuid=9cceb735-52ea-4086-8cfb-69cc7bfa2297
```

With writers stopped, SQLite created a DB-native backup of the 16-row database,
fsynced the file and parent directory, and returned `PRAGMA integrity_check =
ok`. The old attachment was cleaned up and drained. A separate `rotationnew`
volume, backing root, trusted attachment identity, PV/VG/LV, XFS filesystem,
provider profile `rotation-key-v2`, and K2 endpoint set were then created.

After K2 initialized the new volume, an isolated transient nbdkit attempted the
same volume with K1 served under the K2 profile. This wrong-key canary failed
before daemon readiness with an explicit authentication-tag/canary
error. Both superblock and canary copies had identical hashes before and after
the refusal. The production service was not used for this intentional failure,
so its configured recovery coordinator could not race the negative control.

The correct K2 service then validated both peers and mounted the new volume.
SQLite restored the native backup and matched all 16 external ledger entries,
then committed rows 16 through 23.
The database reached 24 externally acknowledged rows. After a full cleanup,
daemon restart, trusted reattach, and mount verification, all 24 rows and
payload hashes still matched.

Final offline deep checks passed on both the retained K1 volume and the active
K2 volume. Each reported a valid key canary and `check passed`.
Both reported zero invalid slots.

## Harness corrections and cleanup

Two earlier attempts ended in the harness after already passing credential
rotation controls. The first used an RFC 3339 timestamp that Debian 12's
`journalctl --since` did not parse. The second deliberately failed the packaged
daemon with the wrong key; its normal `OnFailure` recovery chain restarted the
instance and raced the harness's manual attach. The final harness used a local
journal timestamp and isolated only the deliberate wrong-key probe in a
transient unit. Both fixes were exercised by tests that failed before the
script changes and passed afterward.

The final client status was `state=passed`, `phase=key-migration`, and
`rows=24`. The outer supervisor exited 0. It deleted all three VMs and their
boot disks, wrote `resources_absent=1`, and both independent project queries
returned empty instance and disk lists.

## Qualification boundary

This run closes MAKI-019 only for the tested stopped bearer and mTLS client
credential transition and the tested SQLite DB-native migration into a distinct
reference-provider key/profile. It demonstrates that the existing-volume
canary stayed stable across authentication changes, that a known wrong key was
refused on the new volume after initialization, and that the logical database
survived the cutover and restart.

It does not qualify server certificate or server-CA rotation, hot credential
reload, same-key/profile endpoint-address rotation, an in-place key change,
rollback after writes begin on the new volume, provider key retirement, a
production database profile, DNS/proxy/packet-loss behavior, vendor rate
limits, long-duration load, or physical power loss. Those items still require
target-specific execution and change-management evidence.
