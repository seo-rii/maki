# Remote HTTP provider database fault validation (2026-09-18)

## Result

Revision `c385c996bbbce0332f964706da6c2296da3f8e69` passed a
disposable Debian 12 GCE campaign that combined the shipped systemd graph,
actual Maki nbdkit, kernel NBD, a pinned single-PV/LV XFS filesystem, SQLite
WAL, and two authenticated HTTP crypto-provider processes. The providers used
the repository's AES-256-GCM-SIV implementation and bound ciphertext to the
volume UUID, unit index, format version, and compatibility ID.

SQLite committed 32 deterministic 32 KiB rows with `synchronous=FULL`. Each
database commit preceded a record in an independently fsynced acknowledgement
ledger. Provider A and B were stopped separately while writes continued, then
both were stopped while a new transaction was attempted. During that total
outage the writer stayed blocked and the ledger remained at 24 rows. Restoring
provider B allowed exactly one new commit; the observed outage interval was
4,094 ms. Both providers then returned and the database reached 32 rows.

An independent reader matched every row ID, payload digest, and body SHA-256
against the external ledger and reported `PRAGMA integrity_check=ok`. After a
full drain, packaged-target stop, and lifecycle restart, the same 32 rows and
hashes matched again with `integrity_check=ok`. The final drain and offline
check left no NBD connection or device-mapper mapping.

This closes the missing database-through-remote-provider fault observation for
the exact profile below. It is not production approval for a vendor endpoint,
wide-area network, another database, or a larger deployment.

## Fixed environment

| Item | Executed value |
|---|---|
| Maki revision | `c385c996bbbce0332f964706da6c2296da3f8e69` |
| Successful instance ID | `2193866549037708493` |
| Successful boot disk ID | `8400060035098555597` |
| Image | `debian-12-bookworm-v20260908` |
| Machine | `n2-standard-4` in `asia-northeast3-a` |
| NBD client | `3.27.1`, commit `f96f7fca3b37f4254c26c95f5c6c9dae70e030a1` |
| Storage graph | `/dev/nbd15`, one pinned PV/VG, 384 MiB LV, XFS |
| Maki volume | 512 MiB; 4 KiB device and crypto units |
| Provider | Two loopback HTTP processes; AES-256-GCM-SIV; bearer credential loaded by systemd |
| Dispatch | `availability_policy = "stall"`; 2 s transport timeout; exponential retry; batch size 1 |
| Database | SQLite WAL; `synchronous=FULL`; `wal_autocheckpoint=1` |
| Evidence | `/home/seorii/logs/maki-remote-provider-db-20260918` |

The qualification provider was built outside the repository and wrapped the
same `maki-crypto-local` provider used by Maki. It exposed only `/health`,
`/encrypt`, and `/decrypt` on loopback. Every crypto request required a bearer
credential. Logs recorded the endpoint, operation, and unit index, without
payloads or credentials. Maki's create-time self-test exercised encryption,
decryption, tamper rejection, and context binding through each endpoint before
the volume was attached.

## Fault and oracle protocol

The campaign used this ordered sequence:

1. With both endpoints healthy, commit and externally acknowledge rows 0–7.
2. Stop provider A, require provider B's served-request count to rise, then
   commit rows 8–15.
3. Restart A, stop B, require A's served-request count to rise, then commit
   rows 16–23.
4. Stop both endpoints and start the row-24 transaction. After three seconds,
   require the writer to remain alive and the external ledger to remain at 24.
   Restart B, wait for the same writer to finish, and require the ledger to
   advance to exactly 25.
5. Restart A, commit rows 25–31, and compare the whole database with the ledger.
6. Drain and stop the packaged lifecycle, run the offline check, restart the
   lifecycle, compare all rows again, then perform the final drain, stop, and
   offline check.

The body generator derives each 32 KiB value from its row ID. The ledger stores
the resulting SHA-256 after SQLite has committed and then fsyncs the file and
its parent directory. Readers calculate the body hash independently and reject
a missing, extra, reordered, or substituted row.

## Observations

| Observation | Result |
|---|---:|
| Harness checks | 12 passed, exit 0 |
| Provider requests logged | 21,326 |
| Provider A count during B outage | 8,271 → 8,461 |
| Provider B count during A outage | 10,066 → 10,254 |
| Maki endpoint failovers | 0 → 2 → 4 → 6 |
| Maki provider retries | 0 → 2 → 4 → 9 |
| Total-outage ledger | 24 before recovery, 25 after recovery |
| Total-outage interval | 4,094 ms |
| Final rows | 32 exact IDs and hashes |
| SQLite integrity | `ok` before and after lifecycle restart |
| Journal state at all metric snapshots | appended sequence equals durable sequence; zero pending bytes and sync failures |
| Offline checks | passed before restart and after final stop |

Both endpoints served encrypt and decrypt calls. During the one-endpoint
outages, metrics showed the stopped endpoint's circuit open and the remaining
endpoint closed. The final snapshot recorded six failovers and nine retries,
with zero checkpoint failures, zero journal sync failures, and zero reported
plaintext cache bytes.

## Harness correction

The first disposable VM completed build, installation, provider startup, and
volume creation, then failed before daemon startup. The harness generated the
bearer token as a 64-character hexadecimal string. Maki's file credential
loader intentionally decodes pure, even-length hexadecimal input as binary key
material, so the HTTP header resolver correctly rejected the result as invalid
UTF-8. This was a harness representation error, not a product failure.

The rerun prefixed the random token with non-hexadecimal text and asserted that
the token could not be mistaken for encoded key material. The failed-harness
instance (`6561479394328655579`) and its auto-delete disk were removed before a
new VM was created. Both exact lookups failed after deletion.

## Evidence and cloud cleanup

The private evidence directory contains the input hashes, bounded launcher
status, external ledger, both database snapshots, metrics at each provider
state, systemd journals, drain and offline-check results, GCP resource
identities, and deletion observations. `validate-evidence.py` independently
rechecked the 12 pass records, row and body hashes, outage ordering, metrics,
provider counts, both harness classifications, and resource cleanup. It
reported `evidence_validation=passed`. The 102-entry evidence manifest verifies
without a mismatch.

The provider key and bearer token never left either disposable VM and were
explicitly excluded from the downloaded archive. A remote pre-archive scan
found neither secret in any collected file. GCP account and network identities
were redacted locally. The successful VM and boot disk were then deleted;
exact-name lookups failed and project-wide queries recorded:

```text
remaining_maki_instances=0
remaining_maki_disks=0
```

## Scope and limits

The result covers a short, single-VM, loopback HTTP campaign using two
independent provider processes, one credential and key, one SQLite database,
one Maki volume, and one pinned PV/VG/LV. It verifies process-stop failover and
stall/resume behavior through the actual kernel and filesystem path. It also
verifies graceful packaged lifecycle restart after the provider faults.

It does not cover TLS, a real network partition, DNS, proxies, vendor rate
limits, malformed responses, credential or endpoint rotation, a provider with
independent key storage, cross-host provider failure domains, DB errors under a
bounded-error policy, concurrent daemon or VM loss during an outage, another
database, multi-volume mapping, long-duration load, latency targets, peak RSS,
distribution package install or upgrade, DB-native or legacy migration,
physical power loss, or a vendor endpoint. Those items remain release and
operational qualification work.
