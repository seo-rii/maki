# Server CA and endpoint rotation validation — 2026-09-19

This report records a stopped server-certificate and private-CA rotation,
followed by an endpoint-address replacement that retains the same encryption
key and volume. The tested source revision was
`da89ae3773a87fe77e6046ca03c7e912dddbcc87` with `rustls 0.23.45`.

The final run passed: 48 exact SQLite ACK rows survived all transitions, the
offline deep check reported zero invalid slots, and all four VMs and their
disks were deleted. This qualifies the stopped reference-provider profile
below, not a commercial provider or general production deployment.

## Topology and fixed inputs

The campaign used four disposable Debian 12 GCE VMs in one private VPC:

- three `e2-standard-2` providers A, B, and C on distinct private IPv4 addresses,
  with nginx terminating TLS/mTLS on port 8443 in front of the frozen reference
  provider;
- one `n2-standard-4` client running actual Maki nbdkit, kernel NBD, a pinned
  single-PV LVM/XFS attachment, and SQLite WAL with `synchronous=FULL`. Recorded
  versions were Linux 6.1.0-53-cloud-amd64, Rust 1.98.1, nbdkit 1.32.5,
  userspace nbd-client 3.27.1, and SQLite 3.40.1;
- one 512 MiB Maki data volume and a 384 MiB logical volume;
- the same provider encryption key and `cross-host-tls-v1` profile on all three
  providers; the bearer token, client certificate/private key, and trusted
  client CA remain fixed throughout;
- initially old-CA server certificates on A/B, new-CA replacements for A/B,
  and a new-CA certificate on C. Each leaf has its server's IP SAN. B also
  retains an old-CA leaf on isolated port 10443 for a negative trust control.

The frozen scripts, source archives and harness tests, together with the
generated certificate manifest, collected evidence, and supervisor status, are in
`/home/seorii/logs/maki-server-rotation-20260919-v3`. Secret values are not
included in this report.

The ACK ledger lives outside the encrypted Maki volume on the same client VM.
After each successful SQLite commit, the writer appends its row ID and body
SHA-256 to that ledger and fsyncs it. This is an exact logical-data oracle for
the stopped transitions; it is not an independent-host power-loss oracle.

## Server trust and endpoint transitions

Every transition held writers stopped, cleaned up the trusted attachment,
received a successful drain response with a checkpoint sequence, observed
`io_state: drained`, and stopped the daemon. Each restart verified both intended
peers, required `ready`/`running` state, compared both superblock and both canary
hashes, and reattached through the trusted helper before database reads or writes.

| Stage | Configured peers | Client private-CA trust | Exact ACK rows after writes |
| --- | --- | --- | ---: |
| Initial attach | A-old, B-old | Old root | 8 |
| Mixed server generations | A-new, B-old | Old + new roots | 16 |
| Both servers replaced | A-new, B-new | Old + new roots | 24 |
| Old root removed | A-new, B-new | New root only | 32 |
| Address replacement | C-new, B-new | New root only | 40 |
| Lifecycle restart | C-new, B-new | New root only | 48 |

Fresh TLS connections verified each configured address and its exact DER
certificate fingerprint at every positive transition. Both actual Maki peers
reported `validated: true`, `rejected: false`, and `circuit: closed`. The
pre-change database prefix matched its ledger before new writes at every stage.

Before replacing A's address with C's distinct IP, the campaign stopped A's
nginx listener and required `nginx_state=inactive`. C served the same key/profile
and passed the existing-volume checks. B remained available throughout this
address change; no C-only availability result is inferred.

Independent provider evidence matched the initial and final encryption-key,
bearer-token, and trusted-client-CA hashes on every host and across all three
hosts. C's access log contained 714 successful encrypt requests and 1,461
successful decrypt requests, establishing that it handled actual crypto calls
as well as health probes. These counts include qualification traffic and are
not a database throughput measurement.

Two isolated negative controls covered both trust directions:

| Control | Same listener with correct root | Wrong trust | Actual Maki result |
| --- | --- | --- | --- |
| New-CA A:8443 with old-only trust | HTTP 204 | curl exit 60 | Startup refused; root NBD negotiation failed |
| Retained old-CA B:10443 with new-only trust | HTTP 204 | curl exit 60 | Startup refused; root NBD negotiation failed |

Both controls preserved the superblock/canary hashes and used isolated transient
units, leaving the packaged daemon stopped. They did not invoke its automatic
recovery handler. The source certificate manifest proves distinct old/new roots
and server leaves; the negative controls additionally prove refusal at an
otherwise reachable listener.

## Final readback and cleanup

All six stopped volume inspections retained UUID
`3e348389-bb0a-4bf5-8faf-12f9781a5b09`. Provider A/B/C used distinct addresses
`10.178.0.2`, `10.178.0.4`, and `10.178.0.5`. The final C/B attachment matched
all 48 row IDs and body hashes, with `PRAGMA integrity_check = ok`, before
trusted cleanup and acknowledged drain. The offline deep check reported
16,544 allocated slots, zero invalid slots, and checkpoint sequence 20,144.

Both final negative controls recorded `startup_cause: operation-deadline`,
root NBD exit 1, and a natural daemon exit 1. Both also recorded a socket inode
during startup. The paired TLS probes returned 204 with correct trust and curl
60 with incorrect trust; the verdict does not mislabel the deadline itself as
an explicit TLS error.

The standalone evidence verifier passed the full ACK progression, per-peer
validation and leaf fingerprints, unchanged superblock/canary hashes for each
transition, client credential hashes, provider key fingerprints, negative
controls, final readback, deep check, and cleanup. The frozen input manifest
matched before launch and after collection. The final host and supervisor both
exited 0; successful post-deletion instance/disk inventories and a fresh project
query returned empty `maki-*` lists. The earlier two attempts also recorded
empty resource inventories after their failure cleanup.

The final preflight passed 32 tests. TDD corrections included real local
nbdkit startup/negotiation controls and replay of the second cloud attempt's
preserved refusal evidence. Optimized-Python checks also rejected incorrect
outcomes; acceptance predicates do not disappear under `python3 -O`.

## Harness correction and evidence boundary

The first frozen attempt (`maki-server-rotation-20260919-v1`) passed the
mixed old/new-CA peer stage and exact 16-row readback, then stopped when its
negative control saw a Unix socket inode. That check was invalid: nbdkit binds
the socket before calling Maki's `after_fork` initialization, and serves clients
only after that initialization succeeds. See the
[nbdkit callback lifecycle](https://libguestfs.org/nbdkit-plugin.3.html#Callback-lifecycle)
and [v1.32.5 server startup](https://github.com/libguestfs/nbdkit/blob/v1.32.5/server/main.c#L925).
The first attempt exited 1 and deleted all four VMs and their disks. It is not
a completed qualification or evidence of an accepted NBD export with bad trust.

The second attempt (`maki-server-rotation-20260919-v2`) reached a real root NBD
probe failure and a daemon exit 1. Its oracle still required an inner TLS error
string, but the batch scheduler's outer five-second budget instead reported
`retryable: operation deadline exceeded`. The captured systemd result was
`exit-code`, not watchdog termination. This attempt also exited 1 and deleted
all four VMs and disks; later stages were not run.

The corrected control requires root `nbdinfo` to exit 1, systemd
`Result=exit-code` with `ExecMainStatus=1`, a provider startup refusal,
and unchanged superblock/canary hashes. It distinguishes an explicit TLS error
from an operation deadline and requires the paired correct-root HTTP 204 and
wrong-root curl exit 60 controls in either case. The deadline message alone is
not attributed to TLS. Socket inode existence is recorded but does not decide
the result. The isolated
single-endpoint negative daemon uses `bounded-error` with a five-second
operation budget so the intentionally rejected TLS handshake produces a
terminal startup result instead of retrying indefinitely under `stall`;
the normal two-peer workload retains `stall`. A watchdog kill is not a passing
refusal. Earlier campaign reports' wording about socket publication has been
corrected to startup refusal before readiness.

## Limits

This is a planned stopped transition on one reference-provider profile. It
does not qualify hot reload, a commercial crypto vendor, DNS/SNI changes,
proxies, packet loss, rate limits, expired certificates, CRL/OCSP, or production
latency and long-duration load. Removing a private root from the configured CA
file neither revokes that CA nor destroys its private key, and does not remove
built-in public roots.

Provider B remains configured during A-to-C replacement. Validation of C and
readback through C/B do not prove that C alone served the complete database
workload. Retiring A's nginx listener is not a VM/backend power cut. This run
does not add power-loss evidence or qualify encryption-key retirement,
production database migration, or rollback after divergent writes. The R3
review bundle and general production approval remain open.

An offline deep check covers stored structure and checksums; authenticated
database recovery is established separately by the exact row/hash comparisons.
The active CA file is installed by the frozen procedure and checked through
fresh TLS and Maki connections; the campaign does not collect a separate copy
of the active trust file at every stage.
