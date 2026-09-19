# Cross-host TLS reference-provider validation (2026-09-19)

## Result

Revision `47058d2c60b5025ce8a1a2ccaf57ba01943e5e60` passed a disposable
three-host Debian 12 GCE campaign. Two provider VMs and one client VM
communicated over their VPC private addresses. nginx terminated HTTPS on each
provider with a private qualification CA, required an mTLS client certificate,
and forwarded authenticated requests to a reference crypto service. Maki also
sent a bearer credential through its production remote-HTTP mapping.

The client explicitly completed one `TLSv1.2` health request against provider A
and one `TLSv1.3` request against provider B. The nginx access logs recorded
`SUCCESS CN=maki-storage-client` and HTTP 204 for both. The Maki build used
`rustls v0.23.45`, and the installed client recorded the full source revision
above.

The actual Maki nbdkit, kernel NBD, LVM, XFS, and SQLite WAL path then retained
32 externally acknowledged rows. Writes continued with provider A stopped and
again with provider B stopped. With both provider VMs stopped, the next writer
remained active and the independently fsynced ledger stayed at 24. Starting B
allowed that same transaction to reach 25; after both providers returned, the
database reached 32. A full Maki stop/start and reattach preserved every row ID
and body hash with `PRAGMA integrity_check=ok`.

The final offline deep check reported durable sequence 17,949, 16,526 allocated
slots, and zero invalid slots. All three instances and their auto-delete boot
disks were deleted; the controller recorded `resources_absent=1`, and final
project queries returned no `maki-*` instance or disk.

This is a scoped cross-host HTTPS and reference-provider result. It is
not a commercial vendor qualification and does not approve Maki for production.

## Fixed environment

| Item | Executed value |
|---|---|
| Maki revision | `47058d2c60b5025ce8a1a2ccaf57ba01943e5e60` |
| Zone and network | `asia-northeast3-a`; GCE VPC private IPv4 addresses |
| Provider A | `e2-standard-2`; instance ID `1978225166047768575` |
| Provider B | `e2-standard-2`; instance ID `2612863286190010354` |
| Client | `n2-standard-4`; instance ID `6603580124053106451` |
| Image | Debian 12 Bookworm; client kernel `6.1.0-53-cloud-amd64` |
| HTTP client TLS | `rustls v0.23.45` |
| TLS edge | nginx 1.22.1; qualification CA; required client certificate |
| Authentication | mTLS client subject `CN=maki-storage-client` plus bearer credential |
| NBD client | `3.27.1`, commit `f96f7fca3b37f4254c26c95f5c6c9dae70e030a1` |
| Storage graph | `/dev/nbd15`, pinned PV/VG, 384 MiB LV, XFS |
| Maki volume | 512 MiB; 4 KiB device and crypto units |
| Dispatch | two HTTPS endpoints; `availability_policy = "stall"`; 2 s transport timeout |
| Database | SQLite WAL; `synchronous=FULL`; external fsynced acknowledgement ledger |
| Evidence | `/home/seorii/logs/maki-cross-host-tls-final2-20260919` |

The qualification provider used `maki-crypto-local` AES-256-GCM-SIV and checked
the bearer credential before serving `/health`, `/encrypt`, or `/decrypt`.
Ciphertext remained bound to the volume UUID, unit index, format version, and
compatibility ID. Its purpose was to exercise Maki's real HTTP mapping and
failure behavior over a host boundary; it was not a vendor implementation.

## Authentication and refusal controls

Before creating the accepted volume, the campaign attempted three actual NBD
attachments with deliberately invalid transport credentials:

| Control | Required result |
|---|---|
| Wrong CA | Provider verification refused startup before socket publication |
| No client certificate | Provider verification refused startup before socket publication |
| Wrong bearer credential | Provider verification refused startup before socket publication |

Each refusal occurred before a key canary or journal record was published. The
positive health probes pinned TLS 1.2 on A and TLS 1.3 on B; their access-log
gates required the expected protocol, verified client subject, request, and
204 response together.

## Fault and oracle protocol

The successful run used this sequence:

1. Complete the TLS 1.2 and TLS 1.3 health probes and all three refusal
   controls, attach the volume, and commit rows 0–7.
2. Stop provider A and commit rows 8–15 through provider B.
3. Restart A, stop provider B, and commit rows 16–23 through provider A.
4. Stop A as well, start the row-24 transaction, wait eight seconds, and
   require both the live writer and the unchanged 24-row ledger.
5. Start B, require the same writer to complete exactly row 24, then start A
   and commit rows 25–31.
6. Compare all 32 rows with the external ledger, drain and stop Maki, restart
   and reattach, compare again, then clean up and run the offline deep check.

The ledger was appended only after each SQLite commit and fsynced along with
its parent directory. The independent verifier rejected missing, extra,
reordered, or substituted rows and calculated each body hash itself. It
reported row counts 8, 16, 24, 25, and 32 with integrity `ok` at every gate.

The metrics snapshot before restart recorded 17 endpoint failovers and 45
retries, with both circuits closed at collection time. It also recorded zero
crypto deadline expirations, unsafe retry refusals, checkpoint failures, and
journal sync failures.

## Harness correction and immutable rerun

The first final attempt built the current source successfully but its new
explicit curl probes omitted nginx's `:8443` port and attempted TCP port 443.
It failed before the accepted volume path ran. The three VMs were deleted and
the project-wide resource queries were empty. A regression assertion first
reproduced the missing explicit port, then passed after both probe URLs were
corrected.

Earlier development attempts remain archived separately but do not count as
the final result: some used an older source archive, and one run read a changed
evidence gate after launch. Their disposable resources were also deleted. The
final rerun below froze the complete input set before creating a VM.

The successful rerun used a new private directory and did not modify any input
after launch. Its frozen SHA-256 values were:

```text
5acd4a2a48f92fe4a1f16064a6c3a2456e4a62d59da5689a47aaa8ed539c1160  run-gcp.sh
94c74eb10ea38da99cb5dff104359849c722cc857add48b1d02e3d9eb7179074  provider-setup.sh
5a86f13f6aeb4620efd12b1af1481de101d164b1cf147aa276a61b120ae2ef9a  client-validation.sh
1d0cb79bdc89e795e6aa3243555fc8f1eca023d1e343e3c416d4e1ff00d71dc2  maki-current.tar.gz
5b478ed7717a939e7e9fca336acccd451181959114db8224c61b6ec8581bcaa9  provider-server.tar.gz
```

All five hashes reverified after the run. The supervisor and campaign both
exited 0.

## Scope and limits

The result covers one short Debian 12 profile, one Maki client, two reference
provider hosts, private-IP HTTPS, an ad hoc CA, mTLS, a bearer credential,
provider-VM stop/start, one SQLite database, and a single pinned storage graph.
It supplies actual VPC, TLS, authentication, endpoint-failover, total-outage,
restart, and cleanup evidence for that profile.

It does not cover a commercial provider's API, independent key-management
system, public Internet path, DNS or proxy failure, latency and rate limits,
certificate or credential rotation, bounded-error database behavior, packet
loss, concurrent client-VM loss, multiple volumes, another database, a long
soak, or physical power loss. Those remain target-environment qualification
work.
