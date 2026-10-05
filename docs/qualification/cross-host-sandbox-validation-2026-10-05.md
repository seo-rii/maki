# Cross-host remote transports under the shipped sandbox — 2026-10-05

A dated record of one campaign on two disposable GCE VMs (times are UTC); it
does not claim current state. The earlier remote-transport campaigns ran the
client and the providers on one host over loopback, with the provider name
in `/etc/hosts`. Here the client reached a separate provider host over the
VPC by its GCE internal DNS name, with the packaged `maki@.service`
(`SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM`,
`MemoryDenyWriteExecute=yes`). The
[2026-09-19 cross-host campaign](cross-host-tls-provider-validation-2026-09-19.md)
covered HTTP only, before the sandbox existed.

## Environment

| Item | Client | Provider |
|---|---|---|
| Instance | `maki-r5-xhc-daac972f`, `e2-standard-4`, 10.178.0.42 | `maki-r5-xhp-daac972f`, `e2-standard-2`, 10.178.0.41 |
| Image and kernel | Debian 12.15, `6.1.0-53-cloud-amd64` | same |
| Software | systemd 252.39, nbdkit 1.32.5, nbd-client 3.27.1 (source build) | nginx 1.22.1 |
| Network | default VPC, `asia-northeast3-a`; no external path to the provider ports | |

Both VMs had no service account or scopes and a fixed termination time with
`DELETE`. The Maki binaries (`maki`, `maki-attach`, `maki-nbdkit.so`) were
built on the controller at `1a25e88` (Debian 12, same toolchain), stripped,
hashed and copied; the packaged units came from the same revision. The
private CA, the server certificate (SAN: the provider's internal DNS name),
the client certificate, the provider key and the bearer token were generated
on the controller.

The provider host ran the qualification service from the earlier campaigns
(`maki-crypto-local` AES-256-GCM-SIV) as six services behind nginx: endpoint A
on TLS 1.2 (ports 8443, 8445, 8447) and B on TLS 1.3 (8444, 8446, 8448), each
requiring a client certificate.

## Name resolution

The client resolved
`maki-r5-xhp-daac972f.asia-northeast3-a.c.hancomac.internal` to 10.178.0.41
through the system resolver (systemd-resolved configuration with the GCE
metadata server, `169.254.169.254`, as name server); the name was not in
`/etc/hosts`. Which glibc path (`nss-resolve` or direct DNS) served the
daemon's lookups was not recorded. A health request with the client
certificate returned 204 from 10.178.0.41, and one without it returned 400.

## Method

Per transport, a 1 GiB v3 discard volume with XFS on `/dev/nbd15`:

1. A log-only pass (`SystemCallLog=~@system-service`, filter removed) over
   format, writes, an endpoint outage, `fstrim` and a restart; a positive
   control showed the kernel reports a deliberate `swapoff(2)`.
2. Under the shipped unit: 128 MiB written and read back; writes with each
   endpoint unreachable in turn; both unreachable with an `O_DIRECT` writer
   that must stall and then complete when B returns; `fstrim` and
   checkpoint; stop/start and readback; offline deep check.

The client cannot stop services on the provider host, so an endpoint was made
unreachable on the client with an `nft` output rule that rejects its port
with a TCP reset.

## Results

**33 of 33 checks passed** (11 per transport).

- **Sandbox:** no audit `SECCOMP` record from the daemon in any log-only
  pass, and no `EPERM`, `SIGSYS` or seccomp message under the filter, with
  name resolution and TLS over the real NIC.
- **TLS edge** (provider access log): every request carried a verified client
  certificate; A served only TLS 1.2 and B only TLS 1.3. HTTP 280,034 (A) and
  218,815 (B) successful requests plus the attach probes' 422s; gRPC 7,202
  and 4,906; WebSocket 4 and 4 upgrades. No 502s: blocked traffic never
  reached the provider host.
- **Failover and outage:** 24–33 endpoint failovers and 44–49 retries per
  transport; no deadline expiry, unsafe-retry refusal, checkpoint or
  journal-sync failure. The writer stalled with both endpoints unreachable
  and completed when B returned.
- **Discard:** `fstrim` trimmed 775.8 MiB per volume.
- **Deep checks:** all `clean`.

## Not covered

- Real WAN latency and loss between hosts (the VPC hop is sub-millisecond;
  netem results are in the [Debian 13 records](debian13-postgresql-http-validation-2026-10-05.md)).
- A provider host failing as a whole (power, kernel) rather than an endpoint
  becoming unreachable.
- A commercial provider; physical power loss and long soak runs.
