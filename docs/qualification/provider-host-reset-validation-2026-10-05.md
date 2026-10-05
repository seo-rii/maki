# Provider host reset under a writing client — 2026-10-05

A dated record of one campaign on two disposable GCE VMs (times are UTC); it
does not claim current state. Earlier remote-provider campaigns took an
endpoint away while its host stayed up (a stopped service or a client-side
firewall rule). Here the **whole provider host was hard-reset** (`gcloud
compute instances reset`: RAM, kernel and every connection lost, no TCP
reset sent) while a client kept writing through Maki.

## Environment

The two-host setup of the
[cross-host campaign](cross-host-sandbox-validation-2026-10-05.md): Debian
12.15 (`6.1.0-53-cloud-amd64`) on both VMs; client `e2-standard-4` with the
packaged `maki@.service` (`SystemCallFilter=@system-service`,
`SystemCallErrorNumber=EPERM`, `MemoryDenyWriteExecute=yes`), binaries built
at `1a25e88`, nbd-client 3.27.1; provider `e2-standard-2` with nginx 1.22.1
and the qualification service (endpoint A TLS 1.2, B TLS 1.3, client
certificates required), enabled to start at boot. The client reached the
provider by its internal DNS name. Both endpoints are on the provider host, so
a reset takes both away.

## Method

For each of `remote-http`, `remote-websocket` and `remote-grpc`, a 1 GiB v3
volume with XFS on `/dev/nbd15` and `availability_policy = "stall"`:

1. A writer creates 1 MiB files with random content, each `fsync`'d, and
   only then appends (time, SHA-256, name) to an `fsync`'d ledger on the
   client's boot disk: a ledger line is an acknowledged write.
2. After 20 acknowledged files the client asks for a reset. The controller
   records the provider's boot ID, resets the VM, waits until nginx and all
   six provider services are active, records the new boot ID (it must
   differ), and tells the client.
3. The writer must still be running; it must then acknowledge 20 more
   files.
4. Every ledger entry is read back after dropping caches; drain, stop and
   start; every entry is read back again; offline deep check.

## Results

**21 of 21 checks passed** (7 per transport). Three resets, each with a new
boot ID.

| Transport | Files acknowledged | Longest gap between acknowledgements | Gap began after the reset call started | Provider serving again (controller view) | Failovers / retries |
|---|---|---|---|---|---|
| HTTP | 222 | 19.5 s | +1.4 s | 23.0 s | 18 / 53 |
| WebSocket | 352 | 12.2 s | +3.8 s | 29.6 s | 8 / 16 |
| gRPC | 389 | 13.6 s | +8.1 s | 34.1 s | 2 / 3 |

- **No write failed.** With both endpoints gone the writer blocked in
  `fsync` and resumed when the host returned; the WebSocket and gRPC
  connections were re-established to the rebooted host.
- **No acknowledged data lost:** every acknowledged file read back intact,
  live and after a daemon restart; all deep checks `clean`.
- **The gaps are the outage.** Each transport's longest gap began 1.4–8.1 s
  after the controller started the reset call (the API call takes that long
  to act); the 12–20 s gaps are how long the client could not encrypt. The
  controller's "serving again" times are upper bounds: they include the API
  call and SSH polling every 5 s.
- No deadline expiry, unsafe-retry refusal, checkpoint or journal-sync
  failure, and no `EPERM`, `SIGSYS` or seccomp message.

## Limits

- A GCE reset is fast: the provider was unreachable for roughly 12–20 s. A
  host that stays down for minutes, or one that comes back with a different
  address, was not tested.
- The writer is a single sequential stream with `fsync` per file, not a
  database.

## Not covered

- Real WAN latency; a commercial provider; physical power loss and long soak
  runs.
