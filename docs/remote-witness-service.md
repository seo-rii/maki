# Remote witness service

`maki-witness` is a single-volume freshness authority with TLS 1.3 mutual
certificate authentication, writer/admin roles and exact-predecessor
transactions. It supports either a durable local state directory or a pinned
etcd quorum shared by multiple stateless witness frontends. The quorum backend
provides replication and automatic leader failover; volume clients can also
fail over between frontends. The authority and its restore administration must
remain independent of backing snapshots. Recreating it from an older snapshot
can defeat freshness protection.

The rollback backing coordinates attach, takeover, enrollment recovery and
restore with this authority. See [rollback protection](rollback-protection.md)
and [the protocol design](rollback-protection-design.md). This page describes
executable setup and operator procedures. It does not report a production
deployment or an external qualification campaign.

## Initialize a local authority

Build the binary with `cargo build --release --locked -p maki-witness-cli`.
Initialize one authority directory with a fresh, nonzero storage-identity UUID.
This identity differs from the inner volume superblock UUID. Run it as the
service account that will serve the authority (`maki-witness` here), below a
directory that account owns:

```sh
install -d -o maki-witness -g maki-witness -m 0700 /var/lib/maki-witness
sudo -u maki-witness maki-witness init /var/lib/maki-witness/volume 01234567-89ab-cdef-0123-456789abcdef
```

Initialization refuses existing state. Local `serve` holds the authority's
exclusive process lock until exit. Copied local directories are separate
histories; they cannot be used as failover replicas.

Whoever can write the state directory or its `remote.*` files can put an older
record back and roll the authority back. On Unix, `init` and `serve` therefore
require the directory (checked on the opened directory, without following a
symlink) and those files to be owned by root or by the user the command runs
as, and not writable by group or others; a sticky bit does not make shared
write access safe. Anything else is refused before state is written or the
listener is bound, with an error naming the owner. `init` creates missing
directories owner-only (`0700`) as the user that runs it, so an authority
initialized as root must be handed over with `chown -R` before the service
account serves it, and a `serve` run as root refuses a directory owned by the
service account. Group and other read access is allowed: the files hold the
public record that any authenticated client can inspect and SHA-256 digests of
the last request and of the current random 256-bit session capability, which do
not reveal the capability. The check covers the state directory, not its
ancestors; keep those writable only by root or the service account.

Provision a server certificate with the intended DNS name or IP address in its
subject alternative names, plus separate writer and administrator client
certificates. The server CA bundle trusts the client issuers, and clients trust
the server issuer. Each client must also appear in every frontend's explicit
leaf-certificate allow-list. Calculate fingerprints with:

```sh
maki-witness fingerprint /etc/maki-witness/writer.cert.pem
maki-witness fingerprint /etc/maki-witness/admin.cert.pem
```

A local `server.toml` contains:

```toml
state_dir = "/var/lib/maki-witness/volume"
listen = "127.0.0.1:9443"

[server]
timeout_ms = 5000
max_connections = 16

[server.tls]
ca_file = "/etc/maki-witness/client-ca.pem"
cert_file = "/etc/maki-witness/server.cert.pem"
key_file = "/etc/maki-witness/server.key.pem"

[[server.principals]]
certificate_sha256 = "REPLACE_WITH_WRITER_CERTIFICATE_SHA256"
role = "writer"

[[server.principals]]
certificate_sha256 = "REPLACE_WITH_ADMIN_CERTIFICATE_SHA256"
role = "admin"
```

Replace fingerprints with the printed 64-character lower-case SHA-256 values.
Run the authority under its intended service account:

```sh
maki-witness serve /etc/maki-witness/server.toml
```

Readiness follows credential validation, durable state open and socket bind.
The line includes the actual listening address. Service-manager integration,
network policy and independently managed persistent storage are operator
provisioning steps.

A local authority answers a change only after writing and syncing
`remote.next`, renaming it over `remote.state` and syncing the directory. A
failure before the rename (EMFILE, ENOSPC or EIO while opening, writing or
syncing `remote.next`) leaves `remote.state` unchanged: that request is
answered as unavailable and later requests are served normally. After a
failed rename or directory sync either state may be the published one, so
`serve` answers every request as unavailable until it is restarted; it keeps
running and does not exit by itself. The restart serves and re-publishes the
state it reads, and clients resolve their pending request against it. A
`remote.state` that changes, disappears or stops decoding while `serve` holds
its lock also makes it answer unavailable until a restart, which then serves
whatever valid state the file holds: find out what changed it first.

## Initialize a replicated authority

Provision an independently managed, persistent etcd cluster with at least three
members and a working majority quorum. The backend uses etcd's TLS-protected
v3 KV gateway with linearizable reads and transactions. Every witness frontend
for this volume must use the same pinned cluster ID, storage identity and key.
No frontend maintains a local witness replica or initializes a missing key at
startup. A minority partition or unavailable quorum refuses freshness checks
and writes.

Use a dedicated etcd client CA that issues backend credentials only to the
witness service. Backend credentials grant access to the authority's KV state;
never distribute them to volume writers or administrators. Restrict direct
etcd access to trusted service processes. Frontend writer/admin certificates
and allow-lists govern the public witness protocol; they do not restrict a
client that has direct backend access. This feature does not configure etcd
membership, storage, network policy or authentication infrastructure.

Every FLUSH or FUA, like every other backing sync such as a checkpoint,
advances the authority record with an etcd transaction, so etcd's revision
history grows with the volume's write rate. Enable etcd auto-compaction and
monitor the backend quota: at the quota, etcd raises a `NOSPACE` alarm and
refuses writes, and the volume stops.

Record the actual cluster ID from trusted operator inspection. Configure it as
a quoted canonical decimal string so the full unsigned 64-bit range fits TOML.
Replace the example cluster ID and addresses below. The storage identity must be a fresh,
nonzero UUID. Create a standalone `etcd.toml`:

```toml
cluster_id = "1234567890123456789"
storage_identity = "01234567-89ab-cdef-0123-456789abcdef"
key = "/maki/witness/volume"
timeout_ms = 3000

[[endpoints]]
address = "192.0.2.21:2379"
server_name = "etcd-1.example.net"

[[endpoints]]
address = "192.0.2.22:2379"
server_name = "etcd-2.example.net"

[[endpoints]]
address = "192.0.2.23:2379"
server_name = "etcd-3.example.net"

[tls]
ca_file = "/etc/maki-witness/etcd-server-ca.pem"
cert_file = "/etc/maki-witness/etcd-service.cert.pem"
key_file = "/etc/maki-witness/etcd-service.key.pem"
```

Initialize the absent key explicitly. The command UUID must equal the pinned
`storage_identity`:

```sh
maki-witness init-etcd /etc/maki-witness/etcd.toml 01234567-89ab-cdef-0123-456789abcdef
```

This transaction refuses an existing key. If its reply is lost, inspect the
already enrolled key through a frontend; do not delete it and retry enrollment.
The authority value has no expiring lease.

For each frontend, retain `listen` and the `[server]` TLS/allow-list sections
shown above, remove `state_dir`, and add the following instead. The frontend's
listener address and server certificate can differ, but all client-facing
certificates must cover the configured common witness server name:

```toml
[etcd]
cluster_id = "1234567890123456789"
storage_identity = "01234567-89ab-cdef-0123-456789abcdef"
key = "/maki/witness/volume"
timeout_ms = 3000

[[etcd.endpoints]]
address = "192.0.2.21:2379"
server_name = "etcd-1.example.net"

[[etcd.endpoints]]
address = "192.0.2.22:2379"
server_name = "etcd-2.example.net"

[[etcd.endpoints]]
address = "192.0.2.23:2379"
server_name = "etcd-3.example.net"

[etcd.tls]
ca_file = "/etc/maki-witness/etcd-server-ca.pem"
cert_file = "/etc/maki-witness/etcd-service.cert.pem"
key_file = "/etc/maki-witness/etcd-service.key.pem"
```

Exactly one of `state_dir` and `[etcd]` is required. `serve` opens and verifies
existing quorum state before binding its listener. Multiple frontends can serve
this shared key; etcd serializes their concurrent full-state CAS transactions.
The same deterministic state machine and canonical version 2 value serve both
backends. Each transaction compares its predecessor's complete bytes and
modification revision. Each response verifies the pinned cluster ID, and every
selected record verifies the pinned storage identity. An endpoint's cluster
pin is checked by a read before mutation on that endpoint.

Etcd leader failover and frontend failover retain the same history. Etcd
snapshot rollback, cluster recreation and changing the cluster pin require a
separate explicit authority migration; never reset a pin to accept an older
snapshot. The pin detects a different cluster, not a restore of the same one:
restoring an etcd snapshot with the original `--initial-cluster-token` and peer
URLs reproduces the same cluster ID, so frontends accept the older authority
state it holds. Such a restore is an administrator action outside the freshness
guarantee and belongs only in that explicit migration, never in routine etcd
recovery. Never restore the quorum with a volume backup. To move an existing file-backed authority volume to quorum mode, create a
separate destination with a fresh storage identity and perform a verified
logical data migration. Copying an existing local authority value into etcd
while its old service can still run would fork trusted history and is refused
as a migration procedure. Retire the old service and its credentials through
operator-controlled cutover after destination verification.

## Credential and configuration files

Configuration files are bounded to 64 KiB and reject unknown fields. On Unix,
they must not be symlinks or writable by group/others, and must be owned by
root or by the user that runs the command (`serve`, `init-etcd` or `inspect`).
A configuration owned by any other user is refused whatever its mode, because
its owner can rewrite the administrator allow-list, the key path or the
authority it names. A root-owned `0644` file suits both the service account
and root; a command run as root refuses a configuration owned by the service
account. Configurations hold no secrets, so group and other read access is
allowed. Credential files are
regular files bounded to 1 MiB. Private-key files must not be symlinks or
accessible to group/others (`0600` is appropriate), and must be owned by root
or by the user the loading process runs as. A key owned by any other user is
refused whatever its mode, because its owner can read or replace it; a process
run as root therefore refuses a key owned by the service or daemon user. Run
the server as its service account. The remote `maki volume` commands load
their configuration's client key before they contact the authority, so run
`witness`, `snapshot` and `gc` with the daemon's writer configuration as the
daemon user (`sudo -u maki`); a snapshot also needs a backup directory that
user can create. `witness` may instead use the administrator configuration as
root. `takeover`, `restore` and `resume-enrollment` need the administrator
configuration: run them as root and then hand the new writer namespace back
([below](#snapshot-takeover-and-restore)). Certificates and CA bundles may have
any owner. The key loader accepts one
unencrypted PKCS#8, PKCS#1 RSA or SEC1 EC PEM block. Encrypted keys, bag
attributes, extra blocks and trailing non-whitespace text are refused.
Private-key PEM, base64 scratch and decoded DER are erased on drop; the pinned
rustls/ring path owns the signer. Certificate bundles cannot contain private
keys. Use absolute paths to avoid service-manager working-directory ambiguity.

The nbdkit process's opt-in memory admission policy is separate from the witness
service. Choose service-manager memory and locked-memory limits for the
frontends' workload and TLS credentials. The protocol limits below apply
independently of those deployment limits.

## Inspect through an authenticated endpoint

A standalone client configuration selects one frontend:

```toml
address = "192.0.2.10:9443"
server_name = "witness.example.net"
timeout_ms = 5000

[tls]
ca_file = "/etc/maki-witness/server-ca.pem"
cert_file = "/etc/maki-witness/writer.cert.pem"
key_file = "/etc/maki-witness/writer.key.pem"
```

```sh
maki-witness inspect /etc/maki-witness/client.toml
```

Numeric socket addresses keep DNS resolution outside the RPC path;
`server_name` is verified against the endpoint certificate. Inspection prints
the metadata record as JSON without claiming a writer session. Writer
certificates cannot authorize takeover, enrollment recovery or restoration.
Use the volume commands for administrative transitions so physical storage
preparation remains coordinated with authority activation.

Each successful claim installs a fresh random 256-bit session authorization
capability. The owning process keeps it only in zeroizing memory; the authority
stores its domain-separated digest separately from the public record. Activation,
advance and release require that capability in addition to the exact public
predecessor and authenticated role. Inspection never returns the capability or
its digest. Knowing the current session ID or sharing a writer certificate does
not authorize another process to release or modify that session. Administrative
takeover, enrollment recovery and restore install new capabilities and retain
their existing role and predecessor checks. Ambiguous commits resolve only the
same request, including its capability; losing the process's capability requires
the normal explicit administrative recovery procedure.

## Authority protocol compatibility

The authorization boundary uses wire version 2 and the `MAKIRW02` canonical
authority envelope (`format = 2`) for both local files and etcd. Version 1
requests and authority envelopes are refused, including an already active v1
session. There is no in-place upgrade: v1 has no private session authorization
that can be safely assigned to a v2 process. The outer remote COW marker and
manifest format, enrollment binding and inner volume formats are unchanged.

For an existing v1 deployment, keep its old service and client binaries together
and use them to read the exact trusted source. Initialize an independent v2
destination with a fresh storage identity, copy logical data with a trusted
reader/writer, and verify that destination before retiring the old service and
credentials. Do not copy or rewrite an authority record, clear its active claim,
reuse its identity, or convert a backing snapshot into fresh enrollment. A
new frontend refuses legacy state before binding its listener. Upgrade every
frontend and client for a given destination together; mixed wire versions do not
silently downgrade.

## Configure frontend failover

The volume configuration accepts either the existing single `address` or a
list of 1–8 unique `addresses`. A list requires the independently approved
`storage_identity` pin. Do not set both address forms:

```toml
[backing.rollback_protection]
capacity = "128MiB"

[backing.rollback_protection.remote]
addresses = ["192.0.2.10:9443", "192.0.2.11:9443", "192.0.2.12:9443"]
storage_identity = "01234567-89ab-cdef-0123-456789abcdef"
server_name = "witness.example.net"
timeout_ms = 5000
ca_file = "/etc/maki/witness/server-ca.pem"
client_cert_file = "/etc/maki/witness/writer.cert.pem"
client_key_file = "/etc/maki/witness/writer.key.pem"
```

Every listed frontend must use the same authority and role allow-list. Keep a
writer configuration for the daemon and a separate administrator configuration
with the administrator certificate/key, describing the same backing, identity,
geometry and capacity. Normal daemon operation needs no administrator key.
The volume client tries another authenticated frontend within its RPC deadline
on transport failure, keeping the exact operation ID and predecessor. A reply
from a different storage identity is refused. A list of independent local
state directories does not provide safe HA, even when they share an identity;
use a shared pinned quorum backend.

The client starts each call with the last frontend that returned a validated
record. This is only a routing hint: every call still reads the authority, and
all mutation retries preserve their exact operation and session authorization.
If the preferred frontend fails, the remaining frontends share the original
overall deadline and a successful alternate becomes the next preferred address.
Authentication failures, malformed records and predecessor conflicts remain
terminal: the client returns them without trying another frontend. A
stalled former first address therefore consumes time once during
failover rather than on every later successful call. A local socket error, such
as the EPERM Linux returns from `connect()` when a firewall drops the
connection, is a transport failure like a refused connection, not a denial. A
trusted client certificate that a frontend's allow-list does not name is a
denial: the frontend answers it, so an allow-list mistake is reported as
`PermissionDenied`, not as an unavailable witness. A certificate that the
frontend's CA bundle does not trust is refused during the TLS handshake with a
fatal alert, which the client reports as `PermissionDenied` too. In TLS 1.3 the
client writes its request before the frontend has checked its certificate, so
the frontend has often closed the connection by then; the client then reads the
alert the frontend sent before closing instead of reporting the broken pipe or
reset. This relies on Linux keeping received data readable after a reset. A
connection that closes without an alert remains a transport failure.

Inspect through the configured client without claiming a session:

```sh
sudo -u maki maki volume witness /etc/maki/volume-writer.toml
```

## Snapshot, takeover and restore

Stop the volume daemon before an ordinary snapshot while keeping the authority
online. Snapshot refuses a live writer and an occupied backup directory. Run it
as the daemon user, who owns the writer key (a process run as root refuses
that key), into a location that user can create:

```sh
install -d -o maki -g maki -m 0700 /backup/maki
sudo -u maki maki volume snapshot /etc/maki/volume-writer.toml /backup/maki/snapshot-001
```

The command copies authenticated committed data, durably writes the bounded
canonical `snapshot.json` descriptor and prints it as JSON. Keep its approved
root in a separate independently controlled record. A root stored next to the
backup is not its own approval. JSON roots are arrays of 32 bytes; convert them
to lower-case hexadecimal for the commands below. In Python a reviewed current
root is `bytes(record["current"]["anchor"]["root"]).hex()`; a snapshot root is
`bytes(descriptor["anchor"]["root"]).hex()`.

Takeover and restore fence whichever writer currently holds the authority,
a healthy one included: its next commit is refused and its mounted filesystem
sees I/O errors. The packaged recovery unit may then start a new daemon that
claims the new state before you have inspected it, and after a restore that
state is the older snapshot. Quiesce first:

1. Stop the workload lifecycle with `systemctl stop maki-workload@<volume>.target`
   and wait until the workloads, `maki-attach@<volume>.service` and
   `maki@<volume>.service` all report `inactive`
   ([planned shutdown](deployment/postgres.md#6-planned-stop-and-start)).
2. Run takeover or restore below, then inspect the result with
   `maki volume witness`.
3. Return the backing to the daemon user (next paragraph) and only then start
   the target again.

These commands, and `resume-enrollment`, create the new writer namespace
owner-only (`0700` directories, `0600` files) as the user that runs them. Run
as root, which an administrator key readable only by root requires, they leave
a `remote-*` tree the `maki` daemon cannot open, and the next attach fails. Keep
the administrator key unreadable to the daemon user and hand the tree back after
the command instead:

```sh
chown -R maki:maki /var/lib/maki/<volume>
```

For a stale or failed writer, review the current fence/root and replace the
placeholders:

```sh
maki volume takeover /etc/maki/volume-admin.toml EXPECTED_FENCE EXPECTED_CURRENT_ROOT_HEX
```

Takeover authenticates and durably copies the selected state to a new writer
namespace, activates its higher fence, and releases the temporary session.
The previous session fails freshness checks. The command reports success after
an authority read confirms the released new session. A concurrent new claim can
cause confirmation failure even when the transition completed; inspect before
proceeding.

A restore cannot be undone from the backing root. Once the restored state is
activated, the automatic GC pass ([below](#retire-old-writer-namespaces))
retires every lower-fence namespace whose lifetime lock is free. With the
daemon stopped (step 1), that includes the namespace holding the newer state
the restore replaces, so the restore command itself deletes it; a process
that still holds it open only defers the deletion to a later GC. The snapshot
you restore from stays in its backup directory, which GC never touches. If
the newer state may be needed again, as data or as evidence, first snapshot
it into a new backup directory as described above and keep its approved
root. That snapshot claims and releases a writer session, which raises the
fence but keeps the current root, so inspect again with `maki volume witness`
and use the new fence in the restore command. A current generation that no
longer authenticates cannot be snapshotted; preserve a copy of the stopped
backing directory as evidence instead.

An intentional older-snapshot restoration requires its independently approved
root as well:

```sh
maki volume restore /etc/maki/volume-admin.toml /backup/maki/snapshot-001 EXPECTED_FENCE EXPECTED_CURRENT_ROOT_HEX APPROVED_SNAPSHOT_ROOT_HEX
```

Restore validates the canonical descriptor and approved root before requesting
an epoch change. It increases fence, generation and epoch. Malformed,
truncated, oversized, noncanonical or symlinked descriptors are refused. Wrong
approval values and writer credentials cannot authorize restore or takeover.
Snapshot, takeover and restore require Linux.

Restore only reads the snapshot directory: it opens its files read-only and
shares the snapshot's `remote.operation.lock`, which an operation that changes
that directory holds exclusively. The snapshot can therefore stay where nothing
can change it, such as a read-only mount, immutable files, a read-only export,
or files the administrator may not write. Keep the empty lock file in copies:
restore creates a missing one, which needs write access.

The configured `backing.root` must belong to the approved storage identity.
Restore checks its immutable `remote.enrollment` identity and capacity before
claiming the authority, so accidentally selecting another volume's root is
refused. A matching binding allows recovery when the current generation is
damaged. For older roots without that file, the exact current generation must
still authenticate in the target; otherwise restore refuses before changing
the authority. Do not delete or replace a binding to bypass this check.
GC refuses a root whose existing binding conflicts with its current generation,
including one containing a foreign namespace left by an earlier faulty restore.

## Resume interrupted initial enrollment

An initialized descriptor can never be cleared through enrollment recovery,
including when its activation reply was lost. If authority inspection shows
`current = null`, preserve the failed backing and review its exact fence,
storage identity and original configuration capacity. In Python, after
`import uuid`, format the inspected identity as
`str(uuid.UUID(bytes=bytes(record["identity"])))`. Then use administrator
credentials:

```sh
maki volume resume-enrollment /etc/maki/volume-admin.toml EXPECTED_FENCE APPROVED_STORAGE_UUID
```

Add `--discard` for an inner v3 volume; the default initializes inner v2. The
command compares the full authority record, recovers the same storage identity
under a higher fence/session, synchronizes a fresh namespace, and completes
normal initial volume creation. Earlier claim candidates remain fenced out.
A durable `remote.enrollment` binding fixes the approved identity and capacity
before the claim. Explicit recovery can create a missing binding for a valid
legacy marker-only attempt; a different or corrupt existing binding refuses
rather than being silently replaced. Because older activated roots also lack
a binding, recovery first refuses a root holding a GC tombstone or any
namespace manifest other than this identity's empty initial candidate, so a
`backing.root` that names another volume's data changes neither authority nor
root. Only the quiescent lower-fence candidates that check examined may be
retired by the subsequent GC pass; live handles and unknown artifacts are
preserved. Quarantine damaged binding evidence for explicit operator
investigation.

If activation actually succeeded, use exact-current takeover and inspect the
selected state. This command does not reset it or automatically finish inner
volume initialization that stopped after outer activation. See
[enrollment recovery](rollback-protection.md#resume-interrupted-initial-enrollment)
for the compatibility and initialization limits.

## Retire old writer namespaces

A GC pass runs automatically after successful remote activation. To collect
again after old processes have exited, run it with the writer configuration as
the daemon user (a process run as root refuses the daemon-owned writer key):

```sh
sudo -u maki maki volume gc /etc/maki/volume-writer.toml
```

The JSON report separates `removed`, `skipped_live`, `skipped_unrecognized`
and `retained` namespace arrays. Each array retains at most the first 4,096
names in that category. The corresponding fields in `counts` give the total
numbers processed, including any omitted details; `details_truncated` is true
if any array omitted names. Use `counts`, not array lengths, for totals.
An entry whose name is not valid UTF-8 is never a namespace: GC keeps it,
lists it under `skipped_unrecognized` with U+FFFD in place of each invalid
byte sequence, and goes on.

GC walks the root in sorted pages of at most 4,096 names and continues past
pages containing only retained, live or unrecognized entries. Each page scans
the directory anew, so enumeration scratch and report details stay bounded,
while total scan time grows with directory size and page count. This is not a
wall-clock deadline or a bound on the entire process's memory.

GC authenticates the current physical root against its authority,
retains current/pending/restore-source namespaces and unknown entries, and only
considers namespaces with a lower fence. An old writer's lifetime lock keeps
its namespace live even after revocation; GC skips it until every handle has
closed. The current arena's fixed footprint remains allocated.

A root operation lock excludes source-copy races. A retired namespace is
renamed without replacement to a tombstone and the root directory is synced
before unlinking its contents. Later passes can finish partial tombstones.
Authority failure, a changed record, unsafe paths, unexpected files or storage
errors postpone reclamation; a failed automatic pass does not turn successful
activation into an unacknowledged commit. GC never removes external backups.

The confined retirement path requires Linux kernel 5.8 or later with `statx`
mount identity support, a local backing filesystem and same-host lifetime
locks. Do not use it across hosts on a filesystem whose lock semantics do not
provide this exclusion. See [format compatibility](durable-recovery.md#protected-outer-backing-formats)
for tombstone durability details.

## Failure and resource behavior

Each frontend connection carries one versioned, request-ID-bound JSON RPC.
Frames and serialization output are limited to 64 KiB. All timeout fields must
be in `1..=60000` milliseconds. Single-endpoint clients share a deadline across
connect, TLS handshake, request and response. Failover clients share a deadline
across frontend attempts. Backend operations share a deadline across quorum
reads, exact-CAS attempts and backend endpoint failures. Backend state is
limited to 64 KiB, JSON envelopes to 256 KiB and key paths to 1024 ASCII bytes
under `/maki/witness/`; 1–8 unique backend endpoints are supported.

A lost reply may follow a durable mutation. Failover and the volume protocol
retry the exact request; the authority remembers its latest role-bound
operation digest, so an identical retry cannot apply it twice. A reused ID
with different content or role is refused, and an old operation after an
intervening mutation cannot be replayed. Clients never infer that a failed
connection rolled a transaction back. Quorum unavailability stops service;
there is no stale replica or offline fallback.

The server admits 1–256 connection workers and requires 1–256 distinct
allow-listed certificate identities. A connection takes a worker only after
TLS has authenticated an allow-listed certificate. A trusted certificate that
the allow-list does not name never takes one: the server reads its single
request while it holds a pending slot and answers it with a denial bound to that
request, never calling the authority. Until it acquires a worker,
it occupies one of four pending slots per worker, including while waiting after
authentication. If these slots fill, a new arrival evicts the oldest pending
connection and closes its socket. An authenticated waiter can therefore be
disconnected before its deadline; it observes eviction as `ConnectionAborted`
on the server, not as a guaranteed protocol error response to the client.

A separate lifetime limit allows at most five connection tasks per worker,
including active requests, pending connections, and evicted tasks that have not
yet exited. Eviction does not release this capacity: the task retains its charge
until its TLS state and request processing end, including error and unwinding
paths. The accept loop waits for capacity before creating another thread, within
the accepted connection's deadline. Accept and thread-creation failures are
retried with backoff; a failed thread creation releases that connection's socket
and capacity. One absolute deadline covers admission, authentication, worker
waiting, framing and replies; slow fragments cannot extend it. A blocked local
filesystem operation cannot be forcibly cancelled by the socket deadline, but
workers remain bounded and clients time out.

TLS/protocol failures do not log request payloads or peer-provided error text.
Missing or untrusted certificates, unknown identities, wrong server names,
wrong roles, unsupported versions, unknown fields, oversized or truncated
frames, and mismatched response identities fail closed. Credential and
allow-list changes require controlled frontend restarts.

Local state, transport and volume tests exercise persistence faults, concurrent
CAS, real TLS authentication and role enforcement, uncertain replies, writer
fencing, snapshots and enrollment recovery. Quorum tests additionally exercise
leader/front-end loss and loss of majority. These results do not replace
independent-host, persistent-disk or disruptive campaign qualification.

## Diagnostic commands and writer ownership

`maki volume witness <config.toml>` inspects the authority without claiming a
writer. `maki volume inspect`, `maki check`, and `maki check --deep` refuse remote
rollback backing until a read-only backing view is implemented. Opening the
normal remote backing claims a writer and creates a new namespace; diagnostic
commands must not do that implicitly, including when they fail or are killed.
This refusal applies to both active and released authority states. It does not
validate the stored ciphertext or replace an offline data-integrity check.
