# Remote witness service

`maki-witness` is a single-volume freshness authority with durable state,
mutual TLS 1.3, explicit writer/admin identities and exact-predecessor
transactions. It runs separately from the volume backing. Its state directory
must survive independently of volume snapshots and restoration. Restoring or
recreating the witness from an older backup can defeat freshness protection;
this service does not provide distributed consensus or an automatic failover
replica.

The rollback backing's attach, takeover and restore operations coordinate the
physical data generations with this authority. See
[rollback protection](rollback-protection.md) for those operations and
[the protocol design](rollback-protection-design.md) for the durability boundary.
This page describes executable service setup; it does not report a production
deployment or external qualification campaign.

## Initialize and run

Build the binary with `cargo build --release --locked -p maki-witness-cli`.
Initialize one authority directory with a fresh, nonzero storage-identity UUID.
This outer rollback identity is distinct from the inner volume superblock UUID:

```sh
maki-witness init /var/lib/maki-witness/volume 01234567-89ab-cdef-0123-456789abcdef
```

Initialization refuses existing state. `serve` only opens an initialized
state directory and holds its exclusive process lock until exit. Do not start
multiple services on copied authority directories: their independent locks do
not establish one shared ordering.

Provision a server certificate with the intended DNS name or IP address in
its subject alternative names, and separate writer and administrative client
certificates. The server's CA bundle trusts the client issuers; each client's
CA bundle trusts the server issuer. Certificates must also appear in the
server's explicit leaf-certificate allow-list. Calculate each identity with:

```sh
maki-witness fingerprint /etc/maki-witness/writer.cert.pem
maki-witness fingerprint /etc/maki-witness/admin.cert.pem
```

Create `server.toml`, replacing the fingerprint placeholders with the printed
64-character lower-case SHA-256 values:

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

Run the authority in the foreground under the intended service account:

```sh
maki-witness serve /etc/maki-witness/server.toml
```

The readiness line is emitted after credential validation, durable state open,
and socket bind. It includes the actual listening address. Integrating the
binary with a service manager, network policy and independently managed durable
storage is an operator deployment step; running a local test does not establish
those properties.

Configuration files are bounded to 64 KiB and reject unknown fields. On Unix,
configuration files must not be symlinks or writable by group/others. Credential
files are regular files bounded to 1 MiB. Private-key files must not be symlinks
or accessible to group/others (`0600` is appropriate). The key loader accepts
exactly one unencrypted PKCS#8, PKCS#1 RSA or SEC1 EC PEM block; encrypted keys,
bag attributes, additional blocks and trailing non-whitespace text are refused.
Private-key PEM, base64 scratch and decoded DER use buffers erased on drop;
the pinned rustls/ring path owns the resulting signer. Certificate bundles
must contain no private-key blocks. Paths are resolved relative to the working
directory; absolute paths avoid ambiguity under service managers.

## Inspect through the authenticated endpoint

Use a client configuration such as:

```toml
address = "127.0.0.1:9443"
server_name = "localhost"
timeout_ms = 5000

[tls]
ca_file = "/etc/maki-witness/server-ca.pem"
cert_file = "/etc/maki-witness/writer.cert.pem"
key_file = "/etc/maki-witness/writer.key.pem"
```

```sh
maki-witness inspect /etc/maki-witness/client.toml
```

`address` is a numeric socket address, so a blocking DNS lookup cannot escape
the RPC deadline. `server_name` is independently verified against the server
certificate. Inspection prints the current metadata record as JSON; it does
not modify the authority. Writer identities cannot perform takeover or claim
restoration. Administrative credentials authorize those operations and remain
separate from normal daemon credentials. Use the volume commands to perform
administrative transitions, so storage preparation and authority activation
stay coordinated.

## Snapshot, takeover and restore

The volume configuration selects the endpoint through
`[backing.rollback_protection.remote]`, using `address`, `server_name`,
`timeout_ms`, `ca_file`, `client_cert_file` and `client_key_file`. Keep a normal
writer configuration and a separate administrative configuration with the
admin certificate/key. They must describe the same backing and authority.
Administrative credentials are not needed for normal daemon operation.

Inspect without claiming a writer session:

```sh
maki volume witness /etc/maki/volume-writer.toml
```

Stop the volume daemon before an ordinary snapshot, while keeping the authority
online. The snapshot command refuses a live writer and an already occupied
backup directory:

```sh
maki volume snapshot /etc/maki/volume-writer.toml /backup/maki/snapshot-001
```

The command copies authenticated committed data, durably writes the bounded
canonical `snapshot.json` descriptor and prints that descriptor as JSON. Keep
its approved root separately from the backup files, in an independently
controlled record. The root stored next to a backup is not its own approval.
JSON roots are arrays of 32 bytes; convert them to lower-case hexadecimal for
the following commands. For example, in Python a reviewed record's current
root is `bytes(record["current"]["anchor"]["root"]).hex()` and a snapshot's root
is `bytes(descriptor["anchor"]["root"]).hex()`.

A stale or failed writer requires an explicit administrative takeover. Review
the authority's current fence and root, then replace both placeholders:

```sh
maki volume takeover /etc/maki/volume-admin.toml EXPECTED_FENCE EXPECTED_CURRENT_ROOT_HEX
```

Takeover creates a new physical writer namespace, verifies and durably copies
the selected data, activates the new fence, and releases the temporary session.
The previous session fails freshness checks. The command reports success only
after a fresh authority read confirms the released new session. Another writer
claiming it concurrently can therefore cause a confirmation failure even when
the transition itself completed; inspect the authority before proceeding.

Restoration additionally requires the independently approved snapshot root:

```sh
maki volume restore /etc/maki/volume-admin.toml /backup/maki/snapshot-001 EXPECTED_FENCE EXPECTED_CURRENT_ROOT_HEX APPROVED_SNAPSHOT_ROOT_HEX
```

This validates the canonical snapshot descriptor and approved source root before
requesting an epoch change. The authority advances its fence, generation and
epoch; it never decreases them to match the backup. Copying and activation use
the volume protocol, rather than exposing raw authority mutation commands.
Malformed, truncated, oversized, noncanonical or symlinked descriptors are
refused. Wrong approval values and writer-role credentials cannot authorize a
restore or takeover. Volume snapshot/takeover/restore operations require Linux.

If initial enrollment fails after claiming an empty authority, no provided CLI
command resumes a claim that has no current descriptor. Preserve the failed
artifacts for diagnosis. Use a fresh storage identity and new empty backing and
authority directories after checking that no acknowledged volume was enrolled;
never overwrite or reinitialize the existing authority as a recovery shortcut.

The nbdkit process's opt-in memory policy is separate from this service process.
Choose service-manager memory and locked-memory limits (`MemoryMax` and
`LimitMEMLOCK` under systemd) for the authority's workload and TLS credentials.
The configuration bounds below apply independently of those deployment limits.

## Failure and resource behavior

Each connection carries one versioned, request-ID-bound JSON RPC. Frames and
serialization output are limited to 64 KiB. Timeouts must be in `1..=60000`
milliseconds. The client shares one deadline across connect, TLS handshake,
request and response; it never automatically retries a possibly committed
mutation. A missing reply leaves the outcome unknown. The volume protocol
inspects the strongly serialized state or fails closed before serving data.
It must never infer that a failed connection rolled back a transaction.

The server admits at most `max_connections` (1–256) connection workers and
requires 1–256 distinct allow-listed certificate identities. Admission happens
before spawning a worker. An absolute deadline covers each connection's
handshake, frame reads and writes; slow or truncated peers cannot extend it by
sending small fragments. Capacity is released on success, error and Rust
unwinding. State mutations are serialized under the authority's lock. A blocked
local filesystem operation cannot be forcibly cancelled by the socket deadline;
workers remain bounded and clients still time out. The storage and process
supervisor must handle that availability failure.

TLS or protocol failures never log request payloads or peer-provided error
text. Missing/untrusted certificates, unknown identities, wrong server names,
wrong roles, unsupported versions, unknown fields, oversized/truncated frames,
and response identity mismatches fail closed. Certificate/allow-list changes
require a controlled service restart; an established identity is not silently
replaced by an unlisted certificate issued by the same CA.

Transport regression tests exercise real TLS sockets, authentication failures,
role propagation, malformed frames, stalled handshakes and responses, lost
replies without retry, bounded serialization, connection permits and the
service CLI. The state and volume suites separately exercise persistence,
conflicting sessions, takeover, restoration and crash boundaries. These local
suites do not replace independent-host, persistent-disk or disruptive campaign
qualification.
