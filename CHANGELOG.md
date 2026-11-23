# Changelog

All notable changes to Maki, in particular anything that affects on-disk
compatibility, the runtime layout, credentials or operator procedures. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
Maki has no tagged release yet, so everything is under *Unreleased* with the
commit that introduced it. Procedures for each change live in the linked
documents.

## Unreleased

### Breaking changes

- **The command-line binaries exit 2 for misuse, and `maki-attach` actions
  exit 3 off Linux** (AUD-137, AUD-144, 2026-11-23;
  [#363](https://github.com/seo-rii/maki/pull/363)). `maki-witness` exits 2
  instead of 1 for an unknown command, a missing or extra argument and a
  volume identity that is not a UUID, and for an argument that is not UTF-8,
  where it panicked with 101. `maki` exits 2 instead of 1 for `--timeout`
  without a positive number of seconds, `--socket` without a path, beside a
  configuration or on a command without a control round trip, a malformed
  `reload cache` option, and a malformed fence, root or storage identity
  given to `volume takeover`, `restore` or `resume-enrollment`, which is now
  refused before the configuration is read. `maki-attach` exits 2 for a
  malformed `--volume` before it reads any file (it exited 1 for
  `recover-failed-start`, and for the other verbs with an unreadable
  `--config`), and off Linux `recover-failed-start` without `--plan` exits 3
  like every other action, where it exited 0 or 1. The messages are
  unchanged, and a command that fails still exits 1: a script that detects
  misuse by status 1 must test for 2. `maki(8)` and `maki-attach(8)` have an
  EXIT STATUS section.
- **The three remote crypto transports trust one set of TLS roots: the
  host's trust store, the public roots compiled into the binary and
  `ca_file`** (AUD-133, [#369](https://github.com/seo-rii/maki/pull/369)).
  `remote-http` now also trusts the host's trust store (the system bundle, or
  `SSL_CERT_FILE` and `SSL_CERT_DIR` when set), so a private CA installed
  there authenticates an HTTP endpoint without a TLS section, where it was
  refused with `EndpointFatal`. `remote-grpc` now also trusts the compiled-in
  public roots (webpki-roots) and no longer fails to build its provider on a
  host whose trust store is empty: a public endpoint is reachable from such
  an image, and a private endpoint that none of the roots vouches for is
  refused at the TLS handshake instead of at attach. A gRPC deployment with
  `ca_file` on a host whose trust store is empty (a distroless image,
  `SSL_CERT_FILE` naming an empty bundle) trusted that CA alone; it now also
  accepts a server whose certificate chains to a public root and matches the
  endpoint's name, and no setting restores CA-only trust. `remote-websocket`
  is unchanged. `ca_file` still adds to the roots and is parsed strictly; the
  CA bundle errors read the same in all three transports, and an HTTP client
  identity that rustls rejects is reported as `bad client identity: …`. The
  remote witness still trusts only its own CA
  ([providers](docs/configuration.md#providers)).
- **Attach reserves the NBD devices that other volumes' attach records name**
  (AUD-120, [#354](https://github.com/seo-rii/maki/pull/354)). Under the
  attach lock, attach reads every `/run/maki-attach/<volume>.nbd` record
  before it chooses a device: automatic allocation skips a device another
  volume's record names, and a pinned `nbd_device` that such a record names
  is refused even when the device is free in sysfs. A record that outlived
  its connection (a helper killed before the connect or after the
  disconnect) keeps its device until that volume's next attach, cleanup,
  detach or recover, or until `/run` is cleared; when every device is
  connected, in use or recorded, attach fails with "no free /dev/nbdN
  device", which now mentions records. An attach is refused, naming the
  file, while any `<volume>.nbd` entry cannot be read as a trusted record.
  Before, another volume could be handed the device, and every verb of the
  first volume then refused it as a foreign backend
  ([privileged helper](docs/operations.md#privileged-helper)).
- **Detach, cleanup, recovery and grow run LVM only on the recorded devices**
  (AUD-135, [#368](https://github.com/seo-rii/maki/pull/368)). Their
  deactivation runs `vgchange --devices <recorded PVs> --activate n --select
  vg_uuid=<recorded> --config "devices { allow_changes_with_duplicate_pvs=0
  }" <vg>` (the selection where the record names a VG UUID) and growth
  `lvextend --devices <recorded PVs> --config "…" -L <n>b <vg>/<lv>`, instead
  of `vgchange -an <vg>` and `lvextend -L <n>b <vg>/<lv>` resolved over
  LVM's own device scan. A VG of the same name on another disk is never
  extended or deactivated: grow used to report success after extending the
  other disk's LV when the volume's PV was outside LVM's scan, and cleanup
  after a daemon death deactivated the other VG instead of reaching its
  `dmsetup` fallback. A devices file or filter that leaves `/dev/nbd*` out no
  longer stops grow and detach. A record from before mapping proofs and
  activation intents is scoped to its NBD device alone, so such an
  attachment whose PV is a partition now fails detach with "not found" and
  keeps the record; a mapping proof whose uuids do not name one VG UUID is
  refused before any command. The plan and step texts name the scope
  ([privileged helper](docs/operations.md#privileged-helper)).
- **The failed-start hook rolls back an interrupted LVM activation itself**
  (AUD-118, AUD-119, AUD-142, AUD-143;
  [#356](https://github.com/seo-rii/maki/pull/356),
  [#370](https://github.com/seo-rii/maki/pull/370)). When an attach dies
  between LVM activation and its mapping proof, `maki-attach
  recover-failed-start` now deactivates the VG within the recorded scope,
  disconnects the NBD device and retires the record under the attach lock,
  while the daemon still serves and never with an unmount; before, it only
  queued `maki-recover@`, which stops the daemon first, so the mapping had to
  be removed by hand. The hook reads the trusted record first and stops there
  when it holds no activation intent, writing no journal line; with one it
  reads `/etc/maki/attach/<volume>.toml` like `cleanup` (`--config` is still
  refused), waits up to 15 s for the attach unit's control group to settle,
  waits up to 40 s in turn for the attach lock and gives its commands 30 s
  once it holds it, so it can take up to about 87 s within the unit's
  `TimeoutStopSec=120`. Its journal lines name what they are about ("cannot
  tell whether volume pg has an interrupted LVM activation to roll back",
  "did not roll back the interrupted LVM activation of volume pg: …", "could
  not roll back the interrupted LVM activation …"), and `--plan` prints one
  more line. Cleanup's `dmsetup` fallback no longer runs after a `vgchange
  -an` killed by a signal, only after one that exited nonzero, and the
  refusal for an intent whose deactivation fails says what is left. A daemon
  that stops inside that window still needs the documented manual step
  ([systemd deployment](docs/operations.md#systemd-deployment),
  [interrupted activation](docs/operations.md#interrupted-activation-after-the-daemon-stopped)).

- **A volume configuration must be a regular file that no other user can
  change** (AUD-106, 2026-11-23;
  [#339](https://github.com/seo-rii/maki/pull/339)). The daemon, every `maki`
  command that takes a configuration and `maki-benchmark` refuse, before
  parsing it, a file that is a symlink, has a second hard link, is owned by a
  user other than root and the user the process runs as, or is writable by
  its group or others (a file written under `umask 002`, or one with a POSIX
  ACL that grants write access); the daemon fails attach on such a file.
  Group and other read stay allowed. Before upgrading, list the affected
  files and reinstall each with `install -m 0640 -o root -g maki`. A file
  owned by the daemon user is still accepted by the daemon, but refused by
  commands run as root
  ([configuration file](docs/configuration.md#configuration-file),
  [upgrade](docs/operations.md#upgrading-the-runtime-layout)).
- **A root process creates backing and witness entries for the owner of
  their directory, and fails when it cannot** (AUD-111,
  [#344](https://github.com/seo-rii/maki/pull/344)). On Linux, a command run
  as root (`maki check --deep`, `maki-check --deep`, `maki volume inspect`,
  `create`, `takeover`, `restore` or `resume-enrollment`) creates each file
  and directory below a backing root or a local witness directory for the
  owner of the directory it is created in. A root run on a volume the daemon
  user owns therefore no longer leaves root-owned files that stop the next
  attach, and the procedures drop their `chown -R maki:maki` step. A root
  process that cannot change the owner (CAP_CHOWN dropped) now fails instead
  of creating a root-owned entry.
  Opening a local rollback witness as root gives a root-owned anchor in the
  daemon's directory back to the daemon user, refuses an anchor a third user
  owns, and removes a leftover `anchor.next` instead of publishing it; a
  file a third user puts back under that name is refused. A hand-back is
  still needed for a restored copy whose files lost their owners, for a
  volume or witness directory root had to create itself (the `volume create`
  warning, now printed only then, names it) and after a root run that a
  crash interrupted ([volume lifecycle](docs/operations.md#volume-lifecycle),
  [rollback
  protection](docs/rollback-protection.md#local-configuration-and-creation)).
- **Candidate builds refuse release-profile and unstable-toolchain overrides,
  and `maki-nbdkit` requires unwinding panics** (AUD-103,
  [#336](https://github.com/seo-rii/maki/pull/336)).
  `scripts/prepare_release.py` stops before building when its environment
  holds a `CARGO_PROFILE_RELEASE_*`, `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*` or
  `__CARGO_*` variable, or when Cargo configuration outside the committed
  source (above the build directory or in `CARGO_HOME`) has a
  `[profile.release]` or `[unstable]` table or an `include`: unset the
  variable, or commit the profile change. The manifest also records
  `CARGO_INCREMENTAL`, the C toolchain inputs of the native dependencies and
  each external Cargo configuration file with its digest. `maki-nbdkit` no
  longer compiles with `panic = "abort"`, however that strategy is selected,
  because the plugin would lose its panic boundary
  ([releasing](docs/releasing.md#prepare-and-inspect)).
- **A crypto call that ends at its `bounded-error` deadline returns the last
  endpoint error, and `maki_crypto_deadline_exceeded_total` counts every
  expired call once** (AUD-109,
  [#342](https://github.com/seo-rii/maki/pull/342)). Wherever the deadline
  expires, the call returns the last error an endpoint returned before it for
  the RPC batch in progress, with that error's class (`throttled: HTTP 429`,
  for example), or `operation deadline exceeded` when no endpoint failed that
  batch. Before, an RPC cut off by the deadline got the bare deadline error
  whatever the endpoints had answered, and so did a caller whose budget ran
  out in the batch scheduler before the dispatcher's, the usual case on a
  remote volume. The counter no longer follows the error text: it counts each
  call whose own deadline expired exactly once, including one that returns an
  endpoint error and the exit right after a failed RPC. Alert on the counter
  rather than on the error text
  ([metrics](docs/operations.md#metrics-and-health)).
- **A quarantined endpoint is validated again after an inconclusive failure
  instead of staying excluded until the daemon restarts** (AUD-110,
  [#343](https://github.com/seo-rii/maki/pull/343)). A malformed or truncated
  reply during background validation (a proxy error page, an endpoint
  restarting mid-response) used to mark the endpoint `rejected` for the life
  of the process. Only proof that it serves another contract does so now:
  another key, compatibility id or canary, a claimed capability it does not
  honour, or an explicit refusal of the volume's context. An endpoint that
  refuses the volume's key canary with an integrity failure is rejected; it
  used to be deferred and validated again forever. Inconclusive attempts are
  repeated after `circuit_breaker.open_initial`, the spacing doubling up to
  `circuit_breaker.open_max`, instead of at a fixed interval, so an endpoint
  that was unreachable for long can take up to `open_max` to return after it
  recovers ([endpoint
  validation](docs/configuration.md#websocket-and-grpc-contracts)).
- **With `crypto.random_prefix_bytes`, the attach self-test's
  compatibility-id probe reaches the provider** (AUD-107,
  [#340](https://github.com/seo-rii/maki/pull/340)). The random-prefix
  wrapper used to answer that probe itself, so a remote provider that
  declares context binding but ignores the compatibility id, or a transport
  mapping that drops the field, attached with a prefix and was refused
  without one. It is now refused at attach in both cases ("compatibility id
  decrypts to the original plaintext"); fix the provider or the mapping. A
  prefixed volume's self-test sends one more decrypt request ([random
  plaintext
  prefixes](docs/random-plaintext-prefix.md#existing-volumes-and-endpoint-compatibility)).
- **A lock ends when its holder releases it, even while a forked child still
  holds its descriptor** (AUD-108,
  [#341](https://github.com/seo-rii/maki/pull/341)). The volume, rollback,
  witness, attach and control-socket directory locks were released only by
  closing their descriptor, so a child forked by another thread kept them
  held until its `exec`: an attach right after a detach or a create could
  fail with `VOLUME_ALREADY_ATTACHED`, and a closed rollback backing or
  witness store could refuse to reopen. Every lock is now unlocked before its
  descriptor closes. As a consequence, remote GC no longer treats a namespace
  as live because a forked child inherited the descriptor of a lifetime lock
  its holder has dropped; a held lifetime lock still keeps its namespace
  ([backing namespace](docs/architecture.md#backing-namespace)).

- **The `maki-witness` configuration, state directory and state files must be
  owned by root or by the user that runs the command** (AUD-075, AUD-076,
  2026-11-17; [#170](https://github.com/seo-rii/maki/pull/170)). `serve`,
  `init-etcd` and `inspect` refuse a configuration owned by another user, and
  `init` and `serve` refuse a state directory or `remote.state`, `remote.next`
  or `remote.lock` owned by another user or writable by group or others, before
  writing anything or binding the listener. A command run as root therefore
  refuses a configuration or state directory the service account owns:
  `chown -R` the state directory to the account that runs `serve` and
  `chmod go-w` it and its files, or use a root-owned configuration ([witness
  service](docs/remote-witness-service.md#credential-and-configuration-files)).
- **A witness frontend whose allow-list does not name a trusted client
  certificate answers with a final denial** (AUD-077,
  [#179](https://github.com/seo-rii/maki/pull/179)). Failover no longer tries
  another frontend, a mutation is not retried, and a remote rollback session
  stops until it is reopened; before, the dropped connection looked like an
  unavailable witness and another frontend could answer. List every client on
  every frontend ([frontend
  failover](docs/remote-witness-service.md#configure-frontend-failover)).
- **`MAKI_LOG` directives need a level, and `maki` refuses `--timeout` on
  commands without a control round trip** (AUD-094, AUD-095,
  [#188](https://github.com/seo-rii/maki/pull/188)). A directive that is
  neither a level nor `<target>=<level>`, such as a misspelt `warning` (which
  silenced every Maki event, ERROR included) or a bare `maki_core` (which meant
  that target at trace and every other target off), now falls back to `info`
  and logs one `MAKI_LOG is not a valid filter` warning; write
  `maki_core=trace` for one target. Only `status`, `metrics`, `checkpoint`,
  `drain` and `reload` take `--timeout`; `maki volume` and `maki check` refuse
  it with the usage and exit status 2 instead of ignoring it
  ([logging](docs/operations.md#logging)).
- **gRPC method paths, HTTP item fields and `env` credential names are
  validated as the providers send them** (AUD-072 to AUD-074,
  [#172](https://github.com/seo-rii/maki/pull/172)). `encrypt_path` and
  `decrypt_path` must be an absolute path with an optional query and no
  fragment, with characters outside RFC 3986's path and query sets
  percent-encoded. A batch body's top-level `fields` may not use the `payload`,
  `unit_index` or `batch_index` source (map it in `item_fields`), and a
  per-item body may not have `item_fields`. An `env` name may not contain `=`
  or NUL. These configurations used to fail every attach or send empty values
  ([HTTP mapping](docs/configuration.md#remote-http-mapping)).
- **Recovery and `maki check --deep` refuse inconsistent metadata they used to
  disagree on** (AUD-055 to AUD-059,
  [#185](https://github.com/seo-rii/maki/pull/185)). Both refuse a checkpoint
  above the durable proof's horizon, whose acknowledged writes then read zeros;
  a v2/v3 durable sequence or segment index that leaves no room for one more
  record or segment, or a metadata generation in the top quarter of its range,
  after which every write or a later checkpoint failed; and a covered proof
  that names a location past the newer records. Only damage or a foreign writer
  produces these states ([durable
  recovery](docs/durable-recovery.md#cost-and-verification-limits)). The deep
  check reports a lost key canary as an `ERROR` only when the volume has
  history but no ciphertext left, which every attach refuses, and as a warning
  otherwise ([operations](docs/operations.md#volume-lifecycle)).

- **Credential and witness key files must be owned by root or by the user that
  loads them** (AUD-029, AUD-031, 2026-11-16;
  [#158](https://github.com/seo-rii/maki/pull/158),
  [#162](https://github.com/seo-rii/maki/pull/162)). This applies to `file`
  credentials, files in the systemd credentials directory, an HTTP combined
  certificate and private-key PEM, and witness TLS private keys, whatever their
  mode. A process run as root therefore refuses a key owned by the daemon user:
  run `maki-benchmark`, a daemon started by hand or `maki volume witness` with
  the daemon's writer configuration as that user (`sudo -u maki`). See
  [credentials](docs/configuration.md#credentials-and-secrets) and the [witness
  service](docs/remote-witness-service.md#credential-and-configuration-files).
- **An empty or whitespace-only credential is refused like a missing one**
  (AUD-030, [#158](https://github.com/seo-rii/maki/pull/158)), so a token file
  truncated by a failed rotation stops attach instead of sending
  `Authorization: Bearer ` without its token.
- **Credential references must be loadable as written** (AUD-032, AUD-036,
  [#159](https://github.com/seo-rii/maki/pull/159)). A header or metadata
  `format` needs exactly one `{}` placeholder, and `format` on `crypto.key` or
  a `tls.client_key` is refused. A `credential` name, and the file name of a
  `file` path, may contain only ASCII letters, digits, `.`, `_` and `-` and
  must not start with `.`, as the loaders require; `volume create` used to
  store another key name as the volume's immutable key identity, after which
  every attach failed.
- **`nbd.preferred_io` above 32 MiB and geometries that reach the key-canary
  unit index are refused** (AUD-034, AUD-035,
  [#159](https://github.com/seo-rii/maki/pull/159)). nbdkit failed every client
  handshake for the first, and attach refused the second; a stored superblock
  with such a geometry now loads as an invalid copy. See [validation
  rules](docs/configuration.md#validation-rules).
- **`remote-http` request mappings are validated as the provider builds them**
  (AUD-026, [#161](https://github.com/seo-rii/maki/pull/161)). Unknown field
  sources or payload encodings, an encoding on a source other than `payload`, a
  request pointer or `items_path` without a leading slash, pointers of one
  object that overlap (including a field at, under or above `items_path`), and
  a declared context binding without a per-item `unit_index` fail validation
  instead of failing attach or every request. SPEC §18 no longer lists the
  `utf8`, `integer` and `uuid` encodings, which the provider never implemented
  ([HTTP mapping](docs/configuration.md#remote-http-mapping)).

- **Remote transport limits must hold a full ciphertext batch** (BUG-092,
  2026-10-14). gRPC `max_message_bytes`, WebSocket `max_frame_bytes` and, for
  a batched HTTP mapping, `max_response_bytes` are checked against the larger
  of the plaintext and the ciphertext batch (base64 where encoded), and a zero
  WebSocket or gRPC `timeout` is refused. A configuration that validated
  before but could not carry a full batch now fails validation instead of
  failing every full batch at runtime; raise the limit or lower
  `crypto.batch.max_items`/`max_bytes`. HTTP context binding now counts only
  mappings the provider sends (BUG-093). See
  [validation rules](docs/configuration.md#validation-rules).
- **An AES-XTS key with identical halves is refused** (BUG-095, 2026-10-14):
  IEEE 1619 requires distinct data and tweak keys.
- **File credentials and TLS files need absolute paths** (BUG-122,
  2026-10-15). A relative `file` credential name or TLS `ca_file` /
  `client_cert_file` resolved against each process's working directory and
  now fails validation; write the absolute path. See
  [configuration](docs/configuration.md).

- **Remote witness authority and wire v2 require private session ownership**
  (2026-10-12). `MAKIRW02` authority state stores a digest of a random 256-bit
  session capability. Writers must prove the current capability for activation,
  advancement and release; public inspection cannot authorize another writer or
  an older session under the same credential. Authority/wire v1 is refused;
  preserve the old source, create a fresh independent identity and verify a
  logical copy. The outer remote COW marker, enrollment and inner volume bytes
  remain unchanged. See [migration](docs/durable-recovery.md#protected-outer-backing-formats)
  and [service upgrade](docs/remote-witness-service.md#authority-protocol-compatibility).

- **Executing `maki-attach` verbs require a root-controlled attach config**
  (R5-030): a root-owned regular file with one link, not group/other
  writable, below root-owned directories. `--plan` reads any file.
- **A CA bundle or a WebSocket/gRPC `client_cert_file` containing a private
  key is refused** (R5-028); supply the key through `client_key`.
- **The mountpoint directory must be root-owned and not group/other
  writable** (R5-024), like its ancestors: a workload-owned mountpoint let
  the workload stack a FUSE mount over it before attach mounted the volume.
  Recreate it with `install -d -m 0755 /srv/<volume>` (root) before attach;
  the volume's own root directory keeps the workload's ownership.
- **`maki-benchmark` refuses an existing volume without `--destroy-data`**
  (R5-017): it overwrites the start of the device (partition table,
  filesystem superblock) and used to do so to whatever volume its
  configuration named.
- **Credential-like header names refuse literal values** (R5-007). An HTTP
  header or gRPC metadata name containing `auth`, `token`, `secret`,
  `passw`, `cookie`, `session`, `signature`, `credential`, `apikey`,
  `api_key`, `-key` or `_key` must use a credential reference
  ([configuration](docs/configuration.md#credentials-and-secrets)); a
  configuration that put such a value inline no longer validates.
- **Superblock envelope v2 with mirrored durable proofs is required for
  writable volumes** (`1bc0ab5`, 2026-09-12). Older binaries reject v2
  volumes; this build refuses writable recovery of legacy v1 volumes and
  supports them read-only with a warning. There is no in-place upgrade:
  follow [durable recovery and migration](docs/durable-recovery.md). The
  crypto AAD `format_version` is unchanged.
- **Privileged helper runtime layout** (2026-09-05 review fixes). Attachment
  records moved to `/run/maki-attach/<volume>.nbd` with a versioned trusted
  format; legacy `/run/maki/attach/*.nbd` records are refused. The default
  control socket is `/run/maki-control/<volume>/control.sock`. Detach with
  the old helper before upgrading:
  [upgrade procedure](docs/operations.md#upgrading-the-runtime-layout).
- **`nbd-client` 3.27.0 or later is required** for privileged attachment; the
  helper verifies the kernel NBD backend identifier over netlink and fails
  closed otherwise. Debian 12's 3.24 is too old
  ([installation](docs/getting-started/installation-debian.md)).
- **Credential sources no longer fall back**: `credential`, `file` and `env`
  are each read only from the source they declare; the same name may not be
  declared with different sources in one configuration.
- **`crypto.capabilities.mode` accepts only `declared`**; `hybrid` and
  `probed` are configuration errors.
- **Plaintext transports to non-loopback hosts are refused**; `http://`,
  `ws://` and gRPC `http://` endpoints are accepted only for loopback.
- **Production remote-provider contracts must declare `integrity` and
  `context_binding`**, and a provider that declares context binding must
  receive the whole context (volume UUID, compatibility id, format version)
  or attach fails (`be23a11`).
- **`maki-attach grow` takes an absolute `--size-bytes`**; the relative
  `--add-bytes` is rejected because a retry could not identify itself.

### Added

- **Concurrent and mixed benchmark workloads**: configurable concurrency,
  sequential/random access, read ratio, working set, FUA and periodic drained
  FLUSH; setup is separate from measurement. Reports preserve existing schema-1
  fields and add per-class/barrier latency, pending/resource peaks and optional
  Linux RSS. A deterministic endpoint outage/recovery harness compares 1/2/8/32
  callers ([benchmark guide](docs/benchmark.md)).

- **Complete Engine request metrics**: actual active requests are separate from
  retained admission slots. Full read/write/trim/FLUSH/FUA latency includes
  admission, provider and storage waits plus errors and cancellation; exactly
  one outcome is recorded per public Engine call. Explicit journal-sync timing
  includes failed and background barriers; legacy successful storage series
  retain their meaning ([metric boundaries](docs/observability.md#request-counts-and-latency-boundaries)).

- **Same-identity initial remote enrollment recovery**: an administrator can
  resume a never-activated authority using an approved storage identity and
  exact current fence. A durable supplementary v1 identity/capacity binding
  and a fresh writer namespace preserve interrupted artifacts; successful
  activation permanently prevents enrollment reset. Existing remote COW and
  witness-state bytes are unchanged
  ([procedure](docs/rollback-protection.md#resume-interrupted-initial-enrollment),
  [compatibility](docs/durable-recovery.md#protected-outer-backing-formats)).

- **Safe automatic remote-writer namespace reclamation**: authenticate the
  current physical root, retain authority sources and live file handles, then
  durably retire quiescent lower-fence namespaces before confined deletion.
  `maki volume gc` retries cleanup without claiming a writer
  ([rollback protection](docs/rollback-protection.md#remote-namespace-reclamation)).

- **Optional etcd-quorum witness HA**: stateless TLS frontends share a pinned
  cluster/key through linearizable reads and exact canonical-state transactions;
  identity-pinned endpoint sets retry identical operations within one deadline.
  Explicit `maki-witness init-etcd` initializes new authorities; there is no
  automatic local fallback or restore of rolled-back witness state
  ([service guide](docs/remote-witness-service.md)).

- **Remote rollback witness (experimental)**: a TLS 1.3 mTLS service persists
  exact compare-and-swap state, monotonic writer fences and restore epochs.
  A new remote outer backing V2 gives every session a separate reserved
  namespace. Offline snapshot, exact-current takeover and approved-root restore
  commands never lower the witness. Existing local format bytes are unchanged;
  no in-place conversion is supported ([operations](docs/remote-witness-service.md),
  [migration](docs/durable-recovery.md#protected-outer-backing-formats)).
- **Measured whole-process memory admission**: optional
  `security.memory_budget` verifies the applied cgroup-v2 ceiling, visible
  ancestor headroom and memlock before recovery and READY. The opt-in systemd
  template sets operator-measured limits; defaults remain unchanged
  ([configuration](docs/configuration.md#measured-memory-budget)).

- **Benchmark reports**: `maki-benchmark --json` records throughput, IOPS,
  bounded-memory p50/p95/p99 latency estimates, final FLUSH time and verified
  readback; `--fua` selects durable individual writes. Invalid workload
  arguments are refused before creating a volume; recovered geometry is
  rechecked before I/O. See
  [performance profiles](docs/performance.md).
- **Release candidate preparation**: `scripts/prepare_release.py` builds
  committed source in isolation and bundles the Debian package, source
  archive, host/toolchain provenance and SHA-256 checksums without publishing.
  See [release preparation](docs/releasing.md).
- [Deployment qualification profiles](docs/deployment/qualification-profile.md)
  define acceptance criteria for performance, memory, provider maintenance,
  backup/restore and cutover; protected volumes have a separate
  [witness backup/recovery procedure](docs/rollback-protection.md#backup-and-recovery-procedure).

- **Overlay memory bound**: `limits.max_overlay_bytes` (default 256 MiB)
  and `limits.max_overlay_entries` (default 262144) bound the in-memory
  ciphertext overlay independently of the on-disk journal; a write over the
  bound checkpoints inline and fails with ENOSPC if that cannot make room,
  and the worker checkpoints at half the bound (R4-005;
  [configuration](docs/configuration.md#journal-bounds)). Existing
  configurations gain the defaults; set either to `0` to keep the old
  unbounded behaviour.
- **Deep-check verdict**: `maki check --deep` and `maki-check --deep` end
  with `deep check verdict: clean | recoverable | unrecoverable`; slot damage
  that a validated journal record repairs is a warning, not an error
  (R4-004; [operations](docs/operations.md#volume-lifecycle)).
- **Debian package safety**: `prerm` refuses removal while a volume is
  attached (upgrades are exempt), the builder verifies every artifact's ELF
  architecture against `--architecture`, and native library dependencies are
  added to `Depends` with `dpkg-shlibdeps` by default (the build now needs
  `dpkg-dev`; `--no-shlibdeps` opts out for test fixtures only) (R4-003, R4-007;
  [packaging README](packaging/debian/README.md)).
- **Runtime logging**: the nbdkit plugin, `maki` and `maki-check` install a
  stderr `tracing` subscriber (`MAKI_LOG` filter, default `info`), so
  checkpoint, journal-sync, control-server and store-repair warnings reach
  the service journal (R4-001; [operations](docs/operations.md#logging)).
- Opt-in **envelope v3** with durable TRIM and Linux backing-space
  reclamation: `maki volume create <config> --discard` (`8f7606f`,
  `e911471`; [space reclamation](docs/space-reclamation.md)).
- Experimental **rollback-protected backing** with an independent local
  witness for new Linux volumes (`d2c4fb7`, `64ff710`;
  [rollback protection](docs/rollback-protection.md)). Not qualified.
- **Debian package** builder and package contract tests (`8b69efc`,
  `07fed8b`); the package owns nothing under `/etc/maki` and never starts a
  volume.
- **`[lvm_identity]` pins** (complete PV set, VG and target LV UUIDs) in the
  attach configuration. Grow and detach refuse a configuration that changes
  them, and recovery checks the identity attach recorded against them.
- **Native readiness**: the data-plane unit is `Type=notify` and reports
  `READY=1` only after recovery, provider checks and control binding
  (`2a3f023`).
- **Physical write reservation**: `posix_fallocate` of the journal range and
  the checkpoint slot before a record is published (`ced2bda`).
- **Bounded recovery replay** through a fixed 1 MiB payload batch (`733833c`).
- **Volume capacity plan** in `maki volume inspect` (`5803be8`).
- Verified **WSS and gRPC TLS/mTLS** for the WebSocket and gRPC providers
  (`a1aac42`).
- **RustSec dependency audit** in CI (`47058d2`).
- Optional **random plaintext prefix** (`crypto.random_prefix_bytes`, 16 to
  256 bytes in multiples of 16) prepended to every crypto unit before
  provider encryption; new volumes only (`562b397`, `1115e1d`;
  [random plaintext prefixes](docs/random-plaintext-prefix.md)).
- Getting-started, deployment and status documentation; `LICENSE`,
  `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and a documentation link
  checker in CI (2026-09-23).

### Changed

- **A displaced attach record is retired automatically once nothing of its
  attachment remains** (AUD-134, 2026-11-23;
  [#367](https://github.com/seo-rii/maki/pull/367)). A trusted record whose
  NBD device is connected under another identity (an NBD client started
  outside the helper, or two volumes left sharing a device by an older
  helper) was refused by every verb until root removed it by hand. Attach,
  cleanup, recover and detach now retire it under the attach lock, without
  running a command or touching the device, when the record names its VG
  UUID, no device-mapper device of that VG exists on the host, every holder
  of the device and its partitions is an LVM mapping of another VG, nothing
  is mounted at the recorded mountpoint or from a mapping of that VG, no
  other record names the device with the same VG UUID or with none, the
  backend stays the same across two observations, and every observation can
  be read. Otherwise the refusal adds `The record is not retired
  automatically: <reason>`. A record that names no VG UUID (an attach without
  `[lvm_identity]` pins that stopped before the connect) keeps the manual
  step. Cleanup with a configuration that does not match the record is
  refused with "cleanup configuration does not match the trusted attach
  record" ([privileged helper](docs/operations.md#privileged-helper)).
- **`maki volume gc` goes on past a namespace it cannot examine or finish
  retiring** (AUD-113, AUD-138;
  [#357](https://github.com/seo-rii/maki/pull/357),
  [#365](https://github.com/seo-rii/maki/pull/365)). A stale namespace that
  GC cannot open or examine (a root-owned leftover of an interrupted root
  `takeover`, an entry it may not read) is kept and listed in a new
  `skipped_unreadable` array of `{"name", "error"}` objects. One whose
  retirement stopped at a step that changes it alone (an unlink, its
  directory sync or removal, or its rename when its own directory is
  immutable or append-only and the root is neither) is kept as the step left
  it and listed in a new `unfinished` array; a later pass resumes it.
  `counts` gains `skipped_unreadable` and `unfinished`. Both cases used to
  end the pass with an error, leaving every higher-fence namespace on disk
  with a full arena; `maki volume gc` now exits 0 with the entries listed.
  A pass still ends with an error for an authority failure or a changed
  record, a root whose marker, current generation, binding, listing or mount
  identity cannot be read, a rename the root or its filesystem refuses, a
  failed sync of the root directory and an entry that changed identity while
  it was being retired. The automatic pass after an activation, which was
  silent, logs a `WARN` when it did not complete and names the first entry
  it could not examine or finish
  ([retire old writer namespaces](docs/remote-witness-service.md#retire-old-writer-namespaces)).
- **An interrupted creation can be run again** (AUD-114, AUD-115, AUD-136,
  AUD-139; [#358](https://github.com/seo-rii/maki/pull/358),
  [#366](https://github.com/seo-rii/maki/pull/366)). A remote `maki volume
  create` writes its format marker and its binding under a temporary name
  (`rollback.format.next`, `remote.enrollment.next`) and renames them into
  place. `create` completes a root that holds only an unwritten or staged
  marker, and `resume-enrollment` continues a creation cut while it wrote
  the binding, which needed the file moved out by hand; an invalid binding
  that an older binary left keeps that step. `maki-witness init` no longer
  creates an empty `remote.state` first, so an interrupted `init` can be run
  again; an empty `remote.state` is still refused, now with its causes and
  the way out. A local-witness `maki volume create` completes a backing and
  witness directory that hold only what an interrupted creation leaves (the
  marker, the arena, manifest slots that are unwritten or hold the initial
  manifest, `anchor.next`), where it refused every pair that was not empty,
  for example after the arena reservation ran out of space. It still never
  creates over committed data or an existing `anchor`, and a creation that
  stopped after publishing the anchor is still refused. The local witness
  no longer installs an empty anchor first; an empty `anchor` that an
  earlier release left is refused with an explanation
  ([local creation](docs/rollback-protection.md#local-configuration-and-creation),
  [remote enrollment](docs/rollback-protection.md#resume-interrupted-initial-enrollment),
  [witness initialization](docs/remote-witness-service.md#initialize-a-local-authority)).
- **Background validation of a quarantined endpoint treats a generic refusal
  or a provider failure as inconclusive** (AUD-116, AUD-140;
  [#350](https://github.com/seo-rii/maki/pull/350),
  [#364](https://github.com/seo-rii/maki/pull/364)). A request refused
  without an integrity verdict (over HTTP every 4xx the transport classifies
  as a request error, such as 400, 421 or a 422 without the
  `maki-crypto-error` header; a WebSocket `bad-request`; a gRPC
  `InvalidArgument`, `NotFound`, `OutOfRange` or bare `FailedPrecondition`),
  a validation RPC that the endpoint set's own byte budget refuses, and a
  `ProviderFatal` error of the candidate's own provider no longer mark the
  endpoint `rejected` for the life of the daemon. It stays quarantined and is
  validated again every `circuit_breaker.open_initial`, doubling up to
  `open_max`, with a warning per attempt. Only proof of another contract
  excludes it: an integrity refusal of the other endpoint's ciphertext or of
  the key canary, a wrong plaintext, a foreign compatibility id, a claimed
  capability it does not honour or an explicit refusal of the volume's
  context. An endpoint that always answers so is still never admitted and is
  now probed for as long as the daemon runs. Attach is unchanged
  ([endpoint validation](docs/configuration.md#websocket-and-grpc-contracts)).
- **An `EndpointSet` bound to one plaintext size reports only that size**
  (AUD-117, [#351](https://github.com/seo-rii/maki/pull/351)). With
  `with_plaintext_size`, as the daemon builds its set, the reported
  capabilities list the bound size alone (`[512]` instead of `[512, 4096]`,
  or `[512 + prefix]` with a random prefix), so the batch scheduler refuses a
  unit of another size alone at admission instead of letting it fail a
  coalesced call. Limits and security claims are still the intersection over
  every endpoint.

### Fixed

- **2026-11-23 fifth audit: command-line output** (AUD-122, AUD-123;
  [#353](https://github.com/seo-rii/maki/pull/353)). The five binaries no
  longer exit 101 with a panic when stdout or stderr cannot be written. A
  closed stdout is not an error, and the command keeps its own status: a
  clean `maki check … | grep -q …` under `pipefail` passes again and a failed
  check still exits 1. Another failure to write a command's result exits 1
  and names the verdict, a command that has already changed something
  (`volume takeover`, `gc`, `restore`, `maki-attach verify`) only warns, and a
  diagnostic stderr cannot take is dropped. An executing `maki-attach` verb no
  longer panics at a log line or a device announcement nobody reads, and an
  unwritable copy of its plan never decides the outcome. `maki-attach --help`,
  `-h`, `help`, `--version` and `-V`, `maki-witness --version` and `-V`, and
  `maki-benchmark --version` and `-V` exit 0, each only as the sole argument.
  `maki --help` says that the helper verbs only print the `maki-attach`
  command, `maki-attach grow --add-bytes` is refused with the reason, and two
  validation messages lost a stray line break.
- **2026-11-23 fifth audit: privileged helper** (AUD-121). A volume group of
  64 logical volumes, which preflight admits, no longer fails proof capture
  and rolls back on every attach: the inventory behind the mapping proof
  holds 64 devices and 64 mappings, and the preflight refusal of a 65th LV
  names the limit ([#355](https://github.com/seo-rii/maki/pull/355);
  [checking LVM](docs/storage-recovery.md#checking-lvm-before-activation)).
- **2026-11-23 follow-ups: command line and plugin** (AUD-144). The nbdkit
  plugin's five stderr lines (configuration refusals, a failed startup or
  shutdown) no longer turn a log pipe whose reader has gone into a caught
  panic and EIO, and `cargo doc` no longer documents the `maki-witness`
  binary over the `maki_witness` library
  ([#363](https://github.com/seo-rii/maki/pull/363)).
- **2026-11-23 follow-ups: CI on Windows** (AUD-146). The CI formatting step
  runs on Linux only: on Windows `cargo fmt --all --check` passes every
  target's root file to one rustfmt command line, which the workspace has
  outgrown ("The filename or extension is too long", os error 206), so from
  #369's merge `main`'s Windows jobs stopped before their clippy and test
  steps; each pull request's own run passed them. Formatting does not
  depend on the platform; check it on Windows one package at a time with
  `cargo fmt -p <package> --check`
  ([#372](https://github.com/seo-rii/maki/pull/372);
  [running checks](docs/testing.md#run-checks-locally)).
- **2026-11-23 fifth audit and follow-ups: tests and CI** (AUD-128 to
  AUD-132, AUD-145). Eight golden vectors freeze the allocation map, the
  shard catalog, the checkpoint state, the durable proof, the journal
  segment and record headers and the v2 and v3 superblock envelopes, and an
  inventory test requires a vector for every record magic
  ([#352](https://github.com/seo-rii/maki/pull/352)). The Linux CI job runs
  the test targets that need root as root (`scripts/run_root_tests.py`),
  fails when a Python suite leaves bytecode in the checkout and runs every
  script test module ([#360](https://github.com/seo-rii/maki/pull/360));
  since [#366](https://github.com/seo-rii/maki/pull/366) the root step also
  runs maki-backing's unit tests. Tests that passed without asserting (the
  mount-target rule, the release of locked pages, the memory-budget path
  bytes), a test that used failpoints without their lock and native tests
  that skipped without a notice are fixed
  ([#361](https://github.com/seo-rii/maki/pull/361)). Fixtures no longer
  depend on the umask, a `TMPDIR` private to root or a host trust store
  ([#362](https://github.com/seo-rii/maki/pull/362)), nor on `/dev/shm` or a
  short `TMPDIR`, and the Python campaign tests no longer leave a `0077`
  umask behind; `MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1`, which CI sets, makes
  a missing second filesystem fail the rollback tests instead of skipping
  them ([#371](https://github.com/seo-rii/maki/pull/371); [running
  checks](docs/testing.md#automated-ci)). See the remediation log's
  [fifth](docs/review-remediation.md#internal-audit-fifth-round-2026-11-23-aud-113aud-132)
  and
  [sixth](docs/review-remediation.md#sixth-round-follow-ups-2026-11-23-aud-133aud-146)
  rounds.

- **2026-11-23 audit: privileged helper and daemon admission** (AUD-101,
  AUD-102). A mount with an empty source (`mount -t tmpfs '' /dir`) anywhere
  in the namespace no longer fails NBD allocation, attach, detach, cleanup,
  recovery, grow and the workload verify gate for every volume, or the start
  of a memory-budgeted daemon: both mount-table parsers split a record by
  field position. Memory-budget admission reads the table as a stream, so a
  host with thousands of mounts is no longer refused with "oversized kernel
  field /proc/self/mountinfo"; one record longer than 1 MiB still is
  ([#337](https://github.com/seo-rii/maki/pull/337); [memory
  budget](docs/configuration.md#measured-memory-budget)). See the
  [remediation
  log](docs/review-remediation.md#internal-audit-fourth-round-2026-11-23-aud-098aud-112).
- **2026-11-23 audit: storage, remote providers and secrets** (AUD-098 to
  AUD-100). A file whose name is not UTF-8 in a volume's `data/` or
  `journal/` directory no longer fails every attach or leaves `maki check`
  inconclusive: the scans skip it like any other unknown name, while volume
  creation and rollback enrollment still refuse it
  ([#338](https://github.com/seo-rii/maki/pull/338)). A request with a unit
  that is refused before anything is sent (an empty ciphertext recorded by a
  damaged slot, a ciphertext above the provider's maximum, plaintext of a
  size the provider does not accept) now fails alone at scheduler admission;
  with a provider that is not retry-safe it used to fail every request
  coalesced with it, so one such slot gave healthy reads EIO
  ([#334](https://github.com/seo-rii/maki/pull/334);
  [batching](docs/configuration.md#batching-and-pending-bounds)). The search
  of each encrypt result for its own plaintext no longer builds a table
  derived from that plaintext in ordinary heap memory, where it was not
  page-locked and was freed without erasure
  ([#335](https://github.com/seo-rii/maki/pull/335); [transport
  memory](docs/transport-memory.md#local-providers-and-key-material)).
- **2026-11-23 audit: tests** (AUD-112). The preserve-first rule of the A/B
  metadata stores is pinned for every record type by the copy a torn retry
  keeps, and for the checkpoint state at the volume level
  ([#345](https://github.com/seo-rii/maki/pull/345)). The memory-budget
  admission recheck, which no test covered, has one
  ([#337](https://github.com/seo-rii/maki/pull/337)).

- **2026-11-17 audit: durability and recovery** (AUD-052 to AUD-062, AUD-091).
  A worker pass started by the interval, the overlay bound or a write refused
  for space now checkpoints the records already durable when its journal sync
  fails, as watermark and low-space passes did, and a watermark at or below the
  segment size no longer costs a sync and a checkpoint per write
  ([#176](https://github.com/seo-rii/maki/pull/176)). A final journal segment
  exactly one header long whose header fails its checksum, left by an older
  binary's torn header write, no longer blocks attach when the durable proof
  and mark name earlier segments
  ([#177](https://github.com/seo-rii/maki/pull/177)). Allocation map padding
  bits, and positions past the device's end in a partial last shard, no longer
  make a never-written short shard read EIO
  ([#184](https://github.com/seo-rii/maki/pull/184),
  [#186](https://github.com/seo-rii/maki/pull/186)). See the remediation log's
  [second](docs/review-remediation.md#internal-audit-second-round-2026-11-17-aud-052aud-090)
  and
  [third](docs/review-remediation.md#internal-audit-third-round-2026-11-17-aud-091aud-097)
  rounds.
- **2026-11-17 audit: remote providers** (AUD-066 to AUD-071). WebSocket and
  gRPC responses no longer take about 43 and 49 times their size in memory
  while they are parsed ([#173](https://github.com/seo-rii/maki/pull/173)). A
  request of a provider that is not retry-safe now fails over when its attempt
  failed before any request byte was sent (a refused connection, a failed TLS
  handshake, a refused WebSocket upgrade); under `stall` it stays pending while
  its only endpoint refuses connections, instead of failing at once. An
  operation whose deadline expires while it waits for endpoint admission
  reports the last endpoint error, as the other deadline exits do
  ([#174](https://github.com/seo-rii/maki/pull/174)). The patched serde_json
  builds error messages in linear time and erases the owned raw text a
  `&RawValue` rejects ([#183](https://github.com/seo-rii/maki/pull/183)).
- **2026-11-17 audit: witness, rollback protection and admission** (AUD-078 to
  AUD-080, AUD-082, AUD-092, AUD-093). One name that is not UTF-8 in a remote
  rollback backing root no longer makes every GC pass fail (which left
  predecessor namespaces on disk until the filesystem filled), and a damaged
  manifest length no longer allocates about 72 MiB per open
  ([#181](https://github.com/seo-rii/maki/pull/181)). A root
  `maki check --deep`, `maki volume inspect` or other open of a local rollback
  witness keeps the anchor's owner, so the daemon can still attach, and a root
  `maki volume create` names the witness directory in its `chown` warning
  ([#182](https://github.com/seo-rii/maki/pull/182)). Memory-budget admission
  reads the mount table as bytes, so one non-UTF-8, newline or very deep mount
  path elsewhere no longer stops every memory-budgeted volume from starting
  ([#180](https://github.com/seo-rii/maki/pull/180)). A failure before a local
  witness authority renames its new state now fails only that request, instead
  of making `serve` answer every later request as unavailable until a restart,
  and `maki volume restore` reads a snapshot it may not write, such as one on a
  read-only mount or with immutable files
  ([#189](https://github.com/seo-rii/maki/pull/189); [witness
  service](docs/remote-witness-service.md#initialize-a-local-authority)).
- **2026-11-17 audit: tooling and tests** (AUD-063 to AUD-065, AUD-083). The
  vendor erasure contract resolves every workspace feature
  ([#183](https://github.com/seo-rii/maki/pull/183)). `CrashableBacking` and
  `MemBacking` refuse directory names as locks and in `remove` as `FileBacking`
  does, three recovery and journal regressions that could not fail now fail
  without the rewrite they are named after, and MAKI-011 has a dedicated test
  ([#175](https://github.com/seo-rii/maki/pull/175)).

- **2026-11-16 audit: durability and recovery** (AUD-001 to AUD-007). Recovery
  rewrites both superblock copies from their exact bytes and completes a
  missing one before any other repair, so a failed or killed `volume create`
  can no longer leave a volume whose only superblock copy is in the page cache;
  every attach now does a few extra 4 KiB superblock writes and syncs
  ([#164](https://github.com/seo-rii/maki/pull/164)). `maki volume create` also
  refuses a root that still holds an earlier volume's `superblock.*`,
  `shard-catalog.*` or `canary.*`
  ([#164](https://github.com/seo-rii/maki/pull/164)). A torn journal segment
  header left by a failed segment roll no longer blocks attach
  ([#166](https://github.com/seo-rii/maki/pull/166)). Concurrent writers can no
  longer take the space an inline reclaim frees for the write that ran it,
  which turned a reclaimable journal or overlay bound into ENOSPC; this
  replaces the four-round retry of the R4-005 follow-up. Watermark and
  low-space checkpoints sync the journal first instead of applying nothing, and
  still checkpoint durable records when that sync fails
  ([#168](https://github.com/seo-rii/maki/pull/168)). Recovery's rewrite of the
  journal it adopts is covered by a power-loss sweep
  ([#167](https://github.com/seo-rii/maki/pull/167)). See the [remediation
  log](docs/review-remediation.md#internal-audit-2026-11-16-aud-001aud-051).
- **2026-11-16 audit: remote providers** (AUD-019 to AUD-025). A gRPC peer can
  no longer panic a call with malformed `grpc-status-details-bin` or change its
  error class with undecodable `grpc-message` text, and IPv6-literal gRPC TLS
  endpoints can be built ([#150](https://github.com/seo-rii/maki/pull/150)).
  Under `stall`, a contract violation ends an operation only once every
  validated endpoint has broken the contract for it; until then the request
  waits for the remaining peers, including one whose circuit is cooling
  ([#154](https://github.com/seo-rii/maki/pull/154)). A WebSocket upgrade
  refused with any 3xx or 4xx other than 408 and 429 opens that endpoint's
  circuit, a retry-safe request fails over, and attach quarantines the endpoint
  instead of refusing ([#155](https://github.com/seo-rii/maki/pull/155)). HTTP
  refuses a close-delimited success response and a raw encrypt response shorter
  than its plaintext as contract errors, which previously stored a truncated
  body as the unit's ciphertext, and a JSON response no longer takes about 43
  times its size in memory ([#157](https://github.com/seo-rii/maki/pull/157)).
  WebSocket reads no longer rewrite the whole retained read buffer
  ([#160](https://github.com/seo-rii/maki/pull/160)).
- **2026-11-16 audit: logging, witness and privileged helper** (AUD-027,
  AUD-028, AUD-033, AUD-037 to AUD-041). `tungstenite`, `tokio_tungstenite` and
  `reqwest` are capped at `debug`, and `tungstenite::protocol` at `info`,
  whatever `MAKI_LOG` says, so `MAKI_LOG=trace` no longer writes WebSocket
  payloads, upgrade query credentials or close reasons to the journal; their
  trace output is no longer available
  ([#155](https://github.com/seo-rii/maki/pull/155);
  [logging](docs/operations.md#logging)). Validation errors no longer quote an
  HTTP operation path ([#159](https://github.com/seo-rii/maki/pull/159)).
  Enrollment recovery refuses a root that holds another volume's data,
  `maki volume resume-enrollment` refuses a provider the build cannot
  construct, and a local socket denial (netfilter EPERM) is a transport
  failure, so witness failover continues and the rollback backing refuses only
  that operation ([#156](https://github.com/seo-rii/maki/pull/156)). The
  privileged helper reads the mount table as bytes, so one non-UTF-8 mount path
  anywhere no longer fails attach, detach, recovery and NBD allocation for
  every volume, and the workload verify gate runs in a unit without
  `CAP_FOWNER` ([#153](https://github.com/seo-rii/maki/pull/153)).
- **2026-11-16 audit: tooling and tests** (AUD-008 to AUD-018, AUD-042 to
  AUD-046). The privileged validation runner requires the expected permission
  denial instead of any failure, the nightly plugin and fake-provider gates
  require the exact symbol and refusal, and `scripts/run_cargo_tests.py` runs
  `--doc` selections ([#151](https://github.com/seo-rii/maki/pull/151)). The
  vendor erasure check compares resolved features with a reviewed list
  ([#160](https://github.com/seo-rii/maki/pull/160)); the standalone vendor
  test loggers no longer depend on unmaintained `humantime` (RUSTSEC-2026-0542,
  [#155](https://github.com/seo-rii/maki/pull/155)). `CrashableBacking` keeps a
  failed sync's writes uncertain instead of lost, writes back whole 4 KiB
  pages, and ends every handle and lock at a simulated power loss
  ([#165](https://github.com/seo-rii/maki/pull/165)). `MemBacking` applies
  POSIX path rules, a zero-length `allocate_range` is a no-op on every backing
  including `FileBacking`, and the fake provider, `ManualClock` and
  `DeterministicScheduler` follow the contracts they stand in for; two tests
  that failed only as root now inject their faults for root too
  ([#163](https://github.com/seo-rii/maki/pull/163)).

- **Mixed benchmark write verification** (BUG-134, 2026-10-20): check the
  latest expected value at every initialized slot after measurement, including
  writes that no measured read visits. Reports separate written/read-after-write
  slot coverage and final sweep count/time from measured read verdicts, IOPS and
  latency. Fault controls reject discarded measured writes and a lost final
  write; the sweep uses the current engine/cache rather than crash recovery
  ([benchmark guide](docs/benchmark.md)).

- **2026-10-14 project review**: inline reclaim keeps reclaiming while a
  checkpoint has not covered every append, so a concurrent FUA no longer turns
  a write into ENOSPC (BUG-089). `maki-check --deep` fails instead of passing
  when its own superblock read fails (BUG-090). Journal segment and shard file
  names parse only in canonical form, and the fast checker reports the orphan
  shards recovery adopts (BUG-091). An endpoint-fatal answer opens that
  endpoint's circuit at once (BUG-094). The root helper never passes a mount
  source to `blkid` as an option (BUG-096). A configured gRPC CA works on hosts
  with an empty trust store (BUG-097). nbdkit callbacks fail with EIO instead
  of aborting on a panic, and failed requests are logged, rate-limited
  (BUG-098). The nightly release gates run to completion, with the etcd quorum
  gate behind `etcd-qualification` (TEST-003), and tokio's `test-util` is no
  longer part of production builds. See the
  [remediation log](docs/review-remediation.md#project-review-2026-10-14).
- **2026-10-14 second review pass**: binding the control socket refuses any
  file at the address other than a dead socket (BUG-099). Volume creation
  writes the superblock last, so a creation interrupted before it writes a
  superblock copy is not a volume (BUG-100). The checkpoint worker waits one interval after a failed pass
  (BUG-101), and a write refused for free space wakes it (BUG-106). A
  coalesced provider call never carries one unit twice (BUG-102). A remote
  witness that cannot be reached refuses each operation without stopping the
  session; a mismatch still stops it (BUG-103). Witness workers are given only
  to authenticated connections (BUG-104). An encrypt result that carries its
  own plaintext is refused on every call (BUG-105). Remote attach and takeover
  authenticate the current generation in the local root before changing the
  authority, so a damaged or foreign root leaves it unchanged rather than
  Claimed (BUG-107). The crash simulator models inodes and atomic rename, and
  the durability sweeps retire superseded failed writes (TEST-004, TEST-005).
  Control commands take `--socket <path>` in place of the volume
  configuration, so `maki-admin` members can use them, and only parse a
  configuration they are given (BUG-108).
- **2026-10-14 third review pass**: configuration errors never print a value
  (BUG-113). Only encrypting cryptsetup mappings count as encrypted swap
  (BUG-114). A gRPC TLS handshake is bounded by the connect timeout
  (BUG-115), and WebSocket frames outside the response contract fail the
  connection as a contract error (BUG-117). Attach refuses a mountpoint with
  mounts below it (BUG-118) and `grow --size-bytes` takes plain digits only
  (BUG-116). Superblocks with unknown flags or format version are refused
  (BUG-109); `maki-check --deep` no longer writes into a directory that is not
  a volume (BUG-110); the witness keeps accepting after EMFILE (BUG-111);
  `maki` and `maki-check` gain `--help` and `--version` (BUG-112); key-file
  open errors say why (BUG-119); a non-UTF-8 nbdkit `config=` path is refused
  (BUG-120). A power-loss sweep with TRIM joins the release gates (TEST-006),
  a page-lock unit test no longer races on Windows (TEST-007), and witness
  transport tests no longer time out on loaded runners (TEST-008).
- **2026-10-15 fourth review pass**: a gRPC response cut inside a message, or
  OK without one, is a contract error (BUG-121). File credentials and TLS
  files must be absolute paths (BUG-122). A failed hole punch no longer fails
  an idle checkpoint, so drain and shutdown work while punching fails
  (BUG-123). The daemon and CLIs raise the soft descriptor limit for shard
  files, and a failed shard open other than a missing file is reported as
  I/O, not corruption (BUG-124). A panic while the volume write lock is held
  stops the engine until the volume is attached again (BUG-125). An encrypt
  result carrying its plaintext anywhere is refused, and `grow --size-bytes`
  must be a multiple of 512 (BUG-105, BUG-116 follow-ups). The operator guides
  correct the overlay metrics, full-backing behaviour, start-limit reset,
  instance naming and witness takeover procedures.

- **2026-10-12 correctness and recovery review**: journal sync/recovery retries
  reassert accepted file lengths and verified bytes; volume creation holds its
  exclusive lock through final directory sync. Completed batch errors cancel
  earlier pending batches while successful outputs keep unit order. HTTP
  oversized responses and gRPC `Unimplemented` are endpoint failures for
  breaker/failover, with unsafe no-resend preserved. Resolved gRPC metadata and
  daemon intermediates are erased on all ownership paths. Sentinel publication
  is atomic without replacement, and identical retries rewrite then synchronize
  bytes and length. Attach compares stored geometry before provider setup;
  malformed attach CLI options are usage errors; unrepresentable retry probe
  intervals are rejected without library panics. Admission waits without holding
  global capacity and reselects available peers. Rust 1.99 warnings are fixed;
  reproducible Rust 1.94 and latest-stable Linux/Windows jobs run independently.
  See [regressions](docs/review-remediation.md#correctness-and-recovery-review--2026-10-12).
- **Bounded recovery slot-write amplification**: every historical record stays
  validated, while only each unit's latest sequence within the existing batch
  writes slot data; a last discard skips superseded writes. Allocation evidence,
  metadata publication order and batch boundaries are preserved.

- **HTTP response JSON ownership**: completed strings and object keys are
  guarded before the full response is parsed, so malformed partial JSON and
  duplicate replacement erase their owned plaintext too. Single-item and
  batch responses share the guarded parser; serde scratch and transport-private
  allocations remain outside that ownership guarantee
  ([memory scope](docs/transport-memory.md)).
- Current support documentation includes the scoped PostgreSQL 17/Debian 13
  and cross-host provider-reset evidence; it no longer presents completed
  reference-provider campaigns as unexecuted work. Production approval remains
  pending.

- A request's provider batches run concurrently within the
  `max_active_callbacks` limit, and a per-item HTTP mapping (no
  `items_path`) is batched one unit per call. Sequential I/O through such a
  mapping with 10 ms of provider latency went from about 330 KiB/s to
  2.8 MiB/s (R5-039).
- **Writes longer than `nbd.maximum_io` were refused and, under buffered
  writeback, silently lost** (R5-038). Linux 6.12 (Debian 13) sends up to
  1280 KiB per request regardless of the advertised 1 MiB maximum; XFS made
  on such a volume could not be mounted. Longer reads and writes are now
  served in `maximum_io` chunks.
- `maki@.service` starts under systemd 257 (Debian 13), which writes
  `LoadCredential=` files with mode `0440`; the credentials directory now
  accepts group read for the service's own group (R5-037).
- NBD WRITE_ZEROES longer than `nbd.maximum_io` (sent by userspace clients
  such as nbdcopy for the holes of a sparse image) failed with EINVAL: the plugin left it to nbdkit's
  single-`pwrite` emulation. Zeroing is now native and chunked, and may
  discard whole units on a `--discard` volume when the client allows it
  (R5-036).
- A bearer token (HTTP header or gRPC metadata credential) or PEM private
  key that happens to be an even-length hex string is used verbatim; the
  daemon used to hex-decode it like a local key and refused to start
  (R5-035). Tokens generated with `openssl rand -hex` were affected.
- `maki@.service` sets `SystemCallFilter=@system-service` with
  `SystemCallErrorNumber=EPERM`, after three packaged PostgreSQL lifecycles
  ran under it without a denial, and `MemoryDenyWriteExecute=yes`, after the
  local and all three remote providers round-tripped data under it.
- Rollback-protected backing (experimental): a write's cost no longer grows
  with committed data (R5-034); a 64 KiB write at 128 MiB committed went
  from about 150 ms to under 1 ms.
- Lowering `backing.journal_segment_size` no longer makes a cleanly stopped
  volume fail recovery as corrupt (R5-033); the setting is now limited to
  1 GiB.
- `maki@.service` adds kernel-log, clock, hostname, realtime, namespace,
  syscall-ABI and address-family restrictions (R5-031).
- `maki-check` no longer creates a missing root directory (R5-026), and the
  deep check no longer reports nonexistent units of a truncated partial last
  shard (R5-027).
- Detach, cleanup and attach rollback no longer require
  `<mountpoint>/.maki-sentinel` (R5-006): a workload that deleted or
  rewrote it blocked `maki-attach cleanup`. The mount is identified from
  kernel metadata, as recovery already did; attach and `verify` still check
  the sentinel.
- `maki-attach` refuses `mountpoint = "/"` (R5-019).
- `maki volume create` refuses a backing root that still holds an earlier
  volume's `data/`, `journal/` or `checkpoint/` files (R5-018); they used to
  be adopted and served by the new volume.
- Package removal is also refused while a `maki-recover@` unit is active
  (R5-015).
- A huge configured circuit-breaker duration no longer panics the
  dispatcher on the first trip (R5-013); `reload cache` refuses a size of 0
  or larger than the device (R5-014).
- v3 discard works under space pressure and on damaged units (R5-011,
  R5-012): tombstones are admitted against the emergency reserve alone, not
  the checkpoint headroom, and a unit whose slot is damaged can be discarded
  (previously EIO). "Already zero" is decided from the slot header, so a
  discard no longer reads every payload twice under the volume lock.
- v3 discard: **trims longer than `nbd.maximum_io` are accepted** (R5-010).
  The maximum block size bounds payloads; kernel discards (`fstrim`,
  `-o discard`) are far larger and all failed with EINVAL.
- v3 discard: a checkpoint **punches retired slots only after its state is
  durable** (R5-008), so a crash or failed state store can no longer leave
  recovery replaying an older write into a released hole (ENOSPC on a full
  backing). A failed punch now defers reclamation instead of failing the
  checkpoint. A failed shard-catalog commit no longer makes later
  reclamation checkpoints panic (R5-009).
- Remote providers: a **broken endpoint now fails over** (R5-005). A
  contract-violating response (malformed JSON, wrong item count, bad
  encoding) or HTTP 404/405/410 counts as an endpoint failure, opens that
  endpoint's circuit and lets a retry-safe request move to a healthy peer;
  previously every request failed while the circuit stayed closed.
- `remote-http` **ignores environment proxies** (R5-003): an inherited
  `HTTP_PROXY`/`ALL_PROXY` no longer receives plaintext encrypt requests.
  Deployments that relied on a proxy to reach the provider must connect to
  it directly.
- **The volume is mounted `nosuid,nodev`** (R5-002). A setuid binary or a
  device node inside the volume no longer takes effect on the host; attach
  verification refuses a mount without both flags, and `maki@.service` sets
  `DevicePolicy=closed`. Workloads that need setuid programs or device nodes
  on the volume are not supported. The `maki-attach verify` workload gate
  refuses a mount without both flags as well: reattach volumes mounted by an
  earlier build before restarting their workload.
- `remote-http`: a combined certificate/private-key PEM (`client_cert_file`
  without `client_key`) now passes the `file` credential checks (no symlink,
  not group/other-readable); every TLS file must be a regular file, so a
  FIFO cannot hang attach ([configuration](docs/configuration.md)).
- `remote-http`: a header credential that resolves to an invalid header
  value (a control character inside it) is refused at attach as
  `ProviderFatal` instead of failing every request as a retryable error.

- `maki-attach` refuses to mount onto a path a non-root user could redirect:
  every ancestor of the mountpoint must be a root-owned, non-group/other-
  writable real directory and the mountpoint a real directory. A workload
  that replaced the mountpoint with a symlink previously got its filesystem
  mounted by root at the symlink target (e.g. `/etc`), beyond rollback and
  detach ([operations](docs/operations.md#privileged-helper)).
- Pinned NBD devices must be spelled canonically (`/dev/nbd1`, not
  `/dev/nbd01` or `/dev/nbd+1`).

- Remote providers: an integrity (or other non-retryable, request-specific)
  rejection of a coalesced batch no longer fails every request merged into
  it; the batch scheduler re-sends each request alone, so a tampered unit
  read by one client cannot turn another client's healthy read into EIO.
  The re-send happens only for a retry-safe provider (a provider that is
  not retry-safe gets the error fanned out, as before), and each re-send is
  counted in flight and abandoned when its caller leaves (R5-004).

- Configuration validation refuses a `control.socket` that names the same
  file as `nbd.socket` (defaults included); binding the control socket
  replaces whatever is at its path.
- The control server's "unknown command" error echoes at most 64 characters
  of the name, so the response always fits the client's 64 KiB line limit.

- `control.group` resolution retries `getgrnam_r` with a larger buffer on
  `ERANGE`; a directory group whose record exceeded 16 KiB made attach fail.

- `file` and `credential` key sources open the credential once
  (`O_NOFOLLOW | O_NONBLOCK` on Unix) and run the regular-file and mode
  checks on the opened descriptor; checking the path and opening it again
  let a swap in between be loaded as the key, and a FIFO could block the
  open.

- `maki check --deep` now probes the slots the allocation map does not list:
  a damaged header there reads as EIO, but the check walked only allocated
  units and reported such a volume `clean` (R4-004 follow-up;
  [operations](docs/operations.md#volume-lifecycle)).

- A write that still exceeded the overlay bound or the journal hard limit
  after its inline reclaim failed with ENOSPC even when the space was held
  by another writer's volatile records, which that reclaim could not retire;
  it now syncs and reclaims again (up to four rounds) before refusing
  (R4-005 follow-up; [configuration](docs/configuration.md#journal-bounds)).

- `maki-attach` now installs a stderr `tracing` sink (`MAKI_LOG`, default
  `info`); its executed steps and halted-rollback errors were silently
  dropped before ([operations](docs/operations.md#logging)).
- The package `prerm` refuses removal when `systemctl list-units` fails,
  instead of reading the empty output as "no active maki units"
  ([packaging README](packaging/debian/README.md#removal-and-upgrade-behaviour)).

- A plaintext-cache hit now skips the ciphertext payload read (it reads the
  64-byte slot header to establish the version) instead of only skipping
  decryption; a hit no longer re-verifies an already validated payload's
  CRC until the entry is evicted; `cache.verify_on_hit = true` restores
  payload verification on every hit and skips only the decryption (R4-006;
  [configuration](docs/configuration.md#read-cache)).
- Local providers now encrypt and decrypt in place inside pre-allocated
  `SecretBuffer`s and key files are read straight into guarded memory, so
  plaintext and keys never first exist in an unlocked allocation; the
  expanded AES key schedules live in a page-locked `SecretBox` under
  `secure-buffers` and are zeroized on drop (R4-002;
  [transport memory](docs/transport-memory.md#local-providers-and-key-material)).

Every fix has a regression test named in the
[review remediation log](docs/review-remediation.md). Highlights that change
observable behaviour:

- Recovery no longer accepts never-synced page-cache bytes after a process
  restart (K-01) and makes the checkpoint state it selects durable before the
  writer resumes (BUG-022).
- A failed `fdatasync` is never retried bare: the journal rewrites and
  verifies the unsynced records before syncing again (F01 / BUG-021).
- Media damage to a shard data file (truncation, damaged slot headers on
  cleared allocation bits) reads as EIO, never as zeros (S-01 residuals,
  `db39faa`).
- The attach helper rolls back observed steps on failure, refuses foreign
  mounts, verifies the backend identity before every disconnect, and drains
  control sessions on shutdown (BUG-015, BUG-018, O-07, F06).
- HTTP redirects are refused instead of re-sending plaintext (C-01);
  remote error bodies are redacted.
- Circuit-breaker half-open slots are always returned (N-10 / BUG-004);
  per-RPC deadlines cover gRPC readiness plus the call (BUG-017).

### Documentation

- **2026-11-23 fifth audit and follow-ups** (AUD-124 to AUD-127, AUD-141).
  SPEC §43 classifies journal damage by the durable proof and mark instead of
  refusing corruption before a valid successor record, and SPEC, the
  architecture, testing and status pages match the code on envelope v3, the
  discard maps, the conditional swap check, the module layout, recovery's
  replay and discard admission
  ([#347](https://github.com/seo-rii/maki/pull/347)). The configuration guide
  names the nine byte keys that take only plain integers and says what the
  batch byte limit and the cache keys do, and the reclamation, latency and
  key-rotation pages match the code; a test loads every documented volume
  configuration ([#349](https://github.com/seo-rii/maki/pull/349)). The
  guides say that the stop after `maki drain` depends on cleanup's
  single-mapping fallback (detach an attachment with an additional LV before
  the drain), give the key-rotation runbook's stop order for backups and the
  PostgreSQL default-cluster precondition, and the manual pages document
  every option ([#348](https://github.com/seo-rii/maki/pull/348)). SPEC §18
  and a new [provider error
  signals](docs/configuration.md#provider-error-signals) section give the
  integrity tokens a provider must send and each transport's complete error
  classification, and SPEC gives the byte layout of every on-disk record
  ([#359](https://github.com/seo-rii/maki/pull/359)). What an inexact
  WebSocket probe error envelope, an upgrade reply that is not a valid
  upgrade and an HTTP/2 reset or GOAWAY under a gRPC call are classified as
  is documented and pinned, and SPEC §7 lists the remote-volume commands
  ([#364](https://github.com/seo-rii/maki/pull/364),
  [#363](https://github.com/seo-rii/maki/pull/363)). The remediation log
  records the fifth and sixth rounds and marks the statements they
  supersede.

- **2026-11-23 audit** (AUD-104, AUD-105): the nbd-client 3.27 backport
  recipe in the Debian guide stops at the first failed step, builds in a new
  directory, refuses a tarball that does not match the digest the operator
  verified against the upstream signature (`NBD_TARBALL_SHA256`) and installs
  exactly the package it built for the host's architecture; the quoted
  `Depends` line includes `systemd (>= 249)`
  ([installation](docs/getting-started/installation-debian.md#nbd-client-327-or-later),
  [#336](https://github.com/seo-rii/maki/pull/336)). The link checker counts
  a tab after a block quote or list margin to the line's next tab stop, so
  links on such lines are no longer skipped as indented code
  ([#333](https://github.com/seo-rii/maki/pull/333)). The remediation log
  records the fourth audit and marks the statements it supersedes; SPEC §8
  says that non-Unix hosts also hold a volume configuration to 1 MiB, SPEC
  §34 that a quarantined endpoint serves no volume request before its
  validation succeeds, and the architecture page that the echo check finds
  the plaintext anywhere in an encrypt result.

- **2026-11-17 audit** (AUD-081, AUD-084 to AUD-090, AUD-096, AUD-097): the
  link checker verifies reference-style link definitions and references
  ([#171](https://github.com/seo-rii/maki/pull/171)). A copy-on-write backing
  filesystem (btrfs with copy-on-write data, ZFS) is unsupported and btrfs
  NOCOW backing files are not qualified, because there an overwrite needs new
  space despite the reservation ([status](docs/status.md#known-limitations),
  [#171](https://github.com/seo-rii/maki/pull/171)). The workload verify gate
  needs CAP_DAC_READ_SEARCH or CAP_DAC_OVERRIDE in the unit's bounding set, or
  a volume root others can read and search
  ([#171](https://github.com/seo-rii/maki/pull/171),
  [#187](https://github.com/seo-rii/maki/pull/187)). Inside the checkpoint
  headroom raw discards are admitted, but a filesystem's deletes and XFS
  `fstrim` are refused; the key-rotation procedure masks `maki-recover@` while
  it starts units by hand; SPEC §9 lists only the implemented key sources
  ([#178](https://github.com/seo-rii/maki/pull/178)). `maki volume witness`,
  `snapshot` and `gc` run as the daemon user with the writer configuration, and
  enrollment recovery hands the paths back to it
  ([#182](https://github.com/seo-rii/maki/pull/182)). A remote restore's
  automatic GC deletes the newer state it replaces from the backing root;
  snapshot that state first if it may be needed ([witness
  service](docs/remote-witness-service.md#snapshot-takeover-and-restore),
  [#187](https://github.com/seo-rii/maki/pull/187)). The
  `systemd-analyze verify`, `BindsTo=` and quick-start cleanup statements were
  corrected ([#187](https://github.com/seo-rii/maki/pull/187)).

- **2026-11-16 audit** (AUD-047 to AUD-051): the link checker verifies in-page
  and cross-file anchors against GitHub heading slugs
  ([CONTRIBUTING](CONTRIBUTING.md#documentation)), and the deep check no longer
  names a torn-tail heuristic recovery stopped using
  ([#152](https://github.com/seo-rii/maki/pull/152)). Backing files must not
  share extents with reflink copies: a `cp --reflink` copy (coreutils 9's
  default on XFS and btrfs) can make an in-place write fail with ENOSPC despite
  the space reservation; copy with `cp --reflink=never`
  ([status](docs/status.md#known-limitations),
  [#152](https://github.com/seo-rii/maki/pull/152)). Stale statements in
  CLAUDE.md, SPEC, the operations, performance and testing guides and the
  remediation log's citations were corrected
  ([#152](https://github.com/seo-rii/maki/pull/152)). The guides now say that
  recovery checks the identity attach recorded against the `[lvm_identity]`
  pins rather than reading LVM metadata again
  ([#153](https://github.com/seo-rii/maki/pull/153)), and the privileged
  validation runbook names the results its earlier lenient denial checks cover
  ([#151](https://github.com/seo-rii/maki/pull/151)).

- **2026-10-14 project review**: docs that contradicted `status.md` or the code
  were corrected (remote witness status, power-loss tearing, nightly gate
  scope, deep-check report order, `drain` timeout, duration syntax, overlay
  zero limits, etcd restore and compaction). The operator guides wait for stopped units through
  `ActiveState` instead of `systemctl is-active`. The crate
  maps list `maki-witness`, and stale crate and module comments were fixed.

- [Remote transports under the syscall filter](docs/qualification/remote-transport-syscall-filter-validation-2026-10-04.md):
  the first external campaign for WebSocket and gRPC.
- [PostgreSQL over gRPC, NBD zeroing, MemoryDenyWriteExecute](docs/qualification/remote-database-zero-mdwe-validation-2026-10-04.md).
- [Debian 13: remote transports, sandbox, latency, zeroing](docs/qualification/debian13-remote-transport-validation-2026-10-04.md);
  the support matrix lists Debian 13 as campaign-passed (scoped).
- [Debian 13: PostgreSQL 17 over per-item HTTP, R5-039 throughput](docs/qualification/debian13-postgresql-http-validation-2026-10-05.md).
- [Cross-host remote transports under the sandbox](docs/qualification/cross-host-sandbox-validation-2026-10-05.md).
- [Provider host reset under a writing client](docs/qualification/provider-host-reset-validation-2026-10-05.md).
- The quick start and first-volume bootstrap passed `/dev/nbd0` to
  `nbd-client`; version 3.27, which Maki requires, connects over netlink and
  refuses it ("Invalid nbd device target"). They now pass the kernel name
  (`nbd0`); found by the 2026-10-03 packaged-lifecycle campaign.
- Validation reports moved to `docs/qualification/`; the README now links to
  [status](docs/status.md) instead of carrying the campaign history.
- `docs/architecture.md` now describes the experimental rollback-protected
  backing as implemented and the default formats' rollback limitation
  separately.
