# Security policy

Maki stores ciphertext for other people's data and runs a root-owned helper
next to an unprivileged daemon. Security reports are welcome and taken
seriously.

## Supported versions

There is no tagged release yet. Security fixes land on `main`; deployments
are expected to track a specific commit and record it in their qualification
notes (see [status](docs/status.md)).

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

1. Use GitHub's private vulnerability reporting on
   [seo-rii/maki](https://github.com/seo-rii/maki/security/advisories/new).
2. If that is unavailable, open a public issue that says only "security
   contact requested" without details, and a maintainer will provide a private
   channel.

Include what you can of:

- the commit hash or package version you tested;
- the configuration (`volume.toml`, `attach.toml`) with secrets removed;
- the host, kernel, `nbd-client`, LVM and nbdkit versions;
- a reproduction, or the code path and the invariant you believe is broken
  (SPEC §12 lists the durability invariants; SPEC §4–§9 the privilege and
  credential model);
- the impact you observed: plaintext or key exposure, acknowledged data lost
  or served incorrectly, privilege boundary crossed, denial of service.

You should receive an acknowledgement within a few days. Fixes follow the
project's test-first rule: a regression test that fails before the fix and
stays in the tree afterwards. Findings and their fixes are recorded in the
[review remediation log](docs/review-remediation.md) once public.

## Coordinated disclosure

Please allow time for a fix and for deployments to pick it up before
publishing details. If a report needs a different timeline, say so and it
will be discussed. Credit is given in the remediation log unless you prefer
otherwise.

## In scope

- Plaintext or key material reaching the backing store, logs, operation
  plans, core dumps, swap, or remote endpoints other than the configured
  provider (redirects, error bodies).
- Acknowledged FLUSH/FUA data lost, reordered or served from a different
  unit after a crash or restart; corrupted ciphertext served as data instead
  of EIO.
- The privileged helper acting on a device, volume group, mount or record it
  did not verify; credential material reaching the helper.
- Provider responses accepted without the contract checks; TLS verification
  bypasses.
- Unbounded memory or queue growth reachable by an NBD client or a provider.

## Out of scope

- Rollback to an older, internally valid volume image on the default v2/v3
  formats. This is a documented limitation ([status](docs/status.md#known-limitations));
  the experimental rollback-protected backing is where such reports belong.
- Behaviour on platforms marked unsupported in the
  [support matrix](docs/deployment/support-matrix.md).
- Vulnerabilities in nbdkit, nbd-client, LVM2, XFS or the Linux kernel; report
  those upstream (a Maki-side mitigation may still be worth a report).

## Hardening summary

The daemon runs as an unprivileged user with an empty capability set, no core
dumps and locked secret buffers; the helper has no crypto dependency by
construction; secrets are systemd credentials, never configuration literals;
plaintext transports are refused to non-loopback hosts. Details:
[architecture](docs/architecture.md), [configuration](docs/configuration.md#security-settings),
[transport memory](docs/transport-memory.md).
