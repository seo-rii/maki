# Maki documentation

This directory contains maintained documentation for using, operating, and
contributing to Maki. The technical specification remains the normative source
for storage, durability, provider, and security requirements.

## Start here

| Audience | Document |
|---|---|
| Evaluating Maki | [Project README](../README.md) |
| Understanding the design | [Architecture](architecture.md) |
| Creating a volume configuration | [Configuration](configuration.md) |
| Running or recovering a volume | [Operations](operations.md) |
| Cleaning up a disconnected attachment | [Storage recovery and its limits](storage-recovery.md) |
| Checking storage before starting a workload | [Repeatable attachment verification](storage-recovery.md#checking-storage-before-each-workload-start) |
| Understanding required durable evidence and legacy migration | [Durable recovery](durable-recovery.md) |
| Assessing remote plaintext buffer protection | [Transport memory](transport-memory.md) |
| Interpreting status during a storage stall | [Observation freshness](observability.md) |
| Replacing credentials or changing an encryption key | [Credential rotation and key migration](key-rotation.md) |
| Reviewing test evidence or release readiness | [Testing and qualification](testing.md) |
| Checking review findings and their fixes | [Review remediation log](review-remediation.md) |
| Following the R3 fixes and remaining operating limits | [R3 readiness review](production-readiness-review-2026-09-08.md) |
| Reading the 2026-09-05 project assessment | [Project review](project-review-2026-09-05.md) |
| Implementing protocol or format changes | [Technical specification](../SPEC.md) |

## Validation evidence

The [rootless Linux validation report](native-linux-validation-2026-09-02.md)
and [privileged Linux validation report](privileged-linux-validation.md) record
reproducible Debian 12/KVM runs. Reports are historical evidence, not rolling
statements about the current branch. Current qualification status is maintained
in [Testing and qualification](testing.md).

## Documentation policy

Documentation is organized by reader task rather than implementation history.
Tests retain their existing `phase*` filenames and gate names for compatibility,
but those names do not define the public documentation structure.
