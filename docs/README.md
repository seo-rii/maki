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
| Reviewing test evidence or release readiness | [Testing and qualification](testing.md) |
| Checking review findings and their fixes | [Review remediation log](review-remediation.md) |
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
