# Phase 12 — Power-Loss Qualification

Status: **simulation tier complete** (SPEC §54 scenarios ×500 each, 0 violations) · QEMU and bare-metal tiers require dedicated hardware — runbook below.

## Test hierarchy (SPEC §54)

| Tier | Purpose | Status |
|---|---|---|
| Simulation (`CrashableBacking`) | development & CI: every commit | ✅ this repo |
| WSL | development integration | runbook |
| QEMU/KVM hard power cut | pre-release, 300+ cycles (SPEC §56) | runbook |
| Bare metal | final durability qualification | runbook |

## Simulation tier (`maki-core/tests/phase12_powerloss.rs`)

The exact SPEC §54 scenarios against the full engine:

- **Critical test**: `WRITE A · WRITE B · FLUSH success · WRITE C · power cut` ⇒ after recovery **A = new, B = new, C = old or new** — 100 seeds in the PR suite, 500 in the gate.
- **FUA test**: `WRITE A + FUA success · power cut` ⇒ **A = new**.
- **Nondeterminism check**: across seeds, C actually exhibits *both* old and new outcomes — proving the crash model isn't accidentally always-durable (a vacuous pass).

`CrashableBacking`'s crash model — independent survival of every unsynced write, torn tail writes, vanished dirents, resurrected deletions — is a superset of single-power-cut behavior on a POSIX filesystem, so simulation passes are strictly conservative.

## QEMU/KVM runbook (hard VM power cut)

1. Guest: Linux VM with the maki daemon + attached volume on a virtio disk with `cache=none` (or `cache=directsync`) so guest fdatasync reaches the host.
2. Workload in guest: the phase-11 ledger workload (SQLite or the dbsim binary pattern) + `fio --fsync=32` mixed I/O.
3. Power cut: `virsh destroy <vm>` (equivalent to pulling power) at randomized intervals — never `shutdown`.
4. On reboot: `maki-check` on the backing, attach, mount guard, ledger verification (`A=new, B=new, C∈{old,new}` oracle driven by a guest agent that logs acknowledged operations to a *separate host-side* channel — e.g. virtio-serial — so the ledger itself survives independently).
5. Gate: **300+ cycles** (SPEC §56), 0 FLUSH violations, 0 FUA violations, 0 silent corruption, 0 failed recoveries.

## Bare-metal runbook

Same workload + ledger-over-network (log acknowledged ops to a second machine before acking). Power cut via smart PDU (mains cut, not ACPI). Storage stack must be qualified first: disk write-cache configuration verified (`hdparm -W`), XFS on LVM as in production. Gate: release-level counts (SPEC §56), 72-hour mixed workload interleaved with cuts.

## WSL note

WSL2 provides the Linux syscall surface for integration (nbdkit + NBD + XFS in a WSL kernel with `CONFIG_BLK_DEV_NBD`), but its 9p/virtio storage does not deliver honest power-cut semantics — use it for the Phase 6/7 checklists only, never for durability claims.
