# Phase 11 — Database Qualification

Status: **simulation tier complete** (durable transaction loss = 0, silent corruption = 0 across 500 randomized crash runs) · Real-database qualification requires a Linux host with the NBD data path — runbook below.

## Block-level database simulation (`maki-core/tests/phase11_dbsim.rs`)

A miniature WAL database — modeled on SQLite WAL with `synchronous=FULL` — runs on the full engine over `CrashableBacking`:

- **Transaction protocol**: WAL frames (one unit per page image, carrying txn id + epoch) → commit record (frame count + CRC over all frames + epoch) → **FLUSH ⇒ committed** (enters the test's commit ledger) → apply to main pages → FLUSH → WAL slots reused.
- **WAL header with epochs** (SQLite's salt): the header is written and FLUSHed *before any frame of its epoch* — at open, after every recovery, and at every WAL wrap. Recovery replays only header-epoch transactions whose commit record fully validates.
- **Crash injection** at three protocol stages (mid-frame-write, post-commit pre-apply, post-apply), followed by `CrashableBacking::crash` (independent random survival of every unsynced write) and full engine recovery + WAL replay.
- **Oracle**: after every recovery and at final shutdown, every page must equal the image of the last ledger-committed transaction that wrote it.

The simulation caught two real recovery-protocol bugs while being built (kept as regression coverage in the design):
1. **Stale wrap replay** — after a WAL wrap, an older transaction's surviving frames replayed over a newer one (fixed by epochs).
2. **Corrupted-elder fallback** — uncommitted new-epoch frames randomly *kept* by a crash corrupted an old transaction's frames, knocking it out of validation so a still-older transaction replayed over durably-applied newer data (fixed by the flushed WAL header: only header-epoch frames are ever replayable — precisely why SQLite fsyncs the WAL header on reset).

These are database-side bugs, not engine bugs — but they demonstrate the simulation exercises the same protocol surface a real database depends on. Additionally `provider_outage_aborts_transaction_without_corruption` covers SPEC §53 "provider outage": failed writes abort cleanly, committed data intact, engine usable afterwards.

Gates: `phase11_gate_dbsim_smoke` (40 runs, PR suite) · `phase11_gate_dbsim_full` (500 runs × 40 txns, `--ignored`, ~3 s release).

## Real-database qualification runbook (Linux)

Prereqs: Phase 6 Linux checklist done (nbdkit plugin verified), volume attached at `/srv/<v>` via `maki-attach`, mount guard green.

### SQLite
```
sqlite3 /srv/v/test.db 'PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;'
# ledger workload: N writer processes appending to a commit-ledger table,
# kill -9 at random intervals; after each kill:
sqlite3 /srv/v/test.db 'PRAGMA integrity_check;'   # must be "ok"
# every transaction whose COMMIT returned must be present in the table
# repeat with journal_mode=DELETE; repeat with provider outage (stop the
# crypto endpoint mid-workload; stall policy: writes block, then complete)
```

### PostgreSQL
```
initdb on /srv/v; fsync=on, synchronous_commit=on, full_page_writes=on,
data_checksums enabled at initdb
pgbench -i -s 50 && pgbench -c 16 -T 3600   # with random `pg_ctl kill -9`
# after each crash: automatic WAL recovery must succeed, then
pg_amcheck --all; transaction-ledger table cross-check
# plus during-workload: CHECKPOINT, VACUUM FULL, CREATE INDEX CONCURRENTLY
```

### ClickHouse
INSERT + background merges + mutations + partition drops under kill -9 cycles; `CHECK TABLE` after each; hash-oracle table (row-content checksums) verified against an external ledger.

### MinIO
Dedicated volume; multipart uploads (≥5 GiB objects), overwrites, range GETs under restart cycles and provider outages; SHA-256 oracle: every completed PUT's object hash re-verified after each crash.

Phase gate (all engines): DB corruption = 0, durable transaction loss = 0, silent corruption = 0.
