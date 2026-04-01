---
id: investigate_rocksdb_account_count_metadata_drift
key: ZEI-71
title: Investigate RocksDB account_count metadata drift
type: Task
status: Done
priority: Medium
assignee: null
labels:
- storage
- metadata
- investigation
- reliability
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1774927661826.0
comments: []
created_at: 2026-03-30T19:25:03+11:00
updated_at: 2026-04-01T06:13:55.318793794+00:00
closed_at: 2026-04-01T06:13:55.318793323+00:00
---

## Summary

Investigate whether RocksDB `meta:account_count` can drift from the real persisted account set during normal account updates, replay, rollback, and snapshot restore.

## Acceptance Criteria

- [x] Reproduce or rule out `account_count` drift with a focused test or manual check
- [x] Document whether direct `saveAccount()` writes, batched account writes, replay, rollback, and snapshot restore keep `account_count` accurate
- [x] Identify all current consumers of `account_count` and classify the impact as consensus-critical, recovery-critical, or observability-only
- [x] If drift is confirmed, capture the likely root cause and open or link the concrete fix ticket

## Notes

- Observation from `ZEI-18` hardening:
  - `src/core/storage/db.zig` direct `Database.saveAccount()` increments `account_count` on every save, even when updating an existing key
  - `WriteBatch.saveAccount()` does not adjust `account_count` in the same way
- This asymmetry suggests the metadata may overcount during normal writes or diverge between direct-write and batched-write paths.
- The issue may be limited to monitoring/status output, but it should be verified because snapshot restore now writes `account_count` explicitly as part of recovery metadata.
- Result:
  - Drift was confirmed.
  - Root cause was split metadata ownership: direct writes always incremented `account_count`, while batched writes never incremented it.
  - The fix landed directly in `src/core/storage/db.zig` instead of opening a follow-up ticket.
- Current behavior after the fix:
  - Direct `Database.saveAccount()` increments `account_count` only when the account key does not already exist.
  - `WriteBatch.saveAccount()` tracks newly introduced addresses once per batch and updates `account_count` on commit unless the batch explicitly overrides the metadata.
  - Rollback/reset remains correct because `deleteAllAccounts()` explicitly writes `account_count = 0`.
  - Snapshot restore remains correct because restore batches already call `saveAccountCount(snapshot.accounts.len)` explicitly.
  - Replay and normal block application remain correct because they persist account changes through `WriteBatch.saveAccount()`.
- Current consumers:
  - `src/core/monitoring/status.zig` uses `getAccountCount()` for status/metrics output.
  - No consensus, validation, or recovery decisions currently depend on `account_count`.
- Classification:
  - Impact is observability-only with the current codebase, not consensus-critical and not recovery-critical.
- Regression coverage:
  - Added a focused integration test in `src/tests.zig` covering direct updates, batched updates, duplicate in-batch saves, reset via `deleteAllAccounts()`, and explicit restore metadata writes.
