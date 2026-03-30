---
id: investigate_rocksdb_account_count_metadata_drift
key: ZEI-71
title: Investigate RocksDB account_count metadata drift
type: Task
status: Backlog
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
rank: null
comments: []
created_at: 2026-03-30T19:25:03+11:00
updated_at: 2026-03-30T19:25:03+11:00
---

## Summary

Investigate whether RocksDB `meta:account_count` can drift from the real persisted account set during normal account updates, replay, rollback, and snapshot restore.

## Acceptance Criteria

- [ ] Reproduce or rule out `account_count` drift with a focused test or manual check
- [ ] Document whether direct `saveAccount()` writes, batched account writes, replay, rollback, and snapshot restore keep `account_count` accurate
- [ ] Identify all current consumers of `account_count` and classify the impact as consensus-critical, recovery-critical, or observability-only
- [ ] If drift is confirmed, capture the likely root cause and open or link the concrete fix ticket

## Notes

- Observation from `ZEI-18` hardening:
  - `src/core/storage/db.zig` direct `Database.saveAccount()` increments `account_count` on every save, even when updating an existing key
  - `WriteBatch.saveAccount()` does not adjust `account_count` in the same way
- This asymmetry suggests the metadata may overcount during normal writes or diverge between direct-write and batched-write paths.
- The issue may be limited to monitoring/status output, but it should be verified because snapshot restore now writes `account_count` explicitly as part of recovery metadata.
