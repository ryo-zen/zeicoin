---
id: tx_rollback_mid_block
key: ZEI-26
title: Implement transaction rollback for failed mid-block transaction application
type: Bug
status: Backlog
priority: High
assignee: null
labels: [consensus, data-integrity]
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-14T00:00:00+00:00
updated_at: 2026-03-14T00:00:00+00:00
---

## Summary

If a transaction fails partway through being applied to a block, the partial state changes are not rolled back. This can leave the UTXO set or account balances in an inconsistent state. Needs to be fixed before MainNet.

## Acceptance Criteria

- [ ] Identify all state mutation points during block application
- [ ] Implement rollback or use a write batch so partial changes are atomic
- [ ] A transaction failure mid-block leaves chain state identical to pre-block state
- [ ] Existing block application tests pass
- [ ] Add test covering a block with a mix of valid and invalid transactions

## Notes

Noted as a known issue in TODO.md. Likely in the block application path in `src/core/chain/` or `src/core/storage/db.zig`. RocksDB write batches are the idiomatic solution — accumulate all writes in a batch and only commit once all transactions validate successfully.
