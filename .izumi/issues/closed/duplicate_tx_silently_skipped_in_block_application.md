---
id: duplicate_tx_silently_skipped_in_block_application
key: ZEI-101
title: Reject blocks containing duplicate transactions instead of silently skipping them
type: Bug
status: Done
priority: High
assignee: null
labels:
- consensus
- validation
- state
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1775735616883.0
comments: []
created_at: 2026-04-09T11:50:00+00:00
updated_at: 2026-04-09T11:57:00.397103672+00:00
closed_at: null
---

## Summary

When `processBlockTransactions` encounters a transaction whose hash already exists in the chain, it silently skips the tx and continues applying the rest of the block. This means the block is saved to the database with its tx list intact, but the account state does not reflect that transaction. The block content and the state it produced are inconsistent: any peer replaying from genesis will produce different state than 209's current state for that block height.

A block that contains a duplicate transaction is invalid and should be rejected outright, not partially applied.

## Acceptance Criteria

- [x] `processBlockTransactions` returns an error (e.g. `error.DuplicateTransaction`) when any non-coinbase transaction already exists in the chain
- [x] The block is never saved when a duplicate tx is detected
- [x] `force_processing = true` (used during reorg replay) is explicitly excluded from this check with a comment explaining why
- [x] A test covers the case: apply block A with tx T, then attempt to apply block B also containing tx T — block B must be rejected
- [x] `zig build test` passes

## Notes

- Relevant code: `src/core/chain/state.zig:720`
- Current behaviour:
  ```zig
  if (!force_processing and self.database.hasTransaction(io, tx.hash())) {
      log.info("🚫 [DUPLICATE TX] ... SKIPPING");
      continue;  // block is still saved without this tx's state changes
  }
  ```
- Correct behaviour: `return error.DuplicateTransaction` so the caller (commitBlock → addBlockToChain) propagates the failure and the block is not persisted
- `force_processing = true` is set during reorg replay (`reorg_executor.zig`) where re-applying known-good transactions is intentional and expected — that path should remain unaffected
