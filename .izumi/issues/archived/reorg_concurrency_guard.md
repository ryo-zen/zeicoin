---
id: reorg_concurrency_guard
key: ZEI-63
title: Add concurrency guard to prevent block processing during reorg
type: Bug
status: Done
priority: High
assignee: null
labels:
  - consensus
  - reorg
  - concurrency
  - mainnet-blocking
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-30T00:00:00+00:00
updated_at: 2026-03-30T06:48:09+00:00
---

## Summary

`ReorgExecutor.executeReorg()` does not hold `chain_state.mutex` or any other lock during the multi-phase reorg (revert state, apply new blocks, update DB height). If a new block arrives via P2P while a reorg is in progress, normal `processBlockTransactions` / `indexBlock` calls can interleave and corrupt account state or the block index.

## Acceptance Criteria

- [x] A reorg-in-progress guard prevents normal block acceptance from modifying chain state during an active reorg
- [x] The guard is released on all exit paths (success, failure, restore)
- [x] Blocks arriving during reorg are either queued or rejected with a retriable error, not silently dropped
- [x] `zig build test` passes with no regressions
- [x] Docker multi-node test with concurrent block arrival during reorg does not corrupt state

## Notes

- Implemented in `1e5ae08`.
- `ChainProcessor` now exposes a `reorg_in_progress` guard, normal block application paths reject with `error.ReorgInProgress`, and the flag is released in the bulk-reorg defer path.
- `server_handlers.onBlock()` and orphan follow-up paths defer network-received blocks while the guard is active so the data remains cached for retry instead of being dropped.
- Key files: `src/core/chain/processor.zig`, `src/core/server/server_handlers.zig`, `src/core/sync/manager.zig`
