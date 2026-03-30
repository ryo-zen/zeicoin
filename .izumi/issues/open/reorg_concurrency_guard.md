---
id: reorg_concurrency_guard
key: ZEI-63
title: Add concurrency guard to prevent block processing during reorg
type: Bug
status: Backlog
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
updated_at: 2026-03-30T00:00:00+00:00
---

## Summary

`ReorgExecutor.executeReorg()` does not hold `chain_state.mutex` or any other lock during the multi-phase reorg (revert state, apply new blocks, update DB height). If a new block arrives via P2P while a reorg is in progress, normal `processBlockTransactions` / `indexBlock` calls can interleave and corrupt account state or the block index.

## Acceptance Criteria

- [ ] A reorg-in-progress guard prevents normal block acceptance from modifying chain state during an active reorg
- [ ] The guard is released on all exit paths (success, failure, restore)
- [ ] Blocks arriving during reorg are either queued or rejected with a retriable error, not silently dropped
- [ ] `zig build test` passes with no regressions
- [ ] Docker multi-node test with concurrent block arrival during reorg does not corrupt state

## Notes

- Options: (a) hold `chain_state.mutex` for the entire reorg, (b) add an `AtomicBool` reorg flag that `acceptBlock` checks, (c) use a `RwLock` where reorg takes write and normal processing takes read
- Option (b) is simplest and avoids holding a mutex across I/O
- Key files: `src/core/chain/reorg_executor.zig`, `src/core/chain/processor.zig`, `src/core/chain/state.zig`
