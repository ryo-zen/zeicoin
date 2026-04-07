---
id: enforce_reorg_branch_continuity_and_canonical_metadata
key: ZEI-69
title: Enforce reorg branch continuity and recompute canonical block metadata
type: Bug
status: Done
priority: High
assignee: null
labels:
  - consensus
  - reorg
  - correctness
  - mainnet-blocking
sprint: null
story_points: null
due_date: null
parent_id: reorg_safety_and_recovery_hardening
rank: null
comments: []
created_at: 2026-03-30T06:34:03+00:00
updated_at: 2026-03-31T14:17:50+11:00
---

## Summary

`ReorgExecutor` currently assigns replacement-block heights from slice position and saves incoming blocks verbatim. It does not prove that the fetched slice is contiguous with the known fork point, that each block's own `height` matches the expected target height, or that each block's `previous_hash` links to the prior replacement block. It also skips local recomputation of per-block metadata such as cumulative `chain_work`, unlike the normal canonical block-acceptance path.

## Acceptance Criteria

- [x] The sync manager passes the known `fork_height` into the reorg executor instead of requiring the executor to rediscover it
- [x] Reorg application rejects any block whose `block.height` does not equal the expected target height
- [x] Reorg application rejects any replacement slice whose first block does not connect to the known fork point
- [x] Reorg application rejects any replacement slice where `block[n].header.previous_hash != hash(block[n-1])`
- [x] Reorg-applied blocks recompute local cumulative `chain_work` before being saved, matching the normal block-acceptance path
- [x] A regression test covers a misordered or mixed-fork replacement slice and proves it is rejected before canonical state is mutated
- [x] `zig build test` passes with no regressions

## Notes

- Current path differences:
  - `src/core/sync/manager.zig` already knows the fork point
  - `src/core/chain/reorg_executor.zig` still recomputes it from the first block's `previous_hash`
  - `src/core/chain/processor.zig` recomputes `chain_work` on normal acceptance, but `reorg_executor.zig` currently saves the incoming `Block` struct as-is
- Completed in the current `libp2p-integration` worktree on 2026-03-31.
- `SyncManager.executeBulkReorg()` now passes the known `fork_point` into `ChainProcessor.executeBulkReorg()`, which passes it through to `ReorgExecutor.executeReorg()`.
- `ReorgExecutor` no longer rediscovers the fork point from the first competing block; it validates continuity against the supplied canonical fork height.
- `ReorgExecutor.applyBlock()` now recomputes canonical block metadata before persistence, including cumulative `chain_work`.
- Regression coverage now includes:
  - `reorg rejects malformed competing branch before state mutation`
  - `successful reorg recomputes canonical chain_work for replacement blocks`
- Validation passed with `zig build check`, `zig build test`, `./docker/scripts/test_libp2p_zen_server.sh`, and `./docker/scripts/verify_deep_reorg.sh`.
- Related:
  - `ZEI-65` tracks removing the duplicate fork-point search
  - this ticket covers the stronger correctness contract around branch continuity and metadata parity once the known fork point is passed through
