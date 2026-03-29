---
id: batch_sync_chain_continuity_validation
key: ZEI-61
title: "Batch sync must validate chain continuity before applying blocks"
type: Bug
status: Todo
priority: High
assignee: null
labels: ["consensus", "sync", "docker"]
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-29T21:00:00+00:00
updated_at: 2026-03-29T21:00:00+00:00
---

## Summary

During Docker multi-node testing (ZEI-60), a syncing node gets stuck at height 12 because batch sync assembles blocks from competing miners without validating that consecutive blocks form a continuous chain. Block 13 from miner-A has a `previous_hash` pointing to miner-A's block 12, but the syncing node applied miner-B's block 12. The sync retries the same invalid block forever instead of detecting the fork.

## Reproduction

Run `./docker/scripts/test_libp2p_zen_server.sh` with 2 miners and 1 sync-only node. After ~30s, node-1 stalls:

```
info(sync): ❌ [SYNC VALIDATION] Block 13 previous_hash doesn't match block 12 hash
info(sync): ❌ [BATCH SYNC] Failed to apply block 13: error.InvalidBlock
```

## Root Cause

`processSequentialBlocks()` in `batch_sync.zig` applies blocks one-by-one from the pending queue without checking that `block[n].previous_hash == hash(block[n-1])`. Blocks arrive from different peers via `server_handlers.zig:onBlock()` and get cached per-peer by height. When the sync peer's cache contains blocks from two different chain forks (e.g. block 12 from chain-A, block 13 from chain-B), the batch assembles an invalid sequence.

On failure, `failSync()` is called but the same peer and same cached blocks are retried, causing an infinite stall.

## Acceptance Criteria

- [ ] `processSequentialBlocks()` validates `block.header.previous_hash == previous_block_hash` before calling `applyBlock()`
- [ ] When a chain discontinuity is detected mid-batch, the sync session aborts cleanly and resets (does not retry the same invalid block)
- [ ] After abort, the sync manager can re-initiate sync from the current chain tip with a fresh peer or fresh block requests
- [ ] Docker 3-node test with 2 competing miners: sync node converges to one chain without stalling

## Key Files

- `src/core/sync/protocol/batch_sync.zig` — `processSequentialBlocks()` (line ~858)
- `src/core/server/server_handlers.zig` — `onBlock()` caches blocks per-peer without continuity check
- `src/core/sync/manager.zig` — retry/failover logic after sync failure
