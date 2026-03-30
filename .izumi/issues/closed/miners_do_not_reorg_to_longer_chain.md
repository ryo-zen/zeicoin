---
id: miners_do_not_reorg_to_longer_chain
key: ZEI-62
title: "Miners do not reorg to longer chain from competing peer"
type: Bug
status: Done
priority: High
assignee: null
labels: ["consensus", "chain", "reorg"]
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-29T21:00:00+00:00
updated_at: 2026-03-30T06:48:09+00:00
---

## Summary

When two miners produce competing chains in Docker, neither miner reorgs to the other's longer chain. Each miner mines independently on its own fork forever. They diverge at height 13 and never converge — miner-1 reaches height 158 on chain-A while miner-2 reaches height 147 on chain-B, with completely different block hashes.

## Reproduction

```bash
docker compose -f docker/docker-compose.yml up -d
sleep 60
# Compare block hashes at same height:
docker exec zeicoin-miner-1 env ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin block 100
docker exec zeicoin-miner-2 env ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin block 100
# Different hashes — chains diverged and never reconverged
```

## Root Cause

When a block arrives from a peer that doesn't extend the current tip, `processor.zig:acceptBlock()` stores it in the orphan pool — but there is no follow-up check asking: "Does this orphan (plus its descendants) form a chain longer than ours? If so, reorg."

The orphan pool stores the block but nobody triggers a reorg evaluation. The block is effectively ignored.

### Expected behavior (longest-chain rule)

1. Miner-1 at height 50 (chain-A) receives block 51 from miner-2 (chain-B)
2. Block 51's `previous_hash` doesn't match miner-1's block 50 → stored as orphan
3. System should detect: "Peer claims height 51 on a different chain. Is their chain longer/heavier?"
4. If yes → fetch missing blocks from peer, validate, reorg to chain-B
5. If no → keep current chain

Step 3-5 is not implemented.

## Acceptance Criteria

- [x] When a block arrives that doesn't extend the current tip but comes from a peer with a longer chain, a reorg evaluation is triggered
- [x] The reorg evaluation fetches the competing chain from the peer (back to the fork point) and validates it
- [x] If the competing chain is longer, the node reorgs: rolls back blocks to fork point, applies competing chain
- [x] Docker 2-miner test: both miners converge to the same chain within a few blocks of divergence
- [x] Reorg does not trigger on shorter/equal-length competing chains (no flip-flopping)

## Key Files

- `src/core/chain/processor.zig` — `acceptBlock()`, orphan handling
- `src/core/chain/reorg.zig` (if exists) or needs to be created
- `src/core/sync/fork_detector.zig` — `findForkPoint()` exists but isn't called from block reception path
- `src/core/server/server_handlers.zig` — `onBlock()` handler

## Notes

- Core convergence is now fixed on `libp2p-integration`: incoming orphaned competing blocks trigger `triggerPeerSync()`, the decision routes through `SyncManager.startSync()`, and the reorg path uses fetched competing blocks plus local work verification before switching chains.
- Both `./docker/scripts/test_libp2p_zen_server.sh` and `./docker/scripts/verify_deep_reorg.sh` now pass on the current branch.
- Remaining hardening work was split into follow-on tickets: `ZEI-18`, `ZEI-64`, `ZEI-65`, `ZEI-66`, and `ZEI-52`.
