---
id: reorg_orphaned_tx_mempool
key: ZEI-21
title: Wire mempool reorg handler so orphaned transactions are restored after chain reorg
type: Bug
status: Done
priority: High
assignee: null
labels:
- consensus
- reorg
- mempool
- mainnet-blocking
sprint: null
story_points: null
due_date: null
parent_id: reorg_safety_and_recovery_hardening
rank: 1774927662826.0
comments: []
created_at: 2026-03-11T00:00:00+00:00
updated_at: 2026-04-01T09:38:09.825103752+00:00
closed_at: 2026-04-01T09:38:09.825101037+00:00
---

## Summary

When a chain reorg occurs, transactions confirmed in the reverted blocks are silently dropped — they are removed from the chain but never returned to the mempool. Users who sent those transactions would need to re-send them manually. The mempool methods to fix this already exist and are documented as the intended behaviour in `reorg_executor.zig`, but the call is missing.

## Acceptance Criteria

- [x] Reverted non-coinbase transactions are staged in the reorg executor path before state rollback begins
- [x] Staged orphaned transactions are restored only after the new chain is successfully applied
- [x] Coinbase transactions are filtered out and never restored to the mempool
- [x] Transactions already present in the new chain are not re-added to the mempool
- [x] Transactions that are now invalid (e.g. double-spend against new chain state) are silently discarded
- [x] `zig build test` exits successfully with no regressions
- [x] Docker deep reorg verification passed on April 1, 2026 with the post-fix branch still converging correctly

## Notes

**Root cause:** `reorg_executor.zig:40-42` has a comment documenting the intended integration but the call was never made:

```
/// NOTE: Orphaned transactions are handled by MempoolManager:
/// - Before calling this, call mempool.handleReorganization(orphaned_blocks)
/// - This backs up transactions from reverted blocks
/// - After reorg succeeds, transactions are restored to mempool
/// - Invalid transactions are automatically discarded
```

**Implemented fix:** the reorg path now stages reverted non-coinbase transactions before rollback, restores them only after the winning branch is fully applied, and clears the staged set on failure. The mempool layer also skips restoration when a tx is already confirmed on the winning branch, already present in the mempool, or no longer valid under the new chain state.

**Current transaction fate during reorg:**
- Reverted block txs: hash stays in DB (double-spend protection), tx NOT returned to mempool
- Mempool txs during reorg: unaffected
- New chain txs: applied normally via `force_processing=true`

**Mainnet risk:** Users lose confirmed transactions silently on any reorg. On a short testnet chain this is low-impact; on mainnet with real value it is a correctness bug.

**Validation:** On April 1, 2026, `zig build check`, `zig build test`, and `./docker/scripts/verify_deep_reorg.sh` all completed successfully on the implementation branch. The Docker run verified divergence at height 50 followed by successful deep-reorg convergence back onto the winning chain.

**Related:** ZEI-18 (`state_snapshot_noop`) — both involve incomplete reorg recovery. ZEI-5 (`docker_multinode_testing`) — the orphan handling scenario should verify this fix.
