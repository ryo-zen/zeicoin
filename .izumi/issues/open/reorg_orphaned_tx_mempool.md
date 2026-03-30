---
id: reorg_orphaned_tx_mempool
key: ZEI-21
title: Wire mempool reorg handler so orphaned transactions are restored after chain reorg
type: Bug
status: Backlog
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
rank: null
comments: []
created_at: 2026-03-11T00:00:00+00:00
updated_at: 2026-03-30T07:10:22+00:00
---

## Summary

When a chain reorg occurs, transactions confirmed in the reverted blocks are silently dropped — they are removed from the chain but never returned to the mempool. Users who sent those transactions would need to re-send them manually. The mempool methods to fix this already exist and are documented as the intended behaviour in `reorg_executor.zig`, but the call is missing.

## Acceptance Criteria

- [ ] `mempool.handleReorganization(orphaned_blocks)` called in `reorg_executor.zig` before state rollback begins
- [ ] `mempool.restoreOrphanedTransactions()` called after the new chain is successfully applied
- [ ] Coinbase transactions are filtered out and never restored to the mempool
- [ ] Transactions already present in the new chain are not re-added to the mempool
- [ ] Transactions that are now invalid (e.g. double-spend against new chain state) are silently discarded
- [ ] `zig build test` passes with no regressions
- [ ] Docker reorg test verifies: after a reorg, orphaned transactions reappear in the mempool

## Notes

**Root cause:** `reorg_executor.zig:40-42` has a comment documenting the intended integration but the call was never made:

```
/// NOTE: Orphaned transactions are handled by MempoolManager:
/// - Before calling this, call mempool.handleReorganization(orphaned_blocks)
/// - This backs up transactions from reverted blocks
/// - After reorg succeeds, transactions are restored to mempool
/// - Invalid transactions are automatically discarded
```

**The fix is a wiring change** — the methods are fully implemented:
- `src/core/mempool/manager.zig:272` — `handleReorganization(orphaned_blocks)` collects txs from reverted blocks
- `src/core/mempool/manager.zig:284` — `restoreOrphanedTransactions()` re-validates and re-adds to mempool
- `src/core/mempool/cleaner.zig:187` — `backupOrphanedTransactions()` does the actual backup with coinbase filter

**Current transaction fate during reorg:**
- Reverted block txs: hash stays in DB (double-spend protection), tx NOT returned to mempool
- Mempool txs during reorg: unaffected
- New chain txs: applied normally via `force_processing=true`

**Mainnet risk:** Users lose confirmed transactions silently on any reorg. On a short testnet chain this is low-impact; on mainnet with real value it is a correctness bug.

**Related:** ZEI-18 (`state_snapshot_noop`) — both involve incomplete reorg recovery. ZEI-5 (`docker_multinode_testing`) — the orphan handling scenario should verify this fix.
