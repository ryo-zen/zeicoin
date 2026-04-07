---
id: deep_reorg_attack_protection
key: ZEI-52
title: Implement deep reorg attack protection to defend against 51% hashrate attacks
type: Story
status: Done
priority: High
assignee: null
labels:
- consensus
- security
- reorg
- mainnet-blocking
sprint: null
story_points: null
due_date: null
parent_id: reorg_safety_and_recovery_hardening
rank: 1774927671826.0
comments: []
created_at: 2026-03-21T00:00:00+00:00
updated_at: 2026-04-02T05:06:41.098731481+00:00
closed_at: 2026-04-02T05:06:41.098730195+00:00
---

## Summary

Proof-of-work blockchains without reorg depth limits are vulnerable to 51% hashrate attacks where a malicious actor secretly mines a longer private chain and broadcasts it to orphan the honest chain. In August 2025, Monero suffered repeated 9-block-deep reorgs within 60 minutes from a single mining pool. Bitcoin SV experienced a 100-block reorg in 2021. `ZEI-52` is now complete for the first public-testnet protection slice: the sync path enforces a configurable reorg depth cap before competing-branch fetch/apply, deep reorg candidates emit warning diagnostics, the peer-consensus stub has been replaced with the real `GetBlockHash` query path, consensus defaults are stricter, confirmation guidance is documented, and the Docker harness now proves that an over-depth branch is rejected.

## Acceptance Criteria

- [x] **Reorg depth cap**: Nodes reject any reorganization deeper than a configurable `MAX_REORG_DEPTH` (currently `20` on testnet, `100` on mainnet) on the live sync path before competing-branch fetch/apply
- [x] **Peer consensus stub replaced**: `sync/manager.zig` now uses the real `GetBlockHashMessage` request/response path for peer hash verification; the simulated `agreements += 1` logic is removed
- [x] **Consensus mode default raised**: `types.zig` default changed from `.optional` to `.enforced`; `min_peer_responses` now defaults to `1`
- [x] **Reorg alert logging**: Any reorg deeper than the configured alert threshold (default `3`) emits a `log.warn` with depth, fork height, current tip, new tip, and bounded orphaned-hash diagnostics
- [ ] **Finality checkpoints** (longer term): Moved to follow-up `ZEI-75`
- [x] **Withdrawal confirmation guidance**: Document minimum safe confirmation depths (currently `20` testnet, `100` mainnet for high-consequence actions)
- [x] `zig build test` passes with no regressions
- [x] Docker multi-node test demonstrates a reorg deeper than `MAX_REORG_DEPTH` is rejected by honest nodes

## Notes

**Current state (updated 2026-04-02):**

1. **Depth cap now enforced on the live sync path**
   The reorg admission policy now computes `depth = current_height - fork_point` and rejects branches deeper than `types.REORG.max_depth` before competing-branch fetch or canonical-state mutation. The current defaults are `20` for testnet and `100` for mainnet, configurable via `ZEICOIN_MAX_REORG_DEPTH`.

2. **Consensus verification now uses the real peer hash query path**
   `sync/manager.zig` now reuses the same `GetBlockHash` request/wait helper as `fork_detector`, so peer consensus is based on actual peer-reported block hashes at height `H`, not simulated agreement from peer height alone.

3. **Defaults are now stricter**
   - `mode = .enforced`
   - `min_peer_responses = 1`
   - `check_during_normal_operation = false` remains unchanged for now

4. **Docker rollout proof is now landed**
- `docker/scripts/verify_reorg_depth_rejection.sh` builds the current Docker images, partitions the two-miner topology, freezes both sides into a deterministic passive-vs-passive setup, and proves that the honest miner keeps its original verification-height hash when the attacker branch is deeper than `ZEICOIN_MAX_REORG_DEPTH`
- the script deliberately reuses the stable two-miner flow from `verify_reorg.sh` and `verify_deep_reorg.sh` rather than depending on `node-1` to initiate the critical sync path

5. **Defense-in-depth fix**
- the first live Docker runs exposed a second bulk-reorg entry path that could still reach chain replacement without the earlier alert/rejection logging
- `SyncManager.executeBulkReorg()` now re-applies the same depth-policy alert/reject guard before delegating to `ChainProcessor`, so the cap is enforced even if a later sync flow reaches the bulk-reorg wrapper directly

**Original attack scenario this ticket addressed:**
- Attacker mines privately for N blocks (RandomX light mode is low difficulty)
- Broadcasts the longer chain
- before this work landed, the node accepted with no depth check and no real peer verification
- Transactions in orphaned blocks silently dropped (ZEI-21 unfixed) → double-spend window

**Implementation notes:**
- The ticket note saying "before `findForkPoint`" is stale for the current architecture; true reorg depth is only known after the fork point is discovered.
- The current implementation deliberately enforces depth policy in `SyncManager` as admission policy, not inside `ReorgExecutor`, so execution safety and network-facing attack policy stay separated.
- The pre-`ZEI-52` architecture cleanup also removed duplicate fork-point discovery and unified peer hash verification onto one shared path.
- Finality checkpoints have been split into follow-up `ZEI-75` because they require separate rollout/reset/operator decisions beyond the first public-testnet protection layer.
- Validation for the final slice: `zig build check` and `./docker/scripts/verify_reorg_depth_rejection.sh`.

**Configuration additions needed:**
```
ZEICOIN_MAX_REORG_DEPTH=20        # testnet default
ZEICOIN_REORG_ALERT_DEPTH=3       # warn log threshold
ZEICOIN_CONSENSUS_MODE=enforced   # peer hash quorum (now default)
ZEICOIN_CONSENSUS_THRESHOLD=0.51  # fraction of peers required
ZEICOIN_CONSENSUS_MIN_PEERS=1     # now default
```

**Related issues:**
- ZEI-21 (`reorg_orphaned_tx_mempool`) — unfixed tx drop during reorg compounds double-spend risk
- ZEI-18 (`state_snapshot_noop`) — state rollback correctness required before deep reorg defense is reliable
