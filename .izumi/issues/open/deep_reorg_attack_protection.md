---
id: deep_reorg_attack_protection
key: ZEI-52
title: Implement deep reorg attack protection to defend against 51% hashrate attacks
type: Story
status: Todo
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
updated_at: 2026-03-31T09:19:13.504100994+00:00
closed_at: null
---

## Summary

Proof-of-work blockchains without reorg depth limits are vulnerable to 51% hashrate attacks where a malicious actor secretly mines a longer private chain and broadcasts it to orphan the honest chain. In August 2025, Monero suffered repeated 9-block-deep reorgs within 60 minutes from a single mining pool. Bitcoin SV experienced a 100-block reorg in 2021. **Code review confirms ZeiCoin is currently fully vulnerable**: reorg depth is unbounded and the peer consensus check is an unimplemented stub that always returns `true`.

## Acceptance Criteria

- [ ] **Reorg depth cap**: Nodes reject any reorganization deeper than a configurable `MAX_REORG_DEPTH` (e.g. 20 blocks for testnet, 100 for mainnet); the cap is enforced in `reorg_executor.zig:executeReorg()` before `findForkPoint` is called
- [ ] **Peer consensus stub replaced**: `sync/manager.zig:1376` TODO replaced with a real `GetBlockHashMessage` send + response wait; the simulated `agreements += 1` removed
- [ ] **Consensus mode default raised**: `types.zig:61` default changed from `.optional` to `.enforced`; `min_peer_responses` set to a non-zero value (e.g. 1)
- [ ] **Reorg alert logging**: Any reorg deeper than 3 blocks emits a `log.warn` with depth, fork height, orphaned hashes, and new tip
- [ ] **Finality checkpoints** (longer term): Periodic known-good block hashes hardcoded in the binary; blocks behind a checkpoint cannot be reorged
- [ ] **Withdrawal confirmation guidance**: Document minimum safe confirmation depths (e.g. 20 testnet, 100 mainnet)
- [ ] `zig build test` passes with no regressions
- [ ] Docker multi-node test demonstrates a reorg deeper than `MAX_REORG_DEPTH` is rejected by honest nodes

## Notes

**Confirmed vulnerabilities (code review 2026-03-21):**

1. **Unbounded reorg — `reorg_executor.zig:54`**
   The only guard is `new_tip_height >= old_tip_height`. No depth limit exists. Any longer chain of any depth is accepted unconditionally.

2. **Consensus check is a non-functional stub — `sync/manager.zig:1376-1386`**
   ```zig
   // TODO: Send GetBlockHashMessage to peer and wait for response
   // Temporary: assume peer agrees if it has sufficient height
   agreements += 1;  // ← always agrees, never actually queries peers
   ```
   `ZEICOIN_CONSENSUS_MODE=enforced` provides zero protection today.

3. **Permissive defaults — `types.zig:61,70`**
   - `mode = .optional` — failures are warnings only, block always accepted
   - `min_peer_responses = 0` — no peer count required
   - `check_during_normal_operation = false` — consensus not checked during live block processing

**Attack scenario on current testnet:**
- Attacker mines privately for N blocks (RandomX light mode is low difficulty)
- Broadcasts the longer chain
- `executeReorg()` accepts with no depth check, no peer verification
- Transactions in orphaned blocks silently dropped (ZEI-21 unfixed) → double-spend window

**Fix priority order:**
1. Reorg depth cap in `reorg_executor.zig` — a few lines, highest immediate impact
2. Wire real peer hash query in `sync/manager.zig` to replace the stub
3. Raise default consensus mode to `enforced` in `types.zig`

**Configuration additions needed:**
```
ZEICOIN_MAX_REORG_DEPTH=20        # testnet default
ZEICOIN_REORG_ALERT_DEPTH=3       # warn log threshold
ZEICOIN_CONSENSUS_MODE=enforced   # peer hash quorum
ZEICOIN_CONSENSUS_THRESHOLD=0.51  # fraction of peers required
```

**Related issues:**
- ZEI-21 (`reorg_orphaned_tx_mempool`) — unfixed tx drop during reorg compounds double-spend risk
- ZEI-18 (`state_snapshot_noop`) — state rollback correctness required before deep reorg defense is reliable
