---
id: validate_competing_reorg_branch_before_work_comparison
key: ZEI-68
title: Validate competing reorg branch before counting work or applying it
type: Bug
status: Done
priority: High
assignee: null
labels:
- consensus
- reorg
- security
- mainnet-blocking
sprint: null
story_points: null
due_date: null
parent_id: reorg_safety_and_recovery_hardening
rank: 1774854690051.0
comments: []
created_at: 2026-03-30T06:34:03+00:00
updated_at: 2026-03-31T14:09:37+11:00
---

## Summary

The bulk reorg path fetches competing blocks from a peer, sums their claimed header work, and then applies them without running the reorg validator first. This lets an attacker influence both reorg selection and reorg application with unvalidated blocks. The current path also treats an all-zero `header.state_root` as "skip verification", which makes the ancestor-state check optional instead of consensus-enforced.

## Acceptance Criteria

- [x] Competing blocks are validated locally before their work contributes to `shouldReorganize`
- [x] Reorg application validates each incoming block with the reorg-specific validator (or an equivalent canonical validation path) before mutating canonical state
- [x] Reorg work comparison counts only validated blocks, not raw fetched headers
- [x] An all-zero non-genesis `header.state_root` is rejected during reorg validation instead of bypassing the pre-state check
- [x] A regression test covers a forged competing branch whose claimed work exceeds local work but fails validation
- [x] `zig build test` passes with no regressions

## Notes

- Current trust boundary:
  - `src/core/sync/manager.zig` fetches competing blocks
  - `src/core/sync/fork_detector.zig` sums `block.header.getWork()`
  - `src/core/chain/reorg_executor.zig` applies fetched blocks directly
- The validator already exists at `src/core/chain/validator.zig`; the main issue is that the modern bulk-reorg path does not use it
- Landed in `dec6ca4` on `libp2p-integration`.
- `fetchCompetingChainBlocks()` now validates each fetched batch with `chain_validator.validateReorgBranch()` before those blocks can influence `shouldReorganize()`.
- `ReorgExecutor.executeReorg()` now validates the competing branch before rollback-state mutation.
- `ChainValidator.validateReorgBlock()` rejects all-zero non-genesis `header.state_root` values.
- Regression coverage: `forged higher-work competing branch is rejected before reorg state mutation`.
- Validation: `zig build test` passed on 2026-03-31.
- Related:
  - `ZEI-67` covered moving away from peer self-reported work
  - this ticket covers the remaining gap: locally fetched blocks still must be validated before they can influence consensus
