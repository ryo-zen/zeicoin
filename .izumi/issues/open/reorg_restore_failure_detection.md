---
id: reorg_restore_failure_detection
key: ZEI-66
title: Surface chain corruption when reorg restore fails
type: Bug
status: Backlog
priority: Medium
assignee: null
labels:
  - consensus
  - reorg
  - observability
sprint: null
story_points: null
due_date: null
parent_id: reorg_safety_and_recovery_hardening
rank: null
comments: []
created_at: 2026-03-30T00:00:00+00:00
updated_at: 2026-03-30T07:10:22+00:00
---

## Summary

In `reorg_executor.zig:87-89`, if `restoreOriginalChain` fails after a failed revert, the error is logged but the function returns `ReorgResult{success: false}` with no indication that the chain is now in an inconsistent state. The caller has no way to distinguish "reorg failed cleanly" from "reorg failed and restore also failed — state is corrupted."

## Acceptance Criteria

- [ ] `ReorgResult` includes a `chain_corrupted: bool` field (or equivalent) that is set when restore fails
- [ ] The caller (`ChainProcessor.executeBulkReorg`) checks for corruption and triggers a full resync from peers when detected
- [ ] A `log.err` with "CRITICAL" severity is emitted so operators can detect it in monitoring
- [ ] `zig build test` passes with no regressions

## Notes

- Current behavior: the node continues operating with broken state, which will cause cascading failures later
- Ideal recovery: set a `needs_resync` flag and restart sync from genesis or last known good checkpoint
- Key file: `src/core/chain/reorg_executor.zig:87-89`, `src/core/chain/processor.zig:466-472`
