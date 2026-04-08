---
id: reorg_deduplicate_fork_point_search
key: ZEI-65
title: Remove duplicate O(n) fork point search from ReorgExecutor
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
  - reorg
  - performance
  - cleanup
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

Two separate `findForkPoint` implementations exist: `fork_detector.zig:14` uses O(log n) binary search, while `reorg_executor.zig:170` uses O(n) linear scan from height 0. The sync manager already calls the binary search version and knows the fork point before calling `executeReorg`. The linear scan is redundant and slower.

## Acceptance Criteria

- [ ] `ReorgExecutor.executeReorg` accepts `fork_height` as a parameter instead of computing it internally
- [ ] `ReorgExecutor.findForkPoint` is removed
- [ ] All callers (`ChainProcessor.executeBulkReorg`, sync manager) pass the already-known fork point
- [ ] `zig build test` passes with no regressions

## Notes

- If a caller doesn't have the fork point, they should use `fork_detector.findForkPoint` (binary search) rather than the executor recomputing it linearly
- Key files: `src/core/chain/reorg_executor.zig:170`, `src/core/sync/fork_detector.zig:14`, `src/core/chain/processor.zig:448`
