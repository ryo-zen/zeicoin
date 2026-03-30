---
id: reorg_allow_shorter_chain_more_work
key: ZEI-64
title: Allow reorg to shorter chain with more cumulative work
type: Bug
status: Backlog
priority: Medium
assignee: null
labels:
  - consensus
  - reorg
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-30T00:00:00+00:00
updated_at: 2026-03-30T00:00:00+00:00
---

## Summary

`ReorgExecutor.executeReorg()` at line 54 rejects any chain where `new_tip_height < old_tip_height`. This prevents reorging to a shorter chain that has more cumulative proof-of-work — a valid scenario in Bitcoin-style consensus where a shorter chain with higher difficulty blocks can have more total work.

## Acceptance Criteria

- [ ] `executeReorg` no longer rejects chains solely based on height comparison
- [ ] Reorg decision is based on cumulative work (already computed by `fork_detector.shouldReorganize`)
- [ ] `zig build test` passes with no regressions

## Notes

- `fork_detector.shouldReorganize` already compares cumulative work correctly — the height guard in `executeReorg` is a second, contradictory check
- The height check was likely a safety guard during early development; now that work comparison exists, it's redundant and incorrect
- Key file: `src/core/chain/reorg_executor.zig:54`
