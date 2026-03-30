---
id: reorg_safety_and_recovery_hardening
key: ZEI-70
title: Reorg safety and recovery hardening
type: Epic
status: Backlog
priority: High
assignee: null
labels:
  - consensus
  - reorg
  - replay
  - state-root
  - mainnet-blocking
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-30T07:10:22+00:00
updated_at: 2026-03-30T07:10:22+00:00
---

## Summary

Group the remaining reorg, replay, rollback, snapshot, and state-root hardening work under one umbrella so the mainnet-blocking queue is visible in one place and can be worked in a deliberate order.

## Acceptance Criteria

- [ ] Active open reorg/replay/state-root hardening tickets are linked under this epic
- [ ] `.izumi/STATUS.md` references this epic as the umbrella for the reorg queue
- [ ] Completed milestones (`ZEI-61`, `ZEI-62`, `ZEI-63`, `ZEI-67`) are captured in the notes for context
- [ ] `ZEI-18` remains the immediate next implementation task under this epic

## Notes

- Immediate queue:
  - `ZEI-18` — real state snapshots for rollback/recovery
  - `ZEI-68` / `ZEI-69` — validate the competing branch and enforce canonical metadata/continuity
  - `ZEI-21` — restore orphaned transactions to the mempool on reorg
  - `ZEI-52` — deep reorg attack protection
  - `ZEI-64` / `ZEI-65` / `ZEI-66` — follow-on work/cleanup around work comparison, fork-point handling, and restore failure surfacing
- Completed milestones already landed on `libp2p-integration`:
  - `ZEI-61` — batch sync continuity recovery
  - `ZEI-62` — competing-chain reorg convergence in Docker
  - `ZEI-63` — reorg concurrency guard
  - `ZEI-67` — local work verification from fetched headers
- This epic is intentionally broader than a "refactor" umbrella. It covers correctness, safety, recovery, and cleanup across the consensus-critical reorg path.
