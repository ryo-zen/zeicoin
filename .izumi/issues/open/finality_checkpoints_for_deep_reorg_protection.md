---
id: finality_checkpoints_for_deep_reorg_protection
key: ZEI-75
title: Add finality checkpoints for deep reorg protection
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
- consensus
- reorg
- finality
- checkpoints
sprint: null
story_points: null
due_date: null
parent_id: reorg_safety_and_recovery_hardening
rank: 1774927674826.0
comments: []
created_at: 2026-04-02T03:25:13Z
updated_at: 2026-04-02T03:25:13Z
closed_at: null
---

## Summary

Add an explicit finality-checkpoint mechanism so very old canonical history can be pinned by known-good block hashes and rejected from reorg consideration. This is follow-up work to `ZEI-52`: the bounded reorg-depth policy and confirmation guidance are in place, but hardcoded checkpoints remain deferred because they require additional rollout, reset, and operator-policy decisions.

## Acceptance Criteria

- [ ] Define the checkpoint model for ZeiCoin (hardcoded binary list, config-driven list, or hybrid) and document the operational tradeoffs
- [ ] Implement checkpoint validation so competing branches behind the latest active checkpoint are rejected before reorg execution
- [ ] Define the operator/update workflow for testnet resets, checkpoint refreshes, and override/recovery procedures
- [ ] Add focused tests proving checkpoint-protected history cannot be reorganized
- [ ] Update the relevant docs in `/docs` with checkpoint behavior and operational guidance

## Notes

- `ZEI-52` now covers:
  - bounded reorg depth
  - deep-reorg alert logging
  - real peer hash verification
  - stricter consensus defaults
- This ticket is intentionally split out because checkpoints are a larger product/operations decision than the first public-testnet protection layer.
- Key design questions to answer before implementation:
  - Is checkpointing node policy or mandatory network behavior for a given release?
  - How are checkpoints refreshed on a resettable testnet?
  - What is the manual recovery path if a node falls behind or a checkpoint is wrong?
