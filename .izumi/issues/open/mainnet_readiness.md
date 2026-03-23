---
id: mainnet_readiness
key: ZEI-28
title: MainNet readiness — all consensus and infrastructure prerequisites
type: Epic
status: Backlog
priority: High
assignee: null
labels: [mainnet, consensus, infrastructure]
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-14T00:00:00+00:00
updated_at: 2026-03-14T00:00:00+00:00
---

## Summary

Tracks all work that must be completed before MainNet can launch. Covers consensus-critical changes (emission schedule, replay protection, genesis block) and infrastructure prerequisites (bootstrap nodes). None of these can be deferred post-launch as they require a hard fork or infrastructure commitment.

## Acceptance Criteria

- [ ] Block reward halving schedule implemented and tested (ZEI-22)
- [ ] Chain ID replay protection in place on TestNet (ZEI-23)
- [ ] MainNet genesis block parameters decided and hardcoded (ZEI-24)
- [ ] Redundant bootstrap node infrastructure operational (ZEI-25)

## Notes

Child tickets: ZEI-22, ZEI-23, ZEI-24, ZEI-25.
