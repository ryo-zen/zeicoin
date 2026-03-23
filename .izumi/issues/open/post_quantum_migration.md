---
id: post_quantum_migration
key: ZEI-29
title: Post-quantum cryptography migration to ML-DSA
type: Epic
status: Backlog
priority: Low
assignee: null
labels: [security, cryptography, post-quantum]
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

Tracks the full migration from Ed25519 to ML-DSA-44 (CRYSTALS-Dilithium) for transaction signing. Work proceeds in three sequential phases: generic signature interface, research and strategy, then implementation with backward-compatible rollout.

## Acceptance Criteria

- [ ] Generic signature interface designed to support multiple schemes (ZEI-2)
- [ ] Research complete with migration strategy documented (ZEI-14)
- [ ] ML-DSA-44 implemented with staged rollout (ZEI-15)
- [ ] TestNet soak with both Ed25519 and ML-DSA transactions coexisting

## Notes

Child tickets: ZEI-2, ZEI-14, ZEI-15. Sequencing: ZEI-2 unblocks ZEI-14 which unblocks ZEI-15. Planned for Phase 02 of the roadmap after base network stability is achieved.
