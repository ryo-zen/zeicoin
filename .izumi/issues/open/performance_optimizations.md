---
id: performance_optimizations
key: ZEI-13
title: Implement remaining mining performance optimizations (header serialization, merkle, caching)
type: Task
status: Backlog
priority: Low
assignee: null
labels:
- performance
- mining
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-07T00:00:00+00:00
updated_at: 2026-03-10T00:00:00+00:00
---

## Summary

State root caching and RandomX keep-alive subprocess are already complete. The remaining mining performance backlog items are lower priority but would further improve block throughput.

## Acceptance Criteria

- [ ] **P1**: Block header serialization pre-computed once per block candidate; only nonce bytes updated on each attempt (eliminates 500+ redundant serializations per block)
- [ ] **P1**: Merkle root hashing switched from double SHA256 to single BLAKE3 (10-15x speedup)
- [ ] **P2**: Previous block hash cached in memory to eliminate disk I/O on every mining attempt
- [ ] **P2**: Mempool batching timeout made dynamic based on mempool size (reduce idle wait from fixed 2s)
- [ ] **P2**: Difficulty change notification added to mining thread to prevent stale mining on adjustment
- [ ] **P3**: Transaction copying reduced during block assembly (use pointers/references where possible)
- [ ] **P3**: Validation results cached to avoid redundant reprocessing during mining

## Notes

**Already completed:**
- State root lazy cache with dirty flag (`src/core/chain/state.zig`) — 100-1000x speedup
- RandomX keep-alive subprocess — 6-383x speedup (TestNet: 0.1 → 13 H/s, MainNet: 0.04 → 13.7 H/s)

Re-evaluate P2/P3 items against current mining performance before implementing.
