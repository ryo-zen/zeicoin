---
id: getblockbyhash_memory_leak
key: ZEI-27
title: Fix memory leak in getBlockByHash missing errdefer on allocation failure
type: Bug
status: Backlog
priority: Medium
assignee: null
labels: [memory, stability]
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

`getBlockByHash` in `src/core/storage/db.zig` is missing an `errdefer` on its allocation path. If an error occurs after allocation, the allocated memory is never freed. In a long-running node this accumulates over time.

## Acceptance Criteria

- [ ] Locate all allocation sites in `getBlockByHash` (and `getBlock` if affected)
- [ ] Add `errdefer allocator.free(...)` immediately after each allocation
- [ ] No memory leaks reported by `std.testing.allocator` in storage tests
- [ ] Existing tests continue to pass

## Notes

Noted as a known issue in TODO.md. Pattern fix: add `errdefer` immediately after allocation, before any operation that could fail. See Memory Leak Prevention section in CLAUDE.md for the canonical pattern.
