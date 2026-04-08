---
id: mem_zeros_usage
key: ZEI-12
title: Replace excessive std.mem.zeroes() usage with named constants and explicit initialization
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
- code-quality
- refactoring
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1773129741517.0
comments: []
created_at: 2026-01-26T00:00:00+00:00
updated_at: 2026-04-01T05:27:01.560140108+00:00
closed_at: null
---

## Summary

The codebase uses `std.mem.zeroes()` ~710 times (47.9% of all `std.mem` namespace usage). Zig's own documentation flags this as a potential code smell. Replacing it with named constants and explicit initialization improves intent clarity, catches missing field initialization at compile time, and prevents silent bugs when new struct fields are added.

## Acceptance Criteria

- [ ] `src/core/types/constants.zig` created with named null/empty constants (`NULL_HASH`, `EMPTY_SIGNATURE`, `GENESIS_PREV_HASH`, etc.)
- [ ] Constants exported from `src/core/types/types.zig`
- [ ] `std.mem.zeroes()` usage in test code replaced with constants or test helper builders
- [ ] Production code in `src/core/chain/`, `src/core/sync/`, `src/core/mempool/`, `src/core/network/` audited; inappropriate uses replaced
- [ ] Any remaining `zeroes()` usage documented with a comment explaining why it is appropriate
- [ ] `zig build test` passes with no regressions
- [ ] `std.mem.zeroes()` usage reduced by 80%+ (target: ~140 remaining)

## Notes

**Phase 1** (low effort, high value): Create named constants — no behavior change.

**Phase 2**: Refactor `tests.zig` (150+ occurrences) with a `test_helpers.zig` module providing `defaultTestBlock(overrides)` and similar builders.

**Phase 3**: Audit production struct initialization; replace with explicit field initialization where intent is unclear.

**When `zeroes()` is acceptable:** C interop structs; cryptographic byte arrays where zero has explicit semantic meaning (use a named constant instead when possible).

**When NOT acceptable:** Multi-field business logic structs where zero is not a valid default for all fields.
