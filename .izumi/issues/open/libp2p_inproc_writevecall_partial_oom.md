---
id: inproc_writevecall_partial_oom
key: ZEI-49
title: "Fix InProcConnection writeVecAll partial-write on OOM"
type: Bug
status: Backlog
priority: Low
assignee: null
labels: [libp2p, inproc, memory]
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-19T00:00:00+00:00
updated_at: 2026-03-19T00:00:00+00:00
---

## Summary

`InProcConnection.writeVecAll` and `connectionWriteVecAll` iterate over fragments calling `appendSlice` per fragment. If `appendSlice` fails on any fragment beyond the first (OOM), earlier fragments are already written into the buffer but `broadcast` is never called. The reader blocks indefinitely, and the next write compacts the buffer on top of the partial data, producing a corrupted message.

## Acceptance Criteria

- [ ] If any `appendSlice` fails, no partial data is left in the buffer visible to the reader
- [ ] Reader is not left blocked after a failed write
- [ ] Fix covers both `writeVecAll` (direct) and `connectionWriteVecAll` (vtable adapter)

## Notes

Affected code: `libp2p/transport/inproc.zig` — `writeVecAll` (line ~134) and `connectionWriteVecAll` (line ~188).

Simplest fix: pre-compute total size, call `dst.ensureUnusedCapacity(total)` before the loop, then append. Since capacity is guaranteed, no individual `appendSlice` can fail, and the broadcast path is always reached.

Only manifests on OOM — `std.testing.allocator` catches it as a test failure immediately, so it does not affect current tests. Risk increases if `InProcConnection` is used outside of tests.
