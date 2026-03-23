---
id: libp2p_yamux_unit_tests
key: ZEI-46
title: Add unit tests for Yamux demux, flow control, and session lifecycle
type: Subtask
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- yamux
- testing
sprint: null
story_points: 5
due_date: null
parent_id: libp2p_yamux_completion
rank: 1773709068621.0
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-21T23:00:08+11:00
---

## Summary

Add isolated Yamux tests covering demux, flow control, keepalive, backlog limits, and session lifecycle before full integration work.

## Acceptance Criteria

- [x] Test: open 3 streams from each side simultaneously, transfer data, verify delivery
- [x] Test: saturate send window, confirm writer blocks, then resumes after WINDOW_UPDATE
- [x] Test: GO_AWAY closes all open streams and prevents new ones
- [x] Test: RST frame closes target stream without affecting others
- [x] Test: inbound accept backlog limit (64) is enforced
- [x] All tests use in-process pipes (no real TCP)

## Notes

Implemented in `libp2p/muxer/test_yamux.zig` with `std.testing.allocator` and in-process transport coverage for:

- 3x3 simultaneous streams
- explicit flow-control blocking and resume
- RST isolation
- GO_AWAY semantics
- backlog limit enforcement
- keepalive ping/pong and timeout

The suite runs via `zig build test-libp2p`.
