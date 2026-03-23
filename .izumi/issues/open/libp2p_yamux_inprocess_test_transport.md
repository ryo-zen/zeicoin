---
id: yamux_inprocess_test_transport
key: ZEI-48
title: Refactor Yamux unit tests to use in-process transport
type: Subtask
status: Todo
priority: Medium
assignee: null
labels:
- libp2p
- yamux
- testing
sprint: null
story_points: null
due_date: null
parent_id: libp2p_yamux_unit_tests
rank: 9000.0
comments: []
created_at: 2026-03-18T11:10:03+00:00
updated_at: 2026-03-22T05:41:01.784526394+00:00
---

## Summary

Replace Yamux unit test network setup with an in-process duplex transport so tests validate demux/flow-control/session behavior without relying on TCP listener/dial paths.

## Acceptance Criteria

- [ ] Add a test transport path that provides bidirectional in-process I/O compatible with `noise.SecureTransport` usage in Yamux tests
- [ ] Migrate Yamux unit tests that cover demux, flow control, RST isolation, GO_AWAY, and backlog behavior to the in-process path
- [ ] Remove direct `TcpTransport.listen`/`dial` usage from Yamux unit tests
- [ ] Keep existing Yamux behavioral assertions passing under the new in-process harness (`zig build test-libp2p`)
- [ ] Document the in-process harness usage in test code comments or nearby notes to keep future Yamux tests consistent

## Notes

This is the remaining gap for fully satisfying ZEI-46 acceptance criteria (`All tests use in-process pipes (no real TCP)`).
