---
id: libp2p_test_suite
key: ZEI-42
title: Ensure zig build test-libp2p passes end-to-end
type: Subtask
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- testing
sprint: null
story_points: 2
due_date: null
parent_id: libp2p_integration_testing
rank: null
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-21T23:00:08+11:00
---

## Summary

Clean up and complete the libp2p unit test suite so `zig build test-libp2p` passes with zero failures, covering all implemented components.

## Acceptance Criteria

- [x] `zig build test-libp2p` exits 0 with no skipped or failing tests
- [x] Tests cover: multiaddr, peer_id, noise handshake, multistream, yamux, identify
- [x] All tests use `std.testing.allocator` (leak detection)
- [x] Re-enable `run-libp2p-testnode` and `run-libp2p-bench` steps in `build.zig`

## Notes

Current isolated suite imports:

- `multiaddr`
- `peer_id`
- `identify`
- `noise`
- `multistream`
- `yamux`
- `tcp`
- `libp2p_bench`

Verified again on 2026-03-21 with `zig build test-libp2p`.
