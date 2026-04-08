---
id: libp2p_yamux_demux_loop
key: ZEI-37
title: Implement Yamux inbound stream demux loop
type: Subtask
status: Done
priority: High
assignee: null
labels:
- libp2p
- yamux
sprint: null
story_points: 5
due_date: null
parent_id: libp2p_yamux_completion
rank: 1774094706520.0
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-26T12:00:29.613509305+00:00
---

## Summary

The Yamux session in `libp2p/muxer/yamux.zig` can open outbound streams but cannot accept remote-initiated streams. Implement the demux loop that reads frames off the connection and routes them to the correct stream or queues new streams for `accept()`.

## Acceptance Criteria

- [x] Demux loop runs as a concurrent task on the session
- [x] DATA frames are routed to the correct open stream by stream ID
- [x] NEW_STREAM frames create an entry in the inbound accept queue (max 64)
- [x] RST frames close the target stream and wake any blocked readers
- [x] Session shuts down cleanly when the underlying connection closes
- [x] Test: open 3 streams from both sides simultaneously, transfer data on each

## Notes

`libp2p_testnode.zig` shows intended usage patterns. The demux task should run via `std.Io.Future` consistent with the rest of the libp2p stack.

Progress note (2026-03-18): demux validation was completed with a new 3x3 simultaneous stream transfer test in `libp2p/muxer/yamux.zig`, and `zig build test-libp2p` passed.
