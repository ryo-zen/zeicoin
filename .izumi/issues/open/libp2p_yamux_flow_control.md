---
id: libp2p_yamux_flow_control
key: ZEI-38
title: Complete Yamux window flow control and session lifecycle
type: Subtask
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- yamux
sprint: null
story_points: 3
due_date: null
parent_id: libp2p_yamux_completion
rank: 1774094621520.0
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-21T14:14:09.409493024+00:00
---

## Summary

Wire up the WINDOW_UPDATE send path and GO_AWAY/ping session lifecycle frames. The structs exist in `yamux.zig` but the send logic is not fully connected to the read path.

## Acceptance Criteria

- [x] WINDOW_UPDATE is sent when a stream's consumed bytes cross the threshold
- [x] Writer blocks when remote send window is exhausted
- [x] Ping/pong roundtrip works and resets a keepalive timer
- [x] GO_AWAY with error code terminates the session and closes all streams
- [x] Test: saturate a stream's flow control window, confirm writes block then resume after WINDOW_UPDATE

## Notes

Depends on ZEI-37 (demux loop) since WINDOW_UPDATE is sent in response to inbound DATA frames.

Progress note (2026-03-18): implemented periodic keepalive ping + pong-timeout closure in `libp2p/muxer/yamux.zig`, ensured non-normal GO_AWAY closes sessions/streams, and added coverage for keepalive success, timeout closure, and error GO_AWAY stream rejection. Verified with `zig build test-libp2p`, `zig build check`, and `zig build test`.

Progress note (2026-03-18): added explicit flow-control blocking coverage in `yamux blocks on exhausted window then resumes after window update`, which delays receiver reads, verifies writer latency while send window is exhausted, and confirms write completion after WINDOW_UPDATE credit restoration. Verified with `zig build test-libp2p`.
