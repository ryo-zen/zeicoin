---
id: libp2p_yamux_completion
key: ZEI-32
title: Complete Yamux multiplexer MVP
type: Story
status: Done
priority: High
assignee: null
labels:
- libp2p
- networking
- yamux
sprint: null
story_points: 8
due_date: null
parent_id: libp2p_implementation
rank: 1774094708520.0
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-26T12:00:46.869205233+00:00
---

## Summary

Complete the isolated Yamux MVP in `libp2p/muxer/yamux.zig` so the multiplexer can accept inbound streams, enforce per-stream flow control, handle keepalive/session lifecycle, and pass isolated tests.

## Acceptance Criteria

- [x] Inbound stream accept/demux loop processes remote-initiated streams
- [x] Per-stream WINDOW_UPDATE sent when consumed bytes cross threshold
- [x] Ping/pong keepalive works
- [x] GO_AWAY frame terminates session cleanly
- [x] Bounded inbound accept backlog (64) and ACK backlog (256)
- [x] All yamux tests in `zig build test-libp2p` pass

## Notes

Completed through ZEI-37, ZEI-38, and the isolated Yamux test coverage now living in `libp2p/muxer/test_yamux.zig`.
