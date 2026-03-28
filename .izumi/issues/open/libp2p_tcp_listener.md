---
id: libp2p_tcp_listener
key: ZEI-55
title: Add TCP listener and server-side accept loop to libp2p transport
type: Task
status: Done
priority: High
assignee: null
labels:
- libp2p
- transport
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1774605664333.0
comments: []
created_at: 2026-03-24T00:00:00+00:00
updated_at: 2026-03-28T14:43:27.612320044+00:00
---

## Summary

`transport/tcp.zig` implements client-side I/O but has no server-side `listen()`/`accept()`. Without this, the node cannot accept inbound connections from peers.

## Acceptance Criteria

- [x] `TcpListener` struct in `transport/tcp.zig` with `listen(multiaddr)` and `accept() !TcpConnection`
- [x] Accepted connections populate local/remote multiaddr correctly
- [x] Listener integrates with Zig 0.16 `std.Io.net`
- [x] Unit test: bind listener, dial from client, verify accepted connection

## Test Results (2026-03-27)

`zig build test-libp2p -Doptimize=ReleaseFast` — **PASS** (includes TCP dial+accept+round-trip test)

## Notes

Implemented as `TcpTransport.Listener` (not a standalone struct) in `transport/tcp.zig`. Go reference uses `libp2p.Listen()` implicitly via `host.New()`. The Zig equivalent is driven by the host layer.
