---
id: libp2p_tcp_listener
key: ZEI-55
title: "Add TCP listener and server-side accept loop to libp2p transport"
type: Task
status: Backlog
priority: High
assignee: null
labels: [libp2p, transport]
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-24T00:00:00+00:00
updated_at: 2026-03-24T00:00:00+00:00
---

## Summary

`transport/tcp.zig` implements client-side I/O but has no server-side `listen()`/`accept()`. Without this, the node cannot accept inbound connections from peers.

## Acceptance Criteria

- [ ] `TcpListener` struct in `transport/tcp.zig` with `listen(multiaddr)` and `accept() !TcpConnection`
- [ ] Accepted connections populate local/remote multiaddr correctly
- [ ] Listener integrates with Zig 0.16 `std.Io.net`
- [ ] Unit test: bind listener, dial from client, verify accepted connection

## Notes

Go reference uses `libp2p.Listen()` implicitly via `host.New()`. The Zig equivalent should be a standalone `TcpListener` that the host layer drives. See `transport/tcp.zig:457`.
