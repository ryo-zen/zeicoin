---
id: libp2p_host_abstraction
key: ZEI-56
title: "Implement libp2p Host orchestration layer"
type: Task
status: Done
priority: High
assignee: null
labels: [libp2p, architecture]
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-24T00:00:00+00:00
updated_at: 2026-03-27T23:00:00+00:00
---

## Summary

All individual protocol layers exist (Noise, Yamux, Multistream, TCP) but there is no orchestration layer that ties them together. Currently, callers must manually compose: TCP dial → Noise handshake → Yamux session → Multistream negotiation. The Host abstraction provides a single entry point equivalent to Go's `host.NewStream()` and `host.Connect()`.

## Acceptance Criteria

- [ ] `host/host.zig`: `Host` struct with `dial(multiaddr) !*Session` that auto-composes TCP+Noise+Yamux+Multistream
- [ ] `host/host.zig`: `newStream(peer_id, protocol) !*Stream` for outbound protocol streams
- [ ] Listener path: accept inbound conn, run Noise+Yamux+Multistream upgrade, dispatch to handler registry
- [ ] Graceful shutdown via `host.close()` tears down listener + all sessions

## Notes

This is the highest-leverage missing piece. The Go reference does this implicitly via `libp2p.New()`. Estimated ~500-800 lines. Depends on ZEI-55 (TCP listener) and ZEI-57 (stream handler registry).
