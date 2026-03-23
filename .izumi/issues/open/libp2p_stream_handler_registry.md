---
id: libp2p_stream_handler_registry
key: ZEI-57
title: "Implement stream handler registry and protocol dispatch"
type: Task
status: Backlog
priority: Medium
assignee: null
labels: [libp2p, protocol]
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

There is no way to register a handler for an inbound protocol stream. The Go reference uses `h.SetStreamHandler("/proto/1.0.0", fn)` which automatically negotiates Multistream-select and dispatches to the right handler. Zig has no equivalent.

## Acceptance Criteria

- [ ] `host/handler_registry.zig`: `HandlerRegistry` with `register(protocol_id, HandlerFn)` and `dispatch(stream) !void`
- [ ] Dispatch runs Multistream responder negotiation then calls the matched handler
- [ ] Unregistered protocol returns NA via Multistream
- [ ] Accept loop in Host drives registry dispatch for every inbound Yamux stream

## Notes

Go equivalent: `h.SetStreamHandler(testProtocol, handleStream)`. The Multistream responder in `protocol/multistream.zig` already handles the negotiation side — this ticket wires it to a callback map. Depends on ZEI-56 (Host).
