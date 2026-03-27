---
id: libp2p_stream_handler_registry
key: ZEI-57
title: Implement stream handler registry and protocol dispatch
type: Task
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- protocol
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1774303932307.0
comments: []
created_at: 2026-03-24T00:00:00+00:00
updated_at: 2026-03-27T22:05:00+00:00
---

## Summary

There is no way to register a handler for an inbound protocol stream. The Go reference uses `h.SetStreamHandler("/proto/1.0.0", fn)` which automatically negotiates Multistream-select and dispatches to the right handler. Zig has no equivalent.

## Acceptance Criteria

- [x] `host/handler_registry.zig`: `HandlerRegistry` with `register(protocol_id, HandlerFn)` and `dispatch(stream) !void`
- [x] Dispatch runs Multistream responder negotiation then calls the matched handler
- [x] Unregistered protocol returns NA via Multistream
- [ ] Accept loop in Host drives registry dispatch for every inbound Yamux stream (deferred to ZEI-56 Host ticket)

## Notes

Go equivalent: `h.SetStreamHandler(testProtocol, handleStream)`. The Multistream responder in `protocol/multistream.zig` already handles the negotiation side — this ticket wires it to a callback map. Depends on ZEI-56 (Host).

What's done

  - libp2p/host/handler_registry.zig created with:
    - HandlerRegistry struct with register, dispatch, has, count, deinit
    - Handler type: function pointer + userdata ?*anyopaque (Zig equivalent of Go closures)
    - StreamReader/StreamWriter adapters bridging yamux.Stream to multistream's reader/writer interface
    - dispatch runs Negotiator responder negotiation then calls matched handler
    - Returns NoHandlersRegistered if empty, ProtocolNegotiationFailed if negotiation fails
    - Keys are owned/duped by the registry on register, freed on deinit
  - Exported from api.zig as HandlerRegistry and Handler
  - Added to test_suite.zig
  - 4 tests written covering: register/count, dispatch to matched handler, unregistered protocol NA, empty registry

  Test results (2026-03-27): PASS — 40/41 tests pass (1 skipped); all 4 handler registry tests confirmed passing.
  The keepalive ping pong test is intermittently timing-sensitive (unrelated to this ticket).
