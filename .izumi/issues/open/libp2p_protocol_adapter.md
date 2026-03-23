---
id: libp2p_protocol_adapter
key: ZEI-39
title: Write zeicoin wire protocol adapter over libp2p streams
type: Subtask
status: Backlog
priority: High
assignee: null
labels:
- libp2p
- networking
- protocol
sprint: null
story_points: 5
due_date: null
parent_id: libp2p_zen_server_integration
rank: null
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-17T00:00:00+00:00
---

## Summary

Create an adapter that exposes the existing `WireConnection` interface over a Yamux stream instead of a raw TCP `net.Stream`. This lets the upper protocol layers (block sync, mempool, fork detection) remain unchanged while the transport underneath becomes libp2p.

## Acceptance Criteria

- [ ] `LibP2pWireConnection` wraps a Yamux stream and satisfies the `WireConnection` interface
- [ ] Zeicoin protocol is registered as `/zeicoin/1.0.0` via multistream negotiation
- [ ] Framed message reads/writes work identically to the current TCP path
- [ ] Existing protocol handler tests pass with the new adapter in place

## Notes

`wire/wire.zig` currently wraps `net.Stream` directly. The adapter should be a thin shim — avoid changing the wire framing logic itself. `libp2p_testnode.zig` shows how to register and handle a custom protocol.
