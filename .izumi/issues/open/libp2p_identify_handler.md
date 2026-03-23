---
id: libp2p_identify_handler
key: ZEI-58
title: "Wire identify protocol handler into libp2p host connection upgrade"
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

The identify codec (`protocol/identify.zig`) is complete with full encode/decode and tests, but it is never called. No handler sends or receives identify messages on live connections, so peers cannot learn each other's observed addresses or supported protocols.

## Acceptance Criteria

- [ ] Inbound handler: read identify request on `/ipfs/id/1.0.0`, respond with local node info (listen addrs, protocols, public key, agent version)
- [ ] Outbound: after connecting to a peer, open identify stream, read response, update address book with observed addr
- [ ] Handler registered via ZEI-57 registry on host startup
- [ ] Test: two in-process nodes exchange identify and verify observed address is recorded

## Notes

Codec lives in `protocol/identify.zig:167`. The handler is ~100 lines. Depends on ZEI-57 (handler registry).
