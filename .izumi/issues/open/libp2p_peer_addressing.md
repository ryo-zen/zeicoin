---
id: libp2p_peer_addressing
key: ZEI-41
title: Migrate peer addressing to Multiaddr and PeerId format
type: Subtask
status: Backlog
priority: Medium
assignee: null
labels:
- libp2p
- peer-manager
- addressing
sprint: null
story_points: 3
due_date: null
parent_id: libp2p_zen_server_integration
rank: null
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-17T00:00:00+00:00
---

## Summary

Replace bare `ip:port` peer addresses throughout the codebase with Multiaddr strings and track peers by PeerId. This enables identity-bound dialing (refuse connections from wrong PeerId) and is required for peer exchange to work correctly.

## Acceptance Criteria

- [ ] `Peer` struct stores a `PeerId` and a list of known Multiaddrs
- [ ] `status` command displays peers by PeerId (truncated) + address
- [ ] Peer exchange sends/receives Multiaddr-encoded addresses
- [ ] Duplicate connection detection uses PeerId, not address
- [ ] Node identity keypair is loaded from disk or generated on first start

## Notes

`libp2p/peer/peer_id.zig` has `IdentityKey.loadOrCreate()` ready to use. Node key should be stored in `ZEICOIN_DATA_DIR/node_key`.
