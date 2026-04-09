---
id: libp2p_zen_server_integration
key: ZEI-33
title: Wire libp2p transport into zen_server and peer_manager
type: Story
status: Done
priority: High
assignee: null
labels:
- libp2p
- networking
- peer-manager
sprint: null
story_points: 13
due_date: null
parent_id: libp2p_implementation
rank: null
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-17T00:00:00+00:00
---

## Summary

Replace the raw TCP stack in `peer_manager.zig` with the libp2p transport (TCP → Noise → Yamux). Zeicoin's custom wire protocol messages are re-layered as named protocols over Yamux streams, giving the network encryption, multiplexing, and identity-authenticated connections.

## Acceptance Criteria

- [x] `peer_manager.zig` dials and accepts peers via the libp2p stack
- [x] Zeicoin wire protocol runs over a Yamux stream (not raw TCP)
- [x] Peer addressing uses Multiaddr + PeerId (not bare `ip:port`)
- [x] Node identity (Ed25519 keypair) is loaded/created at startup and persisted
- [x] Existing block sync, mempool, and fork detection continue to work
- [x] No plaintext peer connections remain

## Notes

This is the largest integration step. Depends on ZEI-31 (bootstrap config) and ZEI-32 (yamux). Tasks: ZEI-39, ZEI-40, ZEI-41.
