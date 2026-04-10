---
id: libp2p_implementation
key: ZEI-11
title: Wire libp2p isolated transport into zen_server and complete MVP spec gaps
type: Epic
status: Done
priority: Low
assignee: null
labels:
- libp2p
- networking
- p2p
- mainnet-critical
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1773129729893.0
comments: []
created_at: 2026-03-07T00:00:00+00:00
updated_at: 2026-03-21T23:00:08+11:00
---

## Summary

Integrate the libp2p transport stack into `zen_server` and close the remaining MVP spec gaps. The isolated testnode path (TCP → multistream → Noise → yamux → identify → `/zeicoin/peers/1.0.0`) is working end-to-end and locally verified with a 4-node harness. The stack is not yet wired into `zen_server`/`peer_manager`.

## Acceptance Criteria

- [x] Reachable address advertisement: promote self-observations from `identify_info.observed_addr` and self-echoed peer-exchange entries; only advertise non-wildcard dialable addresses confirmed by ≥2 distinct peers or self-echoed with `/p2p/<self-peer-id>`
- [x] Yamux MVP completion: per-stream flow control + WINDOW_UPDATE, ping/pong, go-away session semantics, bounded ACK backlog (256) and inbound accept backlog (64)
- [x] Bootstrap config migrated to multiaddr format with hardcoded fallback list and env var override
- [x] Wire isolated libp2p path into `zen_server` / `peer_manager.zig`
- [x] `zig build test-libp2p` passes
- [x] Docker harness (`./scripts/test_libp2p_docker.sh`) shows organic peer discovery

## Notes

**Already complete (as of 2026-03-08):**
- TCP transport, multistream negotiation, real PeerId (Ed25519), Noise XX handshake, yamux (minimal), identify, `/zeicoin/peers/1.0.0` peer exchange
- Binary multiaddr encoding/decoding, `/p2p/<peer-id>` on exchanged addresses, identity-bound dialing, wildcard address suppression, CIDv1 PeerId parsing
- Address book with scoring/backoff/TTL, dial-out loop, multi-node organic discovery
- Isolated `zig build test-libp2p` passing cleanly
- Docker 4-node peer-discovery harness with a successful 30-minute churned soak

**Remaining spec gaps:**
- `zen_server` integration (step 9 in implementation order) — replaces existing `peer_manager.zig` TCP stack
- bootstrap config migration to Multiaddr + fallback seed list

**Post-MVP (can wait):**
- Persistent peer storage, identify/push, RSA key support, Kademlia DHT (ZEI-20), QUIC transport
- Interoperability tests against external libp2p implementations

**Bootstrap config decision (required before zen_server integration):**

The current `ZEICOIN_BOOTSTRAP=ip:port` env var format must be migrated to multiaddr format (`/ip4/.../tcp/...` or `/dns4/.../tcp/...`). Two approaches needed:

- **Env var** (`ZEICOIN_BOOTSTRAP=/dns4/zei.network/tcp/10801`) — flexible, operator-overridable, good for testnet
- **Hardcoded fallback list** — well-known bootstrap nodes baked into the binary (like Bitcoin's DNS seeds), so new nodes work out of the box with zero config on mainnet

Both should be supported: hardcoded fallback for mainnet, env var override for testnet and private networks. The env var takes precedence; if empty, fall back to the compiled-in list.

See `docs/LIBP2P_CONNECTION_FLOW.md` for full connection flow and Docker topology.
