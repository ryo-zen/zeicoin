---
id: zen_server_kad_session_promotion
key: ZEI-99
title: Fix zen_server non-seed session promotion from Kad-discovered peers
type: Task
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- dht
- networking
- bug
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1775720070611.0
comments: []
created_at: 2026-04-09T17:34:07+10:00
updated_at: 2026-04-09T09:32:31.820169964+00:00
closed_at: 2026-04-09T09:31:39.720358489+00:00
---

## Summary

The `ZEI-98` runtime proof showed that Kad discovery is active in the real `zen_server` lifecycle, but the two non-seed nodes did not consistently promote that Kad knowledge into direct transport sessions with each other.

The fix followed the Go/C++ model: observed transport socket addresses are no longer promoted as remote dial targets, outbound sessions now dispatch inbound streams so identify can complete bidirectionally on existing sessions, and maintenance skips already-connected peers when choosing address-book candidates.

## Acceptance Criteria

- [x] In the `docker/scripts/test_libp2p_zen_server.sh` topology, `miner-2` and `node-1` both reach `Connected Peers: 2`
- [x] Kad/identify-learned addresses promoted into the address book are stable dial targets, not transient observed source ports
- [x] Non-seed direct dials no longer fail with repeated `ConnectionRefused` against ephemeral ports during runtime convergence
- [x] The `zen_server` Docker proof can restore a stronger full-mesh transport assertion instead of only routing-layer convergence
- [x] Any remaining edge cases are documented explicitly in the ticket notes or harness docs

## Notes

- Root cause 1: Zig still learned `conn_info.remote_addr` inside Kad inbound handling, which reintroduced the same transient source-port poisoning that Go explicitly avoids.
- Root cause 2: outbound sessions did not run an inbound stream dispatcher, so a peer that had dialed an existing session could not answer identify streams opened back across that session.
- Runtime fixes landed in:
  - `src/core/network/peer.zig`
  - `src/core/network/peer_manager.zig`
  - `libp2p/dht/query.zig`
  - `libp2p/host/host.zig`
  - `libp2p/peer/address_book.zig`
- Added focused regression harness:
  - `docker/scripts/test_libp2p_zen_server_promotion.sh`
- Passing focused proof:
  - `tmp/zen-server-promotion-20260409-192812`
  - `zeicoin-miner-2 — peers=2 routing_peers=2 kad_addrs=2 refreshes=5`
  - `zeicoin-node-1 — peers=2 routing_peers=2 kad_addrs=2 refreshes=2`
  - `ephemeral refused dials=0` on both non-seeds
- Validation:
  - `zig build test-libp2p` -> `97 passed; 1 skipped; 0 failed`
  - `./docker/scripts/test_libp2p_zen_server_promotion.sh` -> `PASS`
