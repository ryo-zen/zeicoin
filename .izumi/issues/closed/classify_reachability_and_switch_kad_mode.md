---
id: classify_reachability_and_switch_kad_mode
key: ZEI-103
title: Classify reachability and switch Kad mode for NATed nodes
type: Subtask
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- dht
- networking
- nat
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1775780278069.0
comments: []
created_at: 2026-04-10T10:17:31+10:00
updated_at: 2026-04-10T01:08:44.606118584+00:00
closed_at: 2026-04-10T01:08:44.606117765+00:00
---

## Summary

Stop treating every ZeiCoin node as a Kad server. Add an explicit local reachability state and use it to choose Kad client vs server mode at runtime so NATed/private nodes behave as outbound discovery clients while publicly reachable nodes continue to advertise and serve `/kad/1.0.0`.

## Acceptance Criteria

- [ ] A local reachability model exists with at least `unknown`, `private`, and `public` states, and the current state is exposed in logs or status output
- [ ] `src/core/network/peer.zig` no longer hardcodes the local Kad service and routing-table admission path to `.server`
- [ ] NATed/private nodes run Kad in client mode: they can bootstrap, refresh, and query, but do not advertise or register inbound `/kad/1.0.0` server behavior as if they were publicly reachable
- [ ] Publicly reachable nodes continue to run Kad in server mode and preserve current bootstrap/discovery behavior
- [ ] The current outbound-bootstrap proof remains valid for NATed client nodes: bootstrap to `/ip4/209.38.84.23/tcp/10801` succeeds and sync still works
- [ ] Tests cover at least one public-node vs NATed-node scenario so mode selection is exercised in a real runtime or Docker harness, not only in unit tests

## Notes

- This is the immediate correctness slice before full AutoNAT / relay / DCUtR support. Do not block this card on full NAT traversal.
- Relevant current behavior:
  - `src/core/network/peer.zig` initializes `QueryService` with `.server`
  - `src/core/network/peer.zig` also inserts routing peers with `.server`
  - a real local bootstrap probe on 2026-04-10 showed that a node behind NAT can already connect outbound to `209.38.84.23`, complete handshake, and sync as a client
- The first implementation can use current local heuristics plus identify/observed-address information; full AutoNAT evidence can land in a follow-up card.
