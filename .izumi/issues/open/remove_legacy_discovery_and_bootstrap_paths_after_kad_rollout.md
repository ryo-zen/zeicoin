---
id: remove_legacy_discovery_and_bootstrap_paths_after_kad_rollout
key: ZEI-105
title: "Remove legacy discovery and bootstrap paths after Kad rollout"
type: Subtask
status: Backlog
priority: Medium
assignee: null
labels:
- libp2p
- dht
- networking
- cleanup
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: null
comments: []
created_at: 2026-04-10T17:13:24+10:00
updated_at: 2026-04-10T17:13:24+10:00
---

## Summary

Clean up the legacy discovery and bootstrap paths that remain after the Kad rollout so ZeiCoin has one clear runtime source of truth for peer discovery. The current code still carries the old `/zeicoin/peers` message path, a duplicate raw-IP discovery list in `PeerManager`, and split bootstrap dialing behavior between startup and reconnect. Mixed-version hash-based `GET_BLOCKS` fallback also remains even though current rollout policy treats mixed-version coexistence as out of scope. This ticket should remove dead or redundant paths, or explicitly document why any retained compatibility path must stay.

## Acceptance Criteria

- [ ] The `/zeicoin/peers` `GET_PEERS` / `PEERS` discovery path is either removed from the live runtime or explicitly retained with a documented reason and coverage showing why Kad/identify/bootstrap are not sufficient yet
- [ ] `PeerManager.known_addresses` is removed if it is no longer needed, and the libp2p address book remains the canonical discovery store for bootstrap, identify, and Kad-learned peers
- [ ] Startup bootstrap dialing uses the same full-multiaddr path as reconnects so peer ID, DNS, and non-IPv4 semantics are not dropped on initial connect
- [ ] The legacy hash-based `GET_BLOCKS` compatibility path is removed if mixed-version compatibility remains out of scope for testnet rollout; otherwise it is downgraded into an explicitly tracked compatibility ticket
- [ ] Tests or Docker/runtime validation are updated so the retained discovery/bootstrap path is exercised end to end after the cleanup

## Notes

- Current candidate cleanup points:
  - `src/core/server/server_handlers.zig` still serves `GET_PEERS` / `PEERS`
  - `src/core/network/peer_connection.zig` still dispatches `.get_peers` and `.peers`
  - `src/core/network/protocol/messages/peers.zig` still serializes raw IP/port discovery payloads
  - `src/core/network/peer_manager.zig` still owns `known_addresses` even though `libp2p/peer/address_book.zig` is now the richer canonical peerbook
  - `src/core/server/initialization.zig` dials bootstrap nodes via `tcpAddress()` while reconnects in `src/core/network/peer.zig` already use `connectToMultiaddr(&node.multiaddr)`
  - `src/core/server/server_handlers.zig` still has the hash-based `GET_BLOCKS` fallback path for legacy requests
- This is cleanup, not a consensus change. It should not alter block validity, reorg policy, or Kad wire behavior.
- Keep separate from `ZEI-104` AutoNAT work so protocol/reachability changes stay reviewable on their own.
