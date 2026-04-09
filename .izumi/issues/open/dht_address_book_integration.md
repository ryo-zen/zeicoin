---
id: dht_address_book_integration
key: ZEI-85
title: Integrate DHT as peer discovery source in the address book
type: Subtask
status: InProgress
priority: Medium
assignee: null
labels:
- libp2p
- dht
- networking
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: null
comments: []
created_at: 2026-04-09T00:00:00+00:00
updated_at: 2026-04-09T14:44:00+10:00
---

## Summary

Wire the full Kad node into the existing peer discovery pipeline as an additional source alongside `/zeicoin/peers/1.0.0` and bootstrap config. Kad-discovered peers feed into the address book and are subject to the same scoring, backoff, and dial logic, while Kad itself remains non-consensus network infrastructure.

## Acceptance Criteria

- [ ] DHT-discovered peers added to address book with appropriate source tag
- [ ] Any time a Peer record is encountered in any RPC, store associated multiaddrs in peerbook (spec requirement)
- [ ] DHT discovery coexists with existing peer exchange — both sources contribute
- [ ] Server-mode nodes: advertise `/kad/1.0.0` via identify protocol, accept incoming Kademlia streams
- [ ] Client-mode nodes: do NOT advertise `/kad/1.0.0`, do NOT accept incoming streams, but may initiate queries
- [ ] Integration test showing peer discovery via Kad without static bootstrap after initial seed

## Notes

- Key files to modify: `src/core/network/peer_manager.zig`, `src/apps/libp2p_testnode.zig`
- This is step 5 in the implementation order from ZEI-20
- Depends on ZEI-84 (bootstrap/refresh) and ZEI-86 (record/provider layer)
- Kademlia is network infrastructure only — must not influence consensus, validation, or mempool
- Local implementation now wires Kad into `NetworkManager` runtime discovery: bootstrap, `/zeicoin` peer exchange, and Kad all feed the shared libp2p address book and routing table, and maintenance can dial scored address-book candidates beyond the static bootstrap list.
- `zig build check`, `zig build test`, DHT-only libp2p tests, and `./docker/scripts/test_libp2p_kad_smoke.sh` are green on this slice; the remaining libp2p-suite failure is the pre-existing flaky Yamux keepalive test, not a Kad/address-book regression.
