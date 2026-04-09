---
id: dht_docker_validation
key: ZEI-87
title: Docker harness for DHT peer discovery without static bootstrap
type: Subtask
status: Backlog
priority: Medium
assignee: null
labels:
- libp2p
- dht
- networking
- testing
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: null
comments: []
created_at: 2026-04-09T00:00:00+00:00
updated_at: 2026-04-09T11:01:53+10:00
---

## Summary

Create a Docker test harness that validates Kad behavior end to end. Nodes should find each other via Kademlia without relying on static `ZEICOIN_BOOTSTRAP` config after initial seed, and the harness should be capable of exercising the full spec-shaped node rather than only peer routing.

## Acceptance Criteria

- [ ] Docker compose with 3+ nodes, only one configured as initial bootstrap
- [ ] Non-bootstrap nodes discover each other via DHT within a bounded time
- [ ] Test script verifies all nodes have full peer connectivity
- [ ] Validates that removing the bootstrap node doesn't break existing peer connections
- [ ] Harness structure is reusable for later value/provider integration checks
- [ ] Passes in CI-compatible timeouts

## Notes

- Extends existing Docker infra from `docker/scripts/test_libp2p_zen_server.sh`
- This is step 7 (final) in the implementation order from ZEI-20
- Depends on ZEI-85 (address book integration) and should remain compatible with later interop validation work
*** Add File: /home/max/zeicoin/.izumi/issues/open/dht_resource_limits_and_fairness.md
---
id: dht_resource_limits_and_fairness
key: ZEI-89
title: Add Kademlia resource limits and protocol fairness controls
type: Subtask
status: Backlog
priority: High
assignee: null
labels:
- libp2p
- dht
- networking
- reliability
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: null
comments: []
created_at: 2026-04-09T11:01:53+10:00
updated_at: 2026-04-09T11:01:53+10:00
---

## Summary

Protect ZeiCoin's libp2p stack from Kad abuse and starvation. Full `/kad/1.0.0` support adds new inbound and outbound RPC traffic, so the implementation needs explicit limits and fairness controls to prevent DHT work from monopolising streams, memory, or scheduling needed by the ZeiCoin protocol.

## Acceptance Criteria

- [ ] Per-peer and global limits exist for concurrent Kad RPC streams
- [ ] Request size and response size limits exist for Kad protobuf messages
- [ ] Lookup concurrency and maintenance jobs are bounded so Kad traffic cannot starve `/zeicoin/1.0.0`
- [ ] Timeout and cancellation behavior is explicit for inbound handlers and outbound queries
- [ ] Misbehaving or malformed Kad peers are handled by reset/close/quarantine behavior consistent with the host stack
- [ ] Unit or integration tests cover at least one starvation/abuse scenario and one oversized or malformed message scenario

## Notes

- This should modify `libp2p/host/host.zig` and/or the Kad service layer rather than relying on informal caller discipline
- The Kad spec defines wire behavior, but ZeiCoin still needs local protection so the DHT cannot degrade sync or mempool traffic
- Keep the limits configurable enough for Docker and interoperability testing
*** Add File: /home/max/zeicoin/.izumi/issues/open/dht_interoperability_validation.md
---
id: dht_interoperability_validation
key: ZEI-90
title: Validate Kademlia interoperability against an external libp2p implementation
type: Subtask
status: Backlog
priority: Medium
assignee: null
labels:
- libp2p
- dht
- networking
- testing
- interop
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: null
comments: []
created_at: 2026-04-09T11:01:53+10:00
updated_at: 2026-04-09T11:01:53+10:00
---

## Summary

Validate that ZeiCoin's `/kad/1.0.0` implementation interoperates with at least one real libp2p Kad implementation rather than only with ZeiCoin nodes. This is the proof point that the project is actually speaking the canonical protocol instead of a self-consistent fork.

## Acceptance Criteria

- [ ] Test plan names the external implementation and version used for validation
- [ ] ZeiCoin can complete at least one successful `FIND_NODE` exchange with the external implementation
- [ ] ZeiCoin can parse and emit Kad protobuf messages accepted by the external implementation
- [ ] If value/provider support is enabled, at least one record/provider flow is exercised successfully or any incompatibility is documented explicitly
- [ ] Validation artifacts are documented in the ticket notes or linked test script output

## Notes

- Good initial targets are the go-libp2p or rust-libp2p Kad implementations
- This should happen after the codec and core query path are stable, not before
- Docker-only ZeiCoin self-tests are not enough to claim real `/kad/1.0.0` compatibility
