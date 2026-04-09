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
updated_at: 2026-04-09T00:00:00+00:00
---

## Summary

Create a Docker test harness that validates DHT-based peer discovery. Nodes should find each other via Kademlia without relying on static `ZEICOIN_BOOTSTRAP` config after initial seed.

## Acceptance Criteria

- [ ] Docker compose with 3+ nodes, only one configured as initial bootstrap
- [ ] Non-bootstrap nodes discover each other via DHT within a bounded time
- [ ] Test script verifies all nodes have full peer connectivity
- [ ] Validates that removing the bootstrap node doesn't break existing peer connections
- [ ] Passes in CI-compatible timeouts

## Notes

- Extends existing Docker infra from `docker/scripts/test_libp2p_zen_server.sh`
- This is step 7 (final) in the implementation order from ZEI-20
- Depends on ZEI-85 (address book integration)
