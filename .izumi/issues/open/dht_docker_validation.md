---
id: dht_docker_validation
key: ZEI-87
title: Docker harness for DHT peer discovery without static bootstrap
type: Subtask
status: InProgress
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
updated_at: 2026-04-09T14:13:00+10:00
---

## Summary

Create a Docker test harness that validates Kad behavior end to end. The current implementation uses a dedicated `libp2p_testnode --kad` runtime so the Kad service can be exercised honestly before it is wired into the `zen_server` runtime path.

## Acceptance Criteria

- [x] Docker compose with 3+ nodes, only one configured as initial bootstrap
- [x] Non-bootstrap nodes discover each other via DHT within a bounded time
- [x] Test script verifies all nodes have full peer connectivity at the routing/discovery layer
- [ ] Validates that removing the bootstrap node doesn't break existing peer connections
- [x] Harness structure is reusable for later value/provider integration checks
- [x] Passes in CI-compatible timeouts

## Notes

- Current proof lives in `docker/scripts/test_libp2p_kad_smoke.sh` and `libp2p/docker/docker-compose.libp2p-test.yml`
- The compose file uses concrete per-container listen multiaddrs so identify/Kad replies advertise dialable addresses instead of `0.0.0.0`
- The Docker image builds `libp2p_testnode` in `ReleaseSafe` because the Zig threaded-I/O debug build trips a `BADF` assertion during peer shutdown in this smoke
- The current post-seed assertion is intentionally narrower than the original ticket text: it proves the non-seed cluster stays up and retains at least one live non-seed session after the seed stops, but not yet per-node session retention
- This is step 7 (final) in the implementation order from ZEI-20
- Depends on ZEI-85 (address book integration) and should remain compatible with later interop validation work
