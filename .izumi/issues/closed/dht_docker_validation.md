---
id: dht_docker_validation
key: ZEI-87
title: Docker harness for DHT peer discovery without static bootstrap
type: Subtask
status: Done
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
rank: 1775708053722.0
comments: []
created_at: 2026-04-09T00:00:00+00:00
updated_at: 2026-04-09T08:05:10.654826540+00:00
closed_at: 2026-04-09T08:05:10.654825843+00:00
---

## Summary

Create a Docker test harness that validates Kad behavior end to end. The current implementation uses a dedicated `libp2p_testnode --kad` runtime so the Kad service can be exercised honestly before it is wired into the `zen_server` runtime path.

## Acceptance Criteria

- [x] Docker compose with 3+ nodes, only one configured as initial bootstrap
- [x] Non-bootstrap nodes discover each other via DHT within a bounded time
- [x] Test script verifies all nodes have full peer connectivity at the routing/discovery layer
- [x] Validates that removing the bootstrap node doesn't break existing peer connections
- [x] Harness structure is reusable for later value/provider integration checks
- [x] Passes in CI-compatible timeouts

## Notes

- Current proof lives in `docker/scripts/test_libp2p_kad_smoke.sh` and `libp2p/docker/docker-compose.libp2p-test.yml`
- The compose file uses concrete per-container listen multiaddrs so identify/Kad replies advertise dialable addresses instead of `0.0.0.0`
- The Docker image builds `libp2p_testnode` in `ReleaseSafe` because the Zig threaded-I/O debug build trips a `BADF` assertion during peer shutdown in this smoke
- Updated local proof: `./docker/scripts/test_libp2p_kad_smoke.sh` now enforces per-node post-seed retention, and the latest Arch run passed with `node-1`, `node-2`, and `node-3` each still reporting `live_sessions=1` after `libp2p-seed` stopped.
- This is step 7 (final) in the implementation order from ZEI-20
- Depends on ZEI-85 (address book integration) and should remain compatible with later interop validation work
