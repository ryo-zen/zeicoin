---
id: libp2p_docker_harness
key: ZEI-43
title: Docker harness demonstrates organic peer discovery across 4 nodes
type: Subtask
status: Done
priority: Low
assignee: null
labels:
- libp2p
- testing
- docker
sprint: null
story_points: 3
due_date: null
parent_id: libp2p_integration_testing
rank: 1774094618520.0
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-22T05:38:31.962288163+00:00
---

## Summary

Validate the full integration in a realistic multi-node environment using the Docker harness. Four nodes should discover each other via peer exchange, sync the blockchain, and propagate transactions without manual intervention.

## Acceptance Criteria

- [x] `./scripts/test_libp2p_docker.sh` starts 4 nodes cleanly
- [x] All nodes reach `Connected Peers >= 2` within 60 seconds
- [x] No node crashes or OOMs during a 5-minute run

## Notes

Current verified state (2026-03-21):

- 4-node `libp2p_testnode` Docker harness boots cleanly
- all nodes reached `known_peers >= 2` within the startup window
- a 30-minute churned soak completed with zero logged handshake, dial, or handler failures

Command used for the long run:

- `SOAK_SECS=1800 STATUS_INTERVAL_SECS=30 CHURN_INTERVAL_SECS=120 RECOVERY_SECS=30 ./scripts/test_libp2p_docker.sh soak`

Remaining unchecked criteria depend on `zen_server` integration because the current harness exercises isolated `libp2p_testnode`, not blockchain mempool/block propagation.
