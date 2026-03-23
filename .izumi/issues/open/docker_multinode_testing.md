---
id: docker_multinode_testing
key: ZEI-5
title: Build Docker multi-node test environment with reorg and sync scenarios
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
- testing
- docker
- devops
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1773125881061.0
comments: []
created_at: 2026-03-07T00:00:00+00:00
updated_at: 2026-03-17T00:40:37.817147015+00:00
---

## Summary

A fully automated Docker Compose environment that spins up multiple ZeiCoin nodes, lets them mine and sync, and verifies correct behaviour — particularly chain reorgs, peer discovery, and fork resolution.

## Acceptance Criteria

- [x] Basic sync: node B starts and syncs from node A (`docker-compose.yml` + `init-node.sh`)
- [x] Mining competition: two nodes mine simultaneously, one wins, the other syncs (`docker-compose.yml` with both miners enabled)
- [x] Chain reorg: partition nodes, each mines independently, reconnect and resolve fork (`docker/scripts/verify_reorg.sh` + `verify_deep_reorg.sh`)
- [ ] Orphan handling: deliver blocks out of order, verify orphan pool resolves correctly
- [x] Peer reconnection: kill and restart a node, verify it reconnects and catches up (`verify_reorg.sh` does `docker restart zeicoin-miner-2` and polls for sync)
- [x] Each scenario has a pass/fail assertion (not just "runs without crashing") (verify scripts exit 0/1)

## Notes

- Use `ZEICOIN_TEST_MODE=true` for fast block times and low coinbase maturity (2 blocks)
- Initial Docker environment exists in `docker/` but multi-node reorg scenarios are not yet complete
- See `CLAUDE.md` for TEST_MODE parameters
