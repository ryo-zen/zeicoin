---
id: mainnet_bootstrap_infrastructure
key: ZEI-25
title: Set up redundant MainNet bootstrap node infrastructure
type: Task
status: Backlog
priority: Medium
assignee: null
labels: [mainnet, infrastructure]
sprint: null
story_points: null
due_date: null
parent_id: mainnet_readiness
rank: null
comments: []
created_at: 2026-03-14T00:00:00+00:00
updated_at: 2026-03-14T00:00:00+00:00
---

## Summary

TestNet currently relies on a single bootstrap node at `209.38.84.23`. MainNet needs at least two or three geographically distributed, committed bootstrap nodes hardcoded in the binary. A single point of failure here means new nodes cannot join the network.

## Acceptance Criteria

- [ ] At least 2 MainNet bootstrap node addresses identified and committed to uptime
- [ ] Bootstrap node addresses hardcoded in the MainNet configuration path
- [ ] Nodes are geographically distributed (different regions/providers)
- [ ] Bootstrap nodes run on dedicated infrastructure separate from TestNet
- [ ] Monitoring in place to alert if a bootstrap node goes offline

## Notes

Bootstrap node addresses are currently configured via `ZEICOIN_BOOTSTRAP` env var. For MainNet the addresses should also be compiled in as defaults so nodes work out of the box. With libp2p/Kademlia DHT (ZEI-20) this becomes less critical long-term, but hardcoded seeds are still needed for initial network bootstrap.
