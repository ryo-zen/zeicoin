---
id: mainnet_genesis_block
key: ZEI-24
title: Prepare and lock in MainNet genesis block hash and parameters
type: Task
status: Backlog
priority: High
assignee: null
labels: [mainnet, consensus]
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

The current hardcoded genesis hash in `src/core/chain/genesis.zig` is the TestNet genesis. MainNet requires a distinct genesis block with its own hash, timestamp, and parameters. This is consensus-critical and cannot be changed after launch.

## Acceptance Criteria

- [ ] MainNet genesis block parameters decided (timestamp, coinbase, initial difficulty)
- [ ] MainNet genesis hash computed and hardcoded in `genesis.zig`
- [ ] `CURRENT_NETWORK` switch correctly returns MainNet genesis for `.mainnet`
- [ ] TestNet genesis hash unchanged and still valid
- [ ] Node rejects blocks that don't connect to the correct genesis for the configured network

## Notes

Current TestNet genesis hash is in `src/core/chain/genesis.zig`. RandomX fast mode (2GB) is used for MainNet — genesis hash must be computed using fast mode, not light mode. Coordinate timing of genesis block with launch date.
