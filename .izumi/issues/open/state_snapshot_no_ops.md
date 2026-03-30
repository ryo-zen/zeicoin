---
id: state_snapshot_no_ops
key: ZEI-18
title: Implement saveStateSnapshot and loadStateSnapshot to prevent full chain replay on reorg
type: Bug
status: Backlog
priority: High
assignee: null
labels:
- consensus
- reorg
- performance
- mainnet-blocking
sprint: null
story_points: null
due_date: null
parent_id: reorg_safety_and_recovery_hardening
rank: null
comments: []
created_at: 2026-03-07T00:00:00+00:00
updated_at: 2026-03-30T07:10:22+00:00
---

## Summary

`saveStateSnapshot` and `loadStateSnapshot` in `src/core/chain/state_root.zig` are no-ops. Every reorg triggers a full chain replay from genesis. On a long chain this could take minutes or hours and is an O(N) DoS vector if an adversary can repeatedly trigger reorgs.

## Acceptance Criteria

- [ ] `Database` (RocksDB wrapper) gains arbitrary key `put`/`get` methods using a `SNAPSHOT:v1:<height>` key prefix
- [ ] `saveStateSnapshot` serializes the full account state at a given height into RocksDB
- [ ] `loadStateSnapshot` reads back and restores account state, replacing the `replayFromGenesis` fallback
- [ ] Snapshots saved at every fork point detected by `ReorgExecutor` and optionally at regular height intervals (e.g., every 1000 blocks)
- [ ] Failed reorg application in `ReorgExecutor` correctly restores state from snapshot (currently the no-op means partial state mutations are not recovered)

## Notes

- **Current impact on testnet**: Acceptable — chain is short, replay is fast
- **Mainnet risk**: Reorgs could take minutes/hours; repeated reorg attacks stall the node with O(N) work per reorg
- `ReorgExecutor` calls `loadStateSnapshot` in three places (`reorg_executor.zig:81`, `:107`, `:131`) as error recovery — all currently silently no-ops
- RocksDB already supports arbitrary key storage; reference pattern: `PEER:v1:` prefix used in peer persistence design
- See `docs/PEER_PERSISTENCE_ROCKSDB.md` for key prefix conventions
- Related: `processBlockTransactions` in `state.zig:552` applies transactions with no per-block undo — fixing snapshots resolves this as a side effect
