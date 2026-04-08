---
id: state_snapshot_no_ops
key: ZEI-18
title: Implement saveStateSnapshot and loadStateSnapshot to prevent full chain replay on reorg
type: Bug
status: Done
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
updated_at: 2026-03-30T19:20:50+11:00
---

## Summary

`saveStateSnapshot` and `loadStateSnapshot` in `src/core/chain/state_root.zig` are no-ops. Every reorg triggers a full chain replay from genesis. On a long chain this could take minutes or hours and is an O(N) DoS vector if an adversary can repeatedly trigger reorgs.

## Acceptance Criteria

- [x] `Database` (RocksDB wrapper) gains arbitrary key `put`/`get` methods using a `SNAPSHOT:v1:<height>` key prefix
- [x] `saveStateSnapshot` serializes the full account state at a given height into RocksDB
- [x] `loadStateSnapshot` reads back and restores account state, replacing the `replayFromGenesis` fallback
- [x] Snapshots saved at every fork point detected by `ReorgExecutor` and optionally at regular height intervals (e.g., every 1000 blocks)
- [x] Failed reorg application in `ReorgExecutor` correctly restores state from snapshot (currently the no-op means partial state mutations are not recovered)

## Notes

- **Current impact on testnet**: Acceptable — chain is short, replay is fast
- **Mainnet risk**: Reorgs could take minutes/hours; repeated reorg attacks stall the node with O(N) work per reorg
- Landed on `libp2p-integration` on 2026-03-30.
- Snapshots are now anchored by `height + block_hash + state_root`, restore is atomic in one RocksDB batch, and rollback can restore the nearest valid snapshot then replay only the bounded tail.
- Periodic snapshots are now created from canonical progression (genesis and every `SNAPSHOT_INTERVAL` blocks) in addition to exact reorg recovery snapshots.
- Validation passed with `zig build test`, `zig build check`, `./docker/scripts/test_libp2p_zen_server.sh`, and `docker/scripts/verify_deep_reorg.sh`.
- RocksDB already supports arbitrary key storage; reference pattern: `PEER:v1:` prefix used in peer persistence design
- See `docs/PEER_PERSISTENCE_ROCKSDB.md` for key prefix conventions
- Related: `processBlockTransactions` in `state.zig:552` applies transactions with no per-block undo — fixing snapshots resolves this as a side effect
