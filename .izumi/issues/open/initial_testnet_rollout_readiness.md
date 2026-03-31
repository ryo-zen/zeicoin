---
id: initial_testnet_rollout_readiness
key: ZEI-72
title: Initial testnet rollout readiness for the libp2p and consensus branch
type: Epic
status: Backlog
priority: High
assignee: null
labels:
  - testnet
  - rollout
  - libp2p
  - consensus
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-31T16:22:07+11:00
updated_at: 2026-03-31T16:22:07+11:00
---

## Summary

Track the remaining work needed to ship the current libp2p + consensus branch to an initial public testnet. This epic is intentionally scoped to a resettable first rollout: there are currently zero users and zero historical testnet transactions, so backward compatibility and mixed-version migration work are out of scope for this pass.

## Acceptance Criteria

- [ ] `ZEI-71` investigates `account_count` metadata drift and either lands the required fix or explicitly downgrades the issue to observability-only
- [ ] `ZEI-64` allows reorg to a shorter chain with more cumulative work
- [ ] `ZEI-21` restores orphaned transactions to the mempool after reorg
- [ ] `ZEI-66` surfaces restore-failure corruption to the caller and triggers a fail-closed resync or quarantine path
- [ ] `ZEI-52` adds the first deep-reorg protection layer for public testnet operation
- [ ] `ZEI-54` validates `zen_server` libp2p behavior across at least one real network link

## Notes

- This is a tracking overlay epic. It does not reparent tickets that already sit under `ZEI-70` or `ZEI-11`.
- Blockers for the first resettable testnet:
  - `ZEI-71` — classify `account_count` drift before rollout; if it is observability-only, record that decision and remove it from the blocker set
  - `ZEI-64` — consensus correctness: do not reject a shorter chain that has more cumulative work
  - `ZEI-21` — transaction correctness: restore orphaned transactions after reorg
  - `ZEI-66` — fail closed if reorg restore cannot prove canonical recovery
  - `ZEI-52` — add a reorg-depth cap and replace the peer-consensus stub before exposing the network more broadly
  - `ZEI-54` — final real-host validation of the libp2p/`zen_server` path
- Likely stale bookkeeping to audit separately, not first-testnet blockers unless the audit finds a real missing gap:
  - `ZEI-11`, `ZEI-33`, `ZEI-39`, `ZEI-40`, `ZEI-41` — `.izumi/STATUS.md` already records core libp2p integration as functionally in place
  - `ZEI-65` — likely covered by `ZEI-69` now that the known `fork_height` is threaded into the executor path
- Explicitly out of scope for the first rollout:
  - backward compatibility or mixed old/new network coexistence
  - `ZEI-20` Kademlia DHT
  - `ZEI-28` mainnet readiness and its children
  - lower-priority networking polish such as `ZEI-17` unless rollout dry runs show it is materially blocking connectivity
- Suggested order:
  1. `ZEI-71`
  2. `ZEI-64`
  3. `ZEI-21`
  4. `ZEI-66`
  5. `ZEI-52`
  6. `ZEI-54`
