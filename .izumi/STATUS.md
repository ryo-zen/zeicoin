# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-03-31
**Branch:** `libp2p-integration`
**Active initiative:** `ZEI-72` initial testnet rollout readiness, with `ZEI-70` still carrying the reorg hardening queue

**Last worked on:** 2026-03-31 — Created `ZEI-72` to track the first testnet blocker set, explicitly scoped rollout to a resettable network with no backward-compatibility layer, and narrowed `ZEI-66` to corruption signaling plus fail-closed resync handling.
**Next step:** Start `ZEI-71` under `ZEI-72` to classify `account_count` drift as rollout-blocking or observability-only.
**In flight:** `ZEI-72` now overlays the rollout queue; `ZEI-66` issue notes are updated but the code path is not implemented yet.

---

## Project Summary

| State | Summary |
|-------|---------|
| Done | Core libp2p integration is in place: protocol adapter, bootstrap multiaddr handling, peer-manager host wiring, identify handler, connection-pool dedup, and Docker validation. |
| Done | Reorg hardening landed through `ZEI-68`, including early competing-branch validation before work comparison and before canonical-state mutation. |
| Done | Current validation is green across Zig tests, isolated libp2p tests, Docker libp2p smoke, and Docker deep reorg recovery. |
| In play | `ZEI-70` remains the umbrella for the reorg/replay/state-root hardening queue. |
| In play | `ZEI-72` is the overlay tracker for the first resettable testnet rollout blocker set. |
| In play | `ZEI-71` tracks the `account_count` metadata drift investigation. |
| In play | The branch is functionally at “Docker-verified libp2p + Docker-verified reorg recovery works; remaining work is rollout gating, correctness hardening, and real-network validation.” |
| Needs next | `ZEI-71` — investigate `account_count` metadata drift and decide whether it is a rollout blocker or observability-only. |
| Needs next | First-testnet blockers after that: `ZEI-64`, `ZEI-21`, `ZEI-66`, `ZEI-52`, `ZEI-54`. |
| Deferred | `ZEI-20` Kademlia DHT and mainnet-only compatibility/infrastructure work are explicitly out of scope for the first testnet rollout. |

---

## Decisions Made

- The first testnet rollout is treated as resettable because there are currently zero users and zero historical testnet transactions.
- Backward compatibility and mixed-version coexistence are intentionally out of scope for this rollout.
- `ZEI-20` Kademlia DHT is not a blocker for the first testnet; current peer exchange is sufficient.
- Open libp2p integration tickets that conflict with the current branch status should be audited separately, but the only explicit libp2p rollout gate in the current blocker set is `ZEI-54`.

---

## Safety Notes

- Read `docs/REORG_CONSENSUS_SAFETY_PROFILE.md` before touching reorg, replay, rollback, or `state_root` semantics.
- `ChainState.processBlockTransactions()` is the canonical block-state apply path.
- `ChainState.calculateStateRoot()` is the canonical reorg pre-state check.
- Non-genesis all-zero `header.state_root` is invalid.

---

## Validation

- `zig build check`
- `zig build test`
- `zig build test-libp2p`
- `./docker/scripts/test_libp2p_zen_server.sh`
- `./docker/scripts/verify_deep_reorg.sh`

---

Full details: `docs/LIBP2P_INTEGRATION_PLAN.md`
