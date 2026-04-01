# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-04-01
**Branch:** `libp2p-integration`
**Active initiative:** `ZEI-72` initial testnet rollout readiness, with `ZEI-70` still carrying the reorg hardening queue

**Last worked on:** 2026-04-01 — Finished `ZEI-64`, verified the deep Docker reorg test passes cleanly, and added `ZEI-74` to track the misleading `zig build test` failure footer that still appears on successful runs.
**Next step:** Start `ZEI-21` under `ZEI-72` to wire orphaned transactions back into the mempool after successful reorgs.
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
| In play | The branch is functionally at “Docker-verified libp2p + Docker-verified reorg recovery works; remaining work is rollout gating, correctness hardening, and real-network validation.” |
| Done | `ZEI-71` landed: `account_count` now tracks unique persisted accounts across direct writes, batch commits, rollback/reset, and explicit restore metadata; impact was classified as observability-only. |
| Done | `ZEI-64` landed: `executeReorg()` no longer rejects shorter competing branches solely on height, and a regression test now covers the shorter-but-heavier winner case. |
| Needs next | First-testnet blockers now queued as: `ZEI-21`, `ZEI-66`, `ZEI-52`, `ZEI-54`. |
| Deferred | `ZEI-74` tracks the misleading `zig build test` footer; treat it as developer-experience cleanup unless exit codes show a real failure. |
| Deferred | `ZEI-20` Kademlia DHT and mainnet-only compatibility/infrastructure work are explicitly out of scope for the first testnet rollout. |

---

## Decisions Made

- The first testnet rollout is treated as resettable because there are currently zero users and zero historical testnet transactions.
- Backward compatibility and mixed-version coexistence are intentionally out of scope for this rollout.
- `ZEI-20` Kademlia DHT is not a blocker for the first testnet; current peer exchange is sufficient.
- Open libp2p integration tickets that conflict with the current branch status should be audited separately, but the only explicit libp2p rollout gate in the current blocker set is `ZEI-54`.
- `account_count` metadata is currently used for observability/status only; it is not part of consensus or recovery gating.
- Height is not a valid standalone reorg winner criterion; the cumulative-work decision in `fork_detector.shouldReorganize()` remains authoritative.

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
