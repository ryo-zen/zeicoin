# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-04-07
**Branch:** `libp2p-integration`
**Active initiative:** `ZEI-72` initial testnet rollout readiness — **ALL BLOCKERS COMPLETE**

**Last worked on:** 2026-04-07 — Closed `ZEI-54` (two-node libp2p integration test) by running `libp2p_testnode` on loopback: TCP, Noise XX, Yamux, multistream, identify, and peer exchange all validated; redial after listener restart confirmed (score 10→20). This was the last blocker for `ZEI-72`, which is now fully closed.
**Next step:** The first resettable testnet rollout has no remaining blockers. Next is to deploy the `libp2p-integration` branch to the testnet (merge to main, deploy to 209.38.84.23).
**In flight:** Nothing — rollout queue is clear.

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
| Done | All first-testnet blockers complete: `ZEI-71`, `ZEI-64`, `ZEI-21`, `ZEI-66`, `ZEI-52`, `ZEI-54`. Epic `ZEI-72` is closed. |
| Deferred | `ZEI-20` Kademlia DHT and mainnet-only compatibility/infrastructure work are explicitly out of scope for the first testnet rollout. |

---

## Decisions Made

- The first testnet rollout is treated as resettable because there are currently zero users and zero historical testnet transactions.
- Backward compatibility and mixed-version coexistence are intentionally out of scope for this rollout.
- `ZEI-20` Kademlia DHT is not a blocker for the first testnet; current peer exchange is sufficient.
- Open libp2p integration tickets that conflict with the current branch status should be audited separately, but the only explicit libp2p rollout gate in the current blocker set is `ZEI-54`.
- `account_count` metadata is currently used for observability/status only; it is not part of consensus or recovery gating.
- Height is not a valid standalone reorg winner criterion; the cumulative-work decision in `fork_detector.shouldReorganize()` remains authoritative.
- Reorg orphaned-transaction handling now stages reverted non-coinbase transactions before rollback and restores them only after the winning branch is fully applied; confirmation on the winning branch, duplicate mempool presence, and post-reorg validation failures all cause silent discard instead of reinsertion.
- `ZEI-52` should be implemented in two bounded slices: first the depth cap plus alerting, then the real peer-hash quorum and stricter consensus defaults. The ticket note saying "before `findForkPoint`" is stale for the current architecture because the actual reorg depth is only known after the fork point is discovered.
- `ZEI-66` uses fail-closed quarantine rather than another retryable sync failure: `ReorgExecutor` now marks `chain_corrupted` when restore cannot be proven, `ChainProcessor` quarantines further chain mutation attempts, and `SyncManager` has a `.quarantined` state to block automatic sync retries.
- The pre-`ZEI-52` architecture cleanup removed duplicate fork-point discovery in `SyncManager` and replaced the peer-consensus `agreements += 1` stub with the same `GetBlockHash` request/wait helper used by `fork_detector`, so future reorg policy work should build on that shared path rather than adding another peer-hash mechanism.
- The first `ZEI-52` implementation slice now lives in `SyncManager`: deep-reorg admission policy is enforced before competing-branch fetch or canonical mutation, alert logging is emitted for deep candidates, and consensus defaults are now `.enforced` with `min_peer_responses = 1`.
- `ZEI-52` confirmation guidance now lives in `docs/CONFIRMATION_FINALITY_GUIDANCE.md`; long-term hardcoded finality checkpoints were split into new follow-up ticket `ZEI-75`.
- The final `ZEI-52` Docker proof uses the same stable two-miner flow as the existing reorg scripts: partition, verify divergence, freeze the honest chain, let the attacker overtake, freeze the attacker, then reconnect as passive peers so the rejection path is deterministic.
- The final Docker debugging run exposed a second path into bulk reorg execution, so `SyncManager.executeBulkReorg()` now reapplies the same depth-policy alert/reject guard as the earlier admission check before delegating to `ChainProcessor`.
- The shell tests under `tests/` need deterministic local-node setup: edge-case coverage should disable bootstrap and bound dead-host probes with `timeout`, and the libp2p handshake smoke must use `/ip4/.../tcp/...` bootstrap addresses plus distinct client/RPC ports.
- `zig build test` now uses Zig's default `compiler/test_runner.zig` in `simple` mode for both library and integration test compile steps; the empty library-root runner was moved off the default `test` step into `zig build test-lib`, which keeps successful runs user-readable and removes both the bogus `failed command: ... --listen=-` footer and the misleading `All 0 tests passed.` prelude.

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
- `./docker/scripts/verify_reorg_depth_rejection.sh`
- `bash tests/test_cli_smoke.sh`
- `bash tests/test_cli_functions.sh`
- `bash tests/test_cli_edge_cases.sh`
- `bash tests/test_peer_handshake.sh`

---

Full details: `docs/LIBP2P_INTEGRATION_PLAN.md`
