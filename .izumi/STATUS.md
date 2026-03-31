# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-03-31
**Branch:** `libp2p-integration`
**Active initiative:** `ZEI-70` reorg safety and recovery hardening after the canonical replay/state fix

**Last worked on:** 2026-03-31 — Completed `ZEI-69` by threading known `fork_height` through the bulk reorg path, recomputing canonical `chain_work` on reorg-applied blocks, closing `ZEI-68` and `ZEI-69`, and validating with Zig plus both Docker reorg/libp2p scripts.
**Next step:** Start `ZEI-71` to investigate `account_count` metadata drift.
**In flight:** `ZEI-71` remains open; `docs/REORG_EXECUTION_FLOW.md` now documents the live reorg path for follow-on work.

---

## Project Summary

| State | Summary |
|-------|---------|
| Done | Core libp2p integration is in place: protocol adapter, bootstrap multiaddr handling, peer-manager host wiring, identify handler, connection-pool dedup, and Docker validation. |
| Done | Reorg hardening landed through `ZEI-68`, including early competing-branch validation before work comparison and before canonical-state mutation. |
| Done | Current validation is green across Zig tests, isolated libp2p tests, Docker libp2p smoke, and Docker deep reorg recovery. |
| In play | `ZEI-70` remains the umbrella for the reorg/replay/state-root hardening queue. |
| In play | `ZEI-71` tracks the `account_count` metadata drift investigation. |
| In play | The branch is functionally at “local libp2p + Docker-verified reorg recovery works; remaining work is correctness hardening and follow-on network features.” |
| Needs next | `ZEI-71` — investigate `account_count` metadata drift after the reorg/state-root hardening series. |
| Needs next | Reorg follow-ons after that: `ZEI-21`, `ZEI-52`, `ZEI-64`, `ZEI-65`, `ZEI-66`. |
| Needs next | Broader networking follow-ons later: `ZEI-54` real-network integration test, then `ZEI-20` Kademlia DHT. |

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
