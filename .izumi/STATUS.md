# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-03-31
**Branch:** `libp2p-integration`
**Active initiative:** `ZEI-70` reorg safety and recovery hardening after the canonical replay/state fix

**Last worked on:** 2026-03-31 — Landed `ZEI-68` in `dec6ca4` (`fix: validate competing reorg branches early`). Competing branches are now validated before work comparison and before rollback-state mutation, with a forged-higher-work regression added. Validation passed with `zig build check`, `zig build test`, `zig build test-libp2p`, `./docker/scripts/test_libp2p_zen_server.sh`, and `./docker/scripts/verify_deep_reorg.sh`.

**Next step:** Start `ZEI-69` — pass the known `fork_height` into the reorg executor and recompute canonical metadata like `chain_work` on reorg-applied blocks.

**In flight:** `ZEI-71` remains open for the `account_count` metadata drift investigation. No other reorg work is intentionally left half-finished.

---

## libp2p Integration — Phase Summary

| Phase | Ticket | What | Status |
|-------|--------|------|--------|
| 1 | ZEI-39 | Protocol adapter (`LibP2pWireConnection`) | **Done** ✅ |
| 2 | ZEI-31/35/36 | Bootstrap config → multiaddr | **Done** ✅ |
| 3 | ZEI-40/41 | peer_manager → libp2p Host | **Done** ✅ |
| 4 | ZEI-58 | Wire identify handler | **Done** ✅ |
| 5 | ZEI-59 | Connection pool (dedup dials) | **Done** ✅ |
| 6 | ZEI-49 | Fix inproc writeVecAll OOM bug | **Done** ✅ |
| 7 | ZEI-60 | Docker validation | **Done** ✅ (infra + test pass, revealed ZEI-61/62) |
| 8 | ZEI-54 | Real-network integration test | Pending - after the current reorg/mainnet hardening queue |
| 9 | ZEI-20 | Kademlia DHT | Post-MVP |

Full details: `docs/LIBP2P_INTEGRATION_PLAN.md`
