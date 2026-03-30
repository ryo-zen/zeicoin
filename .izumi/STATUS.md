# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-03-30
**Branch:** `libp2p-integration`
**Active initiative:** ZEI-60 Docker restart/reconnect validation + ZEI-62 miner reorg bug

**Last worked on:** 2026-03-30 — Implemented ZEI-61 recovery in `src/core/sync/protocol/batch_sync.zig` and `src/core/network/peer_manager.zig`. Batch sync now clears stale peer block cache and restarts from current tip after `InvalidBlock` / `InvalidPreviousHash` continuity failures. `zig build check` passes. Docker regression no longer stalls on fork: `zeicoin-node-1` advanced 6 → 15 → 18 before the script failed later on bootstrap reconnect.

**Next step:** Investigate the Docker restart/reconnect failure after `docker restart zeicoin-miner-1` (likely related to `.izumi/issues/open/reconnect_backoff_spiral.md`). Start from `tmp/zen-server-docker-20260330-111925/` and `docker/scripts/test_libp2p_zen_server.sh`, then rerun the script after a reconnect fix. After that, return to ZEI-62 miner reorg behavior.

**In flight:** ZEI-61 code changes are uncommitted in `src/core/sync/protocol/batch_sync.zig` and `src/core/network/peer_manager.zig`. Docker logs from the latest regression run are saved in `tmp/zen-server-docker-20260330-111925/`. Containers are down (script cleanup trap). The `TEST_MODE` mining fix (min_batch_size=0 for empty blocks) is still uncommitted.

---

## Decisions Made This Session

- **ZEI-61 restart is deferred, not immediate** — `processSequentialBlocks()` now queues a restart request and `retrievePendingBlocks()` performs the reset/restart after it exits its active-batch iteration. This avoids mutating the batch tracker mid-loop.
- **Continuity mismatches purge peer block cache** — `Peer.clearReceivedBlocks()` clears stale `received_blocks*` entries before re-requesting the range, preventing the same bad block from being replayed forever.
- **Continuity errors mapped narrowly** — only `error.InvalidBlock` and `error.InvalidPreviousHash` trigger the restart-from-tip path; other apply failures still hard-fail the sync.
- **Dockerfile uses local Zig tarball** — `COPY .docker-cache/zig-nightly.tar.xz` instead of `wget` from squirl.dev (URL was broken). Test script auto-caches from `~/Downloads/` or `~/zig-latest-nightly/`.
- **C_INCLUDE_PATH for libpq** — Ubuntu 24.04 puts `libpq-fe.h` in `/usr/include/postgresql/`, added `ENV C_INCLUDE_PATH=/usr/include/postgresql` to Dockerfile.
- **TEST_MODE mines empty blocks** — Changed `min_batch_size` from 1 to 0 in TEST_MODE so Docker miners produce coinbase-only blocks without waiting for transactions (`src/core/miner/manager.zig:88`).
- **No backward compatibility** — (carried forward) Old formats/paths are deleted, not shimmed.
- **Static IPs for Docker** — `172.33.0.0/24` subnet, miner-1=`.10`, miner-2=`.11`, node-1=`.12`. Avoids DNS resolution issues with multiaddr.

---

## ZEI-61 Investigation Summary

**Bug:** Sync node stalls at height 12 when two miners produce competing chains.

**Root cause chain:**
1. Two miners fork at height 13 (different block 13 with different previous_hash)
2. Sync node applies blocks 1-12 from one miner (chain-A)
3. Block 13 from other miner (chain-B) arrives — its `previous_hash` points to chain-B's block 12
4. `validateBlockBeforeApply()` in `manager.zig:1247` correctly rejects it (previous_hash mismatch)
5. `failSync()` is called, state set to `.failed`
6. Sync retries but gets the same stale cached block 13 from the peer → infinite stall

**Fix approach:**
- In `processSequentialBlocks()`, when block application fails with hash mismatch, call `resetSyncState()` (not just `failSync`) to clear state fully
- Clear the sync peer's received block cache so fresh blocks are requested on retry
- Alternatively: track which peer each block came from and only request from one consistent peer per sync session

**Key files:**
- `src/core/sync/protocol/batch_sync.zig` — `processSequentialBlocks()` line ~858, `failSync()` line ~1112
- `src/core/sync/manager.zig` — `validateBlockBeforeApply()` line ~1198, retry logic
- `src/core/server/server_handlers.zig` — `onBlock()` caches blocks per-peer

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
| 8 | ZEI-54 | Real-network integration test | Pending - after ZEI-61 fix |
| 9 | ZEI-20 | Kademlia DHT | Post-MVP |

Full details: `docs/LIBP2P_INTEGRATION_PLAN.md`

---

## Consensus Bugs Found During Docker Testing

| Ticket | Bug | Severity | Status |
|--------|-----|----------|--------|
| ZEI-61 | Batch sync stalls on chain fork (previous_hash mismatch → infinite retry) | High | Patched locally — node-1 converges in Docker; full script still blocked later by reconnect failure |
| ZEI-62 | Miners don't reorg to longer chain (orphaned blocks never trigger reorg eval) | High | Todo — after ZEI-61 |

---

## Broader Project State

- **Network:** Local libp2p-to-libp2p Docker testing works. `209.38.84.23` still on old protocol.
- **Zig version:** 0.16.0-dev.2193+fc517bd01 — migration complete
- **Current networking:** `zen_server` uses `libp2p.Host` for peer connections (Noise XX + yamux)
- **Docker:** 3-node topology works (2 miners + 1 sync node), test script at `docker/scripts/test_libp2p_zen_server.sh`
