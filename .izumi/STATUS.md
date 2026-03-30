# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-03-30
**Branch:** `libp2p-integration`
**Active initiative:** ZEI-62 reorg stability after restart/reconnect under long-running Docker traffic

**Last worked on:** 2026-03-30 — Fixed two remaining deep-reorg blockers, then reran the long Docker fork/reconnect scenario successfully. Runtime fix: `validateBlockPoW()` now accepts TEST_MODE difficulty targets with `base_bytes = 0` and still does full RandomX validation. Harness fix: `docker/scripts/verify_deep_reorg.sh` now preserves miner-1’s compose volume/IP/env when freezing it and force-cleans named containers before/after the run. After rebuilding the Docker images, `verify_deep_reorg.sh` passed end-to-end: the chains diverged at height 50, miner-1 was frozen/restarted in passive mode, miner-2 reconnected and converged back to miner-1’s height-50 hash. I also verified that the follow-up reorg/security tickets from the latest review already exist in Izumi (`ZEI-63`/`64`/`65`/`66`/`67`, plus existing `ZEI-18` and `ZEI-52`). `zig build check`, `zig build test`, and `git diff --check` all pass.

**Next step:** Start the mainnet-blocking follow-up queue with `ZEI-63` (reorg concurrency guard), then `ZEI-67` (verify peer work locally), then `ZEI-18` (real snapshots / avoid replay-from-genesis fallback).

**In flight:** Uncommitted work is still in `src/core/chain/orphan_pool.zig`, `src/core/chain/processor.zig`, `src/core/chain/reorg_executor.zig`, `src/core/chain/state.zig`, `src/core/crypto/randomx.zig`, `src/core/miner/validation.zig`, `src/core/network/bootstrap.zig`, `src/core/network/peer.zig`, `src/core/network/peer_connection.zig`, `src/core/network/peer_manager.zig`, `src/core/server/command_line.zig`, `src/core/server/initialization.zig`, `src/core/server/server_handlers.zig`, `src/core/sync/manager.zig`, `docker/scripts/verify_deep_reorg.sh`, and this file. The scripted Docker stack was cleaned up by the deep reorg script on exit; the earlier smoke-test logs are still in `tmp/zen-server-docker-rerun-20260330-133403/`. `.gitignore` still has an unrelated local modification.

---

## Decisions Made This Session

- **Sync polling loops need session fencing** — older `startSync()` poll loops can wake up after a newer sync/reorg has already started; without a per-session generation guard they can overwrite the current manager state with stale batch-sync failure/idle state.
- **Outbound peer sends need serialization** — `WireConnection` uses a shared send buffer, so concurrent `sendMessage()` calls on one peer can corrupt or lose frames; `Peer.sendMessage()` now runs under `send_mutex`.
- **Peer state must flip to disconnected on error exits** — if `PeerConnection.run()` returns via error, leaving `.connected` behind makes fork detection wait on dead peers; disconnect state is now set in the top-level `defer`.
- **Network-decoded orphan blocks cannot be stored by reference** — `peer_connection` deinitializes decoded messages after handler return, so `server_handlers.onBlock()` must clone a block before inserting it into `orphan_pool`.
- **Orphan ownership must move as a full list, not a raw slice** — returning `[]Block` from `getOrphansByParent()` loses allocation metadata and caused invalid frees in orphan/reorg cleanup; the pool now returns the owned `ArrayList`.
- **Reorg state roots are pre-block commitments** — `BlockHeader.state_root` matches the account state before the block executes, not after. Reorg validation must therefore check current state before applying each replacement block.
- **Reorg verifier must use `ChainState.calculateStateRoot()`** — `state_root.calculateStateRoot()` used a different hashing algorithm than mining/validation, which made reorg checks impossible even when account state was otherwise correct.
- **Coinbase tx hashes are not safe dedupe keys across heights** — `processCoinbaseTransaction()` can see the same coinbase tx hash on different blocks for the same miner/reward; block-level dedupe must guard replay instead. The tx-hash duplicate skip was removed.
- **Successful reorgs must not delete the overwritten height range** — `saveBlock()` during reorg already writes replacement blocks in-place. Deleting `fork+1..old_tip` afterward removes the new chain and leads to `ReplayFailed` / later sync corruption.
- **Replay must include coinbase maturity transitions** — `replayFromGenesis()` now calls `matureCoinbaseRewards()` so rollback state matches live chain application.
- **Failed reorg recovery must restore blocks first, then replay state** — the snapshot helpers in `state_root.zig` are markers only. `executeReorg()` now treats rollback as: restore backed-up canonical blocks, delete any stray heights above the old tip, set DB height back, then rebuild state/index from genesis to the restored tip.
- **Current Docker restart/reconnect smoke test is green after the rollback fix** — `./docker/scripts/test_libp2p_zen_server.sh` passed on 2026-03-30 with logs in `tmp/zen-server-docker-rerun-20260330-133403/`, and the old failure markers did not appear in that run.
- **TEST_MODE difficulty with `base_bytes = 0` is valid** — Docker/test-mode blocks still require full RandomX hashing plus threshold comparison. `validateBlockPoW()` must reject only structurally impossible targets (`> 32` bytes), not `0`.
- **Deep reorg freeze must preserve miner-1 identity and data** — restarting miner-1 with the wrong mount/env/IP made the harness boot a fresh genesis node and falsely fail convergence. `verify_deep_reorg.sh` now reuses the compose data volume, fixed `172.33.0.10` address, and TEST_MODE/bootstrap env.
- **Deep reorg harness must clean up manual containers explicitly** — freezing miner-1 creates a non-compose container, so the script now force-removes named test containers before startup and removes the passive miner-1 container before final `docker compose down -v`.
- **Reconnect tracks missing bootstrap peers, not just zero peers** — maintenance now retries any configured bootstrap address that lacks an active peer, so restarted bootstrap nodes are rediscovered even if the node still has another live connection.
- **Explicit empty bootstrap disables fallback** — `ZEICOIN_BOOTSTRAP=""` is now treated as an intentional “no bootstrap” setting, which keeps Docker seed nodes from dialing the hardcoded external testnet bootstrap.
- **Docker validation is now clean enough to advance** — `./docker/scripts/test_libp2p_zen_server.sh` passes end-to-end, and the latest logs show only local Docker bootstrap addresses for the configured topology.
- **High-height scripted deep reorg is now green too** — after rebuilding Docker images on 2026-03-30, `docker/scripts/verify_deep_reorg.sh` passed with divergence at height 50 and convergence back to miner-1’s height-50 hash after the forced restart/reconnect.
- **Post-Docker mainnet blockers are now explicit** — after the deep reorg path went green, the next priority queue is `ZEI-63` (concurrency guard), `ZEI-67` (local work verification), and `ZEI-18` (real snapshots). `ZEI-64`/`65`/`66` remain important follow-ons, with `ZEI-52` covering related deep-reorg defenses.
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
| ZEI-61 | Batch sync stalls on chain fork (previous_hash mismatch → infinite retry) | High | Fixed — committed as `a87f3e4`, Docker node converges |
| ZEI-62 | Miners don't reorg to longer chain (orphaned blocks never trigger reorg eval) | High | InProgress — replay/root/coinbase bugs fixed, TEST_MODE PoW validation fixed, deep-reorg harness fixed, and both smoke + scripted high-height restart/reconnect Docker validations now pass |

---

## Broader Project State

- **Network:** Local libp2p-to-libp2p Docker testing works. `209.38.84.23` still on old protocol.
- **Zig version:** 0.16.0-dev.2193+fc517bd01 — migration complete
- **Current networking:** `zen_server` uses `libp2p.Host` for peer connections (Noise XX + yamux)
- **Docker:** 3-node topology works (2 miners + 1 sync node), test script at `docker/scripts/test_libp2p_zen_server.sh`
