# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-03-29
**Branch:** `libp2p-integration`
**Active initiative:** Wire libp2p into zen_server (ZEI-11)

**Last worked on:** 2026-03-29 — Phases 1-6 are committed on this branch. All connections now go through `libp2p.Host` (Noise XX + yamux). Raw TCP server removed. Node identity key persists to `ZEICOIN_DATA_DIR/node_key`. This session fixed the local shutdown path in the working tree: the listener now wakes `accept()` cleanly during stop, peer/session shutdown is coordinated, and the latest `zig build check`, `zig build`, `zig build test`, plus a two-node local libp2p smoke test all pass.

**Next step:** Commit the shutdown fix, then run Phase 7 integration only against libp2p-capable bootstrap peers. Do not use `209.38.84.23` for validation yet; it still speaks the old protocol.

**In flight:** Working tree contains uncommitted shutdown/cleanup fixes in `host`, `yamux`, and peer shutdown coordination.

---

## Decisions Made This Session

- **No backward compatibility** — ZeiCoin has no users. Old formats/paths are deleted, not shimmed. Applies to: bootstrap env var format, raw TCP path in peer_manager, etc.
- **Bootstrap format:** Switched to multiaddr (`/ip4/x.x.x.x/tcp/port` or with `/p2p/<peer-id>`). Old `ip:port` format logs a migration hint and is skipped.
- **Bootstrap fallback:** Hardcoded in `bootstrap.zig` (no JSON config file). `config/bootstrap_testnet.json` deleted.
- **Integration plan doc:** `docs/LIBP2P_INTEGRATION_PLAN.md` is the source of truth for phase order, acceptance criteria, and key file locations.
- **Real-network validation target:** Skip `209.38.84.23` until it is upgraded to libp2p. A failure against that node is expected legacy-protocol incompatibility, not a regression on this branch.
- **Shutdown strategy:** Wake the blocked listener with a loopback connection during stop rather than closing the listening socket from another thread.

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
| 7 | ZEI-54 | Real-network integration test | Pending - needs libp2p-capable bootstrap peer |
| 8 | ZEI-20 | Kademlia DHT | Post-MVP |

Full details: `docs/LIBP2P_INTEGRATION_PLAN.md`

---

## libp2p Stack — What Is Already Built

Everything in `libp2p/` is complete and tested. Nothing in this directory needs to be written — only wired in.

| Component | File | State |
|-----------|------|-------|
| TCP transport + listener | `libp2p/transport/tcp.zig` | Done (ZEI-55) |
| In-process transport (tests) | `libp2p/transport/inproc.zig` | Done |
| Noise XX encryption | `libp2p/security/noise.zig` | Done |
| Yamux muxer | `libp2p/muxer/yamux.zig` | Done |
| Multistream negotiation | `libp2p/protocol/multistream.zig` | Done |
| Identify codec | `libp2p/protocol/identify.zig` | Done and wired into Host |
| PeerId / IdentityKey | `libp2p/peer/peer_id.zig` | Done |
| Multiaddr | `libp2p/multiaddr/multiaddr.zig` | Done |
| Host orchestration | `libp2p/host/host.zig` | Done and integrated into `zen_server` |
| Handler registry | `libp2p/host/handler_registry.zig` | Done |
| Stress harness | `libp2p/libp2p_stress.zig` | Done (ZEI-50) |
| 4-node test harness | `libp2p/libp2p_testnode.zig` | Done |

---

## Broader Project State

- **Network:** Local libp2p-to-libp2p server testing passes. `209.38.84.23` is still on the old protocol and should not be used as a libp2p validation target yet.
- **Zig version:** 0.16.0-dev.2193+fc517bd01 — migration complete
- **Current networking:** `zen_server` now uses `libp2p.Host` for peer connections (Noise XX + yamux)
- **Other open work:** See `.izumi/issues/open/` — mainnet readiness, post-quantum crypto, docker testing, etc. All deprioritised until libp2p integration is done.
