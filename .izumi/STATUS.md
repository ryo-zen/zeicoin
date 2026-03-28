# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-03-28
**Branch:** `libp2p-integration`
**Active initiative:** Wire libp2p into zen_server (ZEI-11)

**Last worked on:** 2026-03-28 — Phase 1 complete. `src/core/network/libp2p_wire.zig` written and tested.

**Next step:** Phase 2 — bootstrap config migration. Create `src/core/network/bootstrap.zig`, replace `ZEICOIN_BOOTSTRAP=ip:port` parsing with multiaddr format. No old-format fallback.

**In flight:** Nothing — Phase 1 committed cleanly.

---

## Decisions Made This Session

- **No backward compatibility** — ZeiCoin has no users. Old formats/paths are deleted, not shimmed. Applies to: bootstrap env var format, raw TCP path in peer_manager, etc.
- **Bootstrap format:** Switching directly to multiaddr (`/ip4/x.x.x.x/tcp/port/p2p/<peer-id>`). Old `ip:port` format removed entirely.
- **Integration plan doc:** `docs/LIBP2P_INTEGRATION_PLAN.md` is the source of truth for phase order, acceptance criteria, and key file locations.

---

## libp2p Integration — Phase Summary

| Phase | Ticket | What | Status |
|-------|--------|------|--------|
| 1 | ZEI-39 | Protocol adapter (`LibP2pWireConnection`) | **Done** ✅ |
| 2 | ZEI-31/35/36 | Bootstrap config → multiaddr | Not started |
| 3 | ZEI-40/41 | peer_manager → libp2p Host | Not started |
| 4 | ZEI-58 | Wire identify handler | Not started |
| 5 | ZEI-59 | Connection pool (dedup dials) | Not started |
| 6 | ZEI-49 | Fix inproc writeVecAll OOM bug | Not started |
| 7 | ZEI-54 | Real-network integration test | Not started |
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
| Identify codec | `libp2p/protocol/identify.zig` | Done (not yet called) |
| PeerId / IdentityKey | `libp2p/peer/peer_id.zig` | Done |
| Multiaddr | `libp2p/multiaddr/multiaddr.zig` | Done |
| Host orchestration | `libp2p/host/host.zig` | Done (ZEI-56) |
| Handler registry | `libp2p/host/handler_registry.zig` | Done |
| Stress harness | `libp2p/libp2p_stress.zig` | Done (ZEI-50) |
| 4-node test harness | `libp2p/libp2p_testnode.zig` | Done |

---

## Broader Project State

- **Network:** TestNet live at `209.38.84.23`
- **Zig version:** 0.16.0-dev.2193+fc517bd01 — migration complete
- **Current networking:** Raw plaintext TCP (`src/core/network/peer_manager.zig`) — being replaced by libp2p
- **Other open work:** See `.izumi/issues/open/` — mainnet readiness, post-quantum crypto, docker testing, etc. All deprioritised until libp2p integration is done.
