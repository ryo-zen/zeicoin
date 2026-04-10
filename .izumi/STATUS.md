# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-04-10
**Branch:** `kademlia-dht`
**Active initiative:** Testnet hardening and post-rollout cleanup after the Kad/libp2p sprint

**Last worked on:** 2026-04-10 — Landed `ZEI-103` startup reachability/Kad mode selection in `src/core/network/peer.zig`, added Docker/runtime validation coverage including the Kad partition-heal harness, confirmed outbound bootstrap from a NATed local node, and rewrote `ZEI-104` to track the official AutoNAT v2 flow (per-address probing, `/libp2p/autonat/2/*`, nonce dial-backs, and amplification defense).
**Next step:** Start `ZEI-104` as an AutoNAT v2 client/server wire implementation that records per-address evidence, then follow with host handler unregister/runtime mode switching before relay / DCUtR work.
**In flight:** No uncommitted product changes should remain after this handoff. Branch `kademlia-dht` now contains the committed `ZEI-103` reachability/Kad-mode work, Docker reachability overrides, the Kad partition-heal validation script, and the related ticket/status updates (`ZEI-54` archived, `ZEI-103` closed, `ZEI-104` opened). Validation artifacts under `tmp/zen-server-docker-20260410-104231` and `tmp/nat-kad-client-probe-*` are disposable.

---

## Project Summary

| State | Summary |
|-------|---------|
| Done | The Kad/libp2p sprint (`ZEI-81`..`ZEI-99`) is complete on this branch, including remote bootstrap validation against `209.38.84.23`. |
| Done | Core libp2p integration is in place: protocol adapter, bootstrap multiaddr handling, peer-manager host wiring, identify handler, connection-pool dedup, and Docker validation. |
| Done | Reorg hardening landed through `ZEI-68`, including early competing-branch validation before work comparison and before canonical-state mutation. |
| Done | Current validation is green across Zig tests, isolated libp2p tests, Docker libp2p smoke, and Docker deep reorg recovery. |
| In play | `ZEI-70` remains the umbrella for the reorg/replay/state-root hardening queue. |
| Done | `ZEI-72` rollout blocker set is complete and the branch has been deployed to the resettable testnet. |
| In play | The project is now at “live testnet deployment with Docker-verified libp2p + Docker-verified reorg recovery; remaining work is real-network validation, correctness hardening, and follow-up cleanup.” |
| Done | `ZEI-71` landed: `account_count` now tracks unique persisted accounts across direct writes, batch commits, rollback/reset, and explicit restore metadata; impact was classified as observability-only. |
| Done | `ZEI-64` landed: `executeReorg()` no longer rejects shorter competing branches solely on height, and a regression test now covers the shorter-but-heavier winner case. |
| Done | All first-testnet blockers complete: `ZEI-71`, `ZEI-64`, `ZEI-21`, `ZEI-66`, `ZEI-52`, `ZEI-54`. Epic `ZEI-72` is closed. |
| Backlog | `ZEI-20` remains as an umbrella/mainnet follow-up item even though the current testnet Kad implementation work is complete on this branch. |

---

## Decisions Made

- `zeicoin-mining.service` is now the only long-running systemd server unit; `zeicoin-server.service` was removed to avoid split ownership and restart conflicts.
- Systemd-managed nodes now use `.env.testnet` for config plus `.env.local` for secrets; bootstrap clients must use multiaddr format and the bootstrap seed must set `ZEICOIN_BOOTSTRAP=` explicitly empty.
- `ZEI-103` is intentionally startup-fixed for local Kad mode: ZeiCoin now maps `public -> server` and `private/unknown -> client`, defers runtime switching until AutoNAT plus a host handler-unregister path exist, and admits remote peers to the Kad routing table only when identify advertises `/kad/1.0.0`.
- `ZEICOIN_REACHABILITY=public|private|unknown` is a temporary manual override for environments like the isolated Docker bridge where RFC1918 addresses are still mutually reachable and should behave as Kad servers.
- `ZEI-104` is now scoped to the official AutoNAT v2 spec rather than a generic AutoNAT-style dial-back: per-address requests, `/libp2p/autonat/2/dial-request` plus `/libp2p/autonat/2/dial-back`, nonce verification, and the `DialDataRequest` amplification-defense path are all part of the card.
- A block containing a transaction that already exists in the chain is invalid and must be rejected during block application; silently skipping duplicates is not allowed.
- Batch sync must validate proof-of-work on every received block, not just structural continuity.
- The first testnet rollout is treated as resettable because there are currently zero users and zero historical testnet transactions.
- The first resettable testnet rollout has now happened; the current phase is operational validation rather than deployment prep.
- Backward compatibility and mixed-version coexistence are intentionally out of scope for this rollout.
- `ZEI-20` Kademlia DHT is not a blocker for the first testnet; current peer exchange is sufficient.
- `ZEI-20` should respect the real libp2p Kademlia spec if implemented under `/kad/1.0.0`; a narrower discovery-only subset must be split or renamed rather than silently reusing the canonical protocol ID.
- The current DHT subtask split (`ZEI-81`..`ZEI-87`) covers routing table, RPC codec, lookup, refresh, address-book integration, scope choice, and Docker validation, but resource-limiting, explicit mode-classification policy, and external interoperability validation are still only implicit and should be tracked clearly before coding starts.
- Full `/kad/1.0.0` work should not start on top of the current extracted address book shape: `ZEI-85` assumes a real peerbook that stores repeated multiaddrs per peer, but `libp2p/peer/address_book.zig` still stores one flat address per entry and drops non-IPv4 addresses, so those prerequisites should be tracked and landed before `ZEI-81` / `ZEI-83`.
- The missing Kad prerequisites are now tracked explicitly as `ZEI-91` (peerbook reshape), `ZEI-92` (DNS/IPv6 multiaddr support), and `ZEI-93` (identify decode hardening); `ZEI-89` already covers stream/resource controls and remains part of the prerequisite path before broad rollout.
- `AGENTS.md` now explicitly names `/home/max/zeicoin/reference/go-libp2p-kad-dht` and `/home/max/zeicoin/reference/go-libp2p` as the first fallback reference implementations when libp2p/Kad behavior is ambiguous.
- `ZEI-91` now lives in the active local libp2p module as `libp2p/peer/address_book.zig`: peer identity is the primary grouping key when known, addresses are stored per peer with source flags (`identify`, `peer_exchange`, `bootstrap`, `kad`), and anonymous address state is migrated forward when a later observation supplies the peer ID.
- The prior `yamux keepalive ping pong keeps session alive` failure was timing-sensitive rather than peerbook-related; the test now uses a wider keepalive/sleep budget so `zig build test-libp2p` stays stable under full-suite scheduler load.
- `ZEI-92` widened discovery from IPv4-only assumptions to `/ip4`, `/ip6`, and DNS-based TCP multiaddrs: the peerbook no longer drops those families, the TCP transport can resolve DNS multiaddrs for dialing, identify/testnode observed-address handling preserves IPv6, and bootstrap parsing accepts non-IPv4 TCP multiaddrs.
- `ZEI-93` was intentionally implemented as the smallest Kad unblocker rather than full identify parity: unknown well-formed protobuf fields now skip generically for wire types `0/1/2/5`, malformed frames still fail closed, and signed peer record parsing remains a separate follow-up if a concrete consumer appears.
- `ZEI-81` is intentionally a pure data-structure slice: the routing table owns bucket admission, recency ordering, SHA-256 + XOR distance, closest-peer selection, and a two-step ping-and-replace workflow, but it performs no network I/O and requires callers to pass an explicit Kad mode (`client` vs `server`) for admission decisions.
- `ZEI-82` is intentionally a wire-layer slice: `libp2p/dht/message.zig` owns Kad protobuf structs, unknown-field-safe decode, and uvarint frame read/write helpers for `/kad/1.0.0`, while inbound stream loops and `FIND_NODE` request handling remain with `ZEI-83`.
- `ZEI-83` now lives in `libp2p/dht/query.zig`: the service registers `/kad/1.0.0` only in server mode, handles repeated inbound Kad RPCs on one stream, performs iterative `FIND_NODE` lookups with bounded `alpha`, learns discovered peers into both the peerbook and routing table, emits transport multiaddrs in Kad `Peer` records, and drops the local peer from discovered candidates before continuing the lookup.
- `ZEI-84` now extends the same query service: bootstrap runs do self-lookup first, then one generated lookup target per non-empty bucket, refresh scheduling is configurable, timeout is enforced per run before starting the next lookup, and the current implementation is unit-tested but not yet proven in Docker as a standalone DHT refresh harness.
- `ZEI-85` now bridges the isolated Kad work into the actual runtime discovery flow: `NetworkManager` owns a shared libp2p address book + routing table + Kad query service, bootstrap and `/zeicoin` peer exchange addresses feed the same discovery source, and maintenance dials from address-book candidates instead of relying only on static bootstrap reconnects.
- `ZEI-86` now lives on top of `libp2p/dht/store.zig`: Kad value/provider records are kept in-memory with explicit deterministic value selection (`std.mem.order` on record bytes until namespaced validators exist), expiry, due-for-republish tracking, sender-matching validation for inbound `ADD_PROVIDER`, and handler coverage for `PUT_VALUE` / `GET_VALUE` / `ADD_PROVIDER` / `GET_PROVIDERS`.
- `ZEI-87` currently has a dedicated libp2p-only Docker proof rather than a full `zen_server` proof: `libp2p_testnode --kad` now hosts the Kad query service, the smoke validates 4-node Kad discovery convergence in Docker, and the post-seed check is intentionally weaker than full per-node session retention.
- The dedicated Kad Docker compose must use concrete per-container listen multiaddrs instead of `0.0.0.0`, otherwise identify/Kad replies advertise wildcard addresses that other nodes correctly refuse to dial.
- The dedicated Kad Docker image is built with `ReleaseSafe` because the current Zig threaded-I/O debug build hits a `BADF` assertion during peer shutdown in this smoke even though the release-safe run completes and preserves the intended proof.
- The old late-suite Yamux keepalive flake was test-structure noise rather than a transport bug: the deterministic fix was to remove EOF/half-close dependence from `yamux keepalive ping pong keeps session alive` and assert the post-idle request/reply exchange directly instead.
- The temporary Go interop harness is intentionally scratch-only and ignored for now: it lives under `tmp/go_kad_interop/` with logs under `tmp/kad-go-interop-*`, not under tracked `tools/` or `docker/scripts/`.
- The full local Go interop unblock required multiple protocol-layer fixes, not just one Noise tweak: explicit empty-prologue / empty-payload transcript hashing in Noise XX, Noise `extensions.stream_muxers` handling for early yamux, identify protobuf-delimited framing and real `public_key` bytes, responder-side multistream fallback for `/tls/1.0.0` → `/noise`, yamux acceptance of Go-opened `WINDOW_UPDATE|SYN` streams, and normalization of raw provider peer IDs in inbound `ADD_PROVIDER`.
- `ZEI-90` now has a passing local proof against `github.com/libp2p/go-libp2p v0.48.0` plus the checked-out `reference/go-libp2p-kad-dht`: the scratch probe successfully exercises `PING`, `FIND_NODE`, `PUT_VALUE` / `GET_VALUE`, and `ADD_PROVIDER` / `GET_PROVIDERS` against the ZeiCoin Kad node.
- The current automated validation already covers isolated Kad discovery convergence (`docker/scripts/test_libp2p_kad_smoke.sh`), real-runtime `zen_server` Kad refresh + block sync (`docker/scripts/test_libp2p_zen_server.sh`), and in-process transport/muxer churn (`libp2p/libp2p_stress.zig`); the biggest remaining robustness gaps are topology-heal after partition, rolling restart/churn, formalized Go interop in CI, and longer-duration soak/resource-bound coverage.
- The real-runtime Kad partition-heal proof now lives in `docker/scripts/verify_kad_partition_heal.sh`; to keep the signal focused on recovery rather than fork policy, the harness restarts `miner-2` in passive mode before isolating `node-1`, waits for the old peer sessions to drain fully, then verifies post-heal hash agreement at a fixed target height instead of chasing a moving mined tip.
- A real local `zen_server` client-only probe against the public bootstrap now exists as an operational data point: with `ZEICOIN_BIND_IP=127.0.0.1`, isolated temp data, `ZEICOIN_P2P_PORT=11901`, `ZEICOIN_API_PORT=10802`, and `ZEICOIN_BOOTSTRAP=/ip4/209.38.84.23/tcp/10801`, the node explicitly logged "node is behind NAT", connected outbound, synced to height 2, and maintained one live peer session. This supports the current claim that NATed nodes work well as outbound clients even before relay/hole-punch support lands.
- `ZEI-20` Notes still mention `zen_server` integration as unfinished, but archived `ZEI-11` and `ZEI-33` show that prerequisite is already complete; future DHT planning should treat libp2p host integration as done and focus on Kademlia-specific gaps.
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
- `./docker/scripts/verify_kad_partition_heal.sh`
- `./docker/scripts/verify_deep_reorg.sh`
- `./docker/scripts/verify_reorg_depth_rejection.sh`
- `bash tests/test_cli_smoke.sh`
- `bash tests/test_cli_functions.sh`
- `bash tests/test_cli_edge_cases.sh`
- `bash tests/test_peer_handshake.sh`

---

Full details: `docs/LIBP2P_INTEGRATION_PLAN.md`
