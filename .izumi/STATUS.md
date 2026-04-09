# ZeiCoin — Working State

> Read this first. Update this last.

---

## Current State

**Date:** 2026-04-09
**Branch:** `libp2p-integration`
**Active initiative:** Post-rollout testnet validation and hardening

**Last worked on:** 2026-04-09 — Implemented the minimal `ZEI-93` unblocker: `libp2p/protocol/identify.zig` now skips unknown protobuf fields for wire types `0/1/2/5`, preserves current decode behavior for known fields, and `zig build test-libp2p` is green with new regression coverage.
**Next step:** Start Kad routing-table / `FIND_NODE` work (`ZEI-81` / `ZEI-83`) on top of the now-complete prerequisite set, or audit `ZEI-89` resource-limiting expectations before external interop claims.
**In flight:** `libp2p/protocol/identify.zig` has the `ZEI-93` minimal hardening and tests locally; session state still needs the final commit/push if not already done.

---

## Project Summary

| State | Summary |
|-------|---------|
| Done | Core libp2p integration is in place: protocol adapter, bootstrap multiaddr handling, peer-manager host wiring, identify handler, connection-pool dedup, and Docker validation. |
| Done | Reorg hardening landed through `ZEI-68`, including early competing-branch validation before work comparison and before canonical-state mutation. |
| Done | Current validation is green across Zig tests, isolated libp2p tests, Docker libp2p smoke, and Docker deep reorg recovery. |
| In play | `ZEI-70` remains the umbrella for the reorg/replay/state-root hardening queue. |
| Done | `ZEI-72` rollout blocker set is complete and the branch has been deployed to the resettable testnet. |
| In play | The project is now at “live testnet deployment with Docker-verified libp2p + Docker-verified reorg recovery; remaining work is real-network validation, correctness hardening, and follow-up cleanup.” |
| Done | `ZEI-71` landed: `account_count` now tracks unique persisted accounts across direct writes, batch commits, rollback/reset, and explicit restore metadata; impact was classified as observability-only. |
| Done | `ZEI-64` landed: `executeReorg()` no longer rejects shorter competing branches solely on height, and a regression test now covers the shorter-but-heavier winner case. |
| Done | All first-testnet blockers complete: `ZEI-71`, `ZEI-64`, `ZEI-21`, `ZEI-66`, `ZEI-52`, `ZEI-54`. Epic `ZEI-72` is closed. |
| Deferred | `ZEI-20` Kademlia DHT and mainnet-only compatibility/infrastructure work are explicitly out of scope for the first testnet rollout. |

---

## Decisions Made

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
- `./docker/scripts/verify_deep_reorg.sh`
- `./docker/scripts/verify_reorg_depth_rejection.sh`
- `bash tests/test_cli_smoke.sh`
- `bash tests/test_cli_functions.sh`
- `bash tests/test_cli_edge_cases.sh`
- `bash tests/test_peer_handshake.sh`

---

Full details: `docs/LIBP2P_INTEGRATION_PLAN.md`
