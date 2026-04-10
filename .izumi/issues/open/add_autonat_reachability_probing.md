---
id: add_autonat_reachability_probing
key: ZEI-104
title: "Implement AutoNAT v2 reachability probing for libp2p nodes"
type: Subtask
status: Backlog
priority: Medium
assignee: null
labels:
- libp2p
- networking
- nat
- reachability
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: null
comments: []
created_at: 2026-04-10T10:19:22+10:00
updated_at: 2026-04-10T10:52:17+10:00
---

## Summary

Implement libp2p AutoNAT v2-compatible reachability probing so ZeiCoin nodes can learn public dialability from external evidence instead of local heuristics alone. The implementation should follow the official per-address AutoNAT v2 flow: clients send a priority-ordered list of public address candidates plus a nonce on `/libp2p/autonat/2/dial-request`, servers dial exactly one selected address, validate delivery through `/libp2p/autonat/2/dial-back`, and apply the amplification-attack-prevention step when the selected address IP differs from the client's observed IP. Probe results should feed the reachability state introduced by `ZEI-103` and become the basis for later relay and DCUtR work.

## Acceptance Criteria

- [ ] ZeiCoin implements the AutoNAT v2 wire flow on `/libp2p/autonat/2/dial-request` and `/libp2p/autonat/2/dial-back`, using the spec message set (`DialRequest`, `DialResponse`, `DialDataRequest`, `DialDataResponse`, `DialBack`, `DialBackResponse`) with unsigned-varint length framing
- [ ] The AutoNAT client sends a priority-ordered list of public address candidates plus a fixed64 nonce; private, loopback, and link-local addresses are excluded from outbound probe requests
- [ ] The AutoNAT server selects the first address it is willing and able to dial and MUST NOT dial any other address from the request; unsupported-family and non-public addresses are refused rather than probed
- [ ] `DialResponse.addrIdx`, `DialResponse.status`, and `DialResponse.dialStatus` follow the spec semantics, including `E_REQUEST_REJECTED`, `E_DIAL_REFUSED`, `E_INTERNAL_ERROR`, `E_DIAL_ERROR`, `E_DIAL_BACK_ERROR`, and `OK`
- [ ] Successful dial-back is verified by nonce on `/libp2p/autonat/2/dial-back`; the client discards mismatched nonces and does not rely on the server peer ID for dial-back validation
- [ ] When the selected address IP differs from the client's observed IP, the server performs the AutoNAT v2 amplification-defense step using `DialDataRequest`; the client may accept or reject the cost; the byte target is configurable and defaults inside the spec's recommended 30k-100k range
- [ ] `DialDataResponse.data` chunks are capped at 4096 bytes and the server counts only payload bytes toward the requested total before attempting the dial
- [ ] Reachability evidence is tracked per address and rolled up into the local reachability state used by `ZEI-103`; default policy queries multiple distinct servers and does not promote an address or node to `public` on a single positive result
- [ ] Publicly reachable ZeiCoin nodes can serve AutoNAT probes without coupling the result to consensus, sync, or mempool behavior
- [ ] Tests cover the same-IP dial path, the different-IP amplification-defense path, refused/private-address cases, status-code handling, and an integration scenario showing that a NATed node stays Kad client while a public node is eligible for server mode once AutoNAT evidence exists

## Notes

- This is a follow-up to `ZEI-103`, not a substitute for it. `ZEI-103` already fixed startup Kad mode selection; `ZEI-104` should now replace or augment heuristic reachability evidence with AutoNAT v2 evidence.
- AutoNAT v2 is per-address, not only per-node. ZeiCoin can keep the current node-level runtime decision by deriving it from address-level evidence, but the stored probe results should stay address-scoped.
- Runtime Kad mode switching still depends on adding a host handler unregister path. `ZEI-104` can land the evidence pipeline first and feed startup mode selection before live mode flips are added.
- Keep this separate from relay and hole punching:
  - `ZEI-103` = startup reachability state + Kad mode selection
  - `ZEI-104` = AutoNAT v2 per-address external reachability evidence
  - later follow-up = relay reservations / DCUtR based on that evidence
- The AutoNAT v2 spec also recommends:
  - querying multiple servers and periodically rechecking addresses
  - refusing unsupported IPv4/IPv6 families
  - not reusing the server listen port for dial-back attempts, to avoid accidental hole punches
- Reference: https://github.com/libp2p/specs/blob/master/autonat/autonat-v2.md
