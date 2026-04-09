---
id: add_dns_and_ipv6_multiaddr_support
key: ZEI-92
title: Add DNS and IPv6 multiaddr support to peer discovery
type: Subtask
status: Done
priority: High
assignee: null
labels:
- libp2p
- dht
- networking
- interop
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1775697307709.0
comments: []
created_at: 2026-04-09T11:14:22+10:00
updated_at: 2026-04-09T07:46:50.553156353+00:00
closed_at: 2026-04-09T07:46:50.553155698+00:00
---

## Summary

Stop dropping valid non-IPv4 peer addresses. ZeiCoin's current peer discovery path only treats `/ip4/.../tcp/...` multiaddrs as dialable, which blocks interoperability with peers advertised through identify or Kad using IPv6 or DNS-based TCP multiaddrs.

## Acceptance Criteria

- [x] Peer discovery accepts dialable `/ip4`, `/ip6`, and DNS-based TCP multiaddrs instead of hard-rejecting non-IPv4 addresses
- [x] Multiaddr canonicalization and deduplication continue to work across supported address families
- [x] Identify self-observation and advertised-address learning no longer discard valid IPv6 or DNS addresses
- [x] Host identify responses preserve observed IPv6 addresses when available
- [x] Dial-candidate selection ignores only truly unusable addresses, not entire address families
- [x] Tests cover learning and preserving IPv6 and DNS multiaddrs through identify and peerbook paths

## Notes

- Primary files: `libp2p/peer/address_book.zig`, `libp2p/host/host.zig`
- This should land with or immediately after `ZEI-91`
- Kad `Message.Peer` records commonly carry repeated addrs, so address-family support is a prerequisite for meaningful interop
