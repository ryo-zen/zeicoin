---
id: libp2p_extract_address_book
key: ZEI-88
title: Extract SharedAddressBook from libp2p_testnode into reusable module
type: Task
status: Backlog
priority: High
assignee: null
labels:
- libp2p
- networking
- refactor
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: null
comments: []
created_at: 2026-04-09T00:00:00+00:00
updated_at: 2026-04-09T00:00:00+00:00
---

## Summary

`SharedAddressBook` is currently defined inline in `libp2p/libp2p_testnode.zig`. The DHT needs to feed discovered peers into the address book, so it must be a standalone module importable by both the DHT layer and the application layer.

## Acceptance Criteria

- [ ] Extract `SharedAddressBook` to `libp2p/peer/address_book.zig`
- [ ] Export via `libp2p/api.zig` as `pub const AddressBook = ...`
- [ ] `libp2p_testnode.zig` imports from the new module instead of defining inline
- [ ] All existing address book functionality preserved (learn, dial success/failure, scoring, backoff, pruning, snapshots, self-observations)
- [ ] Interface supports adding peers by PeerId + multiaddrs (what the DHT will provide)
- [ ] `zig build test` passes
- [ ] `zig build check` passes

## Notes

- Blocker for ZEI-81 through ZEI-87 (DHT needs to write discovered peers into address book)
- Keep the API surface minimal — only expose what the DHT and application layers need
- The DHT spec requires storing multiaddrs from every encountered Peer record in the peerbook
