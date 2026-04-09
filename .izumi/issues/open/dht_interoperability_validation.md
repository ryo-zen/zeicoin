---
id: dht_interoperability_validation
key: ZEI-90
title: Validate Kademlia interoperability against an external libp2p implementation
type: Subtask
status: Backlog
priority: Medium
assignee: null
labels:
- libp2p
- dht
- networking
- testing
- interop
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: null
comments: []
created_at: 2026-04-09T11:01:53+10:00
updated_at: 2026-04-09T11:01:53+10:00
---

## Summary

Validate that ZeiCoin's `/kad/1.0.0` implementation interoperates with at least one real libp2p Kad implementation rather than only with ZeiCoin nodes. This is the proof point that the project is actually speaking the canonical protocol instead of a self-consistent fork.

## Acceptance Criteria

- [ ] Test plan names the external implementation and version used for validation
- [ ] ZeiCoin can complete at least one successful `FIND_NODE` exchange with the external implementation
- [ ] ZeiCoin can parse and emit Kad protobuf messages accepted by the external implementation
- [ ] If value/provider support is enabled, at least one record/provider flow is exercised successfully or any incompatibility is documented explicitly
- [ ] Validation artifacts are documented in the ticket notes or linked test script output

## Notes

- Good initial targets are the go-libp2p or rust-libp2p Kad implementations
- This should happen after the codec and core query path are stable, not before
- Docker-only ZeiCoin self-tests are not enough to claim real `/kad/1.0.0` compatibility
