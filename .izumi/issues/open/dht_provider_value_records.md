---
id: dht_provider_value_records
key: ZEI-86
title: Decide scope for provider and value record support
type: Subtask
status: Backlog
priority: Low
assignee: null
labels:
- libp2p
- dht
- networking
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

The full libp2p Kademlia spec includes PUT_VALUE, GET_VALUE, ADD_PROVIDER, and GET_PROVIDERS. ZeiCoin currently only needs peer routing. This ticket is a scope decision: either implement the full record layer or explicitly re-scope ZEI-20 to peer-routing-only and rename the protocol if needed.

## Acceptance Criteria

- [ ] Decision documented: full DHT records vs peer-routing-only
- [ ] If peer-routing-only: ZEI-20 acceptance criteria updated, protocol ID reviewed
- [ ] If full records: implement PUT_VALUE/GET_VALUE/ADD_PROVIDER/GET_PROVIDERS with storage, refresh, and expiry
- [ ] Follow-up tickets created for whichever path is chosen

## Notes

- This is step 6 in the implementation order from ZEI-20
- The spec warns against using `/kad/1.0.0` protocol ID for a narrower-than-spec implementation
- Peer-routing-only is likely sufficient for ZeiCoin's needs — but the decision should be explicit
