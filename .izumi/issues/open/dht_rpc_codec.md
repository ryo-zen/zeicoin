---
id: dht_rpc_codec
key: ZEI-82
title: Implement Kademlia RPC protobuf codec for /kad/1.0.0
type: Subtask
status: InProgress
priority: High
assignee: null
labels:
- libp2p
- dht
- networking
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1000.0
comments: []
created_at: 2026-04-09T00:00:00+00:00
updated_at: 2026-04-09T13:03:18+10:00
closed_at: null
---

## Summary

Implement the Kademlia wire protocol codec in `libp2p/dht/message.zig`. Messages use unsigned-varint length-prefixed protobuf encoding on the `/kad/1.0.0` protocol ID, per the libp2p Kademlia spec.

## Acceptance Criteria

- [ ] Full protobuf schema: `Record` (key, value, timeReceived), `Message` (type, key, record, closerPeers, providerPeers), `Message.Peer` (id, addrs, connection), `ConnectionType` enum, `MessageType` enum
- [ ] All six MessageTypes: PUT_VALUE(0), GET_VALUE(1), ADD_PROVIDER(2), GET_PROVIDERS(3), FIND_NODE(4), PING(5)
- [ ] Unsigned-varint length-prefix framing per multiformats unsigned-varint spec
- [ ] Stream-per-RPC: open stream, send request, read response, close stream. Reset stream on error.
- [ ] Stream reuse: must handle additional RPC requests on an incoming stream (spec requirement)
- [ ] Peer info serialization: PeerId bytes + repeated multiaddr bytes + ConnectionType
- [ ] Record serialization includes `key`, `value`, and `timeReceived`, with unknown protobuf fields ignored safely on decode
- [ ] PING is deprecated — handle incoming PING for backward compat but never actively send
- [ ] Unit tests for round-trip encode/decode of all message types

## Notes

- Create `libp2p/dht/message.zig`
- Spec reference: `reference/libp2p-specs/kad-dht/README.md` (protobuf schema at line 403)
- This is step 2 in the implementation order from ZEI-20
- `clusterLevelRaw` (field 10) is NOT USED but must be handled in the codec for compat
- Keep the codec suitable for external interop, not just ZeiCoin-to-ZeiCoin round-trips
- Current implementation boundary: `ZEI-82` owns protobuf/uvarint codec plus framed Kad message read/write helpers; inbound `/kad/1.0.0` handler loops and request semantics that span multiple RPCs remain with `ZEI-83`
