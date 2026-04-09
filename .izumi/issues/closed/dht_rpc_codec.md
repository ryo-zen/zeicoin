---
id: dht_rpc_codec
key: ZEI-82
title: Implement Kademlia RPC protobuf codec for /kad/1.0.0
type: Subtask
status: Done
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
updated_at: 2026-04-09T07:52:26.403560344+00:00
closed_at: 2026-04-09T07:52:26.403559477+00:00
---

## Summary

Implement the Kademlia wire protocol codec in `libp2p/dht/message.zig`. Messages use unsigned-varint length-prefixed protobuf encoding on the `/kad/1.0.0` protocol ID, per the libp2p Kademlia spec.

## Acceptance Criteria

- [x] Full protobuf schema: `Record` (key, value, timeReceived), `Message` (type, key, record, closerPeers, providerPeers), `Message.Peer` (id, addrs, connection), `ConnectionType` enum, `MessageType` enum
- [x] All six MessageTypes: PUT_VALUE(0), GET_VALUE(1), ADD_PROVIDER(2), GET_PROVIDERS(3), FIND_NODE(4), PING(5)
- [x] Unsigned-varint length-prefix framing per multiformats unsigned-varint spec
- [x] Stream-per-RPC: open stream, send request, read response, close stream. Reset stream on error.
- [x] Peer info serialization: PeerId bytes + repeated multiaddr bytes + ConnectionType
- [x] Record serialization includes `key`, `value`, and `timeReceived`, with unknown protobuf fields ignored safely on decode
- [x] PING is deprecated — handle incoming PING for backward compat but never actively send
- [x] Unit tests for round-trip encode/decode of all message types

## Notes

- Create `libp2p/dht/message.zig`
- Spec reference: `reference/libp2p-specs/kad-dht/README.md` (protobuf schema at line 403)
- This is step 2 in the implementation order from ZEI-20
- `clusterLevelRaw` (field 10) is NOT USED but must be handled in the codec for compat
- Keep the codec suitable for external interop, not just ZeiCoin-to-ZeiCoin round-trips
- Current implementation boundary: `ZEI-82` owns protobuf/uvarint codec plus framed Kad message read/write helpers; inbound `/kad/1.0.0` handler loops and request semantics that span multiple RPCs remain with `ZEI-83`
- Stream reuse on an inbound `/kad/1.0.0` stream is tracked and validated under `ZEI-83`, not `ZEI-82`
