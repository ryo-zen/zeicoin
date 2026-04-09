---
id: harden_identify_decoder_for_interop
key: ZEI-93
title: Harden identify protobuf decoding for external interoperability
type: Subtask
status: Done
priority: Medium
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
updated_at: 2026-04-09T02:20:00.767488539+00:00
closed_at: 2026-04-09T02:20:00.767487768+00:00
---

## Summary

Make `libp2p/protocol/identify.zig` tolerant of foreign or future identify payloads by skipping unknown protobuf fields generically instead of rejecting any unexpected wire type. Kad interop depends on identify for protocol advertisement and address learning, so ZeiCoin should harden this before claiming real external compatibility.

## Acceptance Criteria

- [x] Identify decode skips unknown protobuf fields for all supported wire types instead of erroring on non-length-delimited fields
- [x] Known identify fields continue to decode exactly as today
- [x] Malformed protobuf payloads still fail closed with explicit errors
- [x] Tests cover at least one identify payload containing extra unknown fields from another implementation shape
- [x] `zig build test-libp2p` passes with the hardened decoder

## Notes

- Primary file: `libp2p/protocol/identify.zig`
- This should land before broad Kad interop claims and before `ZEI-90`
- Keep the decoder strict on malformed frames but permissive on unknown well-formed fields
- Validation: `zig build test-libp2p`
