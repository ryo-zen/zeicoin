---
id: kad_external_interop_followup
key: ZEI-95
title: Complete external Kad interoperability validation after Noise fix
type: Task
status: Done
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
parent_id: dht_interoperability_validation
rank: 1775711759957.0
comments: []
created_at: 2026-04-09T15:05:00+10:00
updated_at: 2026-04-09T07:46:50.557939887+00:00
closed_at: 2026-04-09T07:46:50.557939119+00:00
---

## Summary

Finish the external `/kad/1.0.0` interoperability proof once the transport layer can talk to a real go-libp2p host. This should use the existing Go harness to exercise real Kad RPCs in both directions instead of relying only on ZeiCoin self-tests.

## Acceptance Criteria

- [x] ZeiCoin successfully bootstraps to the Go interop host and triggers at least one observed `FIND_NODE`
- [x] Go-originated `FIND_NODE` against ZeiCoin succeeds
- [x] Go-originated `PUT_VALUE` / `GET_VALUE` succeed against ZeiCoin or any incompatibility is documented explicitly
- [x] Go-originated `ADD_PROVIDER` / `GET_PROVIDERS` succeed against ZeiCoin or any incompatibility is documented explicitly
- [x] Validation artifacts are captured in the ticket notes or script logs

## Notes

- Depends on `ZEI-94`
- Relevant files: `tools/go_kad_interop/`, `docker/scripts/test_kad_go_interop.sh`, `.izumi/issues/open/dht_interoperability_validation.md`
