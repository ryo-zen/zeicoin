---
id: validate_zen_server_libp2p_integration_in_docker
key: ZEI-60
title: "Validate zen_server libp2p integration in Docker"
type: Subtask
status: Done
priority: Medium
assignee: null
labels: ["libp2p", "docker", "testing", "integration"]
sprint: null
story_points: null
due_date: null
parent_id: libp2p_zen_server_integration
rank: null
comments: []
created_at: 2026-03-22T05:37:57.386085851+00:00
updated_at: 2026-03-30T19:20:50+11:00
---

## Summary

Validate the newly integrated libp2p `zen_server` path in Docker before moving to real-host testing. This should prove that multiple `zen_server` containers can bootstrap with multiaddr config, establish libp2p connections, sync over Noise + yamux, and survive restart/reconnect scenarios in a non-loopback environment.

## Acceptance Criteria

- [x] A Docker-based `zen_server` topology starts with libp2p-era bootstrap config using multiaddrs, not legacy `host:port`
- [x] At least two `zen_server` containers complete the libp2p connection path successfully and reach steady-state sync without crashing
- [x] Restarting a bootstrap node causes at least one peer to redial and reconnect successfully
- [x] Test logs show the libp2p path is being used end-to-end and do not require `209.38.84.23` or any other legacy pre-libp2p node
- [x] The exact Docker command sequence and expected pass/fail signals are documented for reruns

## Notes

Likely touch points:

- `docker/docker-compose.yml` or a dedicated libp2p-era compose file for `zen_server`
- Docker init scripts that still assume legacy bootstrap formatting
- `src/core/network/bootstrap.zig` if any compose-time assumptions need to be aligned with the current multiaddr parser

Completed on `libp2p-integration`.
- `./docker/scripts/test_libp2p_zen_server.sh` now serves as the documented rerun command with explicit pass/fail behavior.
- Restart/reconnect validation is green, and current logs stay on the Docker-local libp2p topology rather than falling back to legacy external bootstrap peers.
- This Docker validation remained a prerequisite for `ZEI-54`; it does not replace the final real-host test.
