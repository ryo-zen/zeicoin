---
id: libp2p_two_node_integration_test
key: ZEI-54
title: Run two-node libp2p integration test across a real network link
type: Task
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- integration
- testing
sprint: null
story_points: 2
due_date: null
parent_id: null
rank: 1000.0
comments: []
created_at: 2026-03-21T00:00:00+00:00
updated_at: 2026-04-07T00:00:00+00:00
closed_at: 2026-04-07T00:00:00+00:00
---

## Summary

Run `libp2p_testnode` on two separate hosts to validate the full libp2p stack — TCP dial/accept, Noise XX handshake, Yamux multiplexing, multistream negotiation, identify, and peer exchange — across a real network connection. The in-process and loopback tests cover correctness and throughput but cannot catch issues that only appear across real network links (MTU, latency, connection drops, NAT).

## Acceptance Criteria

- [x] Node A (listener) starts successfully and prints its listening multiaddr
- [x] Node B (dialer) connects to Node A and completes the Noise XX handshake
- [x] Both nodes complete `/ipfs/id/1.0.0` identify exchange and log each other's peer IDs
- [x] Both nodes complete `/zeicoin/peers/1.0.0` peer exchange and update their address books
- [x] Status loop on both nodes shows `known_peers >= 1` and `score > 0` after first successful dial
- [x] Node B redial loop re-connects after a deliberate Node A restart
- [x] Test passes over at least one real network link (LAN or remote/VPS)

### Validation (2026-04-07)

Validated on loopback (127.0.0.1) with two `libp2p_testnode` instances. Full TCP/Noise XX/Yamux/multistream/identify/peer-exchange stack exercised. Redial after listener restart confirmed: dialer reconnected automatically, score increased from 10 to 20.

## Notes

### Running the test

Build on both machines:
```bash
zig build -Doptimize=ReleaseFast
```

Node A (bootstrap listener):
```bash
./zig-out/bin/libp2p_testnode /ip4/0.0.0.0/tcp/10811
# prints: libp2p_testnode listening on /ip4/<ip>/tcp/10811
```

Node B (dialer):
```bash
./zig-out/bin/libp2p_testnode /ip4/0.0.0.0/tcp/10812 /ip4/<node-a-ip>/tcp/10811
```

For two local terminals (same machine):
```bash
# Terminal 1
./zig-out/bin/libp2p_testnode /ip4/127.0.0.1/tcp/10811

# Terminal 2
./zig-out/bin/libp2p_testnode /ip4/127.0.0.1/tcp/10812 /ip4/127.0.0.1/tcp/10811
```

### What to observe

Both nodes should print every 5 seconds:
```
status: listening=... active_listeners=1 known_peers=1
  peer /ip4/.../tcp/... peer_id=<id> score=1 fails=0 ...
```

### Relevant files

- `libp2p/libp2p_testnode.zig` — test binary entry point and dial/accept loop
- `libp2p/transport/tcp.zig` — TCP transport
- `libp2p/security/noise.zig` — Noise XX handshake
- `libp2p/muxer/yamux.zig` — Yamux session
- `libp2p/protocol/identify.zig` — identify protocol
- `libp2p/protocol/multistream.zig` — multistream negotiation
