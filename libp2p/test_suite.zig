// Isolated libp2p suite for incremental Zig 0.16 migration.
// Keep this independent from src/lib.zig tests.

test {
    _ = @import("multiaddr/multiaddr.zig");
    _ = @import("peer/peer_id.zig");
    _ = @import("protocol/identify.zig");
    _ = @import("security/noise.zig");
    _ = @import("libp2p_bench.zig");
    _ = @import("muxer/yamux.zig");
    _ = @import("muxer/test_yamux.zig");
    _ = @import("transport/tcp.zig");
    _ = @import("protocol/multistream.zig");
}
