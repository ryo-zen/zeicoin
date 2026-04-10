// Isolated libp2p suite for incremental Zig 0.16 migration.
// Keep this independent from src/lib.zig tests.

test {
    _ = @import("dht/message.zig");
    _ = @import("dht/query.zig");
    _ = @import("dht/routing_table.zig");
    _ = @import("dht/store.zig");
    _ = @import("multiaddr/multiaddr.zig");
    _ = @import("peer/address_book.zig");
    _ = @import("peer/peer_id.zig");
    _ = @import("protocol/identify.zig");
    _ = @import("security/noise.zig");
    _ = @import("libp2p_bench.zig");
    _ = @import("muxer/yamux.zig");
    _ = @import("muxer/test_yamux.zig");
    _ = @import("transport/tcp.zig");
    _ = @import("protocol/multistream.zig");
    _ = @import("host/handler_registry.zig");
    _ = @import("host/host.zig");
}
