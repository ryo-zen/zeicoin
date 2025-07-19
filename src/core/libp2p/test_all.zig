// test_all.zig - Run all libp2p tests

const std = @import("std");

test {
    _ = @import("multiaddr/multiaddr.zig");
    _ = @import("transport/tcp.zig");
    _ = @import("transport/tcp_async.zig");
    _ = @import("transport/test_tcp_async.zig");
    _ = @import("transport/test_tcp_async_context.zig");
    _ = @import("protocol/multistream.zig");
    _ = @import("protocol/test_multistream_async.zig");
    _ = @import("protocol/test_multistream_parser.zig");
    _ = @import("protocol/test_multistream_negotiator.zig");
    _ = @import("libp2p.zig");
}