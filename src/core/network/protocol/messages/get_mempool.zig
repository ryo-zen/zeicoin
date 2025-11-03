// get_mempool.zig - Request mempool transaction inventory from a peer
const std = @import("std");

/// GetMempool message - requests the current mempool transaction inventory
/// The peer will respond with a mempool_inv message containing transaction hashes
pub const GetMempoolMessage = struct {
    // No payload - just a request flag

    pub fn init() GetMempoolMessage {
        return .{};
    }

    pub fn encode(self: GetMempoolMessage, writer: anytype) !void {
        _ = self;
        _ = writer;
        // No data to encode
    }

    pub fn decode(reader: anytype) !GetMempoolMessage {
        _ = reader;
        // No data to decode
        return GetMempoolMessage{};
    }

    pub fn deinit(self: *GetMempoolMessage, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
        // Nothing to clean up
    }
};