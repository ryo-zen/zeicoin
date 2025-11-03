// mempool_inv.zig - Mempool inventory message containing transaction hashes
const std = @import("std");
const types = @import("../../../types/types.zig");

/// MempoolInv message - contains transaction hashes from the mempool
/// Sent in response to a get_mempool request
pub const MempoolInvMessage = struct {
    tx_hashes: []types.Hash,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, hashes: []const types.Hash) !MempoolInvMessage {
        const tx_hashes = try allocator.alloc(types.Hash, hashes.len);
        for (hashes, tx_hashes) |src, *dst| {
            dst.* = src;
        }

        return MempoolInvMessage{
            .tx_hashes = tx_hashes,
            .allocator = allocator,
        };
    }

    pub fn encode(self: MempoolInvMessage, writer: anytype) !void {
        // Write the number of transaction hashes
        try writer.writeInt(u32, @intCast(self.tx_hashes.len), .little);

        // Write each hash
        for (self.tx_hashes) |hash| {
            try writer.writeAll(&hash);
        }
    }

    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !MempoolInvMessage {
        // Read the number of hashes
        const count = try reader.readInt(u32, .little);

        // Limit to prevent DOS attacks (max 50,000 transactions)
        if (count > 50000) {
            return error.TooManyTransactions;
        }

        // Allocate space for hashes
        const tx_hashes = try allocator.alloc(types.Hash, count);
        errdefer allocator.free(tx_hashes);

        // Read each hash
        for (tx_hashes) |*hash| {
            _ = try reader.readAll(&hash.*);
        }

        return MempoolInvMessage{
            .tx_hashes = tx_hashes,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MempoolInvMessage) void {
        if (self.tx_hashes.len > 0) {
            self.allocator.free(self.tx_hashes);
        }
    }
};