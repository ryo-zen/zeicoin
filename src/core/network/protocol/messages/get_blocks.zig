// get_blocks.zig - Request specific blocks by hash
// Used for downloading blocks after header validation

const std = @import("std");
const protocol = @import("../protocol.zig");
const types = @import("../../../types/types.zig");

pub const GetBlocksMessage = struct {
    /// List of block hashes to request
    hashes: []const types.Hash,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, hashes: []const types.Hash) !Self {
        if (hashes.len > protocol.MAX_BLOCKS_PER_MESSAGE) {
            return error.TooManyBlocks;
        }
        
        const hashes_copy = try allocator.dupe(types.Hash, hashes);
        return Self{ .hashes = hashes_copy };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.hashes);
    }
    
    pub fn encode(self: Self, writer: anytype) !void {
        try writer.writeInt(u32, @intCast(self.hashes.len), .little);
        
        for (self.hashes) |hash| {
            try writer.writeAll(&hash);
        }
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Self {
        const count = try reader.readInt(u32, .little);
        if (count > protocol.MAX_BLOCKS_PER_MESSAGE) {
            return error.TooManyBlocks;
        }
        
        const hashes = try allocator.alloc(types.Hash, count);
        errdefer allocator.free(hashes);
        
        for (hashes) |*hash| {
            try reader.readNoEof(hash);
        }
        
        return Self{ .hashes = hashes };
    }
    
    pub fn estimateSize(self: Self) usize {
        return 4 + self.hashes.len * @sizeOf(types.Hash);
    }
};

// Tests
test "GetBlocksMessage encode/decode" {
    const allocator = std.testing.allocator;
    
    const hashes = [_]types.Hash{
        [_]u8{1} ** 32,
        [_]u8{2} ** 32,
        [_]u8{3} ** 32,
    };
    
    var msg = try GetBlocksMessage.init(allocator, &hashes);
    defer msg.deinit(allocator);
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try msg.encode(buffer.writer());
    
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try GetBlocksMessage.decode(allocator, stream.reader());
    defer decoded.deinit(allocator);
    
    try std.testing.expectEqual(msg.hashes.len, decoded.hashes.len);
    for (msg.hashes, decoded.hashes) |original, decoded_hash| {
        try std.testing.expectEqualSlices(u8, &original, &decoded_hash);
    }
}