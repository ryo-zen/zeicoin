// get_headers.zig - Request headers from peer
// Uses block locator pattern for efficient sync

const std = @import("std");
const protocol = @import("../protocol.zig");
const types = @import("../../../types/types.zig");

pub const GetHeadersMessage = struct {
    /// Block locator - hashes at exponentially increasing distances
    block_locator: []const types.Hash,
    /// Stop at this hash (or chain tip if zero)
    stop_hash: types.Hash,
    
    const Self = @This();
    
    pub fn init(
        allocator: std.mem.Allocator,
        locator: []const types.Hash,
        stop: types.Hash,
    ) !Self {
        const locator_copy = try allocator.dupe(types.Hash, locator);
        return Self{
            .block_locator = locator_copy,
            .stop_hash = stop,
        };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.block_locator);
    }
    
    pub fn encode(self: Self, writer: anytype) !void {
        // Write locator count
        try writer.writeInt(u32, @intCast(self.block_locator.len), .little);
        
        // Write locator hashes
        for (self.block_locator) |hash| {
            try writer.writeAll(&hash);
        }
        
        // Write stop hash
        try writer.writeAll(&self.stop_hash);
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Self {
        // Read locator count
        const count = try reader.readInt(u32, .little);
        if (count > 64) { // Reasonable limit
            return error.TooManyLocatorHashes;
        }
        
        // Read locator hashes
        const locator = try allocator.alloc(types.Hash, count);
        errdefer allocator.free(locator);
        
        for (locator) |*hash| {
            try reader.readNoEof(hash);
        }
        
        // Read stop hash
        var stop_hash: types.Hash = undefined;
        try reader.readNoEof(&stop_hash);
        
        return Self{
            .block_locator = locator,
            .stop_hash = stop_hash,
        };
    }
    
    pub fn estimateSize(self: Self) usize {
        return 4 + // count
            self.block_locator.len * @sizeOf(types.Hash) +
            @sizeOf(types.Hash); // stop hash
    }
};

// Block locator builder
pub const BlockLocator = struct {
    /// Build a block locator from current height
    /// Returns hashes at: height, height-1, height-2, height-4, height-8, etc.
    pub fn build(
        allocator: std.mem.Allocator,
        getHashFn: *const fn (height: u32) ?types.Hash,
        current_height: u32,
    ) ![]types.Hash {
        var locator = std.ArrayList(types.Hash).init(allocator);
        defer locator.deinit();
        
        var height = current_height;
        var step: u32 = 1;
        
        while (height > 0) {
            if (getHashFn(height)) |hash| {
                try locator.append(hash);
            }
            
            // Exponential backoff
            if (locator.items.len > 10) {
                step *= 2;
            }
            
            if (height > step) {
                height -= step;
            } else {
                height = 0;
            }
        }
        
        // Always include genesis
        if (getHashFn(0)) |genesis_hash| {
            try locator.append(genesis_hash);
        }
        
        return try locator.toOwnedSlice();
    }
};

// Tests
test "GetHeadersMessage encode/decode" {
    const allocator = std.testing.allocator;
    
    const locator = [_]types.Hash{
        [_]u8{1} ** 32,
        [_]u8{2} ** 32,
        [_]u8{3} ** 32,
    };
    const stop_hash = [_]u8{0xFF} ** 32;
    
    var msg = try GetHeadersMessage.init(allocator, &locator, stop_hash);
    defer msg.deinit(allocator);
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try msg.encode(buffer.writer());
    
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try GetHeadersMessage.decode(allocator, stream.reader());
    defer decoded.deinit(allocator);
    
    try std.testing.expectEqual(msg.block_locator.len, decoded.block_locator.len);
    try std.testing.expectEqualSlices(u8, &msg.stop_hash, &decoded.stop_hash);
}