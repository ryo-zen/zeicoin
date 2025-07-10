// hash.zig - Hash type for network protocol
// Provides consistent hash handling across the protocol

const std = @import("std");
const types = @import("../../../types/types.zig");

// Re-export the core hash type
pub const Hash = types.Hash;

/// Hash list for efficient transmission
pub const HashList = struct {
    hashes: []const Hash,
    
    pub fn encode(self: HashList, writer: anytype) !void {
        try writer.writeInt(u32, @intCast(self.hashes.len), .little);
        for (self.hashes) |hash| {
            try writer.writeAll(&hash);
        }
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype, max_count: usize) !HashList {
        const count = try reader.readInt(u32, .little);
        if (count > max_count) {
            return error.TooManyHashes;
        }
        
        const hashes = try allocator.alloc(Hash, count);
        errdefer allocator.free(hashes);
        
        for (hashes) |*hash| {
            try reader.readNoEof(hash);
        }
        
        return .{ .hashes = hashes };
    }
    
    pub fn deinit(self: *HashList, allocator: std.mem.Allocator) void {
        allocator.free(self.hashes);
    }
};