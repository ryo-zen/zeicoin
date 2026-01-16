// get_block_hash.zig - Request block hash at specific height
// Used for consensus verification during sync

const std = @import("std");

/// Request block hash at a specific height from a peer
pub const GetBlockHashMessage = struct {
    height: u32,

    pub fn serialize(self: GetBlockHashMessage, writer: anytype) !void {
        try writer.writeInt(u32, self.height, .big);
    }

    pub fn deserialize(reader: anytype) !GetBlockHashMessage {
        return GetBlockHashMessage{
            .height = try reader.readInt(u32, .big),
        };
    }

    pub fn encode(self: GetBlockHashMessage, writer: anytype) !void {
        try self.serialize(writer);
    }

    pub fn estimateSize(self: GetBlockHashMessage) usize {
        _ = self;
        return @sizeOf(u32); // 4 bytes for height
    }

    pub fn deinit(self: *GetBlockHashMessage, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
        // No dynamic memory to free
    }
};