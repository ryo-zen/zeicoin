// block_hash.zig - Response with block hash at specific height
// Used for consensus verification during sync

const std = @import("std");
const types = @import("../../../types/types.zig");

/// Response containing block hash at requested height
pub const BlockHashMessage = struct {
    height: u32,
    hash: types.Hash,
    exists: bool, // false if peer doesn't have block at this height

    pub fn serialize(self: BlockHashMessage, writer: anytype) !void {
        var w = writer;
        try w.writeInt(u32, self.height, .big);
        try w.writeAll(&self.hash);
        try w.writeByte(if (self.exists) 1 else 0);
    }

    pub fn deserialize(reader: anytype) !BlockHashMessage {
        var msg: BlockHashMessage = undefined;
        msg.height = try reader.takeInt(u32, .big);
        try reader.readSliceAll(&msg.hash);
        const exists_byte = try reader.takeByte();
        msg.exists = exists_byte != 0;
        return msg;
    }

    pub fn encode(self: BlockHashMessage, writer: anytype) !void {
        try self.serialize(writer);
    }

    pub fn estimateSize(self: BlockHashMessage) usize {
        _ = self;
        return @sizeOf(u32) + 32 + 1; // 4 bytes height + 32 bytes hash + 1 byte exists flag = 37 bytes
    }

    pub fn deinit(self: *BlockHashMessage, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
        // No dynamic memory to free
    }
};
