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
        try writer.writeInt(u32, self.height, .big);
        try writer.writeAll(&self.hash);
        try writer.writeByte(if (self.exists) 1 else 0);
    }

    pub fn deserialize(reader: anytype) !BlockHashMessage {
        var msg: BlockHashMessage = undefined;
        msg.height = try reader.readInt(u32, .big);
        _ = try reader.readAll(&msg.hash);
        const exists_byte = try reader.readByte();
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