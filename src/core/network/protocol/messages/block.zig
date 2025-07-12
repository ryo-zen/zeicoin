// block.zig - Block message for transmitting full blocks

const std = @import("std");
const types = @import("../../../types/types.zig");
const serialize = @import("../../../storage/serialize.zig");

pub const BlockMessage = struct {
    block: types.Block,
    
    pub fn encode(self: BlockMessage, writer: anytype) !void {
        try serialize.serialize(writer, self.block);
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !BlockMessage {
        return .{ .block = try serialize.deserialize(reader, types.Block, allocator) };
    }
    
    pub fn deinit(self: *BlockMessage, allocator: std.mem.Allocator) void {
        self.block.deinit(allocator);
    }
    
    pub fn estimateSize(self: BlockMessage) usize {
        _ = self;
        return 1024 * 1024; // 1MB estimate
    }
};