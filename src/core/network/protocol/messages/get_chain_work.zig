// get_chain_work.zig - Request cumulative chain work from peer
// Used for reorganization decisions - determines which chain has more proof-of-work

const std = @import("std");
const types = @import("../../../types/types.zig");

/// Request cumulative chain work from a peer for a range of blocks
pub const GetChainWorkMessage = struct {
    start_height: u32,
    end_height: u32,

    pub fn encode(self: GetChainWorkMessage, writer: anytype) !void {
        try writer.writeInt(u32, self.start_height, .little);
        try writer.writeInt(u32, self.end_height, .little);
    }

    pub fn decode(_: std.mem.Allocator, reader: anytype) !GetChainWorkMessage {
        return GetChainWorkMessage{
            .start_height = try reader.readInt(u32, .little),
            .end_height = try reader.readInt(u32, .little),
        };
    }

    pub fn estimateSize(_: GetChainWorkMessage) usize {
        return @sizeOf(u32) + @sizeOf(u32); // 8 bytes
    }
};

/// Response containing cumulative chain work for requested range
pub const ChainWorkResponseMessage = struct {
    total_work: types.ChainWork, // u256 cumulative work

    pub fn encode(self: ChainWorkResponseMessage, writer: anytype) !void {
        // Serialize u256 as bytes (32 bytes)
        const work_bytes = std.mem.asBytes(&self.total_work);
        try writer.writeAll(work_bytes);
    }

    pub fn decode(_: std.mem.Allocator, reader: anytype) !ChainWorkResponseMessage {
        var work: types.ChainWork = undefined;
        const work_bytes = std.mem.asBytes(&work);
        _ = try reader.readAll(work_bytes);

        return ChainWorkResponseMessage{
            .total_work = work,
        };
    }

    pub fn estimateSize(_: ChainWorkResponseMessage) usize {
        return 32; // u256 = 32 bytes
    }
};
