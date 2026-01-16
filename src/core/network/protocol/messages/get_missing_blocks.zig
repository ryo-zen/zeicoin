// get_missing_blocks.zig - Messages for requesting specific blocks by hash
// Part of Fix 3: Missing Block Request Logic for orphan block resolution

const std = @import("std");
const Allocator = std.mem.Allocator;
const Block = @import("../../../types/types.zig").Block;
const serialize = @import("../../../storage/serialize.zig");

/// Request specific blocks by their hash
/// Optimized for small, targeted requests (vs batch sync)
pub const GetMissingBlocksMessage = struct {
    /// Array of block hashes to request (max 10 per request)
    block_hashes: std.ArrayList([32]u8),

    /// Maximum blocks to request in single message
    pub const MAX_MISSING_BLOCKS: usize = 10;

    pub fn init(allocator: Allocator) GetMissingBlocksMessage {
        return .{
            .block_hashes = std.ArrayList([32]u8).init(allocator),
        };
    }

    pub fn deinit(self: *GetMissingBlocksMessage, allocator: Allocator) void {
        _ = allocator;
        self.block_hashes.deinit();
    }

    pub fn addHash(self: *GetMissingBlocksMessage, hash: [32]u8) !void {
        if (self.block_hashes.items.len >= MAX_MISSING_BLOCKS) {
            return error.TooManyHashes;
        }
        try self.block_hashes.append(hash);
    }

    /// Encode message for network transmission
    pub fn encode(self: GetMissingBlocksMessage, writer: anytype) !void {
        const count = self.block_hashes.items.len;

        // Validate count
        if (count > MAX_MISSING_BLOCKS) {
            return error.TooManyHashes;
        }

        // Write count (1 byte is enough for max 10)
        try writer.writeByte(@intCast(count));

        // Write each hash (32 bytes each)
        for (self.block_hashes.items) |hash| {
            try writer.writeAll(&hash);
        }
    }

    /// Decode message from network transmission
    pub fn decode(allocator: Allocator, reader: anytype) !GetMissingBlocksMessage {
        var msg = GetMissingBlocksMessage.init(allocator);
        errdefer msg.deinit(allocator);

        // Read count
        const count = try reader.readByte();

        if (count > MAX_MISSING_BLOCKS) {
            return error.TooManyHashes;
        }

        // Read each hash
        var i: usize = 0;
        while (i < count) : (i += 1) {
            var hash: [32]u8 = undefined;
            _ = try reader.readAll(&hash);
            try msg.block_hashes.append(hash);
        }

        return msg;
    }

    /// Estimate encoded size
    pub fn estimateSize(self: GetMissingBlocksMessage) usize {
        return 1 + (self.block_hashes.items.len * 32);
    }
};

/// Response containing requested blocks
pub const MissingBlocksResponseMessage = struct {
    /// The requested blocks (in any order, receiver will sort)
    blocks: std.ArrayList(Block),

    pub fn init(allocator: Allocator) MissingBlocksResponseMessage {
        return .{
            .blocks = std.ArrayList(Block).init(allocator),
        };
    }

    pub fn deinit(self: *MissingBlocksResponseMessage, allocator: Allocator) void {
        for (self.blocks.items) |*block| {
            block.deinit(allocator);
        }
        self.blocks.deinit();
    }

    pub fn addBlock(self: *MissingBlocksResponseMessage, block: Block) !void {
        try self.blocks.append(block);
    }

    /// Encode message (reuse existing block encoding)
    pub fn encode(self: MissingBlocksResponseMessage, writer: anytype) !void {
        const count = self.blocks.items.len;

        if (count > GetMissingBlocksMessage.MAX_MISSING_BLOCKS) {
            return error.TooManyBlocks;
        }

        // Write count
        try writer.writeByte(@intCast(count));

        // Write each block (using existing block serialization)
        for (self.blocks.items) |block| {
            try serialize.serialize(writer, block);
        }
    }

    /// Decode message (reuse existing block decoding)
    pub fn decode(allocator: Allocator, reader: anytype) !MissingBlocksResponseMessage {
        var msg = MissingBlocksResponseMessage.init(allocator);
        errdefer msg.deinit(allocator);

        // Read count
        const count = try reader.readByte();

        if (count > GetMissingBlocksMessage.MAX_MISSING_BLOCKS) {
            return error.TooManyBlocks;
        }

        // Read each block
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const block = try serialize.deserialize(reader, Block, allocator);
            try msg.blocks.append(block);
        }

        return msg;
    }

    /// Estimate encoded size
    pub fn estimateSize(self: MissingBlocksResponseMessage) usize {
        var size: usize = 1; // count byte
        for (self.blocks.items) |block| {
            size += block.estimateSize();
        }
        return size;
    }
};
