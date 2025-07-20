// announce.zig - Announce new inventory items (blocks/transactions)
// Efficient announcement without sending full data

const std = @import("std");
const protocol = @import("../protocol.zig");
const types = @import("../../../types/types.zig");

pub const InventoryItem = struct {
    item_type: protocol.InventoryType,
    hash: types.Hash,
    
    pub fn encode(self: InventoryItem, writer: anytype) !void {
        try writer.writeInt(u32, @intFromEnum(self.item_type), .little);
        try writer.writeAll(&self.hash);
    }
    
    pub fn decode(reader: anytype) !InventoryItem {
        const type_int = try reader.readInt(u32, .little);
        const item_type = std.meta.intToEnum(protocol.InventoryType, type_int) catch {
            return error.InvalidInventoryType;
        };
        
        var hash: types.Hash = undefined;
        try reader.readNoEof(&hash);
        
        return InventoryItem{
            .item_type = item_type,
            .hash = hash,
        };
    }
};

pub const AnnounceMessage = struct {
    items: []const InventoryItem,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, items: []const InventoryItem) !Self {
        if (items.len > protocol.MAX_INV_PER_MESSAGE) {
            return error.TooManyItems;
        }
        
        const items_copy = try allocator.dupe(InventoryItem, items);
        return Self{ .items = items_copy };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
    }
    
    pub fn encode(self: Self, writer: anytype) !void {
        try writer.writeInt(u32, @intCast(self.items.len), .little);
        
        for (self.items) |item| {
            try item.encode(writer);
        }
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Self {
        const count = try reader.readInt(u32, .little);
        if (count > protocol.MAX_INV_PER_MESSAGE) {
            return error.TooManyItems;
        }
        
        const items = try allocator.alloc(InventoryItem, count);
        errdefer allocator.free(items);
        
        for (items) |*item| {
            item.* = try InventoryItem.decode(reader);
        }
        
        return Self{ .items = items };
    }
    
    pub fn estimateSize(self: Self) usize {
        return 4 + // count
            self.items.len * (4 + @sizeOf(types.Hash));
    }
    
    /// Create announcement for a single block
    pub fn announceBlock(allocator: std.mem.Allocator, block_hash: types.Hash) !Self {
        const items = try allocator.alloc(InventoryItem, 1);
        items[0] = .{
            .item_type = .block,
            .hash = block_hash,
        };
        return Self{ .items = items };
    }
    
    /// Create announcement for a single transaction
    pub fn announceTransaction(allocator: std.mem.Allocator, tx_hash: types.Hash) !Self {
        const items = try allocator.alloc(InventoryItem, 1);
        items[0] = .{
            .item_type = .transaction,
            .hash = tx_hash,
        };
        return Self{ .items = items };
    }
};

// Tests
test "AnnounceMessage encode/decode" {
    const allocator = std.testing.allocator;
    
    const items = [_]InventoryItem{
        .{ .item_type = .block, .hash = [_]u8{1} ** 32 },
        .{ .item_type = .transaction, .hash = [_]u8{2} ** 32 },
        .{ .item_type = .transaction, .hash = [_]u8{3} ** 32 },
    };
    
    var msg = try AnnounceMessage.init(allocator, &items);
    defer msg.deinit(allocator);
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try msg.encode(buffer.writer());
    
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try AnnounceMessage.decode(allocator, stream.reader());
    defer decoded.deinit(allocator);
    
    try std.testing.expectEqual(msg.items.len, decoded.items.len);
    
    for (msg.items, decoded.items) |original, decoded_item| {
        try std.testing.expectEqual(original.item_type, decoded_item.item_type);
        try std.testing.expectEqualSlices(u8, &original.hash, &decoded_item.hash);
    }
}

test "AnnounceMessage single item helpers" {
    const allocator = std.testing.allocator;
    
    const block_hash = [_]u8{0xAB} ** 32;
    var block_announce = try AnnounceMessage.announceBlock(allocator, block_hash);
    defer block_announce.deinit(allocator);
    
    try std.testing.expectEqual(@as(usize, 1), block_announce.items.len);
    try std.testing.expectEqual(protocol.InventoryType.block, block_announce.items[0].item_type);
    try std.testing.expectEqualSlices(u8, &block_hash, &block_announce.items[0].hash);
}