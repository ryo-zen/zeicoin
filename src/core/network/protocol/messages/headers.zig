// headers.zig - Headers message for headers-first sync
// Efficient header transmission with zero-copy support

const std = @import("std");
const protocol = @import("../protocol.zig");
const types = @import("../../../types/types.zig");

pub const HeadersMessage = struct {
    headers: []const types.BlockHeader,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, headers: []const types.BlockHeader) !Self {
        const headers_copy = try allocator.dupe(types.BlockHeader, headers);
        return Self{ .headers = headers_copy };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
    }
    
    pub fn encode(self: Self, writer: anytype) !void {
        // Write header count
        try writer.writeInt(u32, @intCast(self.headers.len), .little);
        
        // Write headers
        for (self.headers) |header| {
            try header.serialize(writer);
        }
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Self {
        // Read header count
        const count = try reader.readInt(u32, .little);
        if (count > protocol.MAX_HEADERS_PER_MESSAGE) {
            return error.TooManyHeaders;
        }
        
        // Read headers
        const headers = try allocator.alloc(types.BlockHeader, count);
        errdefer allocator.free(headers);
        
        for (headers) |*header| {
            header.* = try types.BlockHeader.deserialize(reader);
        }
        
        return Self{ .headers = headers };
    }
    
    pub fn estimateSize(self: Self) usize {
        return 4 + // count
            self.headers.len * @sizeOf(types.BlockHeader);
    }
};

/// Zero-copy headers view for efficient processing
pub const HeadersView = struct {
    data: []const u8,
    count: u32,
    
    const Self = @This();
    
    /// Create a view without copying data
    pub fn init(data: []const u8) !Self {
        if (data.len < 4) return error.TooShort;
        
        const count = std.mem.readInt(u32, data[0..4], .little);
        if (count > protocol.MAX_HEADERS_PER_MESSAGE) {
            return error.TooManyHeaders;
        }
        
        const expected_size = 4 + count * @sizeOf(types.BlockHeader);
        if (data.len != expected_size) {
            return error.InvalidSize;
        }
        
        return Self{
            .data = data,
            .count = count,
        };
    }
    
    pub fn iterator(self: Self) Iterator {
        return .{
            .data = self.data[4..], // Skip count
            .remaining = self.count,
        };
    }
    
    pub const Iterator = struct {
        data: []const u8,
        remaining: u32,
        
        pub fn next(self: *Iterator) !?types.BlockHeader {
            if (self.remaining == 0) return null;
            
            const header_size = @sizeOf(types.BlockHeader);
            if (self.data.len < header_size) {
                return error.UnexpectedEndOfData;
            }
            
            var stream = std.io.fixedBufferStream(self.data[0..header_size]);
            const header = try types.BlockHeader.deserialize(stream.reader());
            
            self.data = self.data[header_size..];
            self.remaining -= 1;
            
            return header;
        }
    };
};

// Tests
test "HeadersMessage encode/decode" {
    const allocator = std.testing.allocator;
    
    const headers = [_]types.BlockHeader{
        .{
            .version = 1,
            .previous_hash = [_]u8{1} ** 32,
            .merkle_root = [_]u8{2} ** 32,
            .timestamp = 1234567890,
            .difficulty = 0x1d00ffff,
            .nonce = 0x12345678,
            .witness_root = [_]u8{3} ** 32,
            .state_root = [_]u8{4} ** 32,
            .extra_nonce = 0,
            .extra_data = [_]u8{0} ** 32,
        },
    };
    
    var msg = try HeadersMessage.init(allocator, &headers);
    defer msg.deinit(allocator);
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try msg.encode(buffer.writer());
    
    // Test zero-copy view
    const view = try HeadersView.init(buffer.items);
    var iter = view.iterator();
    
    const first_header = (try iter.next()).?;
    try std.testing.expectEqual(headers[0].version, first_header.version);
    try std.testing.expectEqual(headers[0].timestamp, first_header.timestamp);
    
    // Test normal decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try HeadersMessage.decode(allocator, stream.reader());
    defer decoded.deinit(allocator);
    
    try std.testing.expectEqual(msg.headers.len, decoded.headers.len);
}