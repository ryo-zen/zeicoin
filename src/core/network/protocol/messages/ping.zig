// ping.zig - Ping message for keepalive
// Simple message with nonce for matching pong responses

const std = @import("std");
const protocol = @import("../protocol.zig");

pub const PingMessage = struct {
    nonce: u64,
    
    const Self = @This();
    
    pub fn init() Self {
        return .{
            .nonce = std.crypto.random.int(u64),
        };
    }
    
    pub fn encode(self: Self, writer: anytype) !void {
        try writer.writeInt(u64, self.nonce, .little);
    }
    
    pub fn decode(reader: anytype) !Self {
        return Self{
            .nonce = try reader.readInt(u64, .little),
        };
    }
    
    pub fn estimateSize(self: Self) usize {
        _ = self;
        return @sizeOf(u64);
    }
};

// Tests
test "PingMessage encode/decode" {
    const ping = PingMessage.init();
    
    var buffer: [8]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    
    try ping.encode(stream.writer());
    
    stream.reset();
    const decoded = try PingMessage.decode(stream.reader());
    
    try std.testing.expectEqual(ping.nonce, decoded.nonce);
}