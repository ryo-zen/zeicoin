// pong.zig - Pong message response to ping
// Echoes the nonce from ping message

const std = @import("std");
const protocol = @import("../protocol.zig");

pub const PongMessage = struct {
    nonce: u64,
    
    const Self = @This();
    
    pub fn init(nonce: u64) Self {
        return .{ .nonce = nonce };
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
test "PongMessage encode/decode" {
    const nonce: u64 = 0x123456789ABCDEF0;
    const pong = PongMessage.init(nonce);
    
    var buffer: [8]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    
    try pong.encode(stream.writer());
    
    stream.reset();
    const decoded = try PongMessage.decode(stream.reader());
    
    try std.testing.expectEqual(pong.nonce, decoded.nonce);
}