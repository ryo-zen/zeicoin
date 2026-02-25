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
    
    pub fn encode(self: *const Self, writer: anytype) !void {
        try std.Io.Writer.writeInt(writer, u64, self.nonce, .little);
    }
    
    pub fn decode(reader: anytype) !Self {
        return Self{
            .nonce = try reader.takeInt(u64, .little),
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
    var writer = std.Io.Writer.fixed(&buffer);
    
    try pong.encode(&writer);
    
    var reader = std.Io.Reader.fixed(writer.buffered());
    const decoded = try PongMessage.decode(&reader);
    
    try std.testing.expectEqual(pong.nonce, decoded.nonce);
}
