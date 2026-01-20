// ping.zig - Ping message for keepalive
// Simple message with nonce for matching pong responses

const std = @import("std");
const protocol = @import("../protocol.zig");

pub const PingMessage = struct {
    nonce: u64,
    
    const Self = @This();
    
    pub fn init() Self {
        const io = std.Io.Threaded.global_single_threaded.ioBasic();
        var nonce_bytes: [8]u8 = undefined;
        std.Io.random(io, &nonce_bytes);
        return .{
            .nonce = std.mem.readInt(u64, &nonce_bytes, .little),
        };
    }
    
    pub fn encode(self: Self, writer: anytype) !void {
        var w = writer;
        try std.Io.Writer.writeInt(&w, u64, self.nonce, .little);
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
test "PingMessage encode/decode" {
    const ping = PingMessage.init();
    
    var buffer: [8]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    
    try ping.encode(&writer);
    
    var reader = std.Io.Reader.fixed(writer.buffered());
    const decoded = try PingMessage.decode(&reader);
    
    try std.testing.expectEqual(ping.nonce, decoded.nonce);
}
