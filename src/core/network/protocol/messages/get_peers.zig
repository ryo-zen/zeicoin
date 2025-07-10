// get_peers.zig - Request peer addresses for discovery
// Simple message with no payload

const std = @import("std");

pub const GetPeersMessage = struct {
    pub fn encode(self: GetPeersMessage, writer: anytype) !void {
        _ = self;
        _ = writer;
        // Empty message
    }
    
    pub fn decode(reader: anytype) !GetPeersMessage {
        _ = reader;
        return .{};
    }
    
    pub fn estimateSize(self: GetPeersMessage) usize {
        _ = self;
        return 0;
    }
};