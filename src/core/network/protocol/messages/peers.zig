// peers.zig - Share peer addresses for network discovery

const std = @import("std");

pub const PeerAddress = struct {
    ip: [16]u8, // IPv6 or IPv4-mapped-IPv6
    port: u16,
    services: u64,
    last_seen: i64,
};

pub const PeersMessage = struct {
    addresses: []const PeerAddress,
    
    pub fn init(allocator: std.mem.Allocator, addresses: []const PeerAddress) !PeersMessage {
        const copy = try allocator.dupe(PeerAddress, addresses);
        return .{ .addresses = copy };
    }
    
    pub fn deinit(self: *PeersMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.addresses);
    }
    
    pub fn encode(self: PeersMessage, writer: anytype) !void {
        try std.Io.Writer.writeInt(writer, u32, @intCast(self.addresses.len), .little);
        for (self.addresses) |addr| {
            try writer.writeAll(&addr.ip);
            try std.Io.Writer.writeInt(writer, u16, addr.port, .little);
            try std.Io.Writer.writeInt(writer, u64, addr.services, .little);
            try std.Io.Writer.writeInt(writer, i64, addr.last_seen, .little);
        }
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !PeersMessage {
        const count = try reader.takeInt(u32, .little);
        if (count > 1000) return error.TooManyPeers;
        
        const addresses = try allocator.alloc(PeerAddress, count);
        errdefer allocator.free(addresses);
        
        for (addresses) |*addr| {
            try reader.readSliceAll(&addr.ip);
            addr.port = try reader.takeInt(u16, .little);
            addr.services = try reader.takeInt(u64, .little);
            addr.last_seen = try reader.takeInt(i64, .little);
        }
        
        return .{ .addresses = addresses };
    }
    
    pub fn estimateSize(self: PeersMessage) usize {
        return 4 + self.addresses.len * @sizeOf(PeerAddress);
    }
};