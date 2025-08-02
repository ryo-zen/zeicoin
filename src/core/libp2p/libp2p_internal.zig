// libp2p_internal.zig - Internal libp2p definitions
// Shared internal types and utilities for libp2p components

const std = @import("std");

/// Protocol codes for simplified multiaddr parsing
pub const ProtocolCode = enum {
    ip4,
    ip6,
    tcp,
    udp,
    p2p,
};

/// Multiaddr placeholder type with necessary methods
/// TODO: Implement proper multiaddr parsing and representation
pub const Multiaddr = struct {
    raw: []const u8,
    allocator: std.mem.Allocator,
    owned: bool,
    
    pub fn init(addr: []const u8) Multiaddr {
        return .{ 
            .raw = addr, 
            .allocator = undefined, 
            .owned = false 
        };
    }
    
    pub fn create(allocator: std.mem.Allocator, addr: []const u8) !Multiaddr {
        const owned_addr = try allocator.dupe(u8, addr);
        return .{ 
            .raw = owned_addr, 
            .allocator = allocator, 
            .owned = true 
        };
    }
    
    pub fn deinit(self: *Multiaddr) void {
        if (self.owned) {
            self.allocator.free(self.raw);
        }
    }
    
    pub fn toString(self: *const Multiaddr) []const u8 {
        return self.raw;
    }
    
    /// Extract TCP/IP address if present (simplified implementation)
    pub fn getTcpAddress(self: *const Multiaddr) ?std.net.Address {
        // Simple parsing for common cases like "/ip4/127.0.0.1/tcp/4001"
        var parts = std.mem.tokenizeScalar(u8, self.raw, '/');
        var ip: ?[]const u8 = null;
        var port: ?u16 = null;
        var is_ipv6 = false;
        
        while (parts.next()) |part| {
            if (std.mem.eql(u8, part, "ip4")) {
                if (parts.next()) |ip_str| {
                    ip = ip_str;
                    is_ipv6 = false;
                }
            } else if (std.mem.eql(u8, part, "ip6")) {
                if (parts.next()) |ip_str| {
                    ip = ip_str;
                    is_ipv6 = true;
                }
            } else if (std.mem.eql(u8, part, "tcp")) {
                if (parts.next()) |port_str| {
                    port = std.fmt.parseInt(u16, port_str, 10) catch null;
                }
            }
        }
        
        if (ip != null and port != null) {
            if (is_ipv6) {
                return std.net.Address.parseIp6(ip.?, port.?) catch null;
            } else {
                return std.net.Address.parseIp4(ip.?, port.?) catch null;
            }
        }
        
        return null;
    }
    
    /// Check if multiaddr contains a specific protocol (simplified implementation)
    pub fn hasProtocol(self: *const Multiaddr, protocol: ProtocolCode) bool {
        const protocol_name = switch (protocol) {
            .tcp => "tcp",
            .udp => "udp",
            .ip4 => "ip4",
            .ip6 => "ip6",
            else => return false,
        };
        
        return std.mem.indexOf(u8, self.raw, protocol_name) != null;
    }
};

/// Peer ID placeholder type
/// TODO: Implement proper peer ID based on public key hashing
pub const PeerId = struct {
    id: [32]u8,
    
    pub fn init(id: [32]u8) PeerId {
        return .{ .id = id };
    }
    
    pub fn fromBytes(bytes: []const u8) !PeerId {
        if (bytes.len != 32) return error.InvalidPeerIdLength;
        var id: [32]u8 = undefined;
        @memcpy(&id, bytes[0..32]);
        return .{ .id = id };
    }
    
    pub fn toBytes(self: *const PeerId) *const [32]u8 {
        return &self.id;
    }
};

/// Protocol placeholder types
pub const ProtocolId = []const u8;

/// Common libp2p errors
pub const LibP2PError = error{
    ProtocolNegotiationFailed,
    ConnectionUpgradeFailed,
    SecurityHandshakeFailed,
    MuxerInitializationFailed,
    InvalidProtocolId,
    UnsupportedProtocol,
    ConnectionClosed,
    Timeout,
};