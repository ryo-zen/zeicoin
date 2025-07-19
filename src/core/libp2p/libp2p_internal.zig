// libp2p_internal.zig - Internal libp2p definitions
// Shared internal types and utilities for libp2p components

const std = @import("std");

/// Multiaddr placeholder type
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