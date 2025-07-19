// peer_id.zig - Peer ID implementation for libp2p
// Simplified version for initial implementation

const std = @import("std");
const crypto = std.crypto;

/// Peer ID represents a unique identifier for a peer in the network
pub const PeerId = struct {
    bytes: []u8,
    string: []u8, // Base58 encoded string
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Create a new random peer ID
    pub fn random(allocator: std.mem.Allocator) !Self {
        // Generate random bytes for peer ID (simplified - should use proper key generation)
        var bytes = try allocator.alloc(u8, 32);
        crypto.random.bytes(bytes);
        
        // TODO: Proper base58 encoding
        const string = try std.fmt.allocPrint(allocator, "Qm{x}", .{std.fmt.fmtSliceHexLower(bytes[0..16])});
        
        return .{
            .bytes = bytes,
            .string = string,
            .allocator = allocator,
        };
    }
    
    /// Create from bytes
    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) !Self {
        const bytes_copy = try allocator.dupe(u8, bytes);
        
        // TODO: Proper base58 encoding
        const string = try std.fmt.allocPrint(allocator, "Qm{x}", .{std.fmt.fmtSliceHexLower(bytes[0..@min(16, bytes.len)])});
        
        return .{
            .bytes = bytes_copy,
            .string = string,
            .allocator = allocator,
        };
    }
    
    /// Create from string
    pub fn fromString(allocator: std.mem.Allocator, string: []const u8) !Self {
        // TODO: Proper base58 decoding
        // For now, just store the string
        const string_copy = try allocator.dupe(u8, string);
        const bytes = try allocator.alloc(u8, 32);
        crypto.random.bytes(bytes);
        
        return .{
            .bytes = bytes,
            .string = string_copy,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.bytes);
        self.allocator.free(self.string);
    }
    
    pub fn toString(self: *const Self) []const u8 {
        return self.string;
    }
    
    pub fn getBytes(self: *const Self) []const u8 {
        return self.bytes;
    }
    
    pub fn equals(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.bytes, other.bytes);
    }
};

// Tests
test "create random peer ID" {
    const allocator = std.testing.allocator;
    
    var peer_id = try PeerId.random(allocator);
    defer peer_id.deinit();
    
    try std.testing.expect(peer_id.bytes.len == 32);
    try std.testing.expect(peer_id.string.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, peer_id.string, "Qm"));
}

test "peer ID equality" {
    const allocator = std.testing.allocator;
    
    const bytes = "test_peer_id_bytes_1234567890ab";
    
    var id1 = try PeerId.fromBytes(allocator, bytes);
    defer id1.deinit();
    
    var id2 = try PeerId.fromBytes(allocator, bytes);
    defer id2.deinit();
    
    try std.testing.expect(id1.equals(&id2));
}