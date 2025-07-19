// multiaddr.zig - Multiaddr implementation for libp2p
// Multiaddr is a self-describing network address format
// Example: /ip4/127.0.0.1/tcp/4001/p2p/QmNodeId

const std = @import("std");
const net = std.net;

// Protocol codes from multicodec standard
// https://github.com/multiformats/multicodec
pub const ProtocolCode = enum(u32) {
    ip4 = 4,
    tcp = 6,
    udp = 273,
    dccp = 33,
    ip6 = 41,
    ip6_zone = 42,
    dns = 53,
    dns4 = 54,
    dns6 = 55,
    dns_addr = 56,
    sctp = 132,
    udt = 301,
    utp = 302,
    unix = 400,
    p2p = 421,
    onion = 444,
    onion3 = 445,
    garlic64 = 446,
    quic = 460,
    quic_v1 = 461,
    http = 480,
    https = 443,
    ws = 477,
    wss = 478,
    p2p_websocket_star = 479,
    p2p_stardust = 277,
    p2p_webrtc_star = 275,
    p2p_webrtc_direct = 276,
    p2p_circuit = 290,
};

pub const Protocol = struct {
    code: ProtocolCode,
    size: i32, // -1 for variable length
    name: []const u8,
    
    pub const VAR_LEN: i32 = -1;
    
    pub fn fromString(name: []const u8) ?Protocol {
        // Handle legacy IPFS name
        const search_name = if (std.mem.eql(u8, name, "ipfs")) "p2p" else name;
        
        for (PROTOCOLS) |proto| {
            if (std.mem.eql(u8, proto.name, search_name)) {
                return proto;
            }
        }
        return null;
    }
    
    pub fn fromCode(code: ProtocolCode) ?Protocol {
        for (PROTOCOLS) |proto| {
            if (proto.code == code) {
                return proto;
            }
        }
        return null;
    }
};

// Protocol definitions matching C++ implementation
const PROTOCOLS = [_]Protocol{
    .{ .code = .ip4, .size = 4, .name = "ip4" },
    .{ .code = .tcp, .size = 2, .name = "tcp" },
    .{ .code = .udp, .size = 2, .name = "udp" },
    .{ .code = .dccp, .size = 2, .name = "dccp" },
    .{ .code = .ip6, .size = 16, .name = "ip6" },
    .{ .code = .ip6_zone, .size = Protocol.VAR_LEN, .name = "ip6zone" },
    .{ .code = .dns, .size = Protocol.VAR_LEN, .name = "dns" },
    .{ .code = .dns4, .size = Protocol.VAR_LEN, .name = "dns4" },
    .{ .code = .dns6, .size = Protocol.VAR_LEN, .name = "dns6" },
    .{ .code = .dns_addr, .size = Protocol.VAR_LEN, .name = "dnsaddr" },
    .{ .code = .sctp, .size = 2, .name = "sctp" },
    .{ .code = .udt, .size = 0, .name = "udt" },
    .{ .code = .utp, .size = 0, .name = "utp" },
    .{ .code = .unix, .size = Protocol.VAR_LEN, .name = "unix" },
    .{ .code = .p2p, .size = Protocol.VAR_LEN, .name = "p2p" },
    .{ .code = .onion, .size = 10, .name = "onion" },
    .{ .code = .onion3, .size = 37, .name = "onion3" },
    .{ .code = .garlic64, .size = Protocol.VAR_LEN, .name = "garlic64" },
    .{ .code = .quic, .size = 0, .name = "quic" },
    .{ .code = .quic_v1, .size = 0, .name = "quic-v1" },
    .{ .code = .http, .size = 0, .name = "http" },
    .{ .code = .https, .size = 0, .name = "https" },
    .{ .code = .ws, .size = 0, .name = "ws" },
    .{ .code = .wss, .size = 0, .name = "wss" },
    .{ .code = .p2p_websocket_star, .size = 0, .name = "p2p-websocket-star" },
    .{ .code = .p2p_stardust, .size = 0, .name = "p2p-stardust" },
    .{ .code = .p2p_webrtc_star, .size = 0, .name = "p2p-webrtc-star" },
    .{ .code = .p2p_webrtc_direct, .size = 0, .name = "p2p-webrtc-direct" },
    .{ .code = .p2p_circuit, .size = 0, .name = "p2p-circuit" },
};

pub const Component = struct {
    protocol: Protocol,
    value: []const u8,
    
    pub fn format(self: Component, allocator: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "/{s}/{s}", .{
            self.protocol.name,
            self.value,
        });
    }
};

pub const Multiaddr = struct {
    allocator: std.mem.Allocator,
    components: std.ArrayList(Component),
    string_address: []u8, // Cached string representation
    bytes: std.ArrayList(u8), // Binary representation
    peer_id: ?[]const u8, // Cached peer ID if present
    
    const Self = @This();
    
    pub const Error = error{
        InvalidInput,
        ProtocolNotFound,
        InvalidProtocolValue,
        UnknownProtocol,
        MissingValue,
    };
    
    fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .components = std.ArrayList(Component).init(allocator),
            .string_address = &[_]u8{},
            .bytes = std.ArrayList(u8).init(allocator),
            .peer_id = null,
        };
    }
    
    pub fn deinit(self: *Self) void {
        for (self.components.items) |component| {
            self.allocator.free(component.value);
        }
        self.components.deinit();
        if (self.string_address.len > 0) {
            self.allocator.free(self.string_address);
        }
        self.bytes.deinit();
    }
    
    /// Create a multiaddr from string (factory method like C++)
    pub fn create(allocator: std.mem.Allocator, address: []const u8) !Self {
        var self = Self.init(allocator);
        errdefer self.deinit();
        
        if (address.len == 0 or address[0] != '/') {
            return Error.InvalidInput;
        }
        
        // Store the string representation
        self.string_address = try allocator.dupe(u8, address);
        
        // Parse components
        var parts = std.mem.tokenizeScalar(u8, address[1..], '/');
        while (parts.next()) |proto_str| {
            const protocol = Protocol.fromString(proto_str) orelse {
                return Error.UnknownProtocol;
            };
            
            const value = if (protocol.size != 0) 
                parts.next() orelse return Error.MissingValue
            else 
                "";
            
            const value_copy = try allocator.dupe(u8, value);
            try self.components.append(.{
                .protocol = protocol,
                .value = value_copy,
            });
            
                // Check for peer ID
            if (protocol.code == .p2p and value.len > 0) {
                self.peer_id = value_copy;
            }
        }
        
        // TODO: Convert to bytes representation
        // For now, we'll implement this later with proper varint encoding
        
        return self;
    }
    
    /// Create from bytes (matching C++ API)
    pub fn createFromBytes(allocator: std.mem.Allocator, bytes: []const u8) !Self {
        _ = allocator;
        _ = bytes;
        // TODO: Implement bytes to multiaddr conversion
        return Error.InvalidInput;
    }
    
    /// Get string representation (matches C++ getStringAddress)
    pub fn getStringAddress(self: *const Self) []const u8 {
        return self.string_address;
    }
    
    /// Get bytes representation (matches C++ getBytesAddress)
    pub fn getBytesAddress(self: *const Self) []const u8 {
        return self.bytes.items;
    }
    
    /// Encapsulate another multiaddr (matches C++ API)
    pub fn encapsulate(self: *Self, other: *const Self) !void {
        // Append string representation
        const new_str = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{
            self.string_address,
            other.string_address,
        });
        self.allocator.free(self.string_address);
        self.string_address = new_str;
        
        // Append components
        for (other.components.items) |component| {
            try self.components.append(.{
                .protocol = component.protocol,
                .value = try self.allocator.dupe(u8, component.value),
            });
        }
        
        // Append bytes
        try self.bytes.appendSlice(other.bytes.items);
        
        // Update peer_id if other has one
        if (other.peer_id != null) {
            // Just point to the existing peer_id from the component
            for (self.components.items) |component| {
                if (component.protocol.code == .p2p) {
                    self.peer_id = component.value;
                    break;
                }
            }
        }
    }
    
    /// Decapsulate a multiaddr (matches C++ API)
    pub fn decapsulate(self: *Self, other: *const Self) !bool {
        const needle = other.string_address;
        const pos = std.mem.lastIndexOf(u8, self.string_address, needle) orelse return false;
        
        // Create new string without the suffix
        const new_str = try self.allocator.dupe(u8, self.string_address[0..pos]);
        self.allocator.free(self.string_address);
        self.string_address = new_str;
        
        // Remove components
        const remove_count = other.components.items.len;
        if (self.components.items.len >= remove_count) {
            const start = self.components.items.len - remove_count;
            for (self.components.items[start..]) |component| {
                self.allocator.free(component.value);
            }
            self.components.shrinkRetainingCapacity(start);
        }
        
        // TODO: Update bytes representation
        
        return true;
    }
    
    /// Extract TCP/IP address if present
    pub fn getTcpAddress(self: *const Self) ?net.Address {
        var ip: ?[]const u8 = null;
        var port: ?u16 = null;
        var is_ipv6 = false;
        
        for (self.components.items) |component| {
            switch (component.protocol.code) {
                .ip4 => {
                    ip = component.value;
                    is_ipv6 = false;
                },
                .ip6 => {
                    ip = component.value;
                    is_ipv6 = true;
                },
                .tcp => {
                    port = std.fmt.parseInt(u16, component.value, 10) catch return null;
                },
                else => {},
            }
        }
        
        if (ip != null and port != null) {
            if (is_ipv6) {
                return net.Address.parseIp6(ip.?, port.?) catch null;
            } else {
                return net.Address.parseIp4(ip.?, port.?) catch null;
            }
        }
        
        return null;
    }
    
    /// Check if multiaddr contains a specific protocol
    pub fn hasProtocol(self: *const Self, code: ProtocolCode) bool {
        for (self.components.items) |component| {
            if (component.protocol.code == code) return true;
        }
        return false;
    }
    
    /// Get first value for protocol (matches C++ getFirstValueForProtocol)
    pub fn getFirstValueForProtocol(self: *const Self, code: ProtocolCode) Error![]const u8 {
        for (self.components.items) |component| {
            if (component.protocol.code == code) return component.value;
        }
        return Error.ProtocolNotFound;
    }
    
    /// Get all values for protocol (matches C++ getValuesForProtocol)
    pub fn getValuesForProtocol(self: *const Self, code: ProtocolCode, allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
        var values = std.ArrayList([]const u8).init(allocator);
        for (self.components.items) |component| {
            if (component.protocol.code == code) {
                try values.append(component.value);
            }
        }
        return values;
    }
    
    /// Get peer ID if present (matches C++ getPeerId)
    pub fn getPeerId(self: *const Self) ?[]const u8 {
        return self.peer_id;
    }
};

// Tests
test "create simple TCP multiaddr" {
    const allocator = std.testing.allocator;
    
    var addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/4001");
    defer addr.deinit();
    
    try std.testing.expectEqual(@as(usize, 2), addr.components.items.len);
    try std.testing.expectEqual(ProtocolCode.ip4, addr.components.items[0].protocol.code);
    try std.testing.expectEqualStrings("127.0.0.1", addr.components.items[0].value);
    try std.testing.expectEqual(ProtocolCode.tcp, addr.components.items[1].protocol.code);
    try std.testing.expectEqualStrings("4001", addr.components.items[1].value);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/tcp/4001", addr.getStringAddress());
}

test "extract TCP address" {
    const allocator = std.testing.allocator;
    
    var addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/4001");
    defer addr.deinit();
    
    const tcp_addr = addr.getTcpAddress().?;
    try std.testing.expectEqual(@as(u16, 4001), tcp_addr.getPort());
}

test "multiaddr with p2p protocol" {
    const allocator = std.testing.allocator;
    
    var addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/4001/p2p/QmNodeId");
    defer addr.deinit();
    
    try std.testing.expectEqual(@as(usize, 3), addr.components.items.len);
    try std.testing.expect(addr.hasProtocol(.p2p));
    const peer_id = try addr.getFirstValueForProtocol(.p2p);
    try std.testing.expectEqualStrings("QmNodeId", peer_id);
    try std.testing.expectEqualStrings("QmNodeId", addr.getPeerId().?);
}

test "encapsulate and decapsulate" {
    const allocator = std.testing.allocator;
    
    var addr1 = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/4001");
    defer addr1.deinit();
    
    var addr2 = try Multiaddr.create(allocator, "/p2p/QmNodeId");
    defer addr2.deinit();
    
    try addr1.encapsulate(&addr2);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/tcp/4001/p2p/QmNodeId", addr1.getStringAddress());
    try std.testing.expect(addr1.hasProtocol(.p2p));
    
    const success = try addr1.decapsulate(&addr2);
    try std.testing.expect(success);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/tcp/4001", addr1.getStringAddress());
    try std.testing.expect(!addr1.hasProtocol(.p2p));
}