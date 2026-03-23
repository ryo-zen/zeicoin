// multiaddr.zig - Multiaddr implementation for libp2p
// Multiaddr is a self-describing network address format
// Example: /ip4/127.0.0.1/tcp/4001/p2p/QmNodeId

const std = @import("std");
const net = std.Io.net;
const peer = @import("../peer/peer_id.zig");

const PeerId = peer.PeerId;

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
        if (self.protocol.size == 0) {
            return std.fmt.allocPrint(allocator, "/{s}", .{self.protocol.name});
        }
        return std.fmt.allocPrint(allocator, "/{s}/{s}", .{ self.protocol.name, self.value });
    }
};

pub const Multiaddr = struct {
    allocator: std.mem.Allocator,
    components: std.array_list.Managed(Component),
    string_address: []u8, // Cached string representation
    bytes: std.array_list.Managed(u8), // Binary representation
    peer_id: ?[]const u8, // Cached peer ID if present

    const Self = @This();

    pub const Error = error{
        InvalidInput,
        ProtocolNotFound,
        InvalidProtocolValue,
        UnknownProtocol,
        MissingValue,
        InvalidBinaryEncoding,
    };

    fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .components = std.array_list.Managed(Component).init(allocator),
            .string_address = &[_]u8{},
            .bytes = std.array_list.Managed(u8).init(allocator),
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

            if (protocol.code == .p2p and value.len > 0) {
                self.peer_id = value_copy;
            }
        }

        try self.rebuildCaches();
        return self;
    }

    /// Create from bytes (matching C++ API)
    pub fn createFromBytes(allocator: std.mem.Allocator, bytes: []const u8) !Self {
        var self = Self.init(allocator);
        errdefer self.deinit();

        var off: usize = 0;
        while (off < bytes.len) {
            const code_raw = try readVarint(bytes, &off);
            const protocol = protocolFromCodeRaw(@intCast(code_raw)) orelse return Error.UnknownProtocol;

            const value = try decodeProtocolValue(allocator, protocol, bytes, &off);
            errdefer allocator.free(value);
            try self.components.append(.{
                .protocol = protocol,
                .value = value,
            });
            if (protocol.code == .p2p and value.len > 0) {
                self.peer_id = value;
            }
        }

        try self.rebuildCaches();
        return self;
    }

    /// Get string representation (matches C++ getStringAddress)
    pub fn getStringAddress(self: *const Self) []const u8 {
        return self.string_address;
    }

    pub fn toString(self: *const Self) []const u8 {
        return self.string_address;
    }

    /// Get bytes representation (matches C++ getBytesAddress)
    pub fn getBytesAddress(self: *const Self) []const u8 {
        return self.bytes.items;
    }

    /// Encapsulate another multiaddr (matches C++ API)
    pub fn encapsulate(self: *Self, other: *const Self) !void {
        for (other.components.items) |component| {
            try self.components.append(.{
                .protocol = component.protocol,
                .value = try self.allocator.dupe(u8, component.value),
            });
        }
        try self.rebuildCaches();
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

        try self.rebuildCaches();
        return true;
    }

    /// Extract TCP/IP address if present
    pub fn getTcpAddress(self: *const Self) ?net.IpAddress {
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
                const parsed = net.Ip6Address.parse(ip.?, port.?) catch return null;
                return .{ .ip6 = parsed };
            }
            const parsed = net.Ip4Address.parse(ip.?, port.?) catch return null;
            return .{ .ip4 = parsed };
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
    pub fn getValuesForProtocol(self: *const Self, code: ProtocolCode, allocator: std.mem.Allocator) !std.array_list.Managed([]const u8) {
        var values = std.array_list.Managed([]const u8).init(allocator);
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

    fn rebuildCaches(self: *Self) !void {
        if (self.string_address.len > 0) {
            self.allocator.free(self.string_address);
        }
        self.bytes.clearRetainingCapacity();
        self.peer_id = null;

        self.string_address = try buildStringAddress(self.allocator, self.components.items);
        try encodeComponentsToBytes(self.allocator, &self.bytes, self.components.items);

        for (self.components.items) |component| {
            if (component.protocol.code == .p2p) {
                self.peer_id = component.value;
            }
        }
    }
};

fn buildStringAddress(allocator: std.mem.Allocator, components: []const Component) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    for (components) |component| {
        try out.append('/');
        try out.appendSlice(component.protocol.name);
        if (component.protocol.size != 0) {
            try out.append('/');
            try out.appendSlice(component.value);
        }
    }
    return out.toOwnedSlice();
}

fn protocolFromCodeRaw(code_raw: u32) ?Protocol {
    for (PROTOCOLS) |proto| {
        if (@intFromEnum(proto.code) == code_raw) return proto;
    }
    return null;
}

fn encodeComponentsToBytes(
    allocator: std.mem.Allocator,
    out: *std.array_list.Managed(u8),
    components: []const Component,
) !void {
    for (components) |component| {
        try writeVarintToList(out, @intFromEnum(component.protocol.code));
        try encodeProtocolValue(allocator, out, component.protocol, component.value);
    }
}

fn encodeProtocolValue(
    allocator: std.mem.Allocator,
    out: *std.array_list.Managed(u8),
    protocol: Protocol,
    value: []const u8,
) !void {
    switch (protocol.code) {
        .ip4 => {
            const addr = net.Ip4Address.parse(value, 0) catch return Multiaddr.Error.InvalidProtocolValue;
            try out.appendSlice(&addr.bytes);
        },
        .ip6 => {
            const addr = net.Ip6Address.parse(value, 0) catch return Multiaddr.Error.InvalidProtocolValue;
            try out.appendSlice(&addr.bytes);
        },
        .tcp, .udp, .dccp, .sctp => {
            const port = std.fmt.parseInt(u16, value, 10) catch return Multiaddr.Error.InvalidProtocolValue;
            var buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &buf, port, .big);
            try out.appendSlice(&buf);
        },
        .p2p => {
            var peer_id = PeerId.fromString(allocator, value) catch return Multiaddr.Error.InvalidProtocolValue;
            defer peer_id.deinit();
            try writeVarintToList(out, peer_id.getBytes().len);
            try out.appendSlice(peer_id.getBytes());
        },
        else => {
            if (protocol.size == 0) return;
            if (protocol.size == Protocol.VAR_LEN) {
                try writeVarintToList(out, value.len);
                try out.appendSlice(value);
                return;
            }
            if (value.len != @as(usize, @intCast(protocol.size))) return Multiaddr.Error.InvalidProtocolValue;
            try out.appendSlice(value);
        },
    }
}

fn decodeProtocolValue(
    allocator: std.mem.Allocator,
    protocol: Protocol,
    bytes: []const u8,
    off: *usize,
) ![]u8 {
    switch (protocol.code) {
        .ip4 => {
            if (off.* + 4 > bytes.len) return Multiaddr.Error.InvalidBinaryEncoding;
            const value = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
                bytes[off.*],
                bytes[off.* + 1],
                bytes[off.* + 2],
                bytes[off.* + 3],
            });
            off.* += 4;
            return value;
        },
        .ip6 => {
            if (off.* + 16 > bytes.len) return Multiaddr.Error.InvalidBinaryEncoding;
            const value = try std.fmt.allocPrint(allocator, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                bytes[off.*],      bytes[off.* + 1],  bytes[off.* + 2],  bytes[off.* + 3],
                bytes[off.* + 4],  bytes[off.* + 5],  bytes[off.* + 6],  bytes[off.* + 7],
                bytes[off.* + 8],  bytes[off.* + 9],  bytes[off.* + 10], bytes[off.* + 11],
                bytes[off.* + 12], bytes[off.* + 13], bytes[off.* + 14], bytes[off.* + 15],
            });
            off.* += 16;
            return value;
        },
        .tcp, .udp, .dccp, .sctp => {
            if (off.* + 2 > bytes.len) return Multiaddr.Error.InvalidBinaryEncoding;
            var port_bytes: [2]u8 = undefined;
            @memcpy(&port_bytes, bytes[off.* .. off.* + 2]);
            const port = std.mem.readInt(u16, &port_bytes, .big);
            off.* += 2;
            return std.fmt.allocPrint(allocator, "{}", .{port});
        },
        .p2p => {
            const field_len = try readVarint(bytes, off);
            if (off.* + field_len > bytes.len) return Multiaddr.Error.InvalidBinaryEncoding;
            var peer_id = try PeerId.fromBytes(allocator, bytes[off.* .. off.* + field_len]);
            defer peer_id.deinit();
            off.* += field_len;
            return allocator.dupe(u8, peer_id.toString());
        },
        else => {
            if (protocol.size == 0) return allocator.dupe(u8, "");
            if (protocol.size == Protocol.VAR_LEN) {
                const field_len = try readVarint(bytes, off);
                if (off.* + field_len > bytes.len) return Multiaddr.Error.InvalidBinaryEncoding;
                defer off.* += field_len;
                return allocator.dupe(u8, bytes[off.* .. off.* + field_len]);
            }
            const field_len: usize = @intCast(protocol.size);
            if (off.* + field_len > bytes.len) return Multiaddr.Error.InvalidBinaryEncoding;
            defer off.* += field_len;
            return allocator.dupe(u8, bytes[off.* .. off.* + field_len]);
        },
    }
}

fn writeVarintToList(out: *std.array_list.Managed(u8), value: usize) !void {
    var buf: [10]u8 = undefined;
    const len = writeVarint(&buf, value);
    try out.appendSlice(buf[0..len]);
}

fn writeVarint(out: []u8, value: usize) usize {
    var v = value;
    var i: usize = 0;
    while (v >= 0x80) : (v >>= 7) {
        out[i] = @as(u8, @intCast(v & 0x7F)) | 0x80;
        i += 1;
    }
    out[i] = @as(u8, @intCast(v));
    return i + 1;
}

fn readVarint(data: []const u8, off: *usize) !usize {
    var result: usize = 0;
    var shift: u6 = 0;
    while (off.* < data.len) {
        const b = data[off.*];
        off.* += 1;
        result |= @as(usize, b & 0x7F) << shift;
        if ((b & 0x80) == 0) return result;
        shift += 7;
        if (shift >= @bitSizeOf(usize)) return Multiaddr.Error.InvalidBinaryEncoding;
    }
    return Multiaddr.Error.InvalidBinaryEncoding;
}

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

    const peer_id = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";
    var addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer addr.deinit();

    try std.testing.expectEqual(@as(usize, 3), addr.components.items.len);
    try std.testing.expect(addr.hasProtocol(.p2p));
    const extracted_peer_id = try addr.getFirstValueForProtocol(.p2p);
    try std.testing.expectEqualStrings(peer_id, extracted_peer_id);
    try std.testing.expectEqualStrings(peer_id, addr.getPeerId().?);
}

test "multiaddr binary roundtrip includes p2p multihash bytes" {
    const allocator = std.testing.allocator;

    var addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer addr.deinit();

    try std.testing.expect(addr.getBytesAddress().len > 0);

    var roundtrip = try Multiaddr.createFromBytes(allocator, addr.getBytesAddress());
    defer roundtrip.deinit();

    try std.testing.expectEqualStrings(addr.getStringAddress(), roundtrip.getStringAddress());
    try std.testing.expectEqualStrings(addr.getPeerId().?, roundtrip.getPeerId().?);
}

test "encapsulate and decapsulate" {
    const allocator = std.testing.allocator;

    var addr1 = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/4001");
    defer addr1.deinit();

    var addr2 = try Multiaddr.create(allocator, "/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer addr2.deinit();

    try addr1.encapsulate(&addr2);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA", addr1.getStringAddress());
    try std.testing.expect(addr1.hasProtocol(.p2p));

    const success = try addr1.decapsulate(&addr2);
    try std.testing.expect(success);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/tcp/4001", addr1.getStringAddress());
    try std.testing.expect(!addr1.hasProtocol(.p2p));
}
