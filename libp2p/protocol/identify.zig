const std = @import("std");
const multiaddr = @import("../multiaddr/multiaddr.zig");

const Multiaddr = multiaddr.Multiaddr;

pub const PROTOCOL_ID = "/ipfs/id/1.0.0";

pub const IdentifyInfo = struct {
    protocol_version: []u8,
    agent_version: []u8,
    public_key: []u8,
    listen_addrs: std.array_list.Managed([]u8),
    observed_addr: []u8,
    protocols: std.array_list.Managed([]u8),

    pub fn init(allocator: std.mem.Allocator) IdentifyInfo {
        return .{
            .protocol_version = &[_]u8{},
            .agent_version = &[_]u8{},
            .public_key = &[_]u8{},
            .listen_addrs = std.array_list.Managed([]u8).init(allocator),
            .observed_addr = &[_]u8{},
            .protocols = std.array_list.Managed([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *IdentifyInfo, allocator: std.mem.Allocator) void {
        if (self.protocol_version.len > 0) allocator.free(self.protocol_version);
        if (self.agent_version.len > 0) allocator.free(self.agent_version);
        if (self.public_key.len > 0) allocator.free(self.public_key);
        if (self.observed_addr.len > 0) allocator.free(self.observed_addr);
        for (self.listen_addrs.items) |addr| allocator.free(addr);
        self.listen_addrs.deinit();
        for (self.protocols.items) |proto| allocator.free(proto);
        self.protocols.deinit();
    }
};

pub fn encodeIdentify(
    allocator: std.mem.Allocator,
    protocol_version: []const u8,
    agent_version: []const u8,
    public_key: []const u8,
    listen_addrs: []const []const u8,
    observed_addr: []const u8,
    protocols: []const []const u8,
) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    try writeBytesField(&out, 5, protocol_version);
    try writeBytesField(&out, 6, agent_version);
    try writeBytesField(&out, 1, public_key);
    for (listen_addrs) |addr| try writeBytesField(&out, 2, addr);
    try writeBytesField(&out, 4, observed_addr);
    for (protocols) |proto| try writeBytesField(&out, 3, proto);

    return out.toOwnedSlice();
}

pub fn decodeIdentify(allocator: std.mem.Allocator, encoded: []const u8) !IdentifyInfo {
    var out = IdentifyInfo.init(allocator);
    errdefer out.deinit(allocator);

    var off: usize = 0;
    while (off < encoded.len) {
        const key = try readVarint(encoded, &off);
        const field_number = key >> 3;
        const wire_type = key & 0x07;

        switch (field_number) {
            1 => {
                const value = try readLengthDelimitedField(encoded, &off, wire_type);
                if (out.public_key.len > 0) allocator.free(out.public_key);
                out.public_key = try allocator.dupe(u8, value);
            },
            2 => {
                const value = try readLengthDelimitedField(encoded, &off, wire_type);
                var addr = try Multiaddr.createFromBytes(allocator, value);
                defer addr.deinit();
                try out.listen_addrs.append(try allocator.dupe(u8, addr.getStringAddress()));
            },
            3 => {
                const value = try readLengthDelimitedField(encoded, &off, wire_type);
                try out.protocols.append(try allocator.dupe(u8, value));
            },
            4 => {
                const value = try readLengthDelimitedField(encoded, &off, wire_type);
                if (out.observed_addr.len > 0) allocator.free(out.observed_addr);
                var observed = try Multiaddr.createFromBytes(allocator, value);
                defer observed.deinit();
                out.observed_addr = try allocator.dupe(u8, observed.getStringAddress());
            },
            5 => {
                const value = try readLengthDelimitedField(encoded, &off, wire_type);
                if (out.protocol_version.len > 0) allocator.free(out.protocol_version);
                out.protocol_version = try allocator.dupe(u8, value);
            },
            6 => {
                const value = try readLengthDelimitedField(encoded, &off, wire_type);
                if (out.agent_version.len > 0) allocator.free(out.agent_version);
                out.agent_version = try allocator.dupe(u8, value);
            },
            else => try skipUnknownField(encoded, &off, wire_type),
        }
    }

    return out;
}

fn writeBytesField(out: *std.array_list.Managed(u8), field_number: usize, value: []const u8) !void {
    try writeVarintToList(out, (field_number << 3) | 2);
    try writeVarintToList(out, value.len);
    try out.appendSlice(value);
}

fn writeVarintToList(out: *std.array_list.Managed(u8), value: usize) !void {
    var v = value;
    while (v >= 0x80) : (v >>= 7) {
        try out.append(@as(u8, @intCast(v & 0x7F)) | 0x80);
    }
    try out.append(@as(u8, @intCast(v)));
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
        if (shift >= @bitSizeOf(usize)) return error.VarintOverflow;
    }
    return error.EndOfStream;
}

fn readLengthDelimitedField(data: []const u8, off: *usize, wire_type: usize) ![]const u8 {
    if (wire_type != 2) return error.InvalidWireType;

    const field_len = try readVarint(data, off);
    if (off.* + field_len > data.len) return error.InvalidFieldLength;

    const value = data[off.* .. off.* + field_len];
    off.* += field_len;
    return value;
}

fn skipUnknownField(data: []const u8, off: *usize, wire_type: usize) !void {
    switch (wire_type) {
        0 => _ = try readVarint(data, off),
        1 => {
            if (off.* + 8 > data.len) return error.InvalidFieldLength;
            off.* += 8;
        },
        2 => {
            const field_len = try readVarint(data, off);
            if (off.* + field_len > data.len) return error.InvalidFieldLength;
            off.* += field_len;
        },
        5 => {
            if (off.* + 4 > data.len) return error.InvalidFieldLength;
            off.* += 4;
        },
        else => return error.InvalidWireType,
    }
}

test "identify encode/decode roundtrip" {
    const allocator = std.testing.allocator;

    var listen_ma = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/10001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer listen_ma.deinit();
    const listen = [_][]const u8{listen_ma.getBytesAddress()};
    const protocols = [_][]const u8{ "/zeicoin/peers/1.0.0", "/yamux/1.0.0" };
    const pubkey = [_]u8{0xAA} ** 36;
    var observed_ma = try Multiaddr.create(allocator, "/ip4/10.0.0.7/tcp/55555");
    defer observed_ma.deinit();
    const encoded = try encodeIdentify(
        allocator,
        "/zeicoin/testnet/1.0.0",
        "zeicoin/0.1.0",
        &pubkey,
        &listen,
        observed_ma.getBytesAddress(),
        &protocols,
    );
    defer allocator.free(encoded);

    var decoded = try decodeIdentify(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings("/zeicoin/testnet/1.0.0", decoded.protocol_version);
    try std.testing.expectEqualStrings("zeicoin/0.1.0", decoded.agent_version);
    try std.testing.expectEqual(@as(usize, 1), decoded.listen_addrs.items.len);
    try std.testing.expectEqual(@as(usize, 2), decoded.protocols.items.len);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/tcp/10001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA", decoded.listen_addrs.items[0]);
    try std.testing.expectEqualStrings("/ip4/10.0.0.7/tcp/55555", decoded.observed_addr);
}

test "identify decode skips unknown varint field" {
    const allocator = std.testing.allocator;

    var listen_ma = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/10001");
    defer listen_ma.deinit();
    var observed_ma = try Multiaddr.create(allocator, "/ip4/10.0.0.7/tcp/55555");
    defer observed_ma.deinit();
    const listen = [_][]const u8{listen_ma.getBytesAddress()};
    const protocols = [_][]const u8{"/kad/1.0.0"};
    const pubkey = [_]u8{0xAB} ** 36;

    const encoded = try encodeIdentify(
        allocator,
        "/zeicoin/testnet/1.0.0",
        "zeicoin/0.1.0",
        &pubkey,
        &listen,
        observed_ma.getBytesAddress(),
        &protocols,
    );
    defer allocator.free(encoded);

    var payload = std.array_list.Managed(u8).init(allocator);
    defer payload.deinit();
    try payload.appendSlice(encoded);
    try writeVarintToList(&payload, (9 << 3) | 0);
    try writeVarintToList(&payload, 150);

    var decoded = try decodeIdentify(allocator, payload.items);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings("/zeicoin/testnet/1.0.0", decoded.protocol_version);
    try std.testing.expectEqualStrings("zeicoin/0.1.0", decoded.agent_version);
    try std.testing.expectEqual(@as(usize, 1), decoded.listen_addrs.items.len);
    try std.testing.expectEqual(@as(usize, 1), decoded.protocols.items.len);
    try std.testing.expectEqualStrings("/kad/1.0.0", decoded.protocols.items[0]);
}

test "identify decode skips unknown length-delimited field" {
    const allocator = std.testing.allocator;

    var observed_ma = try Multiaddr.create(allocator, "/ip4/10.0.0.7/tcp/55555");
    defer observed_ma.deinit();
    const protocols = [_][]const u8{"/zeicoin/peers/1.0.0"};
    const pubkey = [_]u8{0xCD} ** 36;

    const encoded = try encodeIdentify(
        allocator,
        "/zeicoin/testnet/1.0.0",
        "zeicoin/0.1.0",
        &pubkey,
        &[_][]const u8{},
        observed_ma.getBytesAddress(),
        &protocols,
    );
    defer allocator.free(encoded);

    var payload = std.array_list.Managed(u8).init(allocator);
    defer payload.deinit();
    try payload.appendSlice(encoded);
    try writeVarintToList(&payload, (8 << 3) | 2);
    try writeVarintToList(&payload, 3);
    try payload.appendSlice(&[_]u8{ 0xDE, 0xAD, 0xBE });

    var decoded = try decodeIdentify(allocator, payload.items);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings("/zeicoin/testnet/1.0.0", decoded.protocol_version);
    try std.testing.expectEqualStrings("zeicoin/0.1.0", decoded.agent_version);
    try std.testing.expectEqual(@as(usize, 1), decoded.protocols.items.len);
    try std.testing.expectEqualStrings("/zeicoin/peers/1.0.0", decoded.protocols.items[0]);
    try std.testing.expectEqualStrings("/ip4/10.0.0.7/tcp/55555", decoded.observed_addr);
}

test "identify decode fails on truncated unknown field" {
    const allocator = std.testing.allocator;

    const payload = [_]u8{
        (9 << 3) | 5,
        0xAA,
        0xBB,
    };

    try std.testing.expectError(error.InvalidFieldLength, decodeIdentify(allocator, &payload));
}
