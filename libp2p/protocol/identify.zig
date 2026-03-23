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
        if (wire_type != 2) return error.InvalidWireType;

        const field_len = try readVarint(encoded, &off);
        if (off + field_len > encoded.len) return error.InvalidFieldLength;
        const value = encoded[off .. off + field_len];
        off += field_len;

        switch (field_number) {
            1 => {
                if (out.public_key.len > 0) allocator.free(out.public_key);
                out.public_key = try allocator.dupe(u8, value);
            },
            2 => {
                var addr = try Multiaddr.createFromBytes(allocator, value);
                defer addr.deinit();
                try out.listen_addrs.append(try allocator.dupe(u8, addr.getStringAddress()));
            },
            3 => try out.protocols.append(try allocator.dupe(u8, value)),
            4 => {
                if (out.observed_addr.len > 0) allocator.free(out.observed_addr);
                var observed = try Multiaddr.createFromBytes(allocator, value);
                defer observed.deinit();
                out.observed_addr = try allocator.dupe(u8, observed.getStringAddress());
            },
            5 => {
                if (out.protocol_version.len > 0) allocator.free(out.protocol_version);
                out.protocol_version = try allocator.dupe(u8, value);
            },
            6 => {
                if (out.agent_version.len > 0) allocator.free(out.agent_version);
                out.agent_version = try allocator.dupe(u8, value);
            },
            else => {}, // ignore unknown fields
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
