// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: MIT

const std = @import("std");
const multiaddr = @import("../multiaddr/multiaddr.zig");
const Multiaddr = multiaddr.Multiaddr;
const ED25519_PUBLIC_KEY_PROTO_LEN: usize = 36;

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

pub fn encodeIdentityPublicKey(public_key: [32]u8) [ED25519_PUBLIC_KEY_PROTO_LEN]u8 {
    var out: [ED25519_PUBLIC_KEY_PROTO_LEN]u8 = undefined;
    out[0] = 0x08;
    out[1] = 0x01;
    out[2] = 0x12;
    out[3] = 0x20;
    @memcpy(out[4..], &public_key);
    return out;
}

pub fn writeDelimitedIdentify(
    allocator: std.mem.Allocator,
    io: std.Io,
    writer: anytype,
    protocol_version: []const u8,
    agent_version: []const u8,
    public_key: []const u8,
    listen_addrs: []const []const u8,
    observed_addr: []const u8,
    protocols: []const []const u8,
) !void {
    const encoded = try encodeIdentify(
        allocator,
        protocol_version,
        agent_version,
        public_key,
        listen_addrs,
        observed_addr,
        protocols,
    );
    defer allocator.free(encoded);

    try writeVarint(io, writer, encoded.len);
    try callWriteAll(writer, io, encoded);
}

pub fn readDelimitedIdentify(allocator: std.mem.Allocator, io: std.Io, reader: anytype) !IdentifyInfo {
    var merged = IdentifyInfo.init(allocator);
    errdefer merged.deinit(allocator);

    var saw_message = false;
    while (true) {
        const frame_len = readVarint(io, reader) catch |err| switch (err) {
            error.EndOfStream => {
                if (!saw_message) return error.EndOfStream;
                break;
            },
            else => return err,
        };

        const buffer = try allocator.alloc(u8, frame_len);
        defer allocator.free(buffer);
        try readNoEof(reader, io, buffer);

        var part = try decodeIdentify(allocator, buffer);
        defer part.deinit(allocator);
        try mergeIdentifyInfo(allocator, &merged, &part);
        saw_message = true;
    }

    return merged;
}

pub fn decodeIdentify(allocator: std.mem.Allocator, encoded: []const u8) !IdentifyInfo {
    var out = IdentifyInfo.init(allocator);
    errdefer out.deinit(allocator);

    var off: usize = 0;
    while (off < encoded.len) {
        const key = try readVarintFromSlice(encoded, &off);
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

fn readVarintFromSlice(data: []const u8, off: *usize) !usize {
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

fn writeVarint(io: std.Io, writer: anytype, value: usize) !void {
    var v = value;
    while (v >= 0x80) {
        try callWriteByte(writer, io, @as(u8, @intCast(v & 0x7F)) | 0x80);
        v >>= 7;
    }
    try callWriteByte(writer, io, @as(u8, @intCast(v)));
}

fn readVarint(io: std.Io, reader: anytype) !usize {
    var result: usize = 0;
    var shift: u6 = 0;

    while (true) {
        const byte = try callReadByte(reader, io);
        const value = byte & 0x7F;
        if (shift >= 64 or (shift == 63 and value > 1)) return error.VarintOverflow;

        result |= @as(usize, value) << shift;
        if ((byte & 0x80) == 0) return result;
        shift += 7;
    }
}

fn readLengthDelimitedField(data: []const u8, off: *usize, wire_type: usize) ![]const u8 {
    if (wire_type != 2) return error.InvalidWireType;

    const field_len = try readVarintFromSlice(data, off);
    if (off.* + field_len > data.len) return error.InvalidFieldLength;

    const value = data[off.* .. off.* + field_len];
    off.* += field_len;
    return value;
}

fn skipUnknownField(data: []const u8, off: *usize, wire_type: usize) !void {
    switch (wire_type) {
        0 => _ = try readVarintFromSlice(data, off),
        1 => {
            if (off.* + 8 > data.len) return error.InvalidFieldLength;
            off.* += 8;
        },
        2 => {
            const field_len = try readVarintFromSlice(data, off);
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

fn mergeIdentifyInfo(allocator: std.mem.Allocator, target: *IdentifyInfo, source: *const IdentifyInfo) !void {
    if (source.protocol_version.len > 0) {
        if (target.protocol_version.len > 0) allocator.free(target.protocol_version);
        target.protocol_version = try allocator.dupe(u8, source.protocol_version);
    }
    if (source.agent_version.len > 0) {
        if (target.agent_version.len > 0) allocator.free(target.agent_version);
        target.agent_version = try allocator.dupe(u8, source.agent_version);
    }
    if (source.public_key.len > 0) {
        if (target.public_key.len > 0) allocator.free(target.public_key);
        target.public_key = try allocator.dupe(u8, source.public_key);
    }
    if (source.observed_addr.len > 0) {
        if (target.observed_addr.len > 0) allocator.free(target.observed_addr);
        target.observed_addr = try allocator.dupe(u8, source.observed_addr);
    }
    for (source.listen_addrs.items) |addr| {
        try target.listen_addrs.append(try allocator.dupe(u8, addr));
    }
    for (source.protocols.items) |proto| {
        try target.protocols.append(try allocator.dupe(u8, proto));
    }
}

fn readNoEof(reader: anytype, io: std.Io, dest: []u8) !void {
    if (comptime @hasDecl(@TypeOf(reader.*), "readSliceAll")) {
        return try reader.readSliceAll(dest);
    }
    if (comptime hasMethodWithIo(@TypeOf(reader.*), "readNoEof")) {
        return try reader.readNoEof(io, dest);
    }
    if (comptime @hasDecl(@TypeOf(reader.*), "readNoEof")) {
        return try reader.readNoEof(dest);
    }

    var offset: usize = 0;
    while (offset < dest.len) {
        const amt = if (comptime hasMethodWithIo(@TypeOf(reader.*), "readSome"))
            try reader.readSome(io, dest[offset..])
        else
            try reader.readSome(dest[offset..]);
        if (amt == 0) return error.EndOfStream;
        offset += amt;
    }
}

fn callReadByte(reader: anytype, io: std.Io) !u8 {
    if (comptime @hasDecl(@TypeOf(reader.*), "takeByte")) {
        return try reader.takeByte();
    }
    if (comptime hasMethodWithIo(@TypeOf(reader.*), "readByte")) {
        return try reader.readByte(io);
    }
    if (comptime @hasDecl(@TypeOf(reader.*), "readByte")) {
        return try reader.readByte();
    }

    var one: [1]u8 = undefined;
    const amt = if (comptime hasMethodWithIo(@TypeOf(reader.*), "readSome"))
        try reader.readSome(io, &one)
    else
        try reader.readSome(&one);
    if (amt == 0) return error.EndOfStream;
    return one[0];
}

fn callWriteAll(writer: anytype, io: std.Io, bytes: []const u8) !void {
    if (comptime hasMethodWithIo(@TypeOf(writer.*), "writeAll")) {
        return try writer.writeAll(io, bytes);
    }
    return try writer.writeAll(bytes);
}

fn callWriteByte(writer: anytype, io: std.Io, byte: u8) !void {
    if (comptime hasMethodWithIo(@TypeOf(writer.*), "writeByte")) {
        return try writer.writeByte(io, byte);
    }
    if (comptime @hasDecl(@TypeOf(writer.*), "writeByte")) {
        return try writer.writeByte(byte);
    }

    var one = [1]u8{byte};
    return try callWriteAll(writer, io, &one);
}

fn hasMethodWithIo(comptime T: type, comptime name: []const u8) bool {
    return @hasDecl(T, name) and switch (@typeInfo(@TypeOf(@field(T, name)))) {
        .@"fn" => |info| info.params.len > 0 and info.params[0].type == std.Io,
        else => false,
    };
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

test "identify delimited read merges multiple messages" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var payload: std.Io.Writer.Allocating = .init(allocator);
    defer payload.deinit();

    var observed_ma = try Multiaddr.create(allocator, "/ip4/10.0.0.7/tcp/55555");
    defer observed_ma.deinit();
    const protocols = [_][]const u8{"/kad/1.0.0"};
    const pubkey = [_]u8{0xAB} ** 36;

    const writer = &payload.writer;
    try writeDelimitedIdentify(
        allocator,
        io,
        writer,
        "/zeicoin/testnet/1.0.0",
        "zeicoin/0.1.0",
        &pubkey,
        &[_][]const u8{},
        observed_ma.getBytesAddress(),
        &[_][]const u8{},
    );
    try writeDelimitedIdentify(
        allocator,
        io,
        writer,
        "",
        "",
        "",
        &[_][]const u8{},
        "",
        &protocols,
    );

    var reader: std.Io.Reader = .fixed(payload.written());
    var decoded = try readDelimitedIdentify(allocator, io, &reader);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings("/zeicoin/testnet/1.0.0", decoded.protocol_version);
    try std.testing.expectEqualStrings("zeicoin/0.1.0", decoded.agent_version);
    try std.testing.expectEqualSlices(u8, &pubkey, decoded.public_key);
    try std.testing.expectEqualStrings("/ip4/10.0.0.7/tcp/55555", decoded.observed_addr);
    try std.testing.expectEqual(@as(usize, 1), decoded.protocols.items.len);
    try std.testing.expectEqualStrings("/kad/1.0.0", decoded.protocols.items[0]);
}
