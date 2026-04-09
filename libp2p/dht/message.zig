const std = @import("std");

pub const PROTOCOL_ID = "/kad/1.0.0";
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

pub const MessageType = enum(i32) {
    PUT_VALUE = 0,
    GET_VALUE = 1,
    ADD_PROVIDER = 2,
    GET_PROVIDERS = 3,
    FIND_NODE = 4,
    PING = 5,
};

pub const ConnectionType = enum(i32) {
    NOT_CONNECTED = 0,
    CONNECTED = 1,
    CAN_CONNECT = 2,
    CANNOT_CONNECT = 3,
};

pub const Record = struct {
    key: []u8,
    value: []u8,
    time_received: []u8,

    pub fn init() Record {
        return .{
            .key = &.{},
            .value = &.{},
            .time_received = &.{},
        };
    }

    pub fn deinit(self: *Record, allocator: std.mem.Allocator) void {
        if (self.key.len > 0) allocator.free(self.key);
        if (self.value.len > 0) allocator.free(self.value);
        if (self.time_received.len > 0) allocator.free(self.time_received);
    }
};

pub const Peer = struct {
    id: []u8,
    addrs: std.array_list.Managed([]u8),
    connection: ConnectionType,

    pub fn init(allocator: std.mem.Allocator) Peer {
        return .{
            .id = &.{},
            .addrs = std.array_list.Managed([]u8).init(allocator),
            .connection = .NOT_CONNECTED,
        };
    }

    pub fn deinit(self: *Peer, allocator: std.mem.Allocator) void {
        if (self.id.len > 0) allocator.free(self.id);
        for (self.addrs.items) |addr| allocator.free(addr);
        self.addrs.deinit();
    }
};

pub const Message = struct {
    type: MessageType,
    cluster_level_raw: i32,
    key: []u8,
    record: ?Record,
    closer_peers: std.array_list.Managed(Peer),
    provider_peers: std.array_list.Managed(Peer),

    pub fn init(allocator: std.mem.Allocator) Message {
        return .{
            .type = .PUT_VALUE,
            .cluster_level_raw = 0,
            .key = &.{},
            .record = null,
            .closer_peers = std.array_list.Managed(Peer).init(allocator),
            .provider_peers = std.array_list.Managed(Peer).init(allocator),
        };
    }

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        if (self.key.len > 0) allocator.free(self.key);
        if (self.record) |*record| record.deinit(allocator);
        for (self.closer_peers.items) |*peer| peer.deinit(allocator);
        self.closer_peers.deinit();
        for (self.provider_peers.items) |*peer| peer.deinit(allocator);
        self.provider_peers.deinit();
    }
};

pub fn encodeMessage(allocator: std.mem.Allocator, message: *const Message) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    try writeEnumField(&out, 1, @intFromEnum(message.type));
    if (message.key.len > 0) try writeBytesField(&out, 2, message.key);
    if (message.record) |*record| try writeMessageField(&out, 3, try encodeRecord(allocator, record));
    for (message.closer_peers.items) |*peer| try writeMessageField(&out, 8, try encodePeer(allocator, peer));
    for (message.provider_peers.items) |*peer| try writeMessageField(&out, 9, try encodePeer(allocator, peer));
    if (message.cluster_level_raw != 0) try writeInt32Field(&out, 10, message.cluster_level_raw);

    return out.toOwnedSlice();
}

pub fn decodeMessage(allocator: std.mem.Allocator, encoded: []const u8) !Message {
    var out = Message.init(allocator);
    errdefer out.deinit(allocator);

    var offset: usize = 0;
    while (offset < encoded.len) {
        const key = try readVarintFromSlice(encoded, &offset);
        const field_number = key >> 3;
        const wire_type = key & 0x07;

        switch (field_number) {
            1 => {
                if (wire_type != 0) return error.InvalidWireType;
                const raw_type = try readVarintFromSlice(encoded, &offset);
                out.type = intToEnum(MessageType, raw_type) orelse return error.InvalidMessageType;
            },
            2 => {
                const value = try readLengthDelimitedField(encoded, &offset, wire_type);
                if (out.key.len > 0) allocator.free(out.key);
                out.key = try allocator.dupe(u8, value);
            },
            3 => {
                const value = try readLengthDelimitedField(encoded, &offset, wire_type);
                if (out.record) |*record| record.deinit(allocator);
                out.record = try decodeRecord(allocator, value);
            },
            8 => {
                const value = try readLengthDelimitedField(encoded, &offset, wire_type);
                try out.closer_peers.append(try decodePeer(allocator, value));
            },
            9 => {
                const value = try readLengthDelimitedField(encoded, &offset, wire_type);
                try out.provider_peers.append(try decodePeer(allocator, value));
            },
            10 => {
                if (wire_type != 0) return error.InvalidWireType;
                out.cluster_level_raw = decodeInt32(try readVarintFromSlice(encoded, &offset));
            },
            else => try skipUnknownField(encoded, &offset, wire_type),
        }
    }

    return out;
}

pub fn writeMessageFrame(
    allocator: std.mem.Allocator,
    io: std.Io,
    writer: anytype,
    message: *const Message,
) !void {
    const encoded = try encodeMessage(allocator, message);
    defer allocator.free(encoded);

    if (encoded.len > MAX_FRAME_SIZE) return error.MessageTooLarge;

    try writeVarint(io, writer, encoded.len);
    try callWriteAll(writer, io, encoded);
}

pub fn readMessageFrame(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: anytype,
) !Message {
    const frame_len = readFrameLength(io, reader) catch |err| switch (err) {
        error.EndOfStream => return error.EndOfStream,
        else => return err,
    };
    if (frame_len > MAX_FRAME_SIZE) return error.MessageTooLarge;

    const buffer = try allocator.alloc(u8, frame_len);
    defer allocator.free(buffer);

    try readNoEof(reader, io, buffer);
    return try decodeMessage(allocator, buffer);
}

pub fn sendRequest(
    allocator: std.mem.Allocator,
    io: std.Io,
    writer: anytype,
    request: *const Message,
) !void {
    try writeMessageFrame(allocator, io, writer, request);
}

pub fn readResponse(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: anytype,
) !Message {
    return try readMessageFrame(allocator, io, reader);
}

fn encodeRecord(allocator: std.mem.Allocator, record: *const Record) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    if (record.key.len > 0) try writeBytesField(&out, 1, record.key);
    if (record.value.len > 0) try writeBytesField(&out, 2, record.value);
    if (record.time_received.len > 0) try writeBytesField(&out, 5, record.time_received);

    return out.toOwnedSlice();
}

fn decodeRecord(allocator: std.mem.Allocator, encoded: []const u8) !Record {
    var out = Record.init();
    errdefer out.deinit(allocator);

    var offset: usize = 0;
    while (offset < encoded.len) {
        const key = try readVarintFromSlice(encoded, &offset);
        const field_number = key >> 3;
        const wire_type = key & 0x07;

        switch (field_number) {
            1 => {
                const value = try readLengthDelimitedField(encoded, &offset, wire_type);
                if (out.key.len > 0) allocator.free(out.key);
                out.key = try allocator.dupe(u8, value);
            },
            2 => {
                const value = try readLengthDelimitedField(encoded, &offset, wire_type);
                if (out.value.len > 0) allocator.free(out.value);
                out.value = try allocator.dupe(u8, value);
            },
            5 => {
                const value = try readLengthDelimitedField(encoded, &offset, wire_type);
                if (out.time_received.len > 0) allocator.free(out.time_received);
                out.time_received = try allocator.dupe(u8, value);
            },
            else => try skipUnknownField(encoded, &offset, wire_type),
        }
    }

    return out;
}

fn encodePeer(allocator: std.mem.Allocator, peer: *const Peer) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    if (peer.id.len > 0) try writeBytesField(&out, 1, peer.id);
    for (peer.addrs.items) |addr| try writeBytesField(&out, 2, addr);
    if (peer.connection != .NOT_CONNECTED) try writeEnumField(&out, 3, @intFromEnum(peer.connection));

    return out.toOwnedSlice();
}

fn decodePeer(allocator: std.mem.Allocator, encoded: []const u8) !Peer {
    var out = Peer.init(allocator);
    errdefer out.deinit(allocator);

    var offset: usize = 0;
    while (offset < encoded.len) {
        const key = try readVarintFromSlice(encoded, &offset);
        const field_number = key >> 3;
        const wire_type = key & 0x07;

        switch (field_number) {
            1 => {
                const value = try readLengthDelimitedField(encoded, &offset, wire_type);
                if (out.id.len > 0) allocator.free(out.id);
                out.id = try allocator.dupe(u8, value);
            },
            2 => {
                const value = try readLengthDelimitedField(encoded, &offset, wire_type);
                try out.addrs.append(try allocator.dupe(u8, value));
            },
            3 => {
                if (wire_type != 0) return error.InvalidWireType;
                const raw_connection = try readVarintFromSlice(encoded, &offset);
                out.connection = intToEnum(ConnectionType, raw_connection) orelse return error.InvalidConnectionType;
            },
            else => try skipUnknownField(encoded, &offset, wire_type),
        }
    }

    return out;
}

fn writeMessageField(out: *std.array_list.Managed(u8), field_number: usize, encoded: []u8) !void {
    defer out.allocator.free(encoded);
    try writeVarintToList(out, (field_number << 3) | 2);
    try writeVarintToList(out, encoded.len);
    try out.appendSlice(encoded);
}

fn writeBytesField(out: *std.array_list.Managed(u8), field_number: usize, value: []const u8) !void {
    try writeVarintToList(out, (field_number << 3) | 2);
    try writeVarintToList(out, value.len);
    try out.appendSlice(value);
}

fn writeEnumField(out: *std.array_list.Managed(u8), field_number: usize, value: anytype) !void {
    try writeVarintToList(out, field_number << 3);
    try writeVarintToList(out, @as(u64, @intCast(value)));
}

fn writeInt32Field(out: *std.array_list.Managed(u8), field_number: usize, value: i32) !void {
    try writeVarintToList(out, field_number << 3);
    const bits: u32 = @bitCast(value);
    try writeVarintToList(out, bits);
}

fn writeVarintToList(out: *std.array_list.Managed(u8), value: anytype) !void {
    var v: u64 = @intCast(value);
    while (v >= 0x80) : (v >>= 7) {
        try out.append(@as(u8, @intCast(v & 0x7F)) | 0x80);
    }
    try out.append(@as(u8, @intCast(v)));
}

fn writeVarint(io: std.Io, writer: anytype, value: usize) !void {
    var v: u64 = value;
    while (v >= 0x80) : (v >>= 7) {
        try callWriteByte(writer, io, @as(u8, @intCast(v & 0x7F)) | 0x80);
    }
    try callWriteByte(writer, io, @as(u8, @intCast(v)));
}

fn readFrameLength(io: std.Io, reader: anytype) !usize {
    var result: usize = 0;
    var shift: u6 = 0;
    var saw_data = false;

    while (true) {
        const byte = callReadByte(reader, io) catch {
            if (!saw_data) return error.EndOfStream;
            return error.TruncatedFrame;
        };
        saw_data = true;

        const value = byte & 0x7F;
        if (shift >= 64 or (shift == 63 and value > 1)) return error.VarintOverflow;

        result |= @as(usize, value) << shift;
        if ((byte & 0x80) == 0) return result;

        shift += 7;
    }
}

fn readVarintFromSlice(data: []const u8, offset: *usize) !u64 {
    var result: u64 = 0;
    var shift: u6 = 0;

    while (offset.* < data.len) {
        const byte = data[offset.*];
        offset.* += 1;

        const value = byte & 0x7F;
        if (shift >= 64 or (shift == 63 and value > 1)) return error.VarintOverflow;

        result |= @as(u64, value) << shift;
        if ((byte & 0x80) == 0) return result;

        shift += 7;
    }

    return error.EndOfStream;
}

fn readLengthDelimitedField(data: []const u8, offset: *usize, wire_type: u64) ![]const u8 {
    if (wire_type != 2) return error.InvalidWireType;

    const field_len = try readVarintFromSlice(data, offset);
    if (field_len > data.len - offset.*) return error.InvalidFieldLength;

    const value = data[offset.* .. offset.* + field_len];
    offset.* += field_len;
    return value;
}

fn skipUnknownField(data: []const u8, offset: *usize, wire_type: u64) !void {
    switch (wire_type) {
        0 => _ = try readVarintFromSlice(data, offset),
        1 => {
            if (data.len - offset.* < 8) return error.InvalidFieldLength;
            offset.* += 8;
        },
        2 => {
            const field_len = try readVarintFromSlice(data, offset);
            if (field_len > data.len - offset.*) return error.InvalidFieldLength;
            offset.* += field_len;
        },
        5 => {
            if (data.len - offset.* < 4) return error.InvalidFieldLength;
            offset.* += 4;
        },
        else => return error.InvalidWireType,
    }
}

fn decodeInt32(raw: u64) i32 {
    const bits: u32 = @truncate(raw);
    return @bitCast(bits);
}

fn intToEnum(comptime Enum: type, raw: u64) ?Enum {
    const info = @typeInfo(Enum).@"enum";
    const Tag = info.tag_type;
    if (raw > std.math.maxInt(Tag)) return null;
    const narrowed: Tag = @intCast(raw);

    inline for (info.fields) |field| {
        if (field.value == narrowed) {
            return @enumFromInt(narrowed);
        }
    }

    return null;
}

fn callReadByte(reader: anytype, io: std.Io) !u8 {
    if (comptime hasMethodWithIo(@TypeOf(reader.*), "readByte")) {
        return try reader.readByte(io);
    }
    return try reader.readByte();
}

fn readNoEof(reader: anytype, io: std.Io, dest: []u8) !void {
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
        if (amt == 0) return error.TruncatedFrame;
        offset += amt;
    }
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
    return try writer.writeByte(byte);
}

fn hasMethodWithIo(comptime T: type, comptime name: []const u8) bool {
    if (!@hasDecl(T, name)) return false;
    const decl = @field(T, name);
    const fn_info = @typeInfo(@TypeOf(decl)).@"fn";
    return fn_info.params.len > 1 and fn_info.params[1].type == std.Io;
}

const multiaddr = @import("../multiaddr/multiaddr.zig");
const Multiaddr = multiaddr.Multiaddr;

const TestBuffer = struct {
    bytes: std.array_list.Managed(u8),
    read_offset: usize,

    fn init(allocator: std.mem.Allocator) TestBuffer {
        return .{
            .bytes = std.array_list.Managed(u8).init(allocator),
            .read_offset = 0,
        };
    }

    fn deinit(self: *TestBuffer) void {
        self.bytes.deinit();
    }

    fn writeAll(self: *TestBuffer, data: []const u8) !void {
        try self.bytes.appendSlice(data);
    }

    fn writeByte(self: *TestBuffer, byte: u8) !void {
        try self.bytes.append(byte);
    }

    fn readByte(self: *TestBuffer) !u8 {
        if (self.read_offset >= self.bytes.items.len) return error.EndOfStream;
        const byte = self.bytes.items[self.read_offset];
        self.read_offset += 1;
        return byte;
    }

    fn readSome(self: *TestBuffer, dest: []u8) !usize {
        if (self.read_offset >= self.bytes.items.len) return 0;
        const remaining = self.bytes.items.len - self.read_offset;
        const amt = @min(dest.len, remaining);
        @memcpy(dest[0..amt], self.bytes.items[self.read_offset .. self.read_offset + amt]);
        self.read_offset += amt;
        return amt;
    }
};

fn addTestAddr(peer: *Peer, allocator: std.mem.Allocator, addr: []const u8) !void {
    var multi = try Multiaddr.create(allocator, addr);
    defer multi.deinit();
    try peer.addrs.append(try allocator.dupe(u8, multi.getBytesAddress()));
}

fn expectPeerEq(expected: *const Peer, actual: *const Peer) !void {
    try std.testing.expectEqualStrings(expected.id, actual.id);
    try std.testing.expectEqual(expected.connection, actual.connection);
    try std.testing.expectEqual(expected.addrs.items.len, actual.addrs.items.len);
    for (expected.addrs.items, actual.addrs.items) |expected_addr, actual_addr| {
        try std.testing.expectEqualSlices(u8, expected_addr, actual_addr);
    }
}

fn expectRecordEq(expected: *const Record, actual: *const Record) !void {
    try std.testing.expectEqualStrings(expected.key, actual.key);
    try std.testing.expectEqualStrings(expected.value, actual.value);
    try std.testing.expectEqualStrings(expected.time_received, actual.time_received);
}

fn expectMessageEq(expected: *const Message, actual: *const Message) !void {
    try std.testing.expectEqual(expected.type, actual.type);
    try std.testing.expectEqual(expected.cluster_level_raw, actual.cluster_level_raw);
    try std.testing.expectEqualStrings(expected.key, actual.key);

    if (expected.record) |*expected_record| {
        try std.testing.expect(actual.record != null);
        try expectRecordEq(expected_record, &actual.record.?);
    } else {
        try std.testing.expect(actual.record == null);
    }

    try std.testing.expectEqual(expected.closer_peers.items.len, actual.closer_peers.items.len);
    for (expected.closer_peers.items, actual.closer_peers.items) |*expected_peer, *actual_peer| {
        try expectPeerEq(expected_peer, actual_peer);
    }

    try std.testing.expectEqual(expected.provider_peers.items.len, actual.provider_peers.items.len);
    for (expected.provider_peers.items, actual.provider_peers.items) |*expected_peer, *actual_peer| {
        try expectPeerEq(expected_peer, actual_peer);
    }
}

test "kad message roundtrip preserves all message types" {
    const allocator = std.testing.allocator;

    const message_types = [_]MessageType{
        .PUT_VALUE,
        .GET_VALUE,
        .ADD_PROVIDER,
        .GET_PROVIDERS,
        .FIND_NODE,
        .PING,
    };

    for (message_types, 0..) |message_type, index| {
        var message = Message.init(allocator);
        defer message.deinit(allocator);
        message.type = message_type;
        message.cluster_level_raw = @intCast(index + 1);
        message.key = try std.fmt.allocPrint(allocator, "key-{d}", .{index});

        var record = Record.init();
        record.key = try allocator.dupe(u8, message.key);
        record.value = try std.fmt.allocPrint(allocator, "value-{d}", .{index});
        record.time_received = try std.fmt.allocPrint(allocator, "2026-04-09T00:00:0{d}Z", .{index});
        message.record = record;

        var closer = Peer.init(allocator);
        closer.id = try std.fmt.allocPrint(allocator, "closer-{d}", .{index});
        closer.connection = .CONNECTED;
        try addTestAddr(&closer, allocator, "/ip4/127.0.0.1/tcp/10801");
        try addTestAddr(&closer, allocator, "/dns4/bootstrap.zei.test/tcp/10802");
        try message.closer_peers.append(closer);

        var provider = Peer.init(allocator);
        provider.id = try std.fmt.allocPrint(allocator, "provider-{d}", .{index});
        provider.connection = .CAN_CONNECT;
        try addTestAddr(&provider, allocator, "/ip6/::1/tcp/10803");
        try message.provider_peers.append(provider);

        const encoded = try encodeMessage(allocator, &message);
        defer allocator.free(encoded);

        var decoded = try decodeMessage(allocator, encoded);
        defer decoded.deinit(allocator);

        try expectMessageEq(&message, &decoded);
    }
}

test "kad message frame helpers support back to back frames" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var first = Message.init(allocator);
    defer first.deinit(allocator);
    first.type = .FIND_NODE;
    first.key = try allocator.dupe(u8, "target-a");

    var second = Message.init(allocator);
    defer second.deinit(allocator);
    second.type = .GET_PROVIDERS;
    second.key = try allocator.dupe(u8, "cid-b");

    var buffer = TestBuffer.init(allocator);
    defer buffer.deinit();

    try writeMessageFrame(allocator, io, &buffer, &first);
    try writeMessageFrame(allocator, io, &buffer, &second);

    var decoded_first = try readMessageFrame(allocator, io, &buffer);
    defer decoded_first.deinit(allocator);
    var decoded_second = try readMessageFrame(allocator, io, &buffer);
    defer decoded_second.deinit(allocator);

    try std.testing.expectEqual(MessageType.FIND_NODE, decoded_first.type);
    try std.testing.expectEqualStrings("target-a", decoded_first.key);
    try std.testing.expectEqual(MessageType.GET_PROVIDERS, decoded_second.type);
    try std.testing.expectEqualStrings("cid-b", decoded_second.key);
    try std.testing.expectError(error.EndOfStream, readMessageFrame(allocator, io, &buffer));
}

test "kad message decode skips unknown fields across supported wire types" {
    const allocator = std.testing.allocator;

    var message = Message.init(allocator);
    defer message.deinit(allocator);
    message.type = .GET_VALUE;
    message.key = try allocator.dupe(u8, "known-key");

    const encoded = try encodeMessage(allocator, &message);
    defer allocator.free(encoded);

    var payload = std.array_list.Managed(u8).init(allocator);
    defer payload.deinit();
    try payload.appendSlice(encoded);
    try writeVarintToList(&payload, (20 << 3) | 0);
    try writeVarintToList(&payload, 150);
    try writeVarintToList(&payload, (21 << 3) | 1);
    try payload.appendNTimes(0xAB, 8);
    try writeVarintToList(&payload, (22 << 3) | 2);
    try writeVarintToList(&payload, 3);
    try payload.appendSlice(&[_]u8{ 0xDE, 0xAD, 0xBE });
    try writeVarintToList(&payload, (23 << 3) | 5);
    try payload.appendSlice(&[_]u8{ 0x11, 0x22, 0x33, 0x44 });

    var decoded = try decodeMessage(allocator, payload.items);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(MessageType.GET_VALUE, decoded.type);
    try std.testing.expectEqualStrings("known-key", decoded.key);
}

test "kad message decode rejects invalid unknown wire type" {
    const allocator = std.testing.allocator;

    var payload = std.array_list.Managed(u8).init(allocator);
    defer payload.deinit();
    try writeVarintToList(&payload, (1 << 3) | 0);
    try writeVarintToList(&payload, 4);
    try writeVarintToList(&payload, (24 << 3) | 3);

    try std.testing.expectError(error.InvalidWireType, decodeMessage(allocator, payload.items));
}

test "kad message decode rejects truncated unknown field" {
    const allocator = std.testing.allocator;

    var payload = std.array_list.Managed(u8).init(allocator);
    defer payload.deinit();
    try writeVarintToList(&payload, (1 << 3) | 0);
    try writeVarintToList(&payload, 4);
    try writeVarintToList(&payload, (24 << 3) | 2);
    try writeVarintToList(&payload, 3);
    try payload.append(0xAA);

    try std.testing.expectError(error.InvalidFieldLength, decodeMessage(allocator, payload.items));
}

test "kad message frame read distinguishes clean eof from truncated frame" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var empty_buffer = TestBuffer.init(allocator);
    defer empty_buffer.deinit();
    try std.testing.expectError(error.EndOfStream, readMessageFrame(allocator, io, &empty_buffer));

    var truncated = TestBuffer.init(allocator);
    defer truncated.deinit();
    try truncated.writeByte(0x02);
    try truncated.writeByte(0x08);

    try std.testing.expectError(error.TruncatedFrame, readMessageFrame(allocator, io, &truncated));
}

test "kad message frame rejects oversized payload length" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var buffer = TestBuffer.init(allocator);
    defer buffer.deinit();
    try writeVarint(io, &buffer, MAX_FRAME_SIZE + 1);

    try std.testing.expectError(error.MessageTooLarge, readMessageFrame(allocator, io, &buffer));
}
