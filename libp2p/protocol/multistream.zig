// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

// multistream.zig - Multistream-select protocol implementation
// Protocol negotiation for libp2p connections

const std = @import("std");

// Protocol constants
pub const PROTOCOL_ID = "/multistream/1.0.0";
pub const MAX_MESSAGE_SIZE: usize = 65535;
pub const MAX_VARINT_SIZE: usize = 3;
pub const NEWLINE: u8 = 0x0A;
pub const NA = "na";

// Message types
pub const MessageType = enum {
    InvalidMessage,
    RightProtocolVersion,
    WrongProtocolVersion,
    LSMessage,
    NAMessage,
    ProtocolName,
};

pub const Message = struct {
    type: MessageType,
    content: []const u8,
};

/// Write a message with length prefix and newline
pub fn writeMessage(io: std.Io, writer: anytype, message: []const u8) !void {
    // Write varint length prefix (includes newline)
    const total_len = message.len + 1;
    try writeVarint(io, writer, total_len);

    // Write message
    try callWriteAll(writer, io, message);

    // Write newline
    try callWriteByte(writer, io, NEWLINE);
}

/// Read a message with length prefix
pub fn readMessage(io: std.Io, reader: anytype, allocator: std.mem.Allocator) ![]u8 {
    // Read varint length
    const len = try readVarint(io, reader);
    if (len > MAX_MESSAGE_SIZE) {
        return error.MessageTooLarge;
    }

    // Allocate buffer
    const buffer = try allocator.alloc(u8, len);
    errdefer allocator.free(buffer);

    // Read message content
    try callReadNoEof(reader, io, buffer);

    // Verify and remove newline
    if (buffer.len == 0 or buffer[buffer.len - 1] != NEWLINE) {
        return error.InvalidMessage;
    }

    const message = try allocator.dupe(u8, buffer[0 .. buffer.len - 1]);
    allocator.free(buffer);
    return message;
}

/// Write varint (unsigned LEB128)
pub fn writeVarint(io: std.Io, writer: anytype, value: usize) !void {
    var v = value;
    while (v >= 0x80) {
        try callWriteByte(writer, io, @as(u8, @intCast(v & 0x7F)) | 0x80);
        v >>= 7;
    }
    try callWriteByte(writer, io, @as(u8, @intCast(v)));
}

/// Read varint (unsigned LEB128)
pub fn readVarint(io: std.Io, reader: anytype) !usize {
    var result: usize = 0;
    var shift: u6 = 0;

    while (true) {
        const byte = try callReadByte(reader, io);
        const value = byte & 0x7F;

        // Check for overflow
        if (shift >= 64 or (shift == 63 and value > 1)) {
            return error.VarintOverflow;
        }

        result |= @as(usize, value) << shift;

        if ((byte & 0x80) == 0) {
            break;
        }

        shift += 7;
    }

    return result;
}

/// Parse message type from content
pub fn parseMessage(content: []const u8) Message {
    if (std.mem.eql(u8, content, PROTOCOL_ID)) {
        return .{
            .type = .RightProtocolVersion,
            .content = content,
        };
    } else if (std.mem.eql(u8, content, NA)) {
        return .{
            .type = .NAMessage,
            .content = content,
        };
    } else if (std.mem.eql(u8, content, "ls")) {
        return .{
            .type = .LSMessage,
            .content = content,
        };
    } else if (std.mem.startsWith(u8, content, "/multistream/")) {
        return .{
            .type = .WrongProtocolVersion,
            .content = content,
        };
    } else if (std.mem.startsWith(u8, content, "/")) {
        return .{
            .type = .ProtocolName,
            .content = content,
        };
    } else {
        return .{
            .type = .InvalidMessage,
            .content = content,
        };
    }
}

/// Multistream negotiator
pub const Negotiator = struct {
    allocator: std.mem.Allocator,
    is_initiator: bool,
    protocols: []const []const u8,
    selected_protocol: ?[]const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, protocols: []const []const u8, is_initiator: bool) Self {
        return .{
            .allocator = allocator,
            .is_initiator = is_initiator,
            .protocols = protocols,
            .selected_protocol = null,
        };
    }

    /// Negotiate protocol selection
    pub fn negotiate(self: *Self, io: std.Io, reader: anytype, writer: anytype) ![]const u8 {
        if (self.is_initiator) {
            return self.negotiateInitiator(io, reader, writer);
        } else {
            return self.negotiateResponder(io, reader, writer);
        }
    }

    /// Initiator side of negotiation
    fn negotiateInitiator(self: *Self, io: std.Io, reader: anytype, writer: anytype) ![]const u8 {
        // Send multistream version
        try writeMessage(io, writer, PROTOCOL_ID);

        // Read response
        const response = try readMessage(io, reader, self.allocator);
        defer self.allocator.free(response);

        const msg = parseMessage(response);
        if (msg.type != .RightProtocolVersion) {
            return error.ProtocolMismatch;
        }

        // Try each protocol in order
        for (self.protocols) |protocol| {
            // Send protocol proposal
            try writeMessage(io, writer, protocol);

            // Read response
            const proto_response = try readMessage(io, reader, self.allocator);
            defer self.allocator.free(proto_response);

            const proto_msg = parseMessage(proto_response);
            switch (proto_msg.type) {
                .ProtocolName => {
                    if (std.mem.eql(u8, proto_msg.content, protocol)) {
                        self.selected_protocol = protocol;
                        return protocol;
                    }
                },
                .NAMessage => continue, // Try next protocol
                else => return error.UnexpectedMessage,
            }
        }

        return error.NoProtocolMatch;
    }

    /// Responder side of negotiation
    fn negotiateResponder(self: *Self, io: std.Io, reader: anytype, writer: anytype) ![]const u8 {
        // Read multistream version
        const version_msg = try readMessage(io, reader, self.allocator);
        defer self.allocator.free(version_msg);

        const msg = parseMessage(version_msg);
        if (msg.type != .RightProtocolVersion) {
            return error.ProtocolMismatch;
        }

        // Send version acknowledgment
        try writeMessage(io, writer, PROTOCOL_ID);

        // Read protocol proposals
        while (true) {
            const proposal = try readMessage(io, reader, self.allocator);
            defer self.allocator.free(proposal);

            const proto_msg = parseMessage(proposal);
            switch (proto_msg.type) {
                .ProtocolName => {
                    // Check if we support this protocol
                    for (self.protocols) |supported| {
                        if (std.mem.eql(u8, proto_msg.content, supported)) {
                            // Send acknowledgment
                            try writeMessage(io, writer, supported);
                            self.selected_protocol = supported;
                            return supported;
                        }
                    }
                    // Not supported, send NA
                    try writeMessage(io, writer, NA);
                },
                .LSMessage => {
                    // List protocols (not implemented)
                    try writeMessage(io, writer, NA);
                },
                else => return error.UnexpectedMessage,
            }
        }
    }
};

fn callWriteAll(writer: anytype, io: std.Io, data: []const u8) !void {
    const Writer = @TypeOf(writer);
    if (comptime hasMethodWithIo(Writer, "writeAll")) {
        try writer.writeAll(io, data);
    } else {
        try writer.writeAll(data);
    }
}

fn callWriteByte(writer: anytype, io: std.Io, b: u8) !void {
    const Writer = @TypeOf(writer);
    if (comptime hasMethodWithIo(Writer, "writeByte")) {
        try writer.writeByte(io, b);
    } else {
        try writer.writeByte(b);
    }
}

fn callReadByte(reader: anytype, io: std.Io) !u8 {
    const Reader = @TypeOf(reader);
    if (comptime hasMethodWithIo(Reader, "readByte")) {
        return try reader.readByte(io);
    }
    return try reader.readByte();
}

fn callReadNoEof(reader: anytype, io: std.Io, dest: []u8) !void {
    const Reader = @TypeOf(reader);
    if (comptime hasMethodWithIo(Reader, "readNoEof")) {
        try reader.readNoEof(io, dest);
    } else {
        try reader.readNoEof(dest);
    }
}

fn hasMethodWithIo(comptime T: type, comptime name: []const u8) bool {
    const Base = switch (@typeInfo(T)) {
        .pointer => |ptr| ptr.child,
        else => T,
    };
    if (!@hasDecl(Base, name)) return false;
    const info = @typeInfo(@TypeOf(@field(Base, name)));
    if (info != .@"fn") return false;
    const params = info.@"fn".params;
    return params.len >= 2 and params[1].type == std.Io;
}

// Tests
const TestIoBuffer = struct {
    bytes: [4096]u8 = undefined,
    write_pos: usize = 0,
    read_pos: usize = 0,

    fn writeAll(self: *TestIoBuffer, data: []const u8) !void {
        if (self.write_pos + data.len > self.bytes.len) return error.NoSpaceLeft;
        @memcpy(self.bytes[self.write_pos .. self.write_pos + data.len], data);
        self.write_pos += data.len;
    }

    fn writeByte(self: *TestIoBuffer, b: u8) !void {
        if (self.write_pos >= self.bytes.len) return error.NoSpaceLeft;
        self.bytes[self.write_pos] = b;
        self.write_pos += 1;
    }

    fn readByte(self: *TestIoBuffer) !u8 {
        if (self.read_pos >= self.write_pos) return error.EndOfStream;
        const b = self.bytes[self.read_pos];
        self.read_pos += 1;
        return b;
    }

    fn readNoEof(self: *TestIoBuffer, out: []u8) !void {
        if (self.read_pos + out.len > self.write_pos) return error.EndOfStream;
        @memcpy(out, self.bytes[self.read_pos .. self.read_pos + out.len]);
        self.read_pos += out.len;
    }
};

test "varint encoding/decoding" {
    const io = std.testing.io;
    // Test values
    const test_values = [_]usize{ 0, 127, 128, 16383, 16384, 65535 };

    for (test_values) |value| {
        var buffer: TestIoBuffer = .{};

        // Write varint
        try writeVarint(io, &buffer, value);

        // Read it back
        const decoded = try readVarint(io, &buffer);

        try std.testing.expectEqual(value, decoded);
    }
}

test "message read/write" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var buffer: TestIoBuffer = .{};

    // Write message
    const test_msg = "/test/protocol/1.0.0";
    try writeMessage(io, &buffer, test_msg);

    // Read it back
    const read_msg = try readMessage(io, &buffer, allocator);
    defer allocator.free(read_msg);

    try std.testing.expectEqualStrings(test_msg, read_msg);
}

test "protocol negotiation - initiator" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var buffer: TestIoBuffer = .{};

    // Simulate responder messages
    try writeMessage(io, &buffer, PROTOCOL_ID); // Version ack
    try writeMessage(io, &buffer, NA); // First protocol rejected
    try writeMessage(io, &buffer, "/yamux/1.0.0"); // Second protocol accepted
    var out_buffer: TestIoBuffer = .{};

    const protocols = [_][]const u8{ "/mplex/1.0.0", "/yamux/1.0.0" };
    var negotiator = Negotiator.init(allocator, &protocols, true);

    const selected = try negotiator.negotiate(io, &buffer, &out_buffer);
    try std.testing.expectEqualStrings("/yamux/1.0.0", selected);
}

test "parse message types" {
    try std.testing.expectEqual(MessageType.RightProtocolVersion, parseMessage(PROTOCOL_ID).type);
    try std.testing.expectEqual(MessageType.NAMessage, parseMessage(NA).type);
    try std.testing.expectEqual(MessageType.LSMessage, parseMessage("ls").type);
    try std.testing.expectEqual(MessageType.ProtocolName, parseMessage("/yamux/1.0.0").type);
    try std.testing.expectEqual(MessageType.WrongProtocolVersion, parseMessage("/multistream/2.0.0").type);
    try std.testing.expectEqual(MessageType.InvalidMessage, parseMessage("invalid").type);
}
