// multistream.zig - Multistream-select protocol implementation
// Protocol negotiation for libp2p connections

const std = @import("std");
const io = std.io;

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
pub fn writeMessage(writer: anytype, message: []const u8) !void {
    // Write varint length prefix (includes newline)
    const total_len = message.len + 1;
    try writeVarint(writer, total_len);
    
    // Write message
    try writer.writeAll(message);
    
    // Write newline
    try writer.writeByte(NEWLINE);
}

/// Read a message with length prefix
pub fn readMessage(reader: anytype, allocator: std.mem.Allocator) ![]u8 {
    // Read varint length
    const len = try readVarint(reader);
    if (len > MAX_MESSAGE_SIZE) {
        return error.MessageTooLarge;
    }
    
    // Allocate buffer
    const buffer = try allocator.alloc(u8, len);
    errdefer allocator.free(buffer);
    
    // Read message content
    try reader.readNoEof(buffer);
    
    // Verify and remove newline
    if (buffer.len == 0 or buffer[buffer.len - 1] != NEWLINE) {
        return error.InvalidMessage;
    }
    
    return buffer[0 .. buffer.len - 1];
}

/// Write varint (unsigned LEB128)
pub fn writeVarint(writer: anytype, value: usize) !void {
    var v = value;
    while (v >= 0x80) {
        try writer.writeByte(@as(u8, @intCast(v & 0x7F)) | 0x80);
        v >>= 7;
    }
    try writer.writeByte(@as(u8, @intCast(v)));
}

/// Read varint (unsigned LEB128)
pub fn readVarint(reader: anytype) !usize {
    var result: usize = 0;
    var shift: u6 = 0;
    
    while (true) {
        const byte = try reader.readByte();
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
    pub fn negotiate(self: *Self, reader: anytype, writer: anytype) ![]const u8 {
        if (self.is_initiator) {
            return self.negotiateInitiator(reader, writer);
        } else {
            return self.negotiateResponder(reader, writer);
        }
    }
    
    /// Initiator side of negotiation
    fn negotiateInitiator(self: *Self, reader: anytype, writer: anytype) ![]const u8 {
        // Send multistream version
        try writeMessage(writer, PROTOCOL_ID);
        
        // Read response
        const response = try readMessage(reader, self.allocator);
        defer self.allocator.free(response);
        
        const msg = parseMessage(response);
        if (msg.type != .RightProtocolVersion) {
            return error.ProtocolMismatch;
        }
        
        // Try each protocol in order
        for (self.protocols) |protocol| {
            // Send protocol proposal
            try writeMessage(writer, protocol);
            
            // Read response
            const proto_response = try readMessage(reader, self.allocator);
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
    fn negotiateResponder(self: *Self, reader: anytype, writer: anytype) ![]const u8 {
        // Read multistream version
        const version_msg = try readMessage(reader, self.allocator);
        defer self.allocator.free(version_msg);
        
        const msg = parseMessage(version_msg);
        if (msg.type != .RightProtocolVersion) {
            return error.ProtocolMismatch;
        }
        
        // Send version acknowledgment
        try writeMessage(writer, PROTOCOL_ID);
        
        // Read protocol proposals
        while (true) {
            const proposal = try readMessage(reader, self.allocator);
            defer self.allocator.free(proposal);
            
            const proto_msg = parseMessage(proposal);
            switch (proto_msg.type) {
                .ProtocolName => {
                    // Check if we support this protocol
                    for (self.protocols) |supported| {
                        if (std.mem.eql(u8, proto_msg.content, supported)) {
                            // Send acknowledgment
                            try writeMessage(writer, supported);
                            self.selected_protocol = supported;
                            return supported;
                        }
                    }
                    // Not supported, send NA
                    try writeMessage(writer, NA);
                },
                .LSMessage => {
                    // List protocols (not implemented)
                    try writeMessage(writer, NA);
                },
                else => return error.UnexpectedMessage,
            }
        }
    }
};

// Tests
test "varint encoding/decoding" {
    const allocator = std.testing.allocator;
    
    // Test values
    const test_values = [_]usize{ 0, 127, 128, 16383, 16384, 65535 };
    
    for (test_values) |value| {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        // Write varint
        try writeVarint(buffer.writer(), value);
        
        // Read it back
        var stream = io.fixedBufferStream(buffer.items);
        const decoded = try readVarint(stream.reader());
        
        try std.testing.expectEqual(value, decoded);
    }
}

test "message read/write" {
    const allocator = std.testing.allocator;
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    // Write message
    const test_msg = "/test/protocol/1.0.0";
    try writeMessage(buffer.writer(), test_msg);
    
    // Read it back
    var stream = io.fixedBufferStream(buffer.items);
    const read_msg = try readMessage(stream.reader(), allocator);
    defer allocator.free(read_msg);
    
    try std.testing.expectEqualStrings(test_msg, read_msg);
}

test "protocol negotiation - initiator" {
    const allocator = std.testing.allocator;
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    // Simulate responder messages
    try writeMessage(buffer.writer(), PROTOCOL_ID); // Version ack
    try writeMessage(buffer.writer(), NA); // First protocol rejected
    try writeMessage(buffer.writer(), "/yamux/1.0.0"); // Second protocol accepted
    
    var stream = io.fixedBufferStream(buffer.items);
    var out_buffer = std.ArrayList(u8).init(allocator);
    defer out_buffer.deinit();
    
    const protocols = [_][]const u8{ "/mplex/1.0.0", "/yamux/1.0.0" };
    var negotiator = Negotiator.init(allocator, &protocols, true);
    
    const selected = try negotiator.negotiate(stream.reader(), out_buffer.writer());
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