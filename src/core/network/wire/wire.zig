// wire.zig - Low-level wire protocol implementation
// Handles message framing, serialization, and connection management

const std = @import("std");
const protocol = @import("../protocol/protocol.zig");
const message_envelope = @import("../protocol/message_envelope.zig");

/// Wire protocol reader for parsing incoming messages
pub const WireReader = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),
    read_pos: usize,

    const Self = @This();

    /// Maximum buffer size to prevent memory exhaustion attacks (16MB)
    const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .buffer = std.ArrayList(u8).init(allocator),
            .read_pos = 0,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.buffer.deinit();
    }
    
    /// Add data from network to buffer
    pub fn addData(self: *Self, data: []const u8) !void {
        // SECURITY: Prevent memory exhaustion via unbounded buffer growth
        if (self.buffer.items.len + data.len > MAX_BUFFER_SIZE) {
            return error.BufferOverflow;
        }
        try self.buffer.appendSlice(data);
    }
    
    /// Try to read a complete message
    pub fn readMessage(self: *Self) !?message_envelope.MessageEnvelope {
        const available = self.buffer.items.len - self.read_pos;
        
        // Need at least header size
        if (available < protocol.MessageHeader.SIZE) {
            return null;
        }
        
        // Try to parse header
        const header_bytes = self.buffer.items[self.read_pos..][0..protocol.MessageHeader.SIZE];
        var stream = std.io.fixedBufferStream(header_bytes);
        
        const header = protocol.MessageHeader.deserialize(stream.reader()) catch {
            // Invalid header, skip byte and try again
            self.read_pos += 1;
            self.compact();
            return error.InvalidHeader;
        };
        
        // Check if we have complete message
        const total_size = protocol.MessageHeader.SIZE + header.payload_length;
        if (available < total_size) {
            return null; // Need more data
        }
        
        // Extract payload
        const payload_start = self.read_pos + protocol.MessageHeader.SIZE;
        const payload_end = payload_start + header.payload_length;
        const payload = self.buffer.items[payload_start..payload_end];
        
        // Verify checksum
        if (!header.verifyChecksum(payload)) {
            // Bad checksum, skip this message
            self.read_pos = payload_end;
            self.compact();
            return error.InvalidChecksum;
        }
        
        // Create message envelope
        const envelope = try message_envelope.MessageEnvelope.init(
            self.allocator,
            header.message_type,
            payload,
        );
        
        // Advance read position
        self.read_pos = payload_end;
        self.compact();
        
        return envelope;
    }
    
    /// Compact buffer by removing read data
    fn compact(self: *Self) void {
        if (self.read_pos > 0) {
            const remaining = self.buffer.items.len - self.read_pos;
            std.mem.copyForwards(u8, self.buffer.items[0..remaining], self.buffer.items[self.read_pos..]);
            self.buffer.items.len = remaining;
            self.read_pos = 0;
        }
        
        // Shrink if buffer is too large and mostly empty
        if (self.buffer.capacity > 1024 * 1024 and self.buffer.items.len < self.buffer.capacity / 4) {
            self.buffer.shrinkAndFree(self.buffer.items.len);
        }
    }
};

/// Wire protocol writer for sending messages
pub const WireWriter = struct {
    allocator: std.mem.Allocator,
    send_buffer: std.ArrayList(u8),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .send_buffer = std.ArrayList(u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.send_buffer.deinit();
    }
    
    /// Write a message to the send buffer
    pub fn writeMessage(self: *Self, msg_type: protocol.MessageType, msg: anytype) !void {
        // Clear send buffer
        self.send_buffer.clearRetainingCapacity();
        
        // Reserve space for header
        try self.send_buffer.resize(protocol.MessageHeader.SIZE);
        
        // Encode message payload
        const payload_start = self.send_buffer.items.len;
        if (@TypeOf(msg) != void) {
            try msg.encode(self.send_buffer.writer());
        }
        // For void messages (like blocks), payload remains empty
        
        const payload = self.send_buffer.items[payload_start..];
        const payload_len = @as(u32, @intCast(payload.len));
        
        // Create and write header
        var header = protocol.MessageHeader.init(msg_type, payload_len);
        header.setChecksum(payload);
        
        var header_stream = std.io.fixedBufferStream(self.send_buffer.items[0..protocol.MessageHeader.SIZE]);
        try header.serialize(header_stream.writer());
    }
    
    /// Get the complete message data for sending
    pub fn getData(self: *Self) []const u8 {
        return self.send_buffer.items;
    }
};

/// Connection state for wire protocol
pub const WireConnection = struct {
    allocator: std.mem.Allocator,
    reader: WireReader,
    writer: WireWriter,
    stats: ConnectionStats,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .reader = WireReader.init(allocator),
            .writer = WireWriter.init(allocator),
            .stats = ConnectionStats.init(),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.reader.deinit();
        self.writer.deinit();
    }
    
    /// Process incoming data
    pub fn receiveData(self: *Self, data: []const u8) !void {
        self.stats.bytes_received += data.len;
        try self.reader.addData(data);
    }
    
    /// Try to read next message
    pub fn readMessage(self: *Self) !?message_envelope.MessageEnvelope {
        const msg = try self.reader.readMessage();
        if (msg) |envelope| {
            self.stats.messages_received += 1;
            std.log.debug("Message received from wire, type: {}, total received: {}", .{envelope.header.message_type, self.stats.messages_received});
        }
        return msg;
    }
    
    /// Send a message
    pub fn sendMessage(self: *Self, msg_type: protocol.MessageType, msg: anytype) ![]const u8 {
        std.log.debug("Writing message type: {} to wire", .{msg_type});
        try self.writer.writeMessage(msg_type, msg);
        self.stats.messages_sent += 1;
        self.stats.bytes_sent += self.writer.getData().len;
        const data = self.writer.getData();
        std.log.debug("Message written, size: {} bytes, total sent: {}", .{data.len, self.stats.messages_sent});
        return data;
    }
};

/// Connection statistics
pub const ConnectionStats = struct {
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    connected_since: i64,
    
    pub fn init() ConnectionStats {
        return .{
            .messages_sent = 0,
            .messages_received = 0,
            .bytes_sent = 0,
            .bytes_received = 0,
            .connected_since = std.time.timestamp(),
        };
    }
};

// Tests
test "WireConnection basic message flow" {
    const allocator = std.testing.allocator;
    const ping = @import("../protocol/messages/ping.zig");
    
    var conn = WireConnection.init(allocator);
    defer conn.deinit();
    
    // Send a ping message
    const ping_msg = ping.PingMessage.init();
    const data = try conn.sendMessage(.ping, ping_msg);
    
    // Simulate receiving the data
    try conn.receiveData(data);
    
    // Read the message back
    if (try conn.readMessage()) |envelope| {
        defer envelope.deinit();
        
        try std.testing.expectEqual(protocol.MessageType.ping, envelope.header.message_type);
        try std.testing.expectEqual(@as(u64, 1), conn.stats.messages_sent);
        try std.testing.expectEqual(@as(u64, 1), conn.stats.messages_received);
    } else {
        return error.NoMessageRead;
    }
}