// message_envelope.zig - Message envelope and transport utilities
// Provides serialization, pooling, and transport infrastructure for all message types

const std = @import("std");
const protocol = @import("protocol.zig");

/// Pooled buffer wrapper to track original allocation size
pub const PooledBuffer = struct {
    data: []u8,
    pool_size: usize,

    pub fn slice(self: PooledBuffer, len: usize) []u8 {
        return self.data[0..@min(len, self.data.len)];
    }
};

/// Message envelope for sending/receiving
pub const MessageEnvelope = struct {
    header: protocol.MessageHeader,
    payload: []u8,
    allocator: ?std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, msg_type: protocol.MessageType, payload: []const u8) !MessageEnvelope {
        // Input validation: Check message type validity
        if (!msg_type.isValid()) {
            return error.InvalidMessageType;
        }

        // Input validation: Check payload size (defense-in-depth)
        if (payload.len > protocol.MAX_MESSAGE_SIZE) {
            return error.PayloadTooLarge;
        }

        const owned_payload = try allocator.dupe(u8, payload);
        errdefer allocator.free(owned_payload);

        var header = protocol.MessageHeader.init(msg_type, @intCast(payload.len));
        header.setChecksum(payload);

        return MessageEnvelope{
            .header = header,
            .payload = owned_payload,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MessageEnvelope) void {
        if (self.allocator) |allocator| {
            allocator.free(self.payload);
        }
    }

    /// Serialize with const correctness - doesn't modify the envelope
    pub fn serialize(self: *const MessageEnvelope, writer: anytype) !void {
        try self.header.serialize(writer);
        try writer.writeAll(self.payload);
    }

    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype) !MessageEnvelope {
        const header = try protocol.MessageHeader.deserialize(reader);

        // Input validation: Check message type validity
        if (!header.message_type.isValid()) {
            return error.InvalidMessageType;
        }

        // Defense-in-depth: Additional size check (already checked in header deserialize)
        if (header.payload_length > protocol.MAX_MESSAGE_SIZE) {
            return error.PayloadTooLarge;
        }

        const payload = try allocator.alloc(u8, header.payload_length);
        errdefer allocator.free(payload);

        try reader.readNoEof(payload);

        // Verify checksum - critical security check
        if (!header.verifyChecksum(payload)) {
            return error.InvalidChecksum;
        }

        return MessageEnvelope{
            .header = header,
            .payload = payload,
            .allocator = allocator,
        };
    }

    /// Zero-copy deserialization using provided buffer
    pub fn deserializeZeroCopy(reader: anytype, backing_buffer: []u8) !MessageEnvelope {
        const header = try protocol.MessageHeader.deserialize(reader);

        // Input validation
        if (!header.message_type.isValid()) {
            return error.InvalidMessageType;
        }

        if (header.payload_length > backing_buffer.len) {
            return error.BufferTooSmall;
        }

        if (header.payload_length > protocol.MAX_MESSAGE_SIZE) {
            return error.PayloadTooLarge;
        }

        const payload = backing_buffer[0..header.payload_length];
        try reader.readNoEof(payload);

        // Verify checksum
        if (!header.verifyChecksum(payload)) {
            return error.InvalidChecksum;
        }

        return MessageEnvelope{
            .header = header,
            .payload = payload,
            .allocator = null, // No allocator - using provided buffer
        };
    }
};

/// Simplified message encoding helper
pub fn encodeMessage(
    allocator: std.mem.Allocator,
    msg_type: protocol.MessageType,
    message: anytype,
) !MessageEnvelope {
    // Input validation
    if (!msg_type.isValid()) {
        return error.InvalidMessageType;
    }

    // Use ArrayList's automatic resizing instead of magic numbers
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try message.encode(buffer.writer());

    return MessageEnvelope.init(allocator, msg_type, buffer.items);
}

/// Fixed memory pool implementation with proper buffer tracking
pub const MessagePool = struct {
    allocator: std.mem.Allocator,
    small_buffers: std.ArrayList(PooledBuffer), // 4KB
    medium_buffers: std.ArrayList(PooledBuffer), // 64KB
    large_buffers: std.ArrayList(PooledBuffer), // 1MB

    // Pool size constants
    pub const SMALL_SIZE = 4 * 1024;
    pub const MEDIUM_SIZE = 64 * 1024;
    pub const LARGE_SIZE = 1024 * 1024;

    // Pool limits to prevent unbounded growth
    const MAX_SMALL_BUFFERS = 20;
    const MAX_MEDIUM_BUFFERS = 10;
    const MAX_LARGE_BUFFERS = 5;

    pub fn init(allocator: std.mem.Allocator) !MessagePool {
        var pool = MessagePool{
            .allocator = allocator,
            .small_buffers = std.ArrayList(PooledBuffer).init(allocator),
            .medium_buffers = std.ArrayList(PooledBuffer).init(allocator),
            .large_buffers = std.ArrayList(PooledBuffer).init(allocator),
        };

        // Pre-allocate some buffers for better performance
        for (0..5) |_| {
            const buf = try allocator.alloc(u8, SMALL_SIZE);
            try pool.small_buffers.append(PooledBuffer{ .data = buf, .pool_size = SMALL_SIZE });
        }
        for (0..3) |_| {
            const buf = try allocator.alloc(u8, MEDIUM_SIZE);
            try pool.medium_buffers.append(PooledBuffer{ .data = buf, .pool_size = MEDIUM_SIZE });
        }
        for (0..2) |_| {
            const buf = try allocator.alloc(u8, LARGE_SIZE);
            try pool.large_buffers.append(PooledBuffer{ .data = buf, .pool_size = LARGE_SIZE });
        }

        return pool;
    }

    pub fn deinit(self: *MessagePool) void {
        for (self.small_buffers.items) |pooled_buf| {
            self.allocator.free(pooled_buf.data);
        }
        for (self.medium_buffers.items) |pooled_buf| {
            self.allocator.free(pooled_buf.data);
        }
        for (self.large_buffers.items) |pooled_buf| {
            self.allocator.free(pooled_buf.data);
        }

        self.small_buffers.deinit();
        self.medium_buffers.deinit();
        self.large_buffers.deinit();
    }

    /// Acquire a buffer of at least the requested size
    pub fn acquire(self: *MessagePool, size: usize) !PooledBuffer {
        if (size <= SMALL_SIZE) {
            if (self.small_buffers.items.len > 0) {
                return self.small_buffers.swapRemove(self.small_buffers.items.len - 1);
            }
            // No pooled buffer available, allocate new one
            const buf = try self.allocator.alloc(u8, SMALL_SIZE);
            return PooledBuffer{ .data = buf, .pool_size = SMALL_SIZE };
        } else if (size <= MEDIUM_SIZE) {
            if (self.medium_buffers.items.len > 0) {
                return self.medium_buffers.swapRemove(self.medium_buffers.items.len - 1);
            }
            const buf = try self.allocator.alloc(u8, MEDIUM_SIZE);
            return PooledBuffer{ .data = buf, .pool_size = MEDIUM_SIZE };
        } else if (size <= LARGE_SIZE) {
            if (self.large_buffers.items.len > 0) {
                return self.large_buffers.swapRemove(self.large_buffers.items.len - 1);
            }
            const buf = try self.allocator.alloc(u8, LARGE_SIZE);
            return PooledBuffer{ .data = buf, .pool_size = LARGE_SIZE };
        } else {
            // For very large messages, allocate directly (non-pooled)
            const buf = try self.allocator.alloc(u8, size);
            return PooledBuffer{ .data = buf, .pool_size = size };
        }
    }

    /// Release a buffer back to the pool
    pub fn release(self: *MessagePool, buffer: PooledBuffer) void {
        // Return to appropriate pool based on original allocation size
        if (buffer.pool_size == SMALL_SIZE and self.small_buffers.items.len < MAX_SMALL_BUFFERS) {
            self.small_buffers.append(buffer) catch {
                // Pool full, free directly
                self.allocator.free(buffer.data);
            };
        } else if (buffer.pool_size == MEDIUM_SIZE and self.medium_buffers.items.len < MAX_MEDIUM_BUFFERS) {
            self.medium_buffers.append(buffer) catch {
                self.allocator.free(buffer.data);
            };
        } else if (buffer.pool_size == LARGE_SIZE and self.large_buffers.items.len < MAX_LARGE_BUFFERS) {
            self.large_buffers.append(buffer) catch {
                self.allocator.free(buffer.data);
            };
        } else {
            // Non-pooled size or pool is full, free directly
            self.allocator.free(buffer.data);
        }
    }

    /// Get pool statistics for monitoring
    pub fn getStats(self: *const MessagePool) struct {
        small_available: usize,
        medium_available: usize,
        large_available: usize,
    } {
        return .{
            .small_available = self.small_buffers.items.len,
            .medium_available = self.medium_buffers.items.len,
            .large_available = self.large_buffers.items.len,
        };
    }
};

// TESTS

// Comprehensive tests for the implementation
test "MessageEnvelope input validation" {
    const allocator = std.testing.allocator;

    // Test invalid message type
    const invalid_msg_type: protocol.MessageType = @enumFromInt(255);
    try std.testing.expectError(error.InvalidMessageType, MessageEnvelope.init(allocator, invalid_msg_type, "test"));

    // Test oversized payload
    const large_payload = try allocator.alloc(u8, protocol.MAX_MESSAGE_SIZE + 1);
    defer allocator.free(large_payload);
    try std.testing.expectError(error.PayloadTooLarge, MessageEnvelope.init(allocator, .ping, large_payload));
}

test "MessageEnvelope round-trip with const correctness" {
    const allocator = std.testing.allocator;

    const test_payload = "Hello, ZeiCoin Network!";
    var envelope = try MessageEnvelope.init(allocator, .ping, test_payload);
    defer envelope.deinit();

    // Test const serialize
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    const const_envelope: *const MessageEnvelope = &envelope;
    try const_envelope.serialize(buffer.writer());

    // Test deserialize
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try MessageEnvelope.deserialize(allocator, stream.reader());
    defer decoded.deinit();

    // Verify integrity
    try std.testing.expectEqual(envelope.header.magic, decoded.header.magic);
    try std.testing.expectEqual(envelope.header.message_type, decoded.header.message_type);
    try std.testing.expectEqualSlices(u8, envelope.payload, decoded.payload);
}

test "MessagePool fixed buffer tracking" {
    const allocator = std.testing.allocator;

    var pool = try MessagePool.init(allocator);
    defer pool.deinit();

    // Acquire and release small buffer
    const small_buf = try pool.acquire(1024);
    try std.testing.expectEqual(@as(usize, MessagePool.SMALL_SIZE), small_buf.pool_size);
    try std.testing.expect(small_buf.data.len >= 1024);

    const stats_before = pool.getStats();
    pool.release(small_buf);
    const stats_after = pool.getStats();

    // Buffer should be returned to pool
    try std.testing.expect(stats_after.small_available > stats_before.small_available);

    // Acquire medium buffer
    const medium_buf = try pool.acquire(32 * 1024);
    try std.testing.expectEqual(@as(usize, MessagePool.MEDIUM_SIZE), medium_buf.pool_size);
    pool.release(medium_buf);

    // Test oversized allocation (non-pooled)
    const large_buf = try pool.acquire(2 * 1024 * 1024); // 2MB
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), large_buf.pool_size);
    pool.release(large_buf); // Should be freed directly, not pooled
}

test "MessageEnvelope zero-copy deserialization" {
    const allocator = std.testing.allocator;

    // Create original message
    const test_payload = "Zero-copy test payload";
    var original = try MessageEnvelope.init(allocator, .pong, test_payload);
    defer original.deinit();

    // Serialize
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try original.serialize(buffer.writer());

    // Test zero-copy deserialize
    var backing_buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try MessageEnvelope.deserializeZeroCopy(stream.reader(), &backing_buffer);

    // Verify (no deinit needed - using backing buffer)
    try std.testing.expectEqual(original.header.message_type, decoded.header.message_type);
    try std.testing.expectEqualSlices(u8, original.payload, decoded.payload);
    try std.testing.expect(decoded.allocator == null); // Should be null for zero-copy
}

test "encodeMessage input validation" {
    const allocator = std.testing.allocator;

    const TestMessage = struct {
        value: u32,

        pub fn encode(self: @This(), writer: anytype) !void {
            try writer.writeInt(u32, self.value, .little);
        }
    };

    const msg = TestMessage{ .value = 42 };

    // Test invalid message type
    const invalid_type: protocol.MessageType = @enumFromInt(255);
    try std.testing.expectError(error.InvalidMessageType, encodeMessage(allocator, invalid_type, msg));

    // Test valid encoding
    var encoded = try encodeMessage(allocator, .transaction, msg);
    defer encoded.deinit();

    try std.testing.expectEqual(protocol.MessageType.transaction, encoded.header.message_type);
    try std.testing.expectEqual(@as(u32, 4), encoded.header.payload_length); // u32 = 4 bytes
}
