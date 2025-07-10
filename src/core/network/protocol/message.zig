// message.zig - Base message interface and utilities
// Provides common functionality for all message types

const std = @import("std");
const protocol = @import("protocol.zig");

/// Generic message interface that all messages must implement
pub const MessageInterface = struct {
    /// Encode the message to a writer
    encodeFn: *const fn (self: *const anyopaque, writer: anytype) anyerror!void,
    
    /// Estimate the encoded size of the message
    estimateSizeFn: *const fn (self: *const anyopaque) usize,
    
    /// Free any allocated memory
    deinitFn: ?*const fn (self: *anyopaque, allocator: std.mem.Allocator) void,
};

/// Message envelope for sending/receiving
pub const MessageEnvelope = struct {
    header: protocol.MessageHeader,
    payload: []u8,
    allocator: ?std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, msg_type: protocol.MessageType, payload: []const u8) !MessageEnvelope {
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
    
    pub fn serialize(self: MessageEnvelope, writer: anytype) !void {
        try self.header.serialize(writer);
        try writer.writeAll(self.payload);
    }
    
    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype) !MessageEnvelope {
        const header = try protocol.MessageHeader.deserialize(reader);
        
        const payload = try allocator.alloc(u8, header.payload_length);
        errdefer allocator.free(payload);
        
        try reader.readNoEof(payload);
        
        // Verify checksum
        if (!header.verifyChecksum(payload)) {
            return error.InvalidChecksum;
        }
        
        return MessageEnvelope{
            .header = header,
            .payload = payload,
            .allocator = allocator,
        };
    }
};

/// Helper to encode any message type
pub fn encodeMessage(
    allocator: std.mem.Allocator,
    msg_type: protocol.MessageType,
    message: anytype,
) !MessageEnvelope {
    const T = @TypeOf(message);
    
    // Estimate size
    const size = if (@hasDecl(T, "estimateSize")) 
        message.estimateSize() 
    else 
        1024; // Default buffer size
    
    // Encode to buffer
    var buffer = try std.ArrayList(u8).initCapacity(allocator, size);
    defer buffer.deinit();
    
    try message.encode(buffer.writer());
    
    return MessageEnvelope.init(allocator, msg_type, buffer.items);
}

/// Memory pool for message handling
pub const MessagePool = struct {
    allocator: std.mem.Allocator,
    small_buffers: std.ArrayList([]u8),   // 4KB
    medium_buffers: std.ArrayList([]u8),  // 64KB
    large_buffers: std.ArrayList([]u8),   // 1MB
    
    const SMALL_SIZE = 4 * 1024;
    const MEDIUM_SIZE = 64 * 1024;
    const LARGE_SIZE = 1024 * 1024;
    
    pub fn init(allocator: std.mem.Allocator) !MessagePool {
        var pool = MessagePool{
            .allocator = allocator,
            .small_buffers = std.ArrayList([]u8).init(allocator),
            .medium_buffers = std.ArrayList([]u8).init(allocator),
            .large_buffers = std.ArrayList([]u8).init(allocator),
        };
        
        // Pre-allocate some buffers
        for (0..10) |_| {
            try pool.small_buffers.append(try allocator.alloc(u8, SMALL_SIZE));
        }
        for (0..5) |_| {
            try pool.medium_buffers.append(try allocator.alloc(u8, MEDIUM_SIZE));
        }
        for (0..2) |_| {
            try pool.large_buffers.append(try allocator.alloc(u8, LARGE_SIZE));
        }
        
        return pool;
    }
    
    pub fn deinit(self: *MessagePool) void {
        for (self.small_buffers.items) |buf| {
            self.allocator.free(buf);
        }
        for (self.medium_buffers.items) |buf| {
            self.allocator.free(buf);
        }
        for (self.large_buffers.items) |buf| {
            self.allocator.free(buf);
        }
        
        self.small_buffers.deinit();
        self.medium_buffers.deinit();
        self.large_buffers.deinit();
    }
    
    pub fn acquire(self: *MessagePool, size: usize) ![]u8 {
        if (size <= SMALL_SIZE) {
            if (self.small_buffers.items.len > 0) {
                const buf = self.small_buffers.pop();
                return buf[0..size];
            }
            return try self.allocator.alloc(u8, SMALL_SIZE);
        } else if (size <= MEDIUM_SIZE) {
            if (self.medium_buffers.items.len > 0) {
                const buf = self.medium_buffers.pop();
                return buf[0..size];
            }
            return try self.allocator.alloc(u8, MEDIUM_SIZE);
        } else if (size <= LARGE_SIZE) {
            if (self.large_buffers.items.len > 0) {
                const buf = self.large_buffers.pop();
                return buf[0..size];
            }
            return try self.allocator.alloc(u8, LARGE_SIZE);
        } else {
            // For very large messages, allocate directly
            return try self.allocator.alloc(u8, size);
        }
    }
    
    pub fn release(self: *MessagePool, buffer: []u8) void {
        // Determine which pool to return to based on capacity
        const cap = buffer.ptr[0..buffer.len].len;
        
        if (cap == SMALL_SIZE) {
            self.small_buffers.append(buffer.ptr[0..SMALL_SIZE]) catch {
                self.allocator.free(buffer.ptr[0..SMALL_SIZE]);
            };
        } else if (cap == MEDIUM_SIZE) {
            self.medium_buffers.append(buffer.ptr[0..MEDIUM_SIZE]) catch {
                self.allocator.free(buffer.ptr[0..MEDIUM_SIZE]);
            };
        } else if (cap == LARGE_SIZE) {
            self.large_buffers.append(buffer.ptr[0..LARGE_SIZE]) catch {
                self.allocator.free(buffer.ptr[0..LARGE_SIZE]);
            };
        } else {
            // Non-pooled size, free directly
            self.allocator.free(buffer);
        }
    }
};

// Test message pool
test "MessagePool basic operations" {
    const allocator = std.testing.allocator;
    
    var pool = try MessagePool.init(allocator);
    defer pool.deinit();
    
    // Acquire and release small buffer
    const small = try pool.acquire(1024);
    try std.testing.expect(small.len >= 1024);
    pool.release(small);
    
    // Acquire and release medium buffer
    const medium = try pool.acquire(32 * 1024);
    try std.testing.expect(medium.len >= 32 * 1024);
    pool.release(medium);
}