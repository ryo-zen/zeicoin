// multistream_parser.zig - Streaming message parser for multistream protocol
// Handles partial reads and message boundary detection

const std = @import("std");
const multistream = @import("multistream.zig");

/// Parser state
pub const ParserState = enum {
    Underflow,    // Need more data
    Ready,        // Complete message available
    Overflow,     // Message too large
    Error,        // Parse error
};

/// Parsed message
pub const ParsedMessage = struct {
    data: []const u8,
    message_type: multistream.MessageType,
};

/// Buffer collector for accumulating partial data
pub const BufferCollector = struct {
    buffer: std.ArrayList(u8),
    expected_size: ?usize,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .buffer = std.ArrayList(u8).init(allocator),
            .expected_size = null,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.buffer.deinit();
    }
    
    pub fn reset(self: *Self) void {
        self.buffer.clearRetainingCapacity();
        self.expected_size = null;
    }
    
    pub fn expectSize(self: *Self, size: usize) !void {
        self.expected_size = size;
        try self.buffer.ensureTotalCapacity(size);
    }
    
    /// Add data and return complete message if ready
    pub fn add(self: *Self, data: []const u8) !?[]const u8 {
        if (self.expected_size == null) return null;
        
        const expected = self.expected_size.?;
        const space_available = expected - self.buffer.items.len;
        const to_copy = @min(data.len, space_available);
        
        try self.buffer.appendSlice(data[0..to_copy]);
        
        if (self.buffer.items.len >= expected) {
            return self.buffer.items;
        }
        
        return null;
    }
    
    pub fn isComplete(self: *const Self) bool {
        if (self.expected_size) |expected| {
            return self.buffer.items.len >= expected;
        }
        return false;
    }
};

/// Varint reader for length prefixes
pub const VarintReader = struct {
    bytes: [multistream.MAX_VARINT_SIZE]u8,
    length: usize,
    value: ?usize,
    
    const Self = @This();
    
    pub fn init() Self {
        return .{
            .bytes = undefined,
            .length = 0,
            .value = null,
        };
    }
    
    pub fn reset(self: *Self) void {
        self.length = 0;
        self.value = null;
    }
    
    pub fn isReady(self: *const Self) bool {
        return self.value != null;
    }
    
    pub fn getValue(self: *const Self) ?usize {
        return self.value;
    }
    
    /// Consume bytes and try to complete varint
    pub fn consume(self: *Self, data: *[]const u8) ParserState {
        while (data.len > 0 and self.length < multistream.MAX_VARINT_SIZE and self.value == null) {
            const byte = data.*[0];
            data.* = data.*[1..];
            
            self.bytes[self.length] = byte;
            self.length += 1;
            
            // Check if this completes the varint
            if ((byte & 0x80) == 0) {
                // Last byte of varint
                self.value = self.decodeVarint() catch return .Error;
                return .Ready;
            }
        }
        
        if (self.length >= multistream.MAX_VARINT_SIZE) {
            return .Overflow;
        }
        
        return .Underflow;
    }
    
    fn decodeVarint(self: *const Self) !usize {
        var result: usize = 0;
        var shift: u6 = 0;
        
        for (self.bytes[0..self.length]) |byte| {
            const value = byte & 0x7F;
            
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
};

/// Streaming multistream message parser
pub const MultistreamParser = struct {
    allocator: std.mem.Allocator,
    state: ParserState,
    varint_reader: VarintReader,
    buffer_collector: BufferCollector,
    expected_message_size: usize,
    messages: std.ArrayList(ParsedMessage),
    
    // Constants
    const MAX_MESSAGE_SIZE = multistream.MAX_MESSAGE_SIZE;
    const MAX_VARINT_BYTES = 3; // Max bytes for message length varint
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .state = .Underflow,
            .varint_reader = VarintReader.init(),
            .buffer_collector = BufferCollector.init(allocator),
            .expected_message_size = 0,
            .messages = std.ArrayList(ParsedMessage).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.buffer_collector.deinit();
        // Note: messages contain slices to buffer_collector data, 
        // so they're freed when buffer_collector is freed
        self.messages.deinit();
    }
    
    pub fn reset(self: *Self) void {
        self.state = .Underflow;
        self.varint_reader.reset();
        self.buffer_collector.reset();
        self.expected_message_size = 0;
        self.messages.clearRetainingCapacity();
    }
    
    pub fn getState(self: *const Self) ParserState {
        return self.state;
    }
    
    pub fn getMessages(self: *const Self) []const ParsedMessage {
        return self.messages.items;
    }
    
    pub fn hasMessages(self: *const Self) bool {
        return self.messages.items.len > 0;
    }
    
    /// Returns number of bytes needed for next read
    pub fn bytesNeeded(self: *const Self) usize {
        switch (self.state) {
            .Underflow => {
                if (self.expected_message_size > 0) {
                    // Need message data
                    return self.expected_message_size - self.buffer_collector.buffer.items.len;
                } else {
                    // Need varint data
                    return 1;
                }
            },
            else => return 0,
        }
    }
    
    /// Consume incoming data and update parser state
    pub fn consume(self: *Self, data: []const u8) !ParserState {
        if (self.state == .Ready or self.state == .Error or self.state == .Overflow) {
            return self.state;
        }
        
        var remaining_data = data;
        
        while (remaining_data.len > 0 and self.state == .Underflow) {
            if (self.expected_message_size == 0) {
                // Reading varint length prefix
                const varint_state = self.varint_reader.consume(&remaining_data);
                
                switch (varint_state) {
                    .Ready => {
                        const msg_size = self.varint_reader.getValue().?;
                        
                        if (msg_size == 0) {
                            // Invalid zero-length message
                            self.reset();
                            continue;
                        }
                        
                        if (msg_size > MAX_MESSAGE_SIZE) {
                            self.state = .Overflow;
                            return self.state;
                        }
                        
                        self.expected_message_size = msg_size;
                        try self.buffer_collector.expectSize(msg_size);
                    },
                    .Overflow => {
                        self.state = .Overflow;
                        return self.state;
                    },
                    .Error => {
                        self.state = .Error;
                        return self.state;
                    },
                    .Underflow => {
                        // Need more varint bytes
                        break;
                    },
                }
            } else {
                // Reading message data
                try self.consumeMessageData(&remaining_data);
            }
        }
        
        return self.state;
    }
    
    /// Consume message data after varint is complete
    fn consumeMessageData(self: *Self, data: *[]const u8) !void {
        const space_needed = self.expected_message_size - self.buffer_collector.buffer.items.len;
        const to_consume = @min(data.len, space_needed);
        
        const complete_message = try self.buffer_collector.add(data.*[0..to_consume]);
        
        // Update remaining data
        data.* = data.*[to_consume..];
        
        if (complete_message) |msg_data| {
            // Message is complete, process it
            try self.processCompleteMessage(msg_data);
            
            // Reset for next message
            self.varint_reader.reset();
            self.buffer_collector.reset();
            self.expected_message_size = 0;
            self.state = .Ready;
        }
    }
    
    /// Process complete message and add to results
    fn processCompleteMessage(self: *Self, msg_data: []const u8) !void {
        // Remove trailing newline if present
        var content = msg_data;
        if (content.len > 0 and content[content.len - 1] == multistream.NEWLINE) {
            content = content[0..content.len - 1];
        }
        
        // Parse message type
        const message = multistream.parseMessage(content);
        
        // Store parsed message
        // Note: We store a slice to buffer_collector data, which is valid
        // until the next reset() call
        try self.messages.append(.{
            .data = content,
            .message_type = message.type,
        });
    }
    
    /// Get first message and remove it from queue
    pub fn popMessage(self: *Self) ?ParsedMessage {
        if (self.messages.items.len == 0) return null;
        
        const msg = self.messages.orderedRemove(0);
        
        // If no more messages, reset state to accept new data
        if (self.messages.items.len == 0) {
            self.state = .Underflow;
        }
        
        return msg;
    }
    
    /// Peek at first message without removing it
    pub fn peekMessage(self: *const Self) ?ParsedMessage {
        if (self.messages.items.len == 0) return null;
        return self.messages.items[0];
    }
};