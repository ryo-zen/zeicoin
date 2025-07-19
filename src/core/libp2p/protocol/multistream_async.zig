// multistream_async.zig - Async multistream-select protocol implementation
// Based on libp2p multistream-select specification with callback-based async I/O

const std = @import("std");
const tcp_async = @import("../transport/tcp_async.zig");
const multistream = @import("multistream.zig");

// Re-export constants and types from base multistream
pub const PROTOCOL_ID = multistream.PROTOCOL_ID;
pub const MAX_MESSAGE_SIZE = multistream.MAX_MESSAGE_SIZE;
pub const NEWLINE = multistream.NEWLINE;
pub const NA = multistream.NA;
pub const MessageType = multistream.MessageType;
pub const Message = multistream.Message;
pub const parseMessage = multistream.parseMessage;

/// Result of async operations
pub const AsyncResult = union(enum) {
    success: []const u8, // Selected protocol
    failure: anyerror,
};

/// Callback function type for negotiation completion
pub const NegotiationCallback = *const fn (result: AsyncResult) void;

/// Session state for async negotiation
const SessionState = enum {
    WaitingForVersionResponse,
    WaitingForProtocolResponse,
    WaitingForProposal,
    Completed,
    Failed,
};

/// Async multistream negotiation session
pub const AsyncSession = struct {
    allocator: std.mem.Allocator,
    connection: *tcp_async.AsyncTcpConnection,
    is_initiator: bool,
    protocols: []const []const u8,
    callback: NegotiationCallback,
    
    // Session state
    state: SessionState,
    current_protocol_index: usize,
    selected_protocol: ?[]const u8,
    
    // Buffers
    read_buffer: []u8,
    write_buffer: std.ArrayList(u8),
    message_buffer: std.ArrayList(u8),
    
    const Self = @This();
    
    pub fn init(
        allocator: std.mem.Allocator,
        connection: *tcp_async.AsyncTcpConnection,
        protocols: []const []const u8,
        is_initiator: bool,
        callback: NegotiationCallback,
    ) !*Self {
        const session = try allocator.create(Self);
        errdefer allocator.destroy(session);
        
        const read_buffer = try allocator.alloc(u8, MAX_MESSAGE_SIZE + multistream.MAX_VARINT_SIZE);
        errdefer allocator.free(read_buffer);
        
        session.* = .{
            .allocator = allocator,
            .connection = connection,
            .is_initiator = is_initiator,
            .protocols = protocols,
            .callback = callback,
            .state = if (is_initiator) .WaitingForVersionResponse else .WaitingForProposal,
            .current_protocol_index = 0,
            .selected_protocol = null,
            .read_buffer = read_buffer,
            .write_buffer = std.ArrayList(u8).init(allocator),
            .message_buffer = std.ArrayList(u8).init(allocator),
        };
        
        return session;
    }
    
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.read_buffer);
        self.write_buffer.deinit();
        self.message_buffer.deinit();
        self.allocator.destroy(self);
    }
    
    /// Start the negotiation process
    pub fn start(self: *Self) !void {
        if (self.is_initiator) {
            try self.sendInitiatorHandshake();
        } else {
            try self.startReading();
        }
    }
    
    /// Send initial multistream version (initiator)
    fn sendInitiatorHandshake(self: *Self) !void {
        try self.writeMessage(PROTOCOL_ID);
        try self.sendCurrentMessage(onHandshakeSent);
    }
    
    /// Start reading for incoming messages
    fn startReading(self: *Self) !void {
        try self.connection.asyncRead(self.read_buffer, onDataRead);
    }
    
    /// Write a message to the write buffer
    pub fn writeMessage(self: *Self, message: []const u8) !void {
        self.write_buffer.clearRetainingCapacity();
        
        // Write varint length prefix (includes newline)
        const total_len = message.len + 1;
        try multistream.writeVarint(self.write_buffer.writer(), total_len);
        
        // Write message and newline
        try self.write_buffer.appendSlice(message);
        try self.write_buffer.append(NEWLINE);
    }
    
    /// Send the current write buffer contents
    fn sendCurrentMessage(self: *Self, callback: *const fn(*tcp_async.AsyncTcpConnection, tcp_async.AsyncResult) void) !void {
        try self.connection.asyncWrite(self.write_buffer.items, callback);
    }
    
    /// Called when handshake is sent (initiator)
    fn onHandshakeSent(conn: *tcp_async.AsyncTcpConnection, result: tcp_async.AsyncResult) void {
        // Get session from connection context (simplified approach for now)
        // In real implementation, we'd store session pointer in connection user data
        _ = conn;
        _ = result;
        // TODO: Implement proper callback context handling
        // For now, this is a placeholder to demonstrate the structure
    }
    
    /// Called when data is read
    fn onDataRead(conn: *tcp_async.AsyncTcpConnection, result: tcp_async.AsyncResult) void {
        // TODO: Implement proper callback context handling
        _ = conn;
        _ = result;
    }
    
    /// Process received data
    fn processReceivedData(self: *Self, bytes_read: usize) !void {
        if (bytes_read == 0) {
            return self.completeWithError(error.ConnectionClosed);
        }
        
        // Parse the message (simplified - assumes complete message received)
        var stream = std.io.fixedBufferStream(self.read_buffer[0..bytes_read]);
        const message = multistream.readMessage(stream.reader(), self.allocator) catch |err| {
            return self.completeWithError(err);
        };
        defer self.allocator.free(message);
        
        const parsed = parseMessage(message);
        try self.handleMessage(parsed);
    }
    
    /// Handle a parsed message based on current state
    fn handleMessage(self: *Self, message: Message) !void {
        switch (self.state) {
            .WaitingForVersionResponse => try self.handleVersionResponse(message),
            .WaitingForProtocolResponse => try self.handleProtocolResponse(message),
            .WaitingForProposal => try self.handleProposal(message),
            .Completed, .Failed => return, // Ignore further messages
        }
    }
    
    /// Handle version response (initiator)
    fn handleVersionResponse(self: *Self, message: Message) !void {
        switch (message.type) {
            .RightProtocolVersion => {
                // Version accepted, start proposing protocols
                try self.proposeNextProtocol();
            },
            .WrongProtocolVersion => {
                return self.completeWithError(error.ProtocolVersionMismatch);
            },
            else => {
                return self.completeWithError(error.UnexpectedMessage);
            }
        }
    }
    
    /// Handle protocol response (initiator)
    fn handleProtocolResponse(self: *Self, message: Message) !void {
        switch (message.type) {
            .ProtocolName => {
                // Check if it matches our proposal
                const proposed = self.protocols[self.current_protocol_index];
                if (std.mem.eql(u8, message.content, proposed)) {
                    self.selected_protocol = proposed;
                    return self.completeWithSuccess(proposed);
                } else {
                    return self.completeWithError(error.ProtocolMismatch);
                }
            },
            .NAMessage => {
                // Protocol rejected, try next one
                self.current_protocol_index += 1;
                try self.proposeNextProtocol();
            },
            else => {
                return self.completeWithError(error.UnexpectedMessage);
            }
        }
    }
    
    /// Handle incoming proposal (responder)
    fn handleProposal(self: *Self, message: Message) !void {
        switch (message.type) {
            .RightProtocolVersion => {
                // Send version acknowledgment
                try self.writeMessage(PROTOCOL_ID);
                try self.sendCurrentMessage(onVersionAckSent);
            },
            .ProtocolName => {
                // Check if we support this protocol
                for (self.protocols) |supported| {
                    if (std.mem.eql(u8, message.content, supported)) {
                        // Send positive response
                        try self.writeMessage(supported);
                        self.selected_protocol = supported;
                        try self.sendCurrentMessage(onProtocolAckSent);
                        return;
                    }
                }
                // Not supported, send NA
                try self.writeMessage(NA);
                try self.sendCurrentMessage(onNASent);
            },
            .LSMessage => {
                // List protocols (simplified - just send NA for now)
                try self.writeMessage(NA);
                try self.sendCurrentMessage(onNASent);
            },
            else => {
                return self.completeWithError(error.UnexpectedMessage);
            }
        }
    }
    
    /// Propose the next protocol (initiator)
    fn proposeNextProtocol(self: *Self) !void {
        if (self.current_protocol_index >= self.protocols.len) {
            return self.completeWithError(error.NoProtocolMatch);
        }
        
        const protocol = self.protocols[self.current_protocol_index];
        try self.writeMessage(protocol);
        self.state = .WaitingForProtocolResponse;
        try self.sendCurrentMessage(onProposalSent);
    }
    
    /// Called when version ack is sent (responder)
    fn onVersionAckSent(conn: *tcp_async.AsyncTcpConnection, result: tcp_async.AsyncResult) void {
        // TODO: Implement proper callback context handling
        _ = conn;
        _ = result;
    }
    
    /// Called when protocol ack is sent (responder)
    fn onProtocolAckSent(conn: *tcp_async.AsyncTcpConnection, result: tcp_async.AsyncResult) void {
        // TODO: Implement proper callback context handling
        _ = conn;
        _ = result;
    }
    
    /// Called when NA is sent (responder)
    fn onNASent(conn: *tcp_async.AsyncTcpConnection, result: tcp_async.AsyncResult) void {
        // TODO: Implement proper callback context handling
        _ = conn;
        _ = result;
    }
    
    /// Called when proposal is sent (initiator)
    fn onProposalSent(conn: *tcp_async.AsyncTcpConnection, result: tcp_async.AsyncResult) void {
        // TODO: Implement proper callback context handling
        _ = conn;
        _ = result;
    }
    
    /// Complete negotiation with success
    fn completeWithSuccess(self: *Self, protocol: []const u8) void {
        if (self.state == .Completed or self.state == .Failed) return;
        
        self.state = .Completed;
        self.callback(.{ .success = protocol });
    }
    
    /// Complete negotiation with error
    fn completeWithError(self: *Self, err: anyerror) void {
        if (self.state == .Completed or self.state == .Failed) return;
        
        self.state = .Failed;
        self.callback(.{ .failure = err });
    }
};

/// Convenience function to start async negotiation
pub fn negotiateAsync(
    allocator: std.mem.Allocator,
    connection: *tcp_async.AsyncTcpConnection,
    protocols: []const []const u8,
    is_initiator: bool,
    callback: NegotiationCallback,
) !*AsyncSession {
    const session = try AsyncSession.init(allocator, connection, protocols, is_initiator, callback);
    try session.start();
    return session;
}