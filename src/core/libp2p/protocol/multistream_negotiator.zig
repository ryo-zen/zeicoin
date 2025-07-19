// multistream_negotiator.zig - Working async multistream negotiation implementation
// Combines context-aware TCP and streaming parser for complete protocol negotiation

const std = @import("std");
const tcp_context = @import("../transport/tcp_async_context.zig");
const parser = @import("multistream_parser.zig");
const multistream = @import("multistream.zig");

/// Negotiation result
pub const NegotiationResult = union(enum) {
    success: []const u8,  // Selected protocol
    failure: anyerror,
    timeout: void,
};

/// Callback for negotiation completion
pub const NegotiationCallback = *const fn (result: NegotiationResult) void;

/// Negotiation session state
pub const SessionState = enum {
    WaitingForVersionResponse,
    WaitingForProtocolResponse, 
    WaitingForProposal,
    SendingVersionAck,
    SendingProtocolAck,
    SendingNA,
    Completed,
    Failed,
};

/// Async multistream negotiation session
pub const MultistreamNegotiator = struct {
    allocator: std.mem.Allocator,
    connection: *tcp_context.AsyncTcpConnection,
    protocols: []const []const u8,
    is_initiator: bool,
    callback: NegotiationCallback,
    
    // Session state
    state: SessionState,
    current_protocol_index: usize,
    selected_protocol: ?[]const u8,
    multistream_negotiated: bool,
    
    // Message processing
    message_parser: parser.MultistreamParser,
    read_buffer: []u8,
    write_buffer: std.ArrayList(u8),
    
    // Write queue for handling concurrent writes
    write_queue: std.ArrayList([]const u8),
    is_writing: bool,
    
    // Constants
    const NEGOTIATION_TIMEOUT_MS = 5000;
    const READ_BUFFER_SIZE = 4096;
    
    const Self = @This();
    
    pub fn init(
        allocator: std.mem.Allocator,
        connection: *tcp_context.AsyncTcpConnection,
        protocols: []const []const u8,
        is_initiator: bool,
        callback: NegotiationCallback,
    ) !*Self {
        const session = try allocator.create(Self);
        errdefer allocator.destroy(session);
        
        const read_buffer = try allocator.alloc(u8, READ_BUFFER_SIZE);
        errdefer allocator.free(read_buffer);
        
        session.* = .{
            .allocator = allocator,
            .connection = connection,
            .protocols = protocols,
            .is_initiator = is_initiator,
            .callback = callback,
            .state = if (is_initiator) .WaitingForVersionResponse else .WaitingForProposal,
            .current_protocol_index = 0,
            .selected_protocol = null,
            .multistream_negotiated = false,
            .message_parser = parser.MultistreamParser.init(allocator),
            .read_buffer = read_buffer,
            .write_buffer = std.ArrayList(u8).init(allocator),
            .write_queue = std.ArrayList([]const u8).init(allocator),
            .is_writing = false,
        };
        
        return session;
    }
    
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.read_buffer);
        self.write_buffer.deinit();
        
        // Free queued write data
        for (self.write_queue.items) |data| {
            self.allocator.free(data);
        }
        self.write_queue.deinit();
        
        self.message_parser.deinit();
        self.allocator.destroy(self);
    }
    
    /// Start the negotiation process
    pub fn start(self: *Self) !void {
        if (self.is_initiator) {
            try self.sendFirstProposal();
        } else {
            try self.startReading();
        }
    }
    
    /// Send first protocol proposal (initiator)
    fn sendFirstProposal(self: *Self) !void {
        self.write_buffer.clearRetainingCapacity();
        
        if (!self.multistream_negotiated) {
            // Send multistream version + first protocol
            try multistream.writeMessage(self.write_buffer.writer(), multistream.PROTOCOL_ID);
            
            if (self.current_protocol_index < self.protocols.len) {
                const protocol = self.protocols[self.current_protocol_index];
                try multistream.writeMessage(self.write_buffer.writer(), protocol);
            }
        } else {
            // Just send protocol
            if (self.current_protocol_index < self.protocols.len) {
                const protocol = self.protocols[self.current_protocol_index];
                try multistream.writeMessage(self.write_buffer.writer(), protocol);
            }
        }
        
        try self.sendMessage(onFirstProposalSent);
    }
    
    /// Send a prepared message
    fn sendMessage(self: *Self, callback: tcp_context.WriteCallback) !void {
        if (self.is_writing) {
            // Queue the write
            const data_copy = try self.allocator.dupe(u8, self.write_buffer.items);
            try self.write_queue.append(data_copy);
            return;
        }
        
        self.is_writing = true;
        const context = tcp_context.createContext(self);
        try self.connection.asyncWriteWithContext(self.write_buffer.items, callback, context);
    }
    
    /// Start reading for incoming messages
    fn startReading(self: *Self) !void {
        const context = tcp_context.createContext(self);
        try self.connection.asyncReadWithContext(self.read_buffer, onDataRead, context);
    }
    
    /// Process queued writes
    fn processWriteQueue(self: *Self) !void {
        if (self.write_queue.items.len == 0) {
            self.is_writing = false;
            return;
        }
        
        // Get next queued write
        const data = self.write_queue.orderedRemove(0);
        defer self.allocator.free(data);
        
        const context = tcp_context.createContext(self);
        try self.connection.asyncWriteWithContext(data, onQueuedWriteComplete, context);
    }
    
    /// Called when first proposal is sent
    fn onFirstProposalSent(
        conn: *tcp_context.AsyncTcpConnection,
        context: *tcp_context.CallbackContext,
        result: tcp_context.AsyncResult,
    ) void {
        _ = conn;
        const session = context.getUserData(MultistreamNegotiator).?;
        
        switch (result) {
            .success => {
                // Start reading for response
                session.startReading() catch |err| {
                    session.completeWithError(err);
                };
            },
            .failure => |err| {
                session.completeWithError(err);
            },
        }
    }
    
    /// Called when queued write completes
    fn onQueuedWriteComplete(
        conn: *tcp_context.AsyncTcpConnection,
        context: *tcp_context.CallbackContext,
        result: tcp_context.AsyncResult,
    ) void {
        _ = conn;
        const session = context.getUserData(MultistreamNegotiator).?;
        
        switch (result) {
            .success => {
                // Process next queued write
                session.processWriteQueue() catch |err| {
                    session.completeWithError(err);
                };
            },
            .failure => |err| {
                session.completeWithError(err);
            },
        }
    }
    
    /// Called when data is read
    fn onDataRead(
        conn: *tcp_context.AsyncTcpConnection,
        context: *tcp_context.CallbackContext,
        result: tcp_context.AsyncResult,
    ) void {
        _ = conn;
        const session = context.getUserData(MultistreamNegotiator).?;
        
        switch (result) {
            .success => |bytes_read| {
                session.processReceivedData(bytes_read) catch |err| {
                    session.completeWithError(err);
                };
            },
            .failure => |err| {
                session.completeWithError(err);
            },
        }
    }
    
    /// Process received data through parser
    fn processReceivedData(self: *Self, bytes_read: usize) !void {
        if (bytes_read == 0) {
            return self.completeWithError(error.ConnectionClosed);
        }
        
        // Feed data to parser
        const data = self.read_buffer[0..bytes_read];
        const parse_state = try self.message_parser.consume(data);
        
        switch (parse_state) {
            .Ready => {
                // Process any available messages
                try self.processMessages();
                
                // Continue reading if not completed
                if (self.state != .Completed and self.state != .Failed) {
                    try self.startReading();
                }
            },
            .Underflow => {
                // Need more data, continue reading
                try self.startReading();
            },
            .Overflow => {
                return self.completeWithError(error.MessageTooLarge);
            },
            .Error => {
                return self.completeWithError(error.ParseError);
            },
        }
    }
    
    /// Process parsed messages
    fn processMessages(self: *Self) !void {
        while (self.message_parser.popMessage()) |message| {
            try self.handleMessage(message);
            
            if (self.state == .Completed or self.state == .Failed) {
                break;
            }
        }
    }
    
    /// Handle a specific message based on current state
    fn handleMessage(self: *Self, message: parser.ParsedMessage) !void {
        switch (self.state) {
            .WaitingForVersionResponse => try self.handleVersionResponse(message),
            .WaitingForProtocolResponse => try self.handleProtocolResponse(message),
            .WaitingForProposal => try self.handleProposal(message),
            .Completed, .Failed => return,
            else => return self.completeWithError(error.UnexpectedState),
        }
    }
    
    /// Handle version response (initiator)
    fn handleVersionResponse(self: *Self, message: parser.ParsedMessage) !void {
        switch (message.message_type) {
            .RightProtocolVersion => {
                self.multistream_negotiated = true;
                self.state = .WaitingForProtocolResponse;
                // Response to our first protocol proposal should come next
            },
            .WrongProtocolVersion => {
                return self.completeWithError(error.ProtocolVersionMismatch);
            },
            .ProtocolName => {
                // Direct protocol response - check if it matches our proposal
                const proposed = self.protocols[self.current_protocol_index];
                if (std.mem.eql(u8, message.data, proposed)) {
                    return self.completeWithSuccess(proposed);
                } else {
                    return self.completeWithError(error.ProtocolMismatch);
                }
            },
            .NAMessage => {
                // First protocol rejected, try next
                self.current_protocol_index += 1;
                try self.proposeNextProtocol();
            },
            else => {
                return self.completeWithError(error.UnexpectedMessage);
            }
        }
    }
    
    /// Handle protocol response (initiator)  
    fn handleProtocolResponse(self: *Self, message: parser.ParsedMessage) !void {
        switch (message.message_type) {
            .ProtocolName => {
                // Check if it matches our proposal
                const proposed = self.protocols[self.current_protocol_index];
                if (std.mem.eql(u8, message.data, proposed)) {
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
    fn handleProposal(self: *Self, message: parser.ParsedMessage) !void {
        switch (message.message_type) {
            .RightProtocolVersion => {
                // Send version acknowledgment
                try self.sendVersionAck();
            },
            .ProtocolName => {
                // Check if we support this protocol
                for (self.protocols) |supported| {
                    if (std.mem.eql(u8, message.data, supported)) {
                        // Send positive response
                        try self.sendProtocolAck(supported);
                        return;
                    }
                }
                // Not supported, send NA
                try self.sendNA();
            },
            .LSMessage => {
                // List protocols (simplified - just send NA for now)
                try self.sendNA();
            },
            else => {
                return self.completeWithError(error.UnexpectedMessage);
            }
        }
    }
    
    /// Propose next protocol (initiator)
    fn proposeNextProtocol(self: *Self) !void {
        if (self.current_protocol_index >= self.protocols.len) {
            return self.completeWithError(error.NoProtocolMatch);
        }
        
        self.write_buffer.clearRetainingCapacity();
        const protocol = self.protocols[self.current_protocol_index];
        try multistream.writeMessage(self.write_buffer.writer(), protocol);
        try self.sendMessage(onProtocolProposalSent);
    }
    
    /// Send version acknowledgment (responder)
    fn sendVersionAck(self: *Self) !void {
        self.write_buffer.clearRetainingCapacity();
        try multistream.writeMessage(self.write_buffer.writer(), multistream.PROTOCOL_ID);
        self.multistream_negotiated = true;
        try self.sendMessage(onVersionAckSent);
    }
    
    /// Send protocol acknowledgment (responder)
    fn sendProtocolAck(self: *Self, protocol: []const u8) !void {
        self.write_buffer.clearRetainingCapacity();
        try multistream.writeMessage(self.write_buffer.writer(), protocol);
        self.selected_protocol = protocol;
        try self.sendMessage(onProtocolAckSent);
    }
    
    /// Send NA (not available) response
    fn sendNA(self: *Self) !void {
        self.write_buffer.clearRetainingCapacity();
        try multistream.writeMessage(self.write_buffer.writer(), multistream.NA);
        try self.sendMessage(onNASent);
    }
    
    /// Called when protocol proposal is sent
    fn onProtocolProposalSent(
        conn: *tcp_context.AsyncTcpConnection,
        context: *tcp_context.CallbackContext,
        result: tcp_context.AsyncResult,
    ) void {
        _ = conn;
        const session = context.getUserData(MultistreamNegotiator).?;
        
        switch (result) {
            .success => {
                session.state = .WaitingForProtocolResponse;
                // Continue reading handled by main read loop
            },
            .failure => |err| {
                session.completeWithError(err);
            },
        }
    }
    
    /// Called when version ack is sent
    fn onVersionAckSent(
        conn: *tcp_context.AsyncTcpConnection,
        context: *tcp_context.CallbackContext,
        result: tcp_context.AsyncResult,
    ) void {
        _ = conn;
        const session = context.getUserData(MultistreamNegotiator).?;
        
        switch (result) {
            .success => {
                // Continue reading for protocol proposals
            },
            .failure => |err| {
                session.completeWithError(err);
            },
        }
    }
    
    /// Called when protocol ack is sent
    fn onProtocolAckSent(
        conn: *tcp_context.AsyncTcpConnection,
        context: *tcp_context.CallbackContext,
        result: tcp_context.AsyncResult,
    ) void {
        _ = conn;
        const session = context.getUserData(MultistreamNegotiator).?;
        
        switch (result) {
            .success => {
                if (session.selected_protocol) |protocol| {
                    session.completeWithSuccess(protocol);
                } else {
                    session.completeWithError(error.InternalError);
                }
            },
            .failure => |err| {
                session.completeWithError(err);
            },
        }
    }
    
    /// Called when NA is sent
    fn onNASent(
        conn: *tcp_context.AsyncTcpConnection,
        context: *tcp_context.CallbackContext,
        result: tcp_context.AsyncResult,
    ) void {
        _ = conn;
        const session = context.getUserData(MultistreamNegotiator).?;
        
        switch (result) {
            .success => {
                // Continue reading for more proposals
            },
            .failure => |err| {
                session.completeWithError(err);
            },
        }
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
    connection: *tcp_context.AsyncTcpConnection,
    protocols: []const []const u8,
    is_initiator: bool,
    callback: NegotiationCallback,
) !*MultistreamNegotiator {
    const negotiator = try MultistreamNegotiator.init(
        allocator,
        connection,
        protocols,
        is_initiator,
        callback,
    );
    
    try negotiator.start();
    return negotiator;
}