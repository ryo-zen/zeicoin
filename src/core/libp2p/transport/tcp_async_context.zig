// tcp_async_context.zig - Context-aware async TCP implementation for libp2p
// Supports user context in callbacks, similar to C++ libp2p approach

const std = @import("std");
const net = std.net;
const posix = std.posix;
const libp2p = @import("../libp2p_internal.zig");
const Multiaddr = libp2p.Multiaddr;
const ProtocolCode = libp2p.ProtocolCode;

/// Async operation result
pub const AsyncResult = union(enum) {
    success: usize,
    failure: anyerror,
};

/// Generic callback context - allows storing user data with callbacks
pub const CallbackContext = struct {
    user_data: ?*anyopaque = null,
    
    /// Helper to cast user_data back to specific type
    pub fn getUserData(self: *const CallbackContext, comptime T: type) ?*T {
        if (self.user_data) |data| {
            return @ptrCast(@alignCast(data));
        }
        return null;
    }
    
    /// Helper to set user data
    pub fn setUserData(self: *CallbackContext, data: anytype) void {
        self.user_data = @ptrCast(data);
    }
};

/// Read callback function type with context
pub const ReadCallback = *const fn (
    conn: *AsyncTcpConnection,
    context: *CallbackContext,
    result: AsyncResult,
) void;

/// Write callback function type with context
pub const WriteCallback = *const fn (
    conn: *AsyncTcpConnection,
    context: *CallbackContext,
    result: AsyncResult,
) void;

/// Async operation tracking
const AsyncOperation = struct {
    callback_context: CallbackContext,
    
    // Union to track different operation types
    operation: union(enum) {
        read: struct {
            buffer: []u8,
            callback: ReadCallback,
        },
        write: struct {
            data: []const u8,
            callback: WriteCallback,
        },
    },
};

/// Context-aware async TCP connection
pub const AsyncTcpConnection = struct {
    stream: net.Stream,
    local_multiaddr: ?Multiaddr,
    remote_multiaddr: ?Multiaddr,
    allocator: std.mem.Allocator,
    is_initiator: bool,
    is_closed: bool,
    bytes_read: u64,
    bytes_written: u64,
    
    // Async operation state
    current_operation: ?AsyncOperation,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, stream: net.Stream, is_initiator: bool) !Self {
        // Set socket to non-blocking
        const flags = try posix.fcntl(stream.handle, posix.F.GETFL, 0);
        const O_NONBLOCK = 0x800; // O_NONBLOCK value for Linux
        _ = try posix.fcntl(stream.handle, posix.F.SETFL, flags | O_NONBLOCK);
        
        var conn = Self{
            .stream = stream,
            .local_multiaddr = null,
            .remote_multiaddr = null,
            .allocator = allocator,
            .is_initiator = is_initiator,
            .is_closed = false,
            .bytes_read = 0,
            .bytes_written = 0,
            .current_operation = null,
        };
        
        try conn.saveMultiaddresses();
        return conn;
    }
    
    pub fn deinit(self: *Self) void {
        if (!self.is_closed) {
            self.is_closed = true;
            self.stream.close();
        }
        
        if (self.local_multiaddr) |*addr| {
            addr.deinit();
        }
        if (self.remote_multiaddr) |*addr| {
            addr.deinit();
        }
    }
    
    /// Async read with user context
    pub fn asyncReadWithContext(
        self: *Self,
        buffer: []u8,
        callback: ReadCallback,
        context: CallbackContext,
    ) !void {
        if (self.is_closed) return error.ConnectionClosed;
        if (self.current_operation != null) return error.OperationInProgress;
        
        // Store operation
        self.current_operation = AsyncOperation{
            .callback_context = context,
            .operation = .{
                .read = .{
                    .buffer = buffer,
                    .callback = callback,
                },
            },
        };
        
        // Try immediate read
        self.tryRead();
    }
    
    /// Async write with user context
    pub fn asyncWriteWithContext(
        self: *Self,
        data: []const u8,
        callback: WriteCallback,
        context: CallbackContext,
    ) !void {
        if (self.is_closed) return error.ConnectionClosed;
        if (self.current_operation != null) return error.OperationInProgress;
        
        // Store operation
        self.current_operation = AsyncOperation{
            .callback_context = context,
            .operation = .{
                .write = .{
                    .data = data,
                    .callback = callback,
                },
            },
        };
        
        // Try immediate write
        self.tryWrite();
    }
    
    /// Convenience function without context (for backward compatibility)
    pub fn asyncRead(
        self: *Self,
        buffer: []u8,
        callback: ReadCallback,
    ) !void {
        try self.asyncReadWithContext(buffer, callback, .{});
    }
    
    /// Convenience function without context (for backward compatibility)
    pub fn asyncWrite(
        self: *Self,
        data: []const u8,
        callback: WriteCallback,
    ) !void {
        try self.asyncWriteWithContext(data, callback, .{});
    }
    
    /// Try to perform read operation
    fn tryRead(self: *Self) void {
        if (self.current_operation == null) return;
        
        const operation = &self.current_operation.?;
        if (operation.operation != .read) return;
        
        const read_op = &operation.operation.read;
        const buffer = read_op.buffer;
        
        const n = self.stream.read(buffer) catch |err| {
            if (err == error.WouldBlock) {
                // Would block - operation remains pending
                // In a real implementation, this would be registered with an event loop
                return;
            }
            
            // Complete with error
            self.completeRead(.{ .failure = err });
            return;
        };
        
        // Complete with success
        self.bytes_read += n;
        self.completeRead(.{ .success = n });
    }
    
    /// Try to perform write operation
    fn tryWrite(self: *Self) void {
        if (self.current_operation == null) return;
        
        const operation = &self.current_operation.?;
        if (operation.operation != .write) return;
        
        const write_op = &operation.operation.write;
        const data = write_op.data;
        
        const n = self.stream.write(data) catch |err| {
            if (err == error.WouldBlock) {
                // Would block - operation remains pending
                return;
            }
            
            // Complete with error
            self.completeWrite(.{ .failure = err });
            return;
        };
        
        // Complete with success
        self.bytes_written += n;
        self.completeWrite(.{ .success = n });
    }
    
    /// Complete read operation and call callback
    fn completeRead(self: *Self, result: AsyncResult) void {
        if (self.current_operation == null) return;
        
        const operation = self.current_operation.?;
        if (operation.operation != .read) return;
        
        const read_op = operation.operation.read;
        var context = operation.callback_context;
        
        // Clear operation before calling callback
        self.current_operation = null;
        
        // Call callback with context
        read_op.callback(self, &context, result);
    }
    
    /// Complete write operation and call callback
    fn completeWrite(self: *Self, result: AsyncResult) void {
        if (self.current_operation == null) return;
        
        const operation = self.current_operation.?;
        if (operation.operation != .write) return;
        
        const write_op = operation.operation.write;
        var context = operation.callback_context;
        
        // Clear operation before calling callback
        self.current_operation = null;
        
        // Call callback with context
        write_op.callback(self, &context, result);
    }
    
    /// Check if operation is pending (for event loops)
    pub fn hasPendingOperation(self: *const Self) bool {
        return self.current_operation != null;
    }
    
    /// Process pending operations (called by event loop)
    pub fn processPendingOperations(self: *Self) void {
        if (self.current_operation == null) return;
        
        switch (self.current_operation.?.operation) {
            .read => self.tryRead(),
            .write => self.tryWrite(),
        }
    }
    
    /// Save multiaddresses from socket endpoints
    fn saveMultiaddresses(self: *Self) !void {
        var local_addr: net.Address = undefined;
        var local_addr_len: posix.socklen_t = @sizeOf(net.Address);
        try posix.getsockname(self.stream.handle, &local_addr.any, &local_addr_len);
        
        var remote_addr: net.Address = undefined;
        var remote_addr_len: posix.socklen_t = @sizeOf(net.Address);
        try posix.getpeername(self.stream.handle, &remote_addr.any, &remote_addr_len);
        
        const formatAddr = struct {
            fn format(alloc: std.mem.Allocator, addr: net.Address) ![]u8 {
                switch (addr.any.family) {
                    posix.AF.INET => {
                        const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
                        return std.fmt.allocPrint(
                            alloc,
                            "/ip4/{}.{}.{}.{}/tcp/{}",
                            .{ bytes[0], bytes[1], bytes[2], bytes[3], addr.getPort() },
                        );
                    },
                    posix.AF.INET6 => {
                        // Simplified IPv6 - real implementation would format properly
                        return std.fmt.allocPrint(alloc, "/ip6/::1/tcp/{}", .{addr.getPort()});
                    },
                    else => return error.UnsupportedAddressFamily,
                }
            }
        }.format;
        
        const local_str = try formatAddr(self.allocator, local_addr);
        defer self.allocator.free(local_str);
        self.local_multiaddr = try Multiaddr.create(self.allocator, local_str);
        
        const remote_str = try formatAddr(self.allocator, remote_addr);
        defer self.allocator.free(remote_str);
        self.remote_multiaddr = try Multiaddr.create(self.allocator, remote_str);
    }
};

/// Helper to create callback context with user data
pub fn createContext(data: anytype) CallbackContext {
    var context = CallbackContext{};
    context.setUserData(data);
    return context;
}