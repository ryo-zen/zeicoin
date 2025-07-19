// tcp_async.zig - Async TCP transport implementation for libp2p
// Provides non-blocking TCP operations with callback-based async I/O

const std = @import("std");
const net = std.net;
const posix = std.posix;
const libp2p = @import("../libp2p_internal.zig");
const Multiaddr = libp2p.Multiaddr;
const ProtocolCode = libp2p.ProtocolCode;

/// Async operation result callback
pub const AsyncResult = union(enum) {
    success: usize,
    failure: anyerror,
};

/// Async TCP connection with non-blocking I/O
pub const AsyncTcpConnection = struct {
    stream: net.Stream,
    local_multiaddr: ?Multiaddr,
    remote_multiaddr: ?Multiaddr,
    allocator: std.mem.Allocator,
    is_initiator: bool,
    is_closed: bool,
    bytes_read: u64,
    bytes_written: u64,
    
    // Async state
    read_buffer: ?[]u8,
    read_callback: ?*const fn (self: *AsyncTcpConnection, result: AsyncResult) void,
    write_data: ?[]const u8,
    write_callback: ?*const fn (self: *AsyncTcpConnection, result: AsyncResult) void,
    
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
            .read_buffer = null,
            .read_callback = null,
            .write_data = null,
            .write_callback = null,
        };
        
        try conn.saveMultiaddresses();
        return conn;
    }
    
    pub fn deinit(self: *Self) void {
        if (self.local_multiaddr) |*ma| {
            ma.deinit();
        }
        if (self.remote_multiaddr) |*ma| {
            ma.deinit();
        }
        if (!self.is_closed) {
            self.close() catch {};
        }
    }
    
    /// Async read with callback
    pub fn asyncRead(self: *Self, buffer: []u8, callback: *const fn (self: *Self, result: AsyncResult) void) !void {
        if (self.is_closed) return error.ConnectionClosed;
        
        // Try immediate read
        const n = self.stream.read(buffer) catch |err| {
            if (err == error.WouldBlock) {
                // Save state for later
                self.read_buffer = buffer;
                self.read_callback = callback;
                return;
            }
            return err;
        };
        
        // Immediate success
        self.bytes_read += n;
        callback(self, .{ .success = n });
    }
    
    /// Async write with callback
    pub fn asyncWrite(self: *Self, data: []const u8, callback: *const fn (self: *Self, result: AsyncResult) void) !void {
        if (self.is_closed) return error.ConnectionClosed;
        
        // Try immediate write
        const n = self.stream.write(data) catch |err| {
            if (err == error.WouldBlock) {
                // Save state for later
                self.write_data = data;
                self.write_callback = callback;
                return;
            }
            return err;
        };
        
        // Immediate success
        self.bytes_written += n;
        callback(self, .{ .success = n });
    }
    
    /// Poll for read readiness
    pub fn pollRead(self: *Self) !void {
        if (self.read_callback == null or self.read_buffer == null) return;
        
        const buffer = self.read_buffer.?;
        const callback = self.read_callback.?;
        
        const n = self.stream.read(buffer) catch |err| {
            if (err == error.WouldBlock) return; // Still not ready
            
            // Clear state and report error
            self.read_buffer = null;
            self.read_callback = null;
            callback(self, .{ .failure = err });
            return;
        };
        
        // Success
        self.bytes_read += n;
        self.read_buffer = null;
        self.read_callback = null;
        callback(self, .{ .success = n });
    }
    
    /// Poll for write readiness
    pub fn pollWrite(self: *Self) !void {
        if (self.write_callback == null or self.write_data == null) return;
        
        const data = self.write_data.?;
        const callback = self.write_callback.?;
        
        const n = self.stream.write(data) catch |err| {
            if (err == error.WouldBlock) return; // Still not ready
            
            // Clear state and report error
            self.write_data = null;
            self.write_callback = null;
            callback(self, .{ .failure = err });
            return;
        };
        
        // Success
        self.bytes_written += n;
        self.write_data = null;
        self.write_callback = null;
        callback(self, .{ .success = n });
    }
    
    pub fn close(self: *Self) !void {
        if (!self.is_closed) {
            self.is_closed = true;
            self.stream.close();
        }
    }
    
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
                            "/ip4/{d}.{d}.{d}.{d}/tcp/{d}",
                            .{ bytes[0], bytes[1], bytes[2], bytes[3], addr.getPort() }
                        );
                    },
                    posix.AF.INET6 => {
                        return error.IPv6NotSupported;
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

/// Async TCP transport with connection timeout support
pub const AsyncTcpTransport = struct {
    allocator: std.mem.Allocator,
    listeners: std.ArrayList(*Listener),
    connections: std.ArrayList(*AsyncTcpConnection),
    
    // Event polling
    poll_thread: ?std.Thread,
    should_stop: bool,
    
    const Self = @This();
    
    pub const Listener = struct {
        server: net.Server,
        multiaddr: Multiaddr,
        allocator: std.mem.Allocator,
        accept_callback: ?*const fn (listener: *Listener, conn: *AsyncTcpConnection) void,
        
        pub fn deinit(self: *Listener) void {
            self.server.deinit();
            self.multiaddr.deinit();
        }
        
        pub fn asyncAccept(self: *Listener, callback: *const fn (listener: *Listener, conn: *AsyncTcpConnection) void) !void {
            self.accept_callback = callback;
            // Set server socket to non-blocking
            const flags = try posix.fcntl(self.server.stream.handle, posix.F.GETFL, 0);
            const O_NONBLOCK = 0x800; // O_NONBLOCK value for Linux
            _ = try posix.fcntl(self.server.stream.handle, posix.F.SETFL, flags | O_NONBLOCK);
        }
        
        pub fn pollAccept(self: *Listener, transport: *AsyncTcpTransport) !void {
            if (self.accept_callback == null) return;
            
            const conn_info = self.server.accept() catch |err| {
                if (err == error.WouldBlock) return;
                return err;
            };
            
            const conn = try transport.allocator.create(AsyncTcpConnection);
            conn.* = try AsyncTcpConnection.init(transport.allocator, conn_info.stream, false);
            try transport.connections.append(conn);
            
            if (self.accept_callback) |cb| {
                cb(self, conn);
            }
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .listeners = std.ArrayList(*Listener).init(allocator),
            .connections = std.ArrayList(*AsyncTcpConnection).init(allocator),
            .poll_thread = null,
            .should_stop = false,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.should_stop = true;
        
        if (self.poll_thread) |thread| {
            thread.join();
        }
        
        for (self.listeners.items) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
        }
        self.listeners.deinit();
        
        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit();
    }
    
    /// Start the event polling thread
    pub fn start(self: *Self) !void {
        self.poll_thread = try std.Thread.spawn(.{}, pollLoop, .{self});
    }
    
    /// Async dial with timeout
    pub fn asyncDial(self: *Self, multiaddr: *const Multiaddr, timeout_ms: u64, callback: *const fn (conn: ?*AsyncTcpConnection) void) !void {
        _ = timeout_ms; // TODO: Implement timeout
        
        if (!self.canDial(multiaddr)) {
            callback(null);
            return;
        }
        
        const tcp_addr = multiaddr.getTcpAddress() orelse {
            callback(null);
            return;
        };
        
        // Create socket
        const family = tcp_addr.any.family;
        const SOCK_NONBLOCK = 0x800; // SOCK_NONBLOCK value for Linux
        const fd = try posix.socket(family, posix.SOCK.STREAM | SOCK_NONBLOCK, 0);
        errdefer posix.close(fd);
        
        // Start non-blocking connect
        posix.connect(fd, &tcp_addr.any, tcp_addr.getOsSockLen()) catch |err| {
            if (err != error.WouldBlock) {
                posix.close(fd);
                callback(null);
                return;
            }
        };
        
        // Create connection object
        const stream = net.Stream{ .handle = fd };
        const conn = try self.allocator.create(AsyncTcpConnection);
        conn.* = try AsyncTcpConnection.init(self.allocator, stream, true);
        try self.connections.append(conn);
        
        // TODO: Set up connect completion callback
        callback(conn);
    }
    
    /// Create async listener
    pub fn listen(self: *Self, multiaddr: *const Multiaddr) !*Listener {
        const tcp_addr = multiaddr.getTcpAddress() orelse {
            return error.InvalidMultiaddr;
        };
        
        const server = try tcp_addr.listen(.{
            .reuse_address = true,
            .reuse_port = true,
        });
        
        const actual_addr = server.listen_address;
        
        const formatAddr = struct {
            fn format(alloc: std.mem.Allocator, addr: net.Address) ![]u8 {
                switch (addr.any.family) {
                    posix.AF.INET => {
                        const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
                        return std.fmt.allocPrint(
                            alloc,
                            "/ip4/{d}.{d}.{d}.{d}/tcp/{d}",
                            .{ bytes[0], bytes[1], bytes[2], bytes[3], addr.getPort() }
                        );
                    },
                    else => return error.UnsupportedAddressFamily,
                }
            }
        }.format;
        
        const actual_str = try formatAddr(self.allocator, actual_addr);
        defer self.allocator.free(actual_str);
        
        const listener = try self.allocator.create(Listener);
        listener.* = .{
            .server = server,
            .multiaddr = try Multiaddr.create(self.allocator, actual_str),
            .allocator = self.allocator,
            .accept_callback = null,
        };
        
        try self.listeners.append(listener);
        return listener;
    }
    
    pub fn canDial(self: *const Self, multiaddr: *const Multiaddr) bool {
        _ = self;
        return multiaddr.hasProtocol(.tcp) and 
               (multiaddr.hasProtocol(.ip4) or multiaddr.hasProtocol(.ip6));
    }
    
    /// Event polling loop
    fn pollLoop(self: *Self) void {
        while (!self.should_stop) {
            // Poll connections
            for (self.connections.items) |conn| {
                conn.pollRead() catch {};
                conn.pollWrite() catch {};
            }
            
            // Poll listeners
            for (self.listeners.items) |listener| {
                listener.pollAccept(self) catch {};
            }
            
            // Small sleep to prevent busy waiting
            std.time.sleep(1 * std.time.ns_per_ms);
        }
    }
};

// Tests
test "async TCP transport" {
    const allocator = std.testing.allocator;
    
    var transport = AsyncTcpTransport.init(allocator);
    defer transport.deinit();
    
    // Start polling
    try transport.start();
    
    // Create listener
    var listen_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_addr.deinit();
    
    const listener = try transport.listen(&listen_addr);
    try std.testing.expect(listener.multiaddr.hasProtocol(.tcp));
}