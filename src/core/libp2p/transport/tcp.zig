// tcp.zig - TCP transport implementation for libp2p
// Provides connection establishment and management over TCP
// Based on the C++ libp2p TCP transport design

const std = @import("std");
const net = std.net;
const libp2p = @import("../libp2p_internal.zig");
const Multiaddr = libp2p.Multiaddr;
const ProtocolCode = libp2p.ProtocolCode;

/// TCP connection matching C++ RawConnection interface
pub const TcpConnection = struct {
    stream: net.Stream,
    local_multiaddr: ?Multiaddr,
    remote_multiaddr: ?Multiaddr,
    allocator: std.mem.Allocator,
    is_initiator: bool,
    is_closed: bool,
    bytes_read: u64,
    bytes_written: u64,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, stream: net.Stream, is_initiator: bool) !Self {
        var conn = Self{
            .stream = stream,
            .local_multiaddr = null,
            .remote_multiaddr = null,
            .allocator = allocator,
            .is_initiator = is_initiator,
            .is_closed = false,
            .bytes_read = 0,
            .bytes_written = 0,
        };
        
        // Save multiaddresses like C++ saveMultiaddresses()
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
    
    /// Read some bytes (matches C++ readSome)
    pub fn readSome(self: *Self, buffer: []u8) !usize {
        if (self.is_closed) return error.ConnectionClosed;
        const n = try self.stream.read(buffer);
        self.bytes_read += n;
        return n;
    }
    
    /// Write some bytes (matches C++ writeSome)
    pub fn writeSome(self: *Self, data: []const u8) !usize {
        if (self.is_closed) return error.ConnectionClosed;
        const n = try self.stream.write(data);
        self.bytes_written += n;
        return n;
    }
    
    pub fn writeAll(self: *Self, data: []const u8) !void {
        if (self.is_closed) return error.ConnectionClosed;
        try self.stream.writeAll(data);
        self.bytes_written += data.len;
    }
    
    /// Close connection (matches C++ close)
    pub fn close(self: *Self) !void {
        if (!self.is_closed) {
            self.is_closed = true;
            self.stream.close();
        }
    }
    
    pub fn isClosed(self: *const Self) bool {
        return self.is_closed;
    }
    
    pub fn isInitiator(self: *const Self) bool {
        return self.is_initiator;
    }
    
    /// Get local multiaddr (matches C++ localMultiaddr)
    pub fn localMultiaddr(self: *const Self) ?Multiaddr {
        return self.local_multiaddr;
    }
    
    /// Get remote multiaddr (matches C++ remoteMultiaddr)
    pub fn remoteMultiaddr(self: *const Self) ?Multiaddr {
        return self.remote_multiaddr;
    }
    
    /// Save multiaddresses from socket (matches C++ saveMultiaddresses)
    fn saveMultiaddresses(self: *Self) !void {
        var local_addr: net.Address = undefined;
        var local_addr_len: std.posix.socklen_t = @sizeOf(net.Address);
        try std.posix.getsockname(self.stream.handle, &local_addr.any, &local_addr_len);
        
        var remote_addr: net.Address = undefined;
        var remote_addr_len: std.posix.socklen_t = @sizeOf(net.Address);
        try std.posix.getpeername(self.stream.handle, &remote_addr.any, &remote_addr_len);
        
        // Helper function to format address
        const formatAddr = struct {
            fn format(alloc: std.mem.Allocator, addr: net.Address) ![]u8 {
                switch (addr.any.family) {
                    std.posix.AF.INET => {
                        const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
                        return std.fmt.allocPrint(
                            alloc,
                            "/ip4/{d}.{d}.{d}.{d}/tcp/{d}",
                            .{ bytes[0], bytes[1], bytes[2], bytes[3], addr.getPort() }
                        );
                    },
                    std.posix.AF.INET6 => {
                        // TODO: Implement IPv6 formatting
                        return error.IPv6NotSupported;
                    },
                    else => return error.UnsupportedAddressFamily,
                }
            }
        }.format;
        
        // Create local multiaddr
        const local_str = try formatAddr(self.allocator, local_addr);
        defer self.allocator.free(local_str);
        self.local_multiaddr = try Multiaddr.create(self.allocator, local_str);
        
        // Create remote multiaddr
        const remote_str = try formatAddr(self.allocator, remote_addr);
        defer self.allocator.free(remote_str);
        self.remote_multiaddr = try Multiaddr.create(self.allocator, remote_str);
    }
};

pub const TcpTransport = struct {
    allocator: std.mem.Allocator,
    listeners: std.ArrayList(*Listener),
    
    const Self = @This();
    
    pub const Listener = struct {
        server: net.Server,
        multiaddr: Multiaddr,
        allocator: std.mem.Allocator,
        
        pub fn deinit(self: *Listener) void {
            self.server.deinit();
            self.multiaddr.deinit();
        }
        
        pub fn accept(self: *Listener) !TcpConnection {
            const conn = try self.server.accept();
            // Accepted connections are not initiators
            return TcpConnection.init(self.allocator, conn.stream, false);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .listeners = std.ArrayList(*Listener).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        for (self.listeners.items) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
        }
        self.listeners.deinit();
    }
    
    /// Dial a multiaddr and return a connection (matches C++ dial)
    pub fn dial(self: *Self, multiaddr: *const Multiaddr) !TcpConnection {
        // Check if we can dial this multiaddr
        if (!self.canDial(multiaddr)) {
            return error.UnsupportedMultiaddr;
        }
        
        // Extract TCP address from multiaddr
        const tcp_addr = multiaddr.getTcpAddress() orelse {
            return error.InvalidMultiaddr;
        };
        
        // Connect to the address
        const stream = try net.tcpConnectToAddress(tcp_addr);
        
        // Create connection as initiator
        return TcpConnection.init(self.allocator, stream, true);
    }
    
    /// Listen on a multiaddr
    pub fn listen(self: *Self, multiaddr: *const Multiaddr) !*Listener {
        // Extract TCP address from multiaddr
        const tcp_addr = multiaddr.getTcpAddress() orelse {
            return error.InvalidMultiaddr;
        };
        
        // Create server
        const server = try tcp_addr.listen(.{
            .reuse_address = true,
            .reuse_port = true,
        });
        
        // Get actual listening address
        const actual_addr = server.listen_address;
        
        // Create listener with actual address
        const listener = try self.allocator.create(Listener);
        errdefer self.allocator.destroy(listener);
        
        // Create multiaddr with actual port
        const actual_str = blk: {
            // Handle both IPv4 and IPv6
            switch (actual_addr.any.family) {
                std.posix.AF.INET => {
                    const bytes = @as(*const [4]u8, @ptrCast(&actual_addr.in.sa.addr));
                    break :blk try std.fmt.allocPrint(
                        self.allocator,
                        "/ip4/{d}.{d}.{d}.{d}/tcp/{d}",
                        .{ bytes[0], bytes[1], bytes[2], bytes[3], actual_addr.getPort() }
                    );
                },
                std.posix.AF.INET6 => {
                    // TODO: Implement IPv6 formatting
                    return error.IPv6NotSupported;
                },
                else => return error.UnsupportedAddressFamily,
            }
        };
        defer self.allocator.free(actual_str);
        
        listener.* = .{
            .server = server,
            .multiaddr = try Multiaddr.create(self.allocator, actual_str),
            .allocator = self.allocator,
        };
        
        try self.listeners.append(listener);
        return listener;
    }
    
    /// Check if transport can dial a multiaddr (matches C++ canDial)
    pub fn canDial(self: *const Self, multiaddr: *const Multiaddr) bool {
        _ = self;
        // Must have TCP and either IP4 or IP6
        if (!multiaddr.hasProtocol(.tcp)) return false;
        return multiaddr.hasProtocol(.ip4) or multiaddr.hasProtocol(.ip6);
    }
    
    /// Check if transport can listen on a multiaddr
    pub fn canListen(self: *const Self, multiaddr: *const Multiaddr) bool {
        return self.canDial(multiaddr); // Same requirements
    }
    
    /// Get protocol ID (matches C++ getProtocolId)
    pub fn getProtocolId(self: *const Self) []const u8 {
        _ = self;
        return "/tcp/1.0.0";
    }
    
};

// Tests
test "TCP transport dial and accept" {
    const allocator = std.testing.allocator;
    
    var transport = TcpTransport.init(allocator);
    defer transport.deinit();
    
    // Create listening multiaddr
    var listen_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_addr.deinit();
    
    // Start listener
    const listener = try transport.listen(&listen_addr);
    
    // Get actual listening port
    const actual_port = listener.server.listen_address.getPort();
    
    // Create dial address with actual port
    const dial_str = try std.fmt.allocPrint(allocator, "/ip4/127.0.0.1/tcp/{}", .{actual_port});
    defer allocator.free(dial_str);
    
    var dial_addr = try Multiaddr.create(allocator, dial_str);
    defer dial_addr.deinit();
    
    // Spawn accept thread
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn accept(l: *TcpTransport.Listener) !void {
            var conn = try l.accept();
            defer conn.deinit();
            
            // Check connection properties
            try std.testing.expect(!conn.isInitiator());
            try std.testing.expect(!conn.isClosed());
            
            // Echo received data
            var buf: [100]u8 = undefined;
            const n = try conn.readSome(&buf);
            try conn.writeAll(buf[0..n]);
        }
    }.accept, .{listener});
    
    // Give accept thread time to start
    std.time.sleep(10 * std.time.ns_per_ms);
    
    // Dial the listener
    var conn = try transport.dial(&dial_addr);
    defer conn.deinit();
    
    // Check connection properties
    try std.testing.expect(conn.isInitiator());
    try std.testing.expect(conn.localMultiaddr() != null);
    try std.testing.expect(conn.remoteMultiaddr() != null);
    
    // Send and receive data
    const msg = "Hello libp2p!";
    try conn.writeAll(msg);
    
    var buf: [100]u8 = undefined;
    const n = try conn.readSome(&buf);
    try std.testing.expectEqualStrings(msg, buf[0..n]);
    
    // Check byte counters
    try std.testing.expectEqual(@as(u64, msg.len), conn.bytes_written);
    try std.testing.expectEqual(@as(u64, n), conn.bytes_read);
    
    accept_thread.join();
}

test "transport capabilities" {
    const allocator = std.testing.allocator;
    
    var transport = TcpTransport.init(allocator);
    defer transport.deinit();
    
    var tcp_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/4001");
    defer tcp_addr.deinit();
    
    try std.testing.expect(transport.canDial(&tcp_addr));
    try std.testing.expect(transport.canListen(&tcp_addr));
    try std.testing.expectEqualStrings("/tcp/1.0.0", transport.getProtocolId());
    
    var ws_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/4001/ws");
    defer ws_addr.deinit();
    
    // Can still dial/listen on TCP part even with ws
    try std.testing.expect(transport.canDial(&ws_addr));
    
    // Test invalid multiaddr
    var invalid_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/udp/4001");
    defer invalid_addr.deinit();
    
    try std.testing.expect(!transport.canDial(&invalid_addr));
}