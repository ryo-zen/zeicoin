// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: MIT

// tcp.zig - TCP transport implementation for libp2p
// Provides connection establishment and management over TCP
// Based on the C++ libp2p TCP transport design

const std = @import("std");
const net = std.Io.net;
const multiaddr = @import("../multiaddr/multiaddr.zig");
const connection_mod = @import("connection.zig");
const Multiaddr = multiaddr.Multiaddr;
const stream_buffer_size = 64 * 1024;

/// TCP connection matching C++ RawConnection interface
pub const TcpConnection = struct {
    stream: net.Stream,
    io: std.Io,
    local_multiaddr: ?Multiaddr,
    remote_multiaddr: ?Multiaddr,
    allocator: std.mem.Allocator,
    is_initiator: bool,
    is_closed: bool,
    socket_closed: bool,
    bytes_read: u64,
    bytes_written: u64,
    rx_buf: [stream_buffer_size]u8 = undefined,
    tx_buf: [stream_buffer_size]u8 = undefined,
    reader: ?net.Stream.Reader = null,
    writer: ?net.Stream.Writer = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, is_initiator: bool) !Self {
        var conn = Self{
            .stream = stream,
            .io = io,
            .local_multiaddr = null,
            .remote_multiaddr = null,
            .allocator = allocator,
            .is_initiator = is_initiator,
            .is_closed = false,
            .socket_closed = false,
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
            self.close(self.io) catch {};
        }
        if (!self.socket_closed) {
            self.stream.close(self.io);
            self.socket_closed = true;
        }
    }

    /// Read some bytes (matches C++ readSome)
    pub fn readSome(self: *Self, io: std.Io, buffer: []u8) !usize {
        if (self.is_closed) return error.ConnectionClosed;
        const reader = self.getReader(io);
        var data = [_][]u8{buffer};
        const n = reader.interface.readVec(&data) catch |err| switch (err) {
            error.EndOfStream => 0,
            error.ReadFailed => return reader.err orelse err,
        };
        self.bytes_read += n;
        return n;
    }

    /// Write some bytes (matches C++ writeSome)
    pub fn writeSome(self: *Self, io: std.Io, data: []const u8) !usize {
        if (self.is_closed) return error.ConnectionClosed;
        const writer = self.getWriter(io);
        writer.interface.writeAll(data) catch {
            return writer.err orelse error.WriteFailed;
        };
        self.bytes_written += data.len;
        return data.len;
    }

    pub fn writeAll(self: *Self, io: std.Io, data: []const u8) !void {
        if (self.is_closed) return error.ConnectionClosed;
        const writer = self.getWriter(io);
        writer.interface.writeAll(data) catch {
            return writer.err orelse error.WriteFailed;
        };
        writer.interface.flush() catch {
            return writer.err orelse error.WriteFailed;
        };
        self.bytes_written += data.len;
    }

    pub fn writeVecAll(self: *Self, io: std.Io, fragments: anytype) !void {
        if (self.is_closed) return error.ConnectionClosed;
        const Fragments = @TypeOf(fragments.*);
        switch (@typeInfo(Fragments)) {
            .array => |array_info| {
                var total_bytes: usize = 0;
                inline for (fragments.*) |fragment| total_bytes += fragment.len;

                var vecs: [array_info.len][]const u8 = fragments.*;
                const writer = self.getWriter(io);
                writer.interface.writeVecAll(&vecs) catch {
                    return writer.err orelse error.WriteFailed;
                };
                writer.interface.flush() catch {
                    return writer.err orelse error.WriteFailed;
                };
                self.bytes_written += total_bytes;
            },
            else => @compileError("writeVecAll expects a pointer to an array of byte slices"),
        }
    }

    pub fn flush(self: *Self, io: std.Io) !void {
        if (self.is_closed or self.writer == null) return;
        const writer = self.getWriter(io);
        writer.interface.flush() catch {
            return writer.err orelse error.WriteFailed;
        };
    }

    /// Close connection (matches C++ close)
    pub fn close(self: *Self, io: std.Io) !void {
        if (!self.is_closed) {
            self.flush(io) catch {};
            self.is_closed = true;
            self.stream.shutdown(io, .both) catch |err| switch (err) {
                error.SocketUnconnected => {},
                else => return err,
            };
        }
    }

    pub fn isClosed(self: *const Self) bool {
        return self.is_closed;
    }

    pub fn isInitiator(self: *const Self) bool {
        return self.is_initiator;
    }

    pub fn connection(self: *Self) connection_mod.Connection {
        return .{ .io = self.io, .ctx = self, .vtable = &connection_vtable };
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
        const remote_str = try formatIpAddressAsMultiaddr(self.allocator, self.stream.socket.address);
        defer self.allocator.free(remote_str);
        self.remote_multiaddr = try Multiaddr.create(self.allocator, remote_str);

        // TODO(0.16): plumb local socket endpoint when needed.
        self.local_multiaddr = null;
    }

    fn getReader(self: *Self, io: std.Io) *net.Stream.Reader {
        if (self.reader == null) {
            self.reader = self.stream.reader(io, &self.rx_buf);
        }
        return &self.reader.?;
    }

    fn getWriter(self: *Self, io: std.Io) *net.Stream.Writer {
        if (self.writer == null) {
            self.writer = self.stream.writer(io, &self.tx_buf);
        }
        return &self.writer.?;
    }

    fn connectionReadSome(ctx: *anyopaque, dest: []u8) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.readSome(self.io, dest);
    }

    fn connectionWriteVecAll(ctx: *anyopaque, fragments: []const []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        if (self.is_closed) return error.ConnectionClosed;

        var total_bytes: usize = 0;
        const writer = self.getWriter(self.io);
        for (fragments) |fragment| {
            writer.interface.writeAll(fragment) catch {
                return writer.err orelse error.WriteFailed;
            };
            total_bytes += fragment.len;
        }
        writer.interface.flush() catch {
            return writer.err orelse error.WriteFailed;
        };
        self.bytes_written += total_bytes;
    }

    fn connectionClose(ctx: *anyopaque) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.close(self.io);
    }

    const connection_vtable = connection_mod.Connection.VTable{
        .readSome = connectionReadSome,
        .writeVecAll = connectionWriteVecAll,
        .close = connectionClose,
    };
};

pub const TcpTransport = struct {
    allocator: std.mem.Allocator,
    listeners: std.array_list.Managed(*Listener),

    const Self = @This();
    pub const DialFuture = std.Io.Future(anyerror!TcpConnection);
    pub const ListenFuture = std.Io.Future(anyerror!*Listener);

    pub const Listener = struct {
        server: net.Server,
        multiaddr: Multiaddr,
        allocator: std.mem.Allocator,
        io: std.Io,
        pub const AcceptFuture = std.Io.Future(anyerror!TcpConnection);

        pub fn deinit(self: *Listener) void {
            self.server.deinit(self.io);
            self.multiaddr.deinit();
        }

        pub fn accept(self: *Listener, io: std.Io) !TcpConnection {
            const stream = try self.server.accept(io);
            // Accepted connections are not initiators
            return TcpConnection.init(self.allocator, io, stream, false);
        }

        pub fn acceptConcurrent(self: *Listener, io: std.Io) std.Io.ConcurrentError!AcceptFuture {
            return io.concurrent(acceptTaskMain, .{ self, io });
        }
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .listeners = std.array_list.Managed(*Listener).init(allocator),
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
    pub fn dial(self: *Self, io: std.Io, addr: *const Multiaddr) !TcpConnection {
        // Check if we can dial this multiaddr
        if (!self.canDial(addr)) {
            return error.UnsupportedMultiaddr;
        }

        const stream = if (addr.getTcpAddress()) |tcp_addr|
            try tcp_addr.connect(io, .{ .mode = .stream })
        else
            try connectDnsMultiaddr(io, addr);

        // Create connection as initiator
        return TcpConnection.init(self.allocator, io, stream, true);
    }

    pub fn dialConcurrent(self: *Self, io: std.Io, addr: *const Multiaddr) std.Io.ConcurrentError!DialFuture {
        return io.concurrent(dialTaskMain, .{ self, io, addr });
    }

    /// Listen on a multiaddr
    pub fn listen(self: *Self, io: std.Io, addr: *const Multiaddr) !*Listener {
        // Extract TCP address from multiaddr
        const tcp_addr = addr.getTcpAddress() orelse {
            return error.InvalidMultiaddr;
        };

        // Create server
        var server = try tcp_addr.listen(io, .{
            .reuse_address = true,
        });

        // Get actual listening address
        const actual_addr = server.socket.address;

        // Create listener with actual address
        const listener = try self.allocator.create(Listener);
        errdefer self.allocator.destroy(listener);

        // Create multiaddr with actual port
        const actual_str = try formatIpAddressAsMultiaddr(self.allocator, actual_addr);
        defer self.allocator.free(actual_str);

        listener.* = .{
            .server = server,
            .multiaddr = try Multiaddr.create(self.allocator, actual_str),
            .allocator = self.allocator,
            .io = io,
        };

        try self.listeners.append(listener);
        return listener;
    }

    pub fn listenConcurrent(self: *Self, io: std.Io, addr: *const Multiaddr) std.Io.ConcurrentError!ListenFuture {
        return io.concurrent(listenTaskMain, .{ self, io, addr });
    }

    /// Check if transport can dial a multiaddr (matches C++ canDial)
    pub fn canDial(self: *const Self, addr: *const Multiaddr) bool {
        _ = self;
        // Must have TCP and a supported dial target family.
        if (!addr.hasProtocol(.tcp)) return false;
        return addr.hasProtocol(.ip4) or
            addr.hasProtocol(.ip6) or
            addr.hasProtocol(.dns) or
            addr.hasProtocol(.dns4) or
            addr.hasProtocol(.dns6) or
            addr.hasProtocol(.dns_addr);
    }

    /// Check if transport can listen on a multiaddr
    pub fn canListen(self: *const Self, addr: *const Multiaddr) bool {
        _ = self;
        return addr.hasProtocol(.tcp) and (addr.hasProtocol(.ip4) or addr.hasProtocol(.ip6));
    }

    /// Get protocol ID (matches C++ getProtocolId)
    pub fn getProtocolId(self: *const Self) []const u8 {
        _ = self;
        return "/tcp/1.0.0";
    }
};

fn acceptTaskMain(listener: *TcpTransport.Listener, io: std.Io) anyerror!TcpConnection {
    return listener.accept(io);
}

fn dialTaskMain(transport: *TcpTransport, io: std.Io, addr: *const Multiaddr) anyerror!TcpConnection {
    return transport.dial(io, addr);
}

fn listenTaskMain(transport: *TcpTransport, io: std.Io, addr: *const Multiaddr) anyerror!*TcpTransport.Listener {
    return transport.listen(io, addr);
}

fn formatIpAddressAsMultiaddr(allocator: std.mem.Allocator, addr: net.IpAddress) ![]u8 {
    return switch (addr) {
        .ip4 => |ip4| std.fmt.allocPrint(
            allocator,
            "/ip4/{d}.{d}.{d}.{d}/tcp/{d}",
            .{ ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3], ip4.port },
        ),
        .ip6 => |ip6| blk: {
            const unresolved: net.Ip6Address.Unresolved = .{
                .bytes = ip6.bytes,
                .interface_name = null,
            };
            break :blk try std.fmt.allocPrint(allocator, "/ip6/{f}/tcp/{d}", .{ unresolved, ip6.port });
        },
    };
}

fn connectDnsMultiaddr(io: std.Io, addr: *const Multiaddr) !net.Stream {
    const dns_info = try getDnsHostInfo(addr);

    const port_text = try addr.getFirstValueForProtocol(.tcp);
    const port = try std.fmt.parseInt(u16, port_text, 10);
    const host_name = try net.HostName.init(dns_info.host);

    var canonical_name_buffer: [net.HostName.max_len]u8 = undefined;
    var lookup_buffer: [16]net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(net.HostName.LookupResult) = .init(&lookup_buffer);
    var lookup_future = io.async(net.HostName.lookup, .{ host_name, io, &lookup_queue, .{
        .port = port,
        .canonical_name_buffer = &canonical_name_buffer,
        .family = dns_info.family,
    } });
    defer lookup_future.cancel(io) catch {};

    var last_connect_error: ?net.IpAddress.ConnectError = null;
    while (lookup_queue.getOne(io)) |dns_result| switch (dns_result) {
        .canonical_name => continue,
        .address => |ip_address| {
            return ip_address.connect(io, .{ .mode = .stream }) catch |err| {
                last_connect_error = err;
                continue;
            };
        },
    } else |err| switch (err) {
        error.Canceled => |e| return e,
        error.Closed => {
            lookup_future.await(io) catch |lookup_err| return lookup_err;
            return last_connect_error orelse error.NoAddressReturned;
        },
    }

    return error.NoAddressReturned;
}

const DnsHostInfo = struct {
    host: []const u8,
    family: ?net.IpAddress.Family,
};

fn getDnsHostInfo(addr: *const Multiaddr) !DnsHostInfo {
    if (addr.getFirstValueForProtocol(.dns4)) |host| {
        return .{ .host = host, .family = .ip4 };
    } else |err| switch (err) {
        error.ProtocolNotFound => {},
        else => return err,
    }
    if (addr.getFirstValueForProtocol(.dns6)) |host| {
        return .{ .host = host, .family = .ip6 };
    } else |err| switch (err) {
        error.ProtocolNotFound => {},
        else => return err,
    }
    if (addr.getFirstValueForProtocol(.dns)) |host| {
        return .{ .host = host, .family = null };
    } else |err| switch (err) {
        error.ProtocolNotFound => {},
        else => return err,
    }
    if (addr.getFirstValueForProtocol(.dns_addr)) |host| {
        return .{ .host = host, .family = null };
    } else |err| switch (err) {
        error.ProtocolNotFound => return error.InvalidMultiaddr,
        else => return err,
    }
}

// Tests
test "TCP transport dial and accept" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var transport = TcpTransport.init(allocator);
    defer transport.deinit();

    // Create listening multiaddr
    var listen_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_addr.deinit();

    var listen_future = try transport.listenConcurrent(io, &listen_addr);
    const listener = try listen_future.await(io);

    // Get actual listening port
    const actual_port = listener.server.socket.address.getPort();

    // Create dial address with actual port
    const dial_str = try std.fmt.allocPrint(allocator, "/ip4/127.0.0.1/tcp/{}", .{actual_port});
    defer allocator.free(dial_str);

    var dial_addr = try Multiaddr.create(allocator, dial_str);
    defer dial_addr.deinit();

    var accept_future = try listener.acceptConcurrent(io);
    defer _ = accept_future.cancel(io) catch {};

    var dial_future = try transport.dialConcurrent(io, &dial_addr);
    var conn = try dial_future.await(io);
    defer conn.deinit();

    var accepted = try accept_future.await(io);
    defer accepted.deinit();

    // Check connection properties
    try std.testing.expect(conn.isInitiator());
    try std.testing.expect(conn.remoteMultiaddr() != null);
    try std.testing.expect(!accepted.isInitiator());
    try std.testing.expect(!accepted.isClosed());

    // Send and receive data
    const msg = "Hello libp2p!";
    try conn.writeAll(io, msg);

    var accepted_buf: [100]u8 = undefined;
    const accepted_n = try accepted.readSome(io, &accepted_buf);
    try accepted.writeAll(io, accepted_buf[0..accepted_n]);

    var buf: [100]u8 = undefined;
    const n = try conn.readSome(io, &buf);
    try std.testing.expectEqualStrings(msg, buf[0..n]);

    // Check byte counters
    try std.testing.expectEqual(@as(u64, msg.len), conn.bytes_written);
    try std.testing.expectEqual(@as(u64, n), conn.bytes_read);

    try std.testing.expectEqual(@as(u64, accepted_n), accepted.bytes_read);
    try std.testing.expectEqual(@as(u64, accepted_n), accepted.bytes_written);
}

test "TCP close wakes blocked read on the same connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var transport = TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_addr.deinit();

    const listener = try transport.listen(io, &listen_addr);
    const actual_port = listener.server.socket.address.getPort();

    const dial_str = try std.fmt.allocPrint(allocator, "/ip4/127.0.0.1/tcp/{}", .{actual_port});
    defer allocator.free(dial_str);

    var dial_addr = try Multiaddr.create(allocator, dial_str);
    defer dial_addr.deinit();

    var accept_future = try listener.acceptConcurrent(io);
    defer _ = accept_future.cancel(io) catch {};

    var dialed = try transport.dial(io, &dial_addr);
    defer dialed.deinit();

    var accepted = try accept_future.await(io);
    defer accepted.deinit();

    const ReaderCtx = struct {
        conn: *TcpConnection,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!usize {
            var buf: [16]u8 = undefined;
            return ctx.conn.readSome(ctx.io, &buf);
        }
    };

    var reader_ctx = ReaderCtx{ .conn = &accepted, .io = io };
    var read_future = try io.concurrent(ReaderCtx.run, .{&reader_ctx});

    try io.sleep(std.Io.Duration.fromMilliseconds(50), .awake);
    try accepted.close(io);

    const result = read_future.await(io) catch |err| switch (err) {
        error.ConnectionClosed,
        error.EndOfStream,
        error.SocketUnconnected,
        => return,
        else => return err,
    };
    try std.testing.expectEqual(@as(usize, 0), result);
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

    var ip6_addr = try Multiaddr.create(allocator, "/ip6/::1/tcp/4001");
    defer ip6_addr.deinit();

    var dns_addr = try Multiaddr.create(allocator, "/dns4/bootstrap.example.com/tcp/4001");
    defer dns_addr.deinit();

    // Can still dial/listen on TCP part even with ws
    try std.testing.expect(transport.canDial(&ws_addr));
    try std.testing.expect(transport.canDial(&ip6_addr));
    try std.testing.expect(transport.canListen(&ip6_addr));
    try std.testing.expect(transport.canDial(&dns_addr));
    try std.testing.expect(!transport.canListen(&dns_addr));

    // Test invalid multiaddr
    var invalid_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/udp/4001");
    defer invalid_addr.deinit();

    try std.testing.expect(!transport.canDial(&invalid_addr));
}

test "format IP address as multiaddr supports ipv6" {
    const allocator = std.testing.allocator;
    const ip = try net.IpAddress.resolve(std.testing.io, "::1", 4001);
    const formatted = try formatIpAddressAsMultiaddr(allocator, ip);
    defer allocator.free(formatted);

    try std.testing.expect(std.mem.startsWith(u8, formatted, "/ip6/"));
    try std.testing.expect(std.mem.endsWith(u8, formatted, "/tcp/4001"));
}
